"""PhishDestroy blocklist aggregator — queries 8 community blocklist feeds.

Emits one ``BlocklistRecord`` per ``(indicator, source)`` pair.  Results are
cached to a temp-dir file keyed by ``sha256(url + ingest_date_bucket)`` with a
6-hour TTL.  A per-source circuit breaker skips a source after 3 consecutive
failures in a single scan run.

Entry point::

    from ssi.osint.blocklist_aggregator import scan
    for record in scan():
        ...
"""

from __future__ import annotations

import hashlib
import json
import logging
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from ssi.osint import with_retries

logger = logging.getLogger(__name__)

# ── Source registry ───────────────────────────────────────────────────────────
# Keys match the ``source`` controlled vocabulary in the provenance contract §3.
_SOURCES: dict[str, str] = {
    "blocklist.metamask": ("https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/config.json"),
    "blocklist.scamsniffer": (
        "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json"
    ),
    "blocklist.openphish": "https://openphish.com/feed.txt",
    "blocklist.seal": ("https://raw.githubusercontent.com/security-alliance/phishing-list/main/list.txt"),
    "blocklist.enkrypt": (
        "https://raw.githubusercontent.com/enkryptcom/scam-lists/main/lists/phishing-domains-list.txt"
    ),
    "blocklist.phishdestroy": ("https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json"),
    "blocklist.polkadot": "https://polkadot.js.org/phishing/all.json",
    "blocklist.cryptofirewall": (
        "https://raw.githubusercontent.com/CryptoFirewall/cryptofirewall-data/main/domains.txt"
    ),
}

_CACHE_DIR = Path(tempfile.gettempdir()) / "ssi_blocklist_cache"
_CIRCUIT_BREAKER_THRESHOLD = 3
_INGEST_JOB = "ssi.osint.blocklist_aggregator"


@dataclass
class BlocklistRecord:
    """A single indicator emitted by the blocklist aggregator."""

    indicator: str
    source: str
    source_provenance: dict


# ── Internal helpers ──────────────────────────────────────────────────────────


def _ingest_bucket(now: datetime) -> str:
    """Round *now* down to the nearest 6-hour ingest window label."""
    bucket_hour = (now.hour // 6) * 6
    return now.strftime(f"%Y-%m-%d-{bucket_hour:02d}h")


def _cache_path(url: str, bucket: str) -> Path:
    key = hashlib.sha256(f"{url}:{bucket}".encode()).hexdigest()
    return _CACHE_DIR / f"{key}.json"


def _record_id(indicator: str, source: str) -> str:
    """Return deterministic ``record_id`` per provenance §2 for blocklist sources."""
    return hashlib.sha256(f"{indicator}|{source}".encode()).hexdigest()


def _content_fingerprint(data: bytes) -> str:
    """Return a 40-char SHA-1 content fingerprint used as ``commit_sha`` for live feeds."""
    return hashlib.sha1(data).hexdigest()  # noqa: S324 — content fingerprint only, not security


def _normalize_indicator(raw: str) -> str:
    """Strip URL scheme and path, leaving just the hostname."""
    raw = raw.strip().lower()
    # Strip scheme
    for scheme in ("https://", "http://"):
        if raw.startswith(scheme):
            raw = raw[len(scheme) :]
            break
    # Strip path, port, query
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    return raw


def _parse_domains(source: str, raw: bytes) -> list[str]:
    """Parse domain list from raw HTTP response bytes for a given *source*."""
    text = raw.decode("utf-8", errors="replace").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Plain-text newline-separated list (openphish, enkrypt, seal, cryptofirewall)
        return [_normalize_indicator(line) for line in text.splitlines() if "." in line and line.strip()]

    # JSON variants:
    if isinstance(data, list):
        # ScamSniffer: ["domain1", "domain2", ...]
        return [_normalize_indicator(str(d)) for d in data if isinstance(d, str) and "." in d]

    if isinstance(data, dict):
        # MetaMask: {"blacklist": [...], ...}
        if "blacklist" in data:
            return [_normalize_indicator(str(d)) for d in data["blacklist"] if isinstance(d, str) and "." in d]
        # PhishDestroy: {"domains": [...]} or {"list": [...]}
        for key in ("domains", "list", "entries"):
            if key in data and isinstance(data[key], list):
                return [_normalize_indicator(str(d)) for d in data[key] if isinstance(d, str) and "." in d]
        # Polkadot: {"deny": ["domain", ...], ...}
        if "deny" in data:
            items: list[str] = []
            deny = data["deny"]
            if isinstance(deny, list):
                items = [_normalize_indicator(str(d)) for d in deny if isinstance(d, str) and "." in d]
            elif isinstance(deny, dict):
                for v in deny.values():
                    if isinstance(v, list):
                        items.extend(_normalize_indicator(str(d)) for d in v if isinstance(d, str) and "." in d)
            return items

    return []


@with_retries(max_retries=2, backoff_seconds=1.0, retryable_exceptions=(httpx.TransportError,))
def _fetch(url: str, http_client: httpx.Client) -> httpx.Response:
    return http_client.get(url, timeout=20.0, follow_redirects=True)


def _load_from_cache(path: Path) -> list[str] | None:
    """Return cached domain list if fresh, else ``None``."""
    if path.is_file():
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _save_to_cache(path: Path, domains: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(domains, f)


# ── Public entry point ────────────────────────────────────────────────────────


def scan(
    *,
    now: datetime | None = None,
    http_client: httpx.Client | None = None,
    cache_dir: Path | None = None,
) -> Iterable[BlocklistRecord]:
    """Scan all 8 blocklist sources and yield one ``BlocklistRecord`` per indicator.

    Args:
        now: Timestamp used for the ingest-date cache bucket (defaults to UTC now).
        http_client: Injected HTTP client (use ``httpx.MockTransport`` in tests).
        cache_dir: Override the cache directory (inject a ``tmp_path`` in tests).
    """
    now = now or datetime.now(UTC)
    bucket = _ingest_bucket(now)
    ingested_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    own_client = http_client is None
    client = http_client or httpx.Client()
    effective_cache_dir = cache_dir or _CACHE_DIR

    consecutive_failures: dict[str, int] = {}

    try:
        for source, url in _SOURCES.items():
            if consecutive_failures.get(source, 0) >= _CIRCUIT_BREAKER_THRESHOLD:
                logger.warning(
                    "Blocklist circuit breaker open",
                    extra={"event": "provider_skipped", "source": source},
                )
                continue

            cache = _cache_path(url, bucket)
            cache = effective_cache_dir / cache.name  # scope to effective_cache_dir
            domains = _load_from_cache(cache)

            if domains is None:
                try:
                    resp = _fetch(url, client)
                    resp.raise_for_status()
                    raw = resp.content
                    fingerprint = _content_fingerprint(raw)
                    domains = _parse_domains(source, raw)
                    _save_to_cache(cache, domains)
                except Exception as exc:
                    consecutive_failures[source] = consecutive_failures.get(source, 0) + 1
                    logger.warning(
                        "Blocklist source fetch failed (%d/%d): %s",
                        consecutive_failures[source],
                        _CIRCUIT_BREAKER_THRESHOLD,
                        exc,
                        extra={"event": "provider_skipped", "source": source},
                    )
                    if consecutive_failures[source] >= _CIRCUIT_BREAKER_THRESHOLD:
                        logger.warning(
                            "Circuit breaker tripped for source after repeated failures",
                            extra={"event": "provider_skipped", "source": source},
                        )
                    continue
            else:
                # Cached — use a placeholder fingerprint (content unchanged within window)
                fingerprint = _content_fingerprint(f"{url}:{bucket}".encode())

            for domain in domains:
                domain = _normalize_indicator(domain)
                if not domain:
                    continue
                yield BlocklistRecord(
                    indicator=domain,
                    source=source,
                    source_provenance={
                        "source": source,
                        "commit_sha": fingerprint,
                        "record_id": _record_id(domain, source),
                        "ingested_at": ingested_at,
                        "ingest_job": _INGEST_JOB,
                    },
                )
    finally:
        if own_client:
            client.close()
