"""PhishDestroy CT log lookup — subdomain enumeration via crt.sh.

Queries the crt.sh JSON endpoint for certificate transparency log entries
associated with a given domain.  Handles 429 rate-limit responses with
exponential back-off (2^n seconds, capped at ``_RATELIMIT_CAP``, up to
``_MAX_RETRIES`` retries).

Entry point::

    from ssi.osint.ctlog_lookup import scan
    entries = scan("example.com")
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

logger = logging.getLogger(__name__)

_CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
_INGEST_JOB = "ssi.osint.ctlog_lookup"


@dataclass
class CTLogEntry:
    """A single certificate transparency log entry for a domain."""

    domain: str
    entry_id: int
    not_before: str
    issuer: str
    source_provenance: dict


# ── Internal helpers ──────────────────────────────────────────────────────────


def _get_ratelimit_settings() -> tuple[int, int]:
    """Return (cap_seconds, max_retries) from settings, with safe defaults."""
    try:
        from ssi.settings import get_settings

        s = get_settings()
        return s.phishdestroy.ctlog_ratelimit_cap_seconds, s.phishdestroy.ctlog_ratelimit_max_retries
    except Exception:
        return 30, 5


def _fetch_with_backoff(
    url: str,
    http_client: httpx.Client,
    cap_seconds: int,
    max_retries: int,
    _sleep: type[None] | None = None,  # injected in tests via monkeypatch
) -> httpx.Response:
    """Fetch *url* with exponential back-off on HTTP 429 responses."""
    for attempt in range(max_retries + 1):
        resp = http_client.get(url, timeout=30.0, follow_redirects=True)
        if resp.status_code != 429:
            return resp
        if attempt >= max_retries:
            resp.raise_for_status()  # surface the 429 to caller after exhausted retries
        delay = min(2**attempt, cap_seconds)
        logger.info(
            "crt.sh rate-limited (attempt %d/%d) — sleeping %.0fs",
            attempt + 1,
            max_retries + 1,
            delay,
        )
        time.sleep(delay)
    # unreachable, but satisfies type checkers
    return resp  # type: ignore[return-value]


# ── Public entry point ────────────────────────────────────────────────────────


def scan(
    domain: str,
    *,
    http_client: httpx.Client | None = None,
) -> list[CTLogEntry]:
    """Return CT log entries for *domain* from crt.sh.

    Args:
        domain: The domain to enumerate subdomains for.
        http_client: Injected HTTP client (use ``httpx.MockTransport`` in tests).

    Returns:
        List of ``CTLogEntry`` objects, deduplicated by entry_id.
    """
    cap_seconds, max_retries = _get_ratelimit_settings()
    url = _CRTSH_URL.format(domain=domain)
    ingested_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    own_client = http_client is None
    client = http_client or httpx.Client()

    try:
        resp = _fetch_with_backoff(url, client, cap_seconds, max_retries)
        resp.raise_for_status()
        rows = resp.json()
    except Exception as exc:
        logger.warning("crt.sh lookup failed for %r: %s", domain, exc)
        return []
    finally:
        if own_client:
            client.close()

    if not isinstance(rows, list):
        logger.warning("crt.sh returned unexpected shape for %r", domain)
        return []

    seen_ids: set[int] = set()
    entries: list[CTLogEntry] = []

    for row in rows:
        if not isinstance(row, dict):
            continue
        entry_id = row.get("id")
        if not isinstance(entry_id, int) or entry_id in seen_ids:
            continue
        seen_ids.add(entry_id)

        name = str(row.get("name_value") or row.get("common_name") or "").strip()
        not_before = str(row.get("not_before") or "")
        issuer = str(row.get("issuer_name") or "")

        entries.append(
            CTLogEntry(
                domain=name,
                entry_id=entry_id,
                not_before=not_before,
                issuer=issuer,
                source_provenance={
                    "source": "ctlog.crtsh",
                    "commit_sha": hashlib.sha1(f"{domain}:{entry_id}".encode()).hexdigest(),
                    "record_id": f"crtsh:{entry_id}",
                    "ingested_at": ingested_at,
                    "ingest_job": _INGEST_JOB,
                },
            )
        )

    return entries
