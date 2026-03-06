"""eCrimeX (eCX) Inbound Poller Service — Phase 3: Orchestrate.

Polls eCX modules for new records since the last known ``record_id`` and
optionally triggers SSI investigations for qualifying phish URLs.

Each polling cycle:
  1. Read the last-polled cursor from the ``ecx_polling_state`` table.
  2. Query eCX ``/search`` for records with ``id > last_polled_id``.
  3. Apply configurable filters (confidence threshold, brands, TLDs).
  4. Deduplicate against existing SSI investigations.
  5. Optionally trigger SSI investigations for new phish URLs.
  6. Update the polling cursor.

The poller is designed to run as a Cloud Run Job on a Cloud Scheduler
cadence (default 15 min) or ad-hoc via ``ssi ecx poll``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ssi.osint.ecrimex import ECXClient
    from ssi.store.scan_store import ScanStore

logger = logging.getLogger(__name__)

# Modules that the poller supports
POLLABLE_MODULES = ("phish", "malicious-domain", "malicious-ip", "cryptocurrency-addresses")

# eCX search field sets per module (must match ECXClient search patterns)
_MODULE_SEARCH_FIELDS: dict[str, list[str]] = {
    "phish": ["id", "url", "brand", "confidence", "status", "discoveredAt", "ip", "asn", "tld", "createdAt"],
    "malicious-domain": ["id", "domain", "classification", "confidence", "status", "discoveredAt"],
    "malicious-ip": ["id", "ip", "brand", "description", "confidence", "status", "asn", "port", "discoveredAt"],
    "cryptocurrency-addresses": [
        "id",
        "currency",
        "address",
        "crimeCategory",
        "siteLink",
        "confidence",
        "status",
        "discoveredAt",
    ],
}


class ECXPoller:
    """Inbound intelligence poller for the eCrimeX data clearinghouse.

    Queries configured eCX modules for new records since the last poll
    cycle and optionally triggers SSI investigations.

    Args:
        client: Authenticated :class:`~ssi.osint.ecrimex.ECXClient`.
        store: :class:`~ssi.store.scan_store.ScanStore` for polling state
            and deduplication queries.
    """

    def __init__(self, client: ECXClient, store: ScanStore) -> None:
        self._client = client
        self._store = store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_poll_cycle(self) -> dict[str, Any]:
        """Execute a full polling cycle across all configured modules.

        Returns:
            Summary dict with per-module counts and overall totals::

                {
                    "modules": {"phish": {"new": 5, "filtered": 2, "triggered": 3}},
                    "total_new": 5,
                    "total_triggered": 3,
                    "errors": [],
                }
        """
        from ssi.settings import get_settings

        settings = get_settings().ecx
        modules = [m for m in settings.polling_modules if m in POLLABLE_MODULES]

        if not modules:
            logger.warning("No valid polling modules configured — nothing to poll")
            return {"modules": {}, "total_new": 0, "total_triggered": 0, "errors": ["no valid modules"]}

        summary: dict[str, Any] = {"modules": {}, "total_new": 0, "total_triggered": 0, "errors": []}

        for module in modules:
            try:
                result = self.poll_module(module)
                summary["modules"][module] = result
                summary["total_new"] += result.get("new", 0)
                summary["total_triggered"] += result.get("triggered", 0)
            except Exception as exc:
                msg = f"{module}: {type(exc).__name__}: {exc}"
                logger.error("Polling failed for module %s: %s", module, msg)
                summary["errors"].append(msg)
                summary["modules"][module] = {"new": 0, "filtered": 0, "triggered": 0, "error": msg}

        logger.info(
            "Poll cycle complete: %d new records across %d modules, %d investigations triggered",
            summary["total_new"],
            len(modules),
            summary["total_triggered"],
        )
        return summary

    def poll_module(self, module: str) -> dict[str, Any]:
        """Poll a single eCX module for new records.

        Args:
            module: eCX module name (e.g. ``"phish"``).

        Returns:
            Dict with ``new``, ``filtered``, ``triggered``, and
            ``last_id`` counts.
        """
        from ssi.settings import get_settings

        settings = get_settings().ecx

        if module not in POLLABLE_MODULES:
            raise ValueError(f"Unsupported polling module: {module!r}")

        # Read cursor
        state = self._store.get_polling_state(module)
        last_id = state["last_polled_id"] if state else 0

        # Query eCX for records newer than our cursor
        records = self._fetch_new_records(module, since_id=last_id)

        if not records:
            logger.debug("No new records in %s since ID %d", module, last_id)
            self._store.upsert_polling_state(module, last_polled_id=last_id, records_found=0, errors=0)
            return {"new": 0, "filtered": 0, "triggered": 0, "last_id": last_id}

        # Sort by ID ascending and find the new high-water mark
        records.sort(key=lambda r: r.get("id", 0))
        new_last_id = max(r.get("id", 0) for r in records)
        new_count = len(records)

        # Apply configurable filters
        filtered = self._apply_filters(records, settings)
        filtered_out = new_count - len(filtered)

        # Deduplicate against existing SSI investigations
        deduped = self._deduplicate(filtered, module)

        # Trigger investigations for qualifying records
        triggered = 0
        if settings.polling_auto_investigate and deduped:
            triggered = self._trigger_investigations(deduped, module)

        # Update cursor
        self._store.upsert_polling_state(module, last_polled_id=new_last_id, records_found=new_count, errors=0)

        logger.info(
            "Polled %s: %d new, %d after filters, %d after dedup, %d triggered (cursor %d → %d)",
            module,
            new_count,
            len(filtered),
            len(deduped),
            triggered,
            last_id,
            new_last_id,
        )
        return {"new": new_count, "filtered": filtered_out, "triggered": triggered, "last_id": new_last_id}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_new_records(self, module: str, *, since_id: int) -> list[dict[str, Any]]:
        """Query eCX for records with ``id > since_id``.

        Uses the eCX search endpoint with an ``idGt`` filter to fetch
        only records newer than the last polling cursor.

        Args:
            module: eCX module name.
            since_id: Fetch records with ID strictly greater than this.

        Returns:
            List of raw record dicts (snake_case keys).
        """
        from ssi.osint.ecrimex import _normalize_keys

        fields = _MODULE_SEARCH_FIELDS.get(module, ["id"])
        body: dict[str, Any] = {
            "filters": {"idGt": since_id},
            "fields": fields,
            "limit": 100,
        }
        resp = self._client._request("POST", f"/{module}/search", json=body)
        data = resp.json().get("data", [])
        return [_normalize_keys(r) for r in data]

    def _apply_filters(self, records: list[dict[str, Any]], settings: Any) -> list[dict[str, Any]]:
        """Filter records by confidence, brand, and TLD constraints.

        Args:
            records: Normalized record dicts.
            settings: :class:`~ssi.settings.config.ECXSettings`.

        Returns:
            Records passing all filter criteria.
        """
        threshold = settings.polling_confidence_threshold
        brands = {b.lower() for b in settings.polling_brands} if settings.polling_brands else set()
        tlds = {t.lower().lstrip(".") for t in settings.polling_tlds} if settings.polling_tlds else set()

        result: list[dict[str, Any]] = []
        for rec in records:
            # Confidence filter
            if rec.get("confidence", 0) < threshold:
                continue

            # Brand filter (if configured)
            if brands:
                rec_brand = (rec.get("brand") or "").lower()
                if rec_brand and rec_brand not in brands:
                    continue

            # TLD filter (if configured)
            if tlds:
                rec_tld = (rec.get("tld") or "").lower().lstrip(".")
                # Fall back to parsing TLD from URL/domain
                if not rec_tld:
                    url_or_domain = rec.get("url") or rec.get("domain") or ""
                    if url_or_domain:
                        try:
                            host = (
                                urlparse(
                                    url_or_domain if "://" in url_or_domain else f"http://{url_or_domain}"
                                ).hostname
                                or ""
                            )
                            rec_tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
                        except Exception:
                            rec_tld = ""
                if rec_tld and rec_tld not in tlds:
                    continue

            result.append(rec)
        return result

    def _deduplicate(self, records: list[dict[str, Any]], module: str) -> list[dict[str, Any]]:
        """Remove records that already have SSI investigations or enrichment cache hits.

        Args:
            records: Filtered record dicts.
            module: eCX module name.

        Returns:
            Records not yet seen by SSI.
        """
        novel: list[dict[str, Any]] = []
        for rec in records:
            query_value = self._extract_query_value(rec, module)
            if not query_value:
                continue

            # Check enrichment cache for existing entries
            cached = self._store.get_cached_ecx_enrichment(module, query_value)
            if cached:
                logger.debug("Skipping already-seen %s record: %s", module, query_value[:60])
                continue

            novel.append(rec)
        return novel

    def _trigger_investigations(self, records: list[dict[str, Any]], module: str) -> int:
        """Submit URLs from new phish records for SSI investigation.

        Only phish records with a ``url`` field are eligible for
        auto-investigation.  Other modules are logged but not yet
        auto-triggered.

        Args:
            records: Deduplicated, filter-passing records.
            module: eCX module name.

        Returns:
            Number of investigations successfully triggered.
        """
        if module != "phish":
            logger.info(
                "Auto-investigate is not yet supported for module %s — %d records logged only",
                module,
                len(records),
            )
            return 0

        triggered = 0
        for rec in records:
            url = rec.get("url", "")
            if not url:
                continue
            try:
                self._start_investigation(url, source_ecx_id=rec.get("id"))
                triggered += 1
            except Exception as exc:
                logger.warning("Failed to trigger investigation for %s: %s", url[:80], exc)
        return triggered

    def _start_investigation(self, url: str, *, source_ecx_id: int | None = None) -> None:
        """Trigger an SSI investigation for a URL.

        Uses the API task submission path so the investigation runs
        asynchronously.

        Args:
            url: Target URL to investigate.
            source_ecx_id: eCX record ID that sourced this investigation.
        """
        from ssi.investigator.orchestrator import run_investigation

        logger.info(
            "eCX poller triggering investigation for %s (eCX ID: %s)",
            url[:80],
            source_ecx_id,
        )
        # Run as a passive-only scan since this is an automated trigger
        run_investigation(
            url=url,
            scan_type="passive",
            metadata={"source": "ecx_poller", "ecx_record_id": source_ecx_id},
        )

    @staticmethod
    def _extract_query_value(record: dict[str, Any], module: str) -> str:
        """Extract the primary query value from a record for dedup lookup.

        Args:
            record: Normalized eCX record dict.
            module: eCX module name.

        Returns:
            The value to use for deduplication (URL, domain, IP, or address).
        """
        if module == "phish":
            return record.get("url", "")
        elif module == "malicious-domain":
            return record.get("domain", "")
        elif module == "malicious-ip":
            return record.get("ip", "")
        elif module == "cryptocurrency-addresses":
            return record.get("address", "")
        return ""


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def get_poller() -> ECXPoller | None:
    """Return a configured :class:`ECXPoller` or ``None``.

    Returns ``None`` when eCX is disabled, polling is disabled, or the
    API key is missing.

    Returns:
        A ready-to-use poller instance, or ``None``.
    """
    from ssi.osint.ecrimex import get_client
    from ssi.settings import get_settings
    from ssi.store import build_scan_store

    settings = get_settings().ecx
    if not settings.polling_enabled:
        return None

    client = get_client()
    if client is None:
        return None

    store = build_scan_store()
    return ECXPoller(client=client, store=store)
