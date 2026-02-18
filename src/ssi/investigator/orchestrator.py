"""Top-level investigation orchestrator.

Coordinates passive and active recon phases and produces an ``InvestigationResult``.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from ssi.models.investigation import InvestigationResult, InvestigationStatus

logger = logging.getLogger(__name__)


def run_investigation(
    url: str,
    output_dir: Path,
    passive_only: bool = True,
    skip_whois: bool = False,
    skip_screenshot: bool = False,
    skip_virustotal: bool = False,
) -> InvestigationResult:
    """Execute a full (or passive-only) investigation against *url*.

    Args:
        url: The suspicious URL to investigate.
        output_dir: Directory where evidence artifacts are written.
        passive_only: When True, skip AI-agent active interaction.
        skip_whois: Skip WHOIS/RDAP lookup.
        skip_screenshot: Skip Playwright screenshot capture.
        skip_virustotal: Skip VirusTotal API check.

    Returns:
        An ``InvestigationResult`` populated with all collected intelligence.
    """

    start = time.monotonic()
    result = InvestigationResult(url=url, passive_only=passive_only)
    result.status = InvestigationStatus.RUNNING

    # Create per-investigation output directory
    inv_dir = output_dir / str(result.investigation_id)
    inv_dir.mkdir(parents=True, exist_ok=True)
    result.output_path = str(inv_dir)

    try:
        # --- Phase 1: Passive Reconnaissance --------------------------------
        logger.info("Phase 1: Passive recon for %s", url)

        if not skip_whois:
            result.whois = _run_whois(url)

        result.dns = _run_dns(url)
        result.ssl = _run_ssl(url)
        result.geoip = _run_geoip(result.dns)

        if not skip_screenshot:
            result.page_snapshot = _run_browser_capture(url, inv_dir)

        if not skip_virustotal:
            _run_virustotal(url, result)

        # --- Phase 2: Active Interaction (future) ---------------------------
        if not passive_only:
            logger.info("Phase 2: Active interaction (not yet implemented)")
            # TODO: AI agent interaction — Phase 2 of the proposal

        # --- Phase 3: Reporting & Evidence Packaging ------------------------
        logger.info("Phase 3: Evidence packaging")
        _package_evidence(result, inv_dir)

        result.status = InvestigationStatus.COMPLETED
        result.success = True

    except Exception as e:
        logger.exception("Investigation failed for %s", url)
        result.status = InvestigationStatus.FAILED
        result.error = str(e)

    result.completed_at = datetime.now(timezone.utc)
    result.duration_seconds = time.monotonic() - start
    return result


# ---------------------------------------------------------------------------
# Phase 1 helpers  (stubbed — wired to real modules in subsequent PRs)
# ---------------------------------------------------------------------------


def _run_whois(url: str):
    """Perform WHOIS/RDAP lookup."""
    from ssi.osint.whois_lookup import lookup_whois

    try:
        return lookup_whois(url)
    except Exception as e:
        logger.warning("WHOIS lookup failed: %s", e)
        return None


def _run_dns(url: str):
    """Resolve DNS records."""
    from ssi.osint.dns_lookup import lookup_dns

    try:
        return lookup_dns(url)
    except Exception as e:
        logger.warning("DNS lookup failed: %s", e)
        return None


def _run_ssl(url: str):
    """Inspect TLS certificate."""
    from ssi.osint.ssl_inspect import inspect_ssl

    try:
        return inspect_ssl(url)
    except Exception as e:
        logger.warning("SSL inspection failed: %s", e)
        return None


def _run_geoip(dns_records):
    """Resolve GeoIP from DNS A records."""
    if not dns_records or not dns_records.a:
        return None
    from ssi.osint.geoip_lookup import lookup_geoip

    try:
        return lookup_geoip(dns_records.a[0])
    except Exception as e:
        logger.warning("GeoIP lookup failed: %s", e)
        return None


def _run_browser_capture(url: str, output_dir: Path):
    """Capture screenshot, DOM, and form inventory via Playwright."""
    from ssi.browser.capture import capture_page

    try:
        return capture_page(url, output_dir)
    except Exception as e:
        logger.warning("Browser capture failed: %s", e)
        return None


def _run_virustotal(url: str, result: InvestigationResult):
    """Check URL against VirusTotal."""
    from ssi.osint.virustotal import check_url

    try:
        indicators = check_url(url)
        result.threat_indicators.extend(indicators)
    except Exception as e:
        logger.warning("VirusTotal check failed: %s", e)


def _package_evidence(result: InvestigationResult, inv_dir: Path):
    """Write result JSON and create evidence ZIP."""
    import json

    report_path = inv_dir / "investigation.json"
    report_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2, default=str))
    result.report_path = str(report_path)
    # TODO: Create ZIP archive of all artifacts
