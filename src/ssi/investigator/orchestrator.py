"""Top-level investigation orchestrator.

Coordinates passive and active recon phases and produces an ``InvestigationResult``.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from ssi.models.investigation import DownloadArtifact, InvestigationResult, InvestigationStatus, ScanType
from ssi.monitoring import CostTracker

if TYPE_CHECKING:
    from ssi.browser.capture import PageSnapshot
    from ssi.models.agent import AgentSession
    from ssi.models.investigation import FraudTaxonomyResult
    from ssi.monitoring.event_bus import EventBus
    from ssi.osint.dns_lookup import DNSRecords
    from ssi.osint.geoip_lookup import GeoIPInfo
    from ssi.osint.ssl_inspect import SSLInfo
    from ssi.osint.whois_lookup import WHOISRecord

logger = logging.getLogger(__name__)


def run_investigation(
    url: str,
    output_dir: Path,
    scan_type: str = "passive",
    passive_only: bool | None = None,
    skip_whois: bool = False,
    skip_screenshot: bool = False,
    skip_virustotal: bool = False,
    skip_urlscan: bool = False,
    report_format: str = "json",
    investigation_id: str | None = None,
    event_bus: EventBus | None = None,
) -> InvestigationResult:
    """Execute an investigation against *url*.

    The investigation behaviour is controlled by *scan_type*:

    * ``passive`` — OSINT only (WHOIS, DNS, SSL, screenshot, VirusTotal,
      urlscan). No AI-agent interaction.
    * ``active`` — AI-agent browser interaction, wallet extraction, and a
      basic page capture (screenshot). Skips passive recon steps.
    * ``full`` — Runs **both** passive recon and active AI-agent interaction.

    The legacy *passive_only* flag is still accepted for backward
    compatibility: when *passive_only* is ``True`` it maps to
    ``scan_type="passive"``; when ``False`` it maps to ``"full"``.
    Callers should prefer *scan_type* directly.

    Args:
        url: The suspicious URL to investigate.
        output_dir: Directory where evidence artifacts are written.
        scan_type: Investigation mode — ``passive``, ``active``, or ``full``.
        passive_only: **Deprecated.** Legacy toggle kept for backward
            compatibility.  Ignored when *scan_type* is explicitly provided
            by callers that also pass *passive_only*.
        skip_whois: Skip WHOIS/RDAP lookup.
        skip_screenshot: Skip Playwright screenshot capture.
        skip_virustotal: Skip VirusTotal API check.
        skip_urlscan: Skip urlscan.io check.
        report_format: Output format — ``json``, ``markdown``, or ``both``.
        investigation_id: Optional pre-assigned scan ID.  When provided the
            ``InvestigationResult.investigation_id`` is set to this value so
            that the DB row created by core at trigger time and the result
            object share the same identifier.
        event_bus: Optional ``EventBus`` for live-monitoring integration.
            When provided, milestone events (state changes, wallet findings,
            screenshots) are emitted so that WebSocket clients receive
            real-time updates.

    Returns:
        An ``InvestigationResult`` populated with all collected intelligence.
    """

    # Resolve scan_type from the legacy passive_only flag when the caller
    # has not explicitly set scan_type (i.e. it still has the default value).
    if passive_only is not None and scan_type == "passive":
        scan_type = "passive" if passive_only else "full"

    resolved_scan_type = ScanType(scan_type)
    run_passive = resolved_scan_type in (ScanType.PASSIVE, ScanType.FULL)
    run_active = resolved_scan_type in (ScanType.ACTIVE, ScanType.FULL)

    start = time.monotonic()

    # When investigation_id is supplied, reuse it so the result matches
    # the scan row pre-created by core at trigger time.
    init_kwargs: dict[str, Any] = {
        "url": url,
        "scan_type": resolved_scan_type,
        "passive_only": resolved_scan_type == ScanType.PASSIVE,
    }
    if investigation_id:
        from uuid import UUID

        init_kwargs["investigation_id"] = UUID(investigation_id)
    result = InvestigationResult(**init_kwargs)
    result.status = InvestigationStatus.RUNNING

    # Create per-investigation output directory with a human-readable prefix
    # e.g. "example-com_a1b2c3d4" instead of just the raw UUID.
    domain_slug = _domain_slug(url)
    short_id = str(result.investigation_id).split("-")[0]  # first 8 hex chars
    dir_name = f"{domain_slug}_{short_id}" if domain_slug else str(result.investigation_id)
    inv_dir = output_dir / dir_name
    inv_dir.mkdir(parents=True, exist_ok=True)
    result.output_path = str(inv_dir)

    # Initialize cost tracker
    from ssi.settings import get_settings

    settings = get_settings()
    cost_tracker: CostTracker | None = None
    if settings.cost.enabled:
        cost_tracker = CostTracker(budget_usd=settings.cost.budget_per_investigation_usd)

    # Initialize scan store for persistence
    scan_store = None
    scan_id: str | None = None
    if settings.storage.persist_scans:
        try:
            from ssi.store import build_scan_store

            scan_store = build_scan_store()
            scan_type_label = resolved_scan_type.value

            # When investigation_id is provided, the scan row was
            # pre-created by core at trigger time.  Skip the INSERT to
            # avoid an IntegrityError on the duplicate primary key and
            # reuse the existing row for persist_investigation().
            # IMPORTANT: use the original investigation_id string (hex,
            # no dashes) — do NOT use str(result.investigation_id) which
            # adds dashes and breaks the DB lookup.
            if investigation_id:
                scan_id = investigation_id
                logger.debug("Reusing pre-created scan record %s", scan_id)
            else:
                scan_id = scan_store.create_scan(
                    url=url,
                    scan_type=scan_type_label,
                    domain=domain_slug,
                    scan_id=str(result.investigation_id),
                    metadata={"output_dir": str(inv_dir)},
                )
                logger.debug("Created scan record %s", scan_id)
        except Exception:
            logger.warning("Failed to initialise scan store — results will not be persisted", exc_info=True)
            scan_store = None

    site_result = None  # Populated from agent_session after Phase 2 completes

    # Helper to emit events to the bus when provided
    def _emit(event_type: str, data: dict[str, Any] | None = None) -> None:
        if event_bus is not None:
            event_bus.emit_sync(event_type, data or {})

    try:
        # --- Pre-flight: Domain resolution check ----------------------------
        domain_resolves = _check_domain_resolution(url)
        if not domain_resolves:
            result.warnings.append(
                "Domain does not resolve (NXDOMAIN). The domain may be unregistered, "
                "expired, or suspended (clientHold). DNS, SSL, GeoIP, and browser "
                "capture will be unavailable. WHOIS lookup will still be attempted."
            )
            logger.warning("Domain does not resolve — DNS/SSL/GeoIP/browser skipped, WHOIS still attempted")

        # --- Phase 1: Passive Reconnaissance --------------------------------
        logger.info("Phase 1: Passive recon for %s (scan_type=%s)", url, resolved_scan_type.value)
        _emit("state_changed", {"new_state": "PASSIVE_RECON", "message": "Starting passive reconnaissance"})

        if run_passive and not skip_whois:
            result.whois = _run_whois(url)
            if cost_tracker:
                cost_tracker.record_api_call("whois")

        if run_passive and domain_resolves:
            result.dns = _run_dns(url)
            if cost_tracker:
                cost_tracker.record_api_call("dns")

            result.ssl = _run_ssl(url)
            if cost_tracker:
                cost_tracker.record_api_call("ssl")

            result.geoip = _run_geoip(result.dns)
            if cost_tracker:
                cost_tracker.record_api_call("geoip")
        elif run_passive and not domain_resolves:
            logger.info("Skipping DNS/SSL/GeoIP — domain does not resolve")

        # Screenshot is captured for all scan types (passive, active, full)
        # unless explicitly skipped by the caller or the domain is unreachable.
        if not skip_screenshot and domain_resolves:
            _emit("state_changed", {"new_state": "SCREENSHOT", "message": "Capturing page screenshot"})
            result.page_snapshot = _run_browser_capture(url, inv_dir)

            # Emit screenshot to live monitor if available
            if result.page_snapshot and result.page_snapshot.screenshot_path and event_bus is not None:
                try:
                    import base64

                    screenshot_file = Path(result.page_snapshot.screenshot_path)
                    if screenshot_file.is_file():
                        screenshot_bytes = screenshot_file.read_bytes()
                        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii")
                        _emit("screenshot_update", {"screenshot_b64": screenshot_b64})
                except Exception:
                    logger.debug("Failed to emit screenshot to event bus", exc_info=True)

            # Collect passive-capture downloads
            if result.page_snapshot and result.page_snapshot.captured_downloads:
                result.downloads.extend(_to_download_artifacts(result.page_snapshot.captured_downloads))

        if run_passive and not skip_virustotal:
            _run_virustotal(url, result)
            if cost_tracker:
                cost_tracker.record_api_call("virustotal")

        if run_passive and not skip_urlscan and domain_resolves:
            _run_urlscan(url, result)
            if cost_tracker:
                cost_tracker.record_api_call("urlscan")
        elif run_passive and not skip_urlscan and not domain_resolves:
            logger.info("Skipping urlscan.io — domain does not resolve")

        # eCrimeX enrichment (Phase 1: passive recon)
        if run_passive:
            _run_ecx_enrichment(url, domain_slug, result)
            if cost_tracker:
                cost_tracker.record_api_call("ecrimex")

        # Budget gate: abort before expensive active phase if already over budget.
        if cost_tracker:
            cost_tracker.check_budget()

        # --- Phase 2: Active Interaction (AI Agent) -------------------------
        agent_session = None
        if run_active and domain_resolves:
            logger.info("Phase 2: Active interaction via AI agent")
            _emit("state_changed", {"new_state": "ACTIVE_INTERACTION", "message": "Starting AI agent interaction"})
            agent_session = _run_agent_interaction(url, inv_dir, event_bus=event_bus)
        elif run_active and not domain_resolves:
            logger.info("Phase 2: Skipping active interaction — domain does not resolve")

        if agent_session:
            # Store raw agent session metrics on the result
            result.token_usage = agent_session.metrics.total_input_tokens + agent_session.metrics.total_output_tokens
            result.agent_steps = [
                {
                    "step": s.step_number,
                    "action": s.action.action_type.value,
                    "element": s.action.element_index,
                    "value": s.action.value[:50] if s.action.value else "",
                    "reasoning": s.action.reasoning,
                    "tokens": s.input_tokens + s.output_tokens,
                    "duration_ms": s.duration_ms,
                    "error": s.error,
                }
                for s in agent_session.steps
            ]

            # Record LLM cost from agent tokens
            if cost_tracker:
                cost_tracker.record_llm_tokens(
                    settings.llm.model,
                    input_tokens=agent_session.metrics.total_input_tokens,
                    output_tokens=agent_session.metrics.total_output_tokens,
                )

            # Collect agent-session downloads
            if agent_session.captured_downloads:
                result.downloads.extend(_to_download_artifacts(agent_session.captured_downloads))

            # Expose agent_session as site_result for persist_investigation
            site_result = agent_session

        # --- Phase 2.5: HAR Analysis ----------------------------------------
        _run_har_analysis(result)

        # Budget gate: abort before wallet extraction / classification if over budget.
        if cost_tracker:
            cost_tracker.check_budget()

        # --- Phase 2.6: Wallet Extraction -----------------------------------
        _emit("state_changed", {"new_state": "WALLET_EXTRACTION", "message": "Extracting wallet addresses"})
        _extract_wallets(result, url)

        # Emit wallet findings
        wallet_count = len(result.wallets) if result.wallets else 0
        if wallet_count > 0:
            for w in result.wallets[:10]:  # Emit first 10 individually
                _emit(
                    "wallet_found",
                    {
                        "address": w.address if hasattr(w, "address") else str(w),
                        "network": w.network if hasattr(w, "network") else "unknown",
                    },
                )
            _emit("log", {"message": f"Found {wallet_count} wallet address(es)"})

        # eCX wallet enrichment (post-extraction, cross-reference with community)
        if result.wallets:
            _run_ecx_wallet_enrichment(result)

        # --- Phase 2.7: Google OSINT ----------------------------------------
        _emit("state_changed", {"new_state": "GOOGLE_OSINT", "message": "Extracting Google OSINT artifacts"})
        _run_google_osint(result, agent_session)

        # --- Phase 3: Classification & Evidence Packaging -------------------
        logger.info("Phase 3: Classification & evidence packaging")
        _emit("state_changed", {"new_state": "CLASSIFICATION", "message": "Classifying fraud type"})
        _run_classification(result)

        result.status = InvestigationStatus.COMPLETED
        result.success = True

    except Exception as e:
        from ssi.exceptions import BudgetExceededError

        if isinstance(e, BudgetExceededError):
            logger.warning("Investigation aborted — %s", e)
            result.status = InvestigationStatus.COMPLETED
            result.success = True  # partial success — data collected so far is valid
            result.warnings.append(f"Investigation aborted early: {e}")
        else:
            logger.exception("Investigation failed for %s", url)
            result.status = InvestigationStatus.FAILED
            result.error = str(e)
        if scan_store and scan_id:
            try:
                scan_store.update_scan(scan_id, status="failed", error_message=str(e))
            except Exception:
                logger.warning("Failed to record scan failure for %s", scan_id, exc_info=True)

    # Record timing and cost *before* evidence packaging so the JSON is complete.
    elapsed = time.monotonic() - start
    result.completed_at = datetime.now(UTC)
    result.duration_seconds = elapsed

    if cost_tracker:
        cost_tracker.record_browser_seconds(elapsed)
        summary = cost_tracker.summary()
        result.cost_summary = summary.model_dump(mode="json")
        if summary.budget_exceeded:
            logger.warning(
                "Investigation exceeded budget: $%.4f / $%.4f",
                summary.total_usd,
                summary.budget_usd,
            )

    # Package evidence last so the serialized JSON reflects final status, timing, and cost.
    _package_evidence(result, inv_dir, report_format=report_format)

    # Upload evidence to GCS when configured (Phase 2A)
    _upload_evidence_to_gcs(result, inv_dir)

    # Persist results to the scan store
    if scan_store and scan_id:
        try:
            scan_store.persist_investigation(scan_id, result, site_result=site_result)
        except Exception:
            logger.warning("Failed to persist scan %s to store", scan_id, exc_info=True)
        # Cache eCX enrichment results
        if result.ecx_enrichment and result.ecx_enrichment.query_count > 0:
            try:
                from ssi.settings import get_settings

                ttl = get_settings().ecx.cache_ttl_hours
                cached = scan_store.cache_ecx_enrichments(scan_id, result.ecx_enrichment, cache_ttl_hours=ttl)
                logger.info("Cached %d eCX enrichment rows for scan %s", cached, scan_id)
            except Exception:
                logger.warning("Failed to cache eCX enrichments for scan %s", scan_id, exc_info=True)

    # eCX submission (Phase 2) — runs after persistence so findings are already
    # on disk regardless of outcome.  Failures here must never propagate.
    if scan_id and result.success:
        _run_ecx_submission(scan_id, result)

    return result


# ---------------------------------------------------------------------------
# Pre-flight check
# ---------------------------------------------------------------------------


def _check_domain_resolution(url: str) -> bool:
    """Return True if the domain in *url* resolves to at least one A/AAAA record."""
    import socket

    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or url

    try:
        socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        return False


# ---------------------------------------------------------------------------
# Phase 1 helpers  (stubbed — wired to real modules in subsequent PRs)
# ---------------------------------------------------------------------------


def _run_whois(url: str) -> WHOISRecord | None:
    """Perform WHOIS/RDAP lookup."""
    from ssi.osint.whois_lookup import lookup_whois

    try:
        return lookup_whois(url)
    except Exception as e:
        logger.warning("WHOIS lookup failed: %s", e)
        return None


def _run_dns(url: str) -> DNSRecords | None:
    """Resolve DNS records."""
    from ssi.osint.dns_lookup import lookup_dns

    try:
        return lookup_dns(url)
    except Exception as e:
        logger.warning("DNS lookup failed: %s", e)
        return None


def _run_ssl(url: str) -> SSLInfo | None:
    """Inspect TLS certificate."""
    from ssi.osint.ssl_inspect import inspect_ssl

    try:
        return inspect_ssl(url)
    except Exception as e:
        logger.warning("SSL inspection failed: %s", e)
        return None


def _run_geoip(dns_records: DNSRecords | None) -> GeoIPInfo | None:
    """Resolve GeoIP from DNS A records."""
    if not dns_records or not dns_records.a:
        return None
    from ssi.osint.geoip_lookup import lookup_geoip

    try:
        return lookup_geoip(dns_records.a[0])
    except Exception as e:
        logger.warning("GeoIP lookup failed: %s", e)
        return None


def _run_browser_capture(url: str, output_dir: Path) -> PageSnapshot | None:
    """Capture screenshot, DOM, and form inventory via Playwright."""
    from ssi.browser.capture import capture_page

    try:
        return capture_page(url, output_dir)
    except Exception as e:
        logger.warning("Browser capture failed: %s", e)
        return None


def _run_virustotal(url: str, result: InvestigationResult) -> None:
    """Check URL against VirusTotal."""
    from ssi.osint.virustotal import check_url

    try:
        indicators = check_url(url)
        result.threat_indicators.extend(indicators)
    except Exception as e:
        logger.warning("VirusTotal check failed: %s", e)


def _run_urlscan(url: str, result: InvestigationResult) -> None:
    """Submit URL to urlscan.io and extract threat indicators."""
    from ssi.osint.urlscan import extract_threat_indicators, scan_url

    try:
        scan_result = scan_url(url)
        if scan_result:
            indicators = extract_threat_indicators(scan_result, url)
            result.threat_indicators.extend(indicators)
    except Exception as e:
        logger.warning("urlscan.io check failed: %s", e)


def _run_har_analysis(result: InvestigationResult) -> None:
    """Analyze HAR files for IOCs and suspicious patterns."""
    from ssi.browser.har_analyzer import analyze_har, har_to_threat_indicators

    har_paths: list[str] = []
    if result.page_snapshot and result.page_snapshot.har_path:
        har_paths.append(result.page_snapshot.har_path)

    # Extract target domain for third-party detection
    target_domain = urlparse(result.url).hostname or ""

    for har_path_str in har_paths:
        try:
            har_path = Path(har_path_str)
            analysis = analyze_har(har_path, target_domain=target_domain)
            if analysis.has_findings:
                indicators = har_to_threat_indicators(analysis, result.url)
                result.threat_indicators.extend(indicators)
                logger.info(
                    "HAR analysis: %d findings from %s",
                    len(indicators),
                    har_path.name,
                )
        except Exception as e:
            logger.warning("HAR analysis failed for %s: %s", har_path_str, e)


def _extract_wallets(result: InvestigationResult, url: str) -> None:
    """Scan all available text sources for cryptocurrency wallet addresses.

    Checks page snapshot visible text, agent step observations, and the
    raw URL itself.  Deduplicates addresses and creates ``WalletEntry``
    objects on the result.
    """
    from ssi.wallet.models import WalletEntry
    from ssi.wallet.patterns import WalletValidator

    validator = WalletValidator()
    text_parts: list[str] = []

    # Page snapshot (passive capture)
    if result.page_snapshot and result.page_snapshot.dom_snapshot_path:
        try:
            dom_text = Path(result.page_snapshot.dom_snapshot_path).read_text(errors="replace")
            text_parts.append(dom_text)
        except Exception:
            pass

    # Agent step observations (active phase)
    for step in result.agent_steps:
        if isinstance(step, dict):
            reasoning = step.get("reasoning", "")
            value = step.get("value", "")
            if reasoning:
                text_parts.append(reasoning)
            if value:
                text_parts.append(value)

    # QR / barcode data decoded from inline images
    qr_texts: list[str] = []
    if result.page_snapshot and result.page_snapshot.inline_images:
        for img_info in result.page_snapshot.inline_images:
            for qr_item in img_info.get("qr_data", []):
                decoded = qr_item if isinstance(qr_item, str) else str(qr_item)
                if decoded:
                    qr_texts.append(decoded)

    combined = "\n".join(text_parts)
    if not combined.strip() and not qr_texts:
        return

    seen: set[str] = set()

    # Scan DOM + agent text with regex
    if combined.strip():
        matches = validator.scan_text(combined)
        for m in matches:
            if m.address in seen:
                continue
            seen.add(m.address)
            result.wallets.append(
                WalletEntry(
                    site_url=url,
                    token_symbol=m.symbol,
                    network_short=m.symbol.lower(),
                    wallet_address=m.address,
                    source="regex_scan",
                    confidence=0.7,
                )
            )

    # Scan QR-decoded strings for wallet addresses (higher confidence)
    if qr_texts:
        qr_combined = "\n".join(qr_texts)
        qr_matches = validator.scan_text(qr_combined)
        for m in qr_matches:
            if m.address in seen:
                continue
            seen.add(m.address)
            result.wallets.append(
                WalletEntry(
                    site_url=url,
                    token_symbol=m.symbol,
                    network_short=m.symbol.lower(),
                    wallet_address=m.address,
                    source="qr_code",
                    confidence=0.9,
                )
            )

    if result.wallets:
        logger.info("Wallet extraction: found %d unique addresses", len(result.wallets))


def _run_google_osint(result: InvestigationResult) -> None:
    """Extract emails and Drive links, then resolve via Google OSINT."""
    import asyncio
    import re

    from ssi.evidence.mapping import route_google_osint_results
    from ssi.osint.google.auth import GoogleAuthManager
    from ssi.osint.google.drive import GoogleDriveScraper
    from ssi.osint.google.maps import GoogleMapsScraper
    from ssi.osint.google.people import GooglePeopleScraper

    text_parts: list[str] = []

    # Page snapshot
    if result.page_snapshot and result.page_snapshot.dom_snapshot_path:
        try:
            from pathlib import Path

            dom_text = Path(result.page_snapshot.dom_snapshot_path).read_text(errors="replace")
            text_parts.append(dom_text)
        except Exception:
            pass

    # Agent steps
    for step in result.agent_steps:
        if isinstance(step, dict):
            if reasoning := step.get("reasoning"):
                text_parts.append(str(reasoning))
            if value := step.get("value"):
                text_parts.append(str(value))

    combined = "\n".join(text_parts)
    if not combined.strip():
        return

    emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", combined))
    drive_links = set(re.findall(r"drive\.google\.com/file/d/([a-zA-Z0-9_-]+)", combined))

    if not emails and not drive_links:
        return

    logger.info("Google OSINT: found %d emails, %d Drive links", len(emails), len(drive_links))

    async def _do_async_scraping() -> None:
        auth = GoogleAuthManager(None)  # type: ignore
        people_scraper = GooglePeopleScraper(auth)
        maps_scraper = GoogleMapsScraper(auth)
        drive_scraper = GoogleDriveScraper(auth)

        for email in emails:
            try:
                people_data = await people_scraper.resolve_email(email)
                maps_data = None
                gaia_id = people_data.get("gaia_id")
                if gaia_id:
                    maps_data = await maps_scraper.get_location_data(gaia_id)

                inds, pii = route_google_osint_results(email, people_data=people_data, maps_data=maps_data)
                result.threat_indicators.extend(inds)
                result.pii_exposures.extend(pii)
            except Exception as e:
                logger.warning("Google People/Maps OSINT failed for %s: %s", email, e)

        for file_id in drive_links:
            try:
                drive_data = await drive_scraper.resolve_file(file_id)
                inds, pii = route_google_osint_results(file_id, drive_data=drive_data)
                result.threat_indicators.extend(inds)
                result.pii_exposures.extend(pii)
            except Exception as e:
                logger.warning("Google Drive OSINT failed for %s: %s", file_id, e)

    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import nest_asyncio

            nest_asyncio.apply()
            loop.run_until_complete(_do_async_scraping())
        else:
            asyncio.run(_do_async_scraping())
    except Exception as e:
        logger.warning("Google OSINT execution failed: %s", e)


def _run_classification(result: InvestigationResult) -> None:
    """Classify the investigation using the five-axis fraud taxonomy."""
    from ssi.classification.classifier import classify_investigation

    try:
        taxonomy = classify_investigation(result)
        result.taxonomy_result = _taxonomy_to_model(taxonomy)
        result.classification = taxonomy.to_scam_classification()
        logger.info(
            "Classification: risk_score=%.1f intent=%s",
            taxonomy.risk_score,
            [lbl.label for lbl in taxonomy.intent],
        )
    except Exception as e:
        logger.warning("Fraud taxonomy classification failed: %s", e)


def _taxonomy_to_model(taxonomy: FraudTaxonomyResult) -> FraudTaxonomyResult:
    """Convert classifier output to the Pydantic model stored on the result."""
    from ssi.models.investigation import FraudTaxonomyResult as TaxonomyModel
    from ssi.models.investigation import TaxonomyScoredLabel

    def _convert_labels(labels: list) -> list[TaxonomyScoredLabel]:
        return [
            TaxonomyScoredLabel(label=lbl.label, confidence=lbl.confidence, explanation=lbl.explanation)
            for lbl in labels
        ]

    return TaxonomyModel(
        intent=_convert_labels(taxonomy.intent),
        channel=_convert_labels(taxonomy.channel),
        techniques=_convert_labels(taxonomy.techniques),
        actions=_convert_labels(taxonomy.actions),
        persona=_convert_labels(taxonomy.persona),
        explanation=taxonomy.explanation,
        risk_score=taxonomy.risk_score,
        taxonomy_version=taxonomy.taxonomy_version,
    )


def _package_evidence(result: InvestigationResult, inv_dir: Path, *, report_format: str = "json") -> None:
    """Write result JSON, optional markdown report, and create evidence ZIP with chain-of-custody."""

    md_content: str | None = None

    # Markdown report
    if report_format in ("markdown", "both", "pdf"):
        from ssi.reports import render_markdown_report

        md_path = inv_dir / "report.md"
        md_content = render_markdown_report(result, output_path=md_path)
        logger.info("Markdown report written to %s", md_path)

    # PDF report
    if report_format in ("pdf", "both"):
        try:
            from ssi.reports.pdf import render_pdf_report

            pdf_path = inv_dir / "report.pdf"
            render_pdf_report(result, pdf_path, markdown_content=md_content)
            result.pdf_report_path = str(pdf_path)
        except ImportError:
            logger.warning("weasyprint not installed — skipping PDF generation")
        except Exception as e:
            logger.warning("PDF generation failed: %s", e)

    # LEO evidence report (always generated when classification exists)
    if result.taxonomy_result or result.classification:
        _write_leo_report(result, inv_dir)

    # STIX IOC bundle
    if result.threat_indicators:
        _write_stix_bundle(result, inv_dir)

    # Wallet manifest (standalone JSON for cross-referencing)
    if result.wallets:
        _write_wallet_manifest(result, inv_dir)

    # Create ZIP archive with chain-of-custody manifest
    _create_evidence_zip(result, inv_dir)

    # Write JSON *last* so it includes report_path, evidence_zip_path,
    # and chain_of_custody populated by the steps above.
    report_path = inv_dir / "investigation.json"
    result.report_path = str(report_path)
    report_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2, default=str))


def _write_leo_report(result: InvestigationResult, inv_dir: Path) -> None:
    """Render a law-enforcement-oriented evidence summary report."""
    from ssi.reports import render_markdown_report

    leo_path = inv_dir / "leo_evidence_report.md"
    render_markdown_report(result, output_path=leo_path, template_name="leo_report.md.j2")
    logger.info("LEO evidence report written to %s", leo_path)


def _write_stix_bundle(result: InvestigationResult, inv_dir: Path) -> None:
    """Write threat indicators as a STIX 2.1 bundle for sharing."""
    from ssi.evidence.stix import investigation_to_stix_bundle

    try:
        bundle = investigation_to_stix_bundle(result)
        stix_path = inv_dir / "stix_bundle.json"
        stix_path.write_text(json.dumps(bundle, indent=2))
        logger.info("STIX bundle written to %s", stix_path)
    except Exception as e:
        logger.warning("STIX bundle generation failed: %s", e)


def _write_wallet_manifest(result: InvestigationResult, inv_dir: Path) -> None:
    """Write a wallet manifest JSON file summarising all extracted wallets.

    The manifest includes per-wallet metadata (token, network, address,
    confidence, source) along with aggregate statistics — suitable for
    ingestion into blockchain-analysis platforms or direct inclusion in
    the evidence ZIP.
    """
    try:
        wallets_data = []
        networks: set[str] = set()
        tokens: set[str] = set()

        for w in result.wallets:
            wallets_data.append(
                {
                    "token_symbol": w.token_symbol,
                    "token_label": w.token_label,
                    "network_short": w.network_short,
                    "network_label": w.network_label,
                    "wallet_address": w.wallet_address,
                    "source": w.source,
                    "confidence": w.confidence,
                    "harvested_at": w.harvested_at.isoformat() if w.harvested_at else None,
                    "site_url": w.site_url,
                }
            )
            if w.network_short:
                networks.add(w.network_short)
            if w.token_symbol:
                tokens.add(w.token_symbol)

        manifest = {
            "investigation_id": str(result.investigation_id),
            "target_url": result.url,
            "wallet_count": len(wallets_data),
            "unique_networks": sorted(networks),
            "unique_tokens": sorted(tokens),
            "wallets": wallets_data,
        }

        manifest_path = inv_dir / "wallet_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        result.wallet_manifest_path = str(manifest_path)
        logger.info("Wallet manifest written to %s (%d wallets)", manifest_path, len(wallets_data))
    except Exception as e:
        logger.warning("Wallet manifest generation failed: %s", e)


def _create_evidence_zip(result: InvestigationResult, inv_dir: Path) -> None:
    """Create a ZIP archive of all evidence artifacts with chain-of-custody metadata.

    Produces ``evidence.zip`` in the investigation directory containing all
    files and a ``manifest.json`` with SHA-256 hashes for integrity verification.
    The chain-of-custody metadata is suitable for LEA submission.
    """
    import hashlib
    import mimetypes
    import zipfile

    from ssi.models.investigation import ChainOfCustody, EvidenceArtifact

    zip_path = inv_dir / "evidence.zip"
    artifacts: list[EvidenceArtifact] = []
    total_size = 0

    # Description map for well-known file names
    descriptions: dict[str, str] = {
        "investigation.json": "Complete investigation result in structured JSON",
        "report.md": "Human-readable investigation report (Markdown)",
        "report.pdf": "Human-readable investigation report (PDF)",
        "leo_evidence_report.md": "Law enforcement evidence summary report",
        "stix_bundle.json": "Threat indicators in STIX 2.1 format",
        "wallet_manifest.json": "Cryptocurrency wallet addresses extracted during investigation",
        "screenshot.png": "Full-page screenshot of target site",
        "dom_snapshot.html": "Complete DOM snapshot of target page",
        "manifest.json": "Chain-of-custody manifest with SHA-256 hashes",
    }

    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in sorted(inv_dir.rglob("*")):
                if file_path.is_file() and file_path.name != "evidence.zip":
                    arcname = str(file_path.relative_to(inv_dir))
                    zf.write(file_path, arcname)

                    sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
                    size = file_path.stat().st_size
                    total_size += size
                    mime, _ = mimetypes.guess_type(file_path.name)

                    artifacts.append(
                        EvidenceArtifact(
                            file=arcname,
                            sha256=sha256,
                            size_bytes=size,
                            description=descriptions.get(file_path.name, ""),
                            mime_type=mime or "application/octet-stream",
                        )
                    )

            # Build chain-of-custody manifest
            try:
                from importlib.metadata import version as pkg_version

                tool_version = pkg_version("ssi")
            except Exception:
                tool_version = "unknown"

            custody = ChainOfCustody(
                investigation_id=str(result.investigation_id),
                target_url=result.url,
                collected_at=datetime.now(UTC).isoformat(),
                tool_version=tool_version,
                artifacts=artifacts,
                total_artifacts=len(artifacts),
                total_size_bytes=total_size,
            )

            # Write manifest into the ZIP
            manifest_data = custody.model_dump(mode="json")
            zf.writestr("manifest.json", json.dumps(manifest_data, indent=2))

            # Store custody on the result
            result.chain_of_custody = custody

        # Compute ZIP hash for the custody record
        zip_hash = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        if result.chain_of_custody:
            result.chain_of_custody.package_sha256 = zip_hash

        result.evidence_zip_path = str(zip_path)
        logger.info(
            "Evidence ZIP created: %s (%d files, %d bytes, SHA-256: %s)",
            zip_path.name,
            len(artifacts),
            total_size,
            zip_hash[:16],
        )

    except Exception as e:
        logger.warning("Failed to create evidence ZIP: %s", e)


def _upload_evidence_to_gcs(result: InvestigationResult, inv_dir: Path) -> None:
    """Upload evidence artifacts to GCS when the storage backend is configured.

    On success, updates ``result.output_path`` to the ``gs://`` URI prefix
    so that downstream stores persist a cloud-resolvable path rather than
    a container-local filesystem path.

    Skips silently when the backend is ``local`` or when GCS upload fails
    (the local evidence directory always remains available as a fallback).
    """
    from ssi.settings import get_settings

    settings = get_settings()
    if settings.evidence.storage_backend != "gcs":
        return

    if not settings.evidence.gcs_bucket:
        logger.warning("GCS evidence backend selected but SSI_EVIDENCE__GCS_BUCKET is empty — skipping upload")
        return

    try:
        from ssi.evidence.storage import EvidenceStorageClient, build_evidence_storage_client

        client = build_evidence_storage_client()
        investigation_id = str(result.investigation_id)
        uploaded = client.upload_directory(investigation_id, inv_dir)
        logger.info("Uploaded %d evidence files to GCS for investigation %s", len(uploaded), investigation_id)

        # Use the same sharded sub-path that upload_directory wrote to.
        gcs_prefix = settings.evidence.gcs_prefix.rstrip("/")
        sharded = EvidenceStorageClient.sharded_subpath(investigation_id)
        result.output_path = f"gs://{settings.evidence.gcs_bucket}/{gcs_prefix}/{sharded}"
        logger.info("Updated evidence_path to %s", result.output_path)
    except Exception as e:
        logger.warning("GCS evidence upload failed (local copy retained): %s", e)


def _run_agent_interaction(
    url: str,
    output_dir: Path,
    event_bus: EventBus | None = None,
) -> AgentSession | None:
    """Launch the AI browser agent for active site interaction.

    Args:
        url: Target URL to investigate.
        output_dir: Directory for agent artifacts (screenshots, session files).
        event_bus: Optional event bus for live screenshot streaming.
            When provided, a ``screenshot_update`` event is emitted after
            each agent step so WebSocket clients see the browser state
            update in real time.

    Returns:
        An ``AgentSession`` or ``None`` if the agent cannot start.
    """
    import base64

    from ssi.browser.agent import BrowserAgent
    from ssi.browser.llm_client import AgentLLMClient

    try:
        llm = AgentLLMClient.from_settings()

        from ssi.settings import get_settings

        provider_name = get_settings().llm.provider

        if not llm.check_connectivity():
            logger.error(
                "LLM provider '%s' connectivity check failed — skipping active interaction. "
                "Verify the provider is configured correctly (model, project, credentials).",
                provider_name,
            )
            return None

        logger.info("LLM provider '%s' connectivity verified — starting agent", provider_name)

        # Build a step callback that emits each post-action screenshot to the
        # live monitor so the Live View panel updates as the agent browses.
        step_callback = None
        if event_bus is not None:

            def _on_screenshot(screenshot_path: str) -> None:
                """Read the screenshot file and emit a screenshot_update event."""
                try:
                    screenshot_bytes = Path(screenshot_path).read_bytes()
                    screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii")
                    event_bus.emit_sync("screenshot_update", {"screenshot_b64": screenshot_b64})
                except Exception:
                    logger.debug("Failed to emit agent step screenshot", exc_info=True)

            step_callback = _on_screenshot

        agent = BrowserAgent(
            llm_client=llm,
            output_dir=output_dir / "agent",
            step_callback=step_callback,
            event_bus=event_bus,
        )
        session = agent.run(url)
        llm.close()
        return session
    except Exception as e:
        logger.exception("Agent interaction failed: %s", e)
        return None


def _to_download_artifacts(raw_downloads: list[dict]) -> list[DownloadArtifact]:
    """Convert raw download dicts (from interceptor) to DownloadArtifact models."""
    artifacts: list[DownloadArtifact] = []
    for d in raw_downloads:
        vt_result = d.get("vt_result", {})
        artifacts.append(
            DownloadArtifact(
                url=d.get("url", ""),
                filename=d.get("suggested_filename", d.get("filename", "")),
                saved_path=d.get("saved_path", ""),
                sha256=d.get("sha256", ""),
                md5=d.get("md5", ""),
                size_bytes=d.get("size_bytes", 0),
                content_type=d.get("content_type", ""),
                is_malicious=d.get("is_malicious", False),
                vt_detections=vt_result.get("detections", 0),
                vt_total_engines=vt_result.get("total_engines", 0),
                vt_context=vt_result.get("context", ""),
            )
        )
    return artifacts


def _run_ecx_enrichment(url: str, domain: str, result: InvestigationResult) -> None:
    """Run eCrimeX enrichment during passive recon.

    Queries phish, malicious-domain, malicious-ip, and report-phishing
    modules.  Results are stored on ``result.ecx_enrichment``.
    """
    from ssi.osint.ecrimex import enrich_from_ecx

    try:
        # Extract primary IP from DNS A records if available
        primary_ip: str | None = None
        if result.dns and result.dns.a:
            primary_ip = result.dns.a[0]

        # Use the real hostname (with dots) for the domain search, not the
        # filesystem-safe slug (which replaces dots with hyphens and would
        # never match anything in the ECX malicious-domain index).
        hostname = urlparse(url if "://" in url else f"https://{url}").hostname or domain
        ecx_result = enrich_from_ecx(url, hostname, ip=primary_ip)
        if ecx_result.has_hits:
            result.ecx_enrichment = ecx_result
            logger.info(
                "eCX enrichment: %d total hits (%d phish, %d domain, %d IP, %d report-phishing)",
                ecx_result.total_hits,
                len(ecx_result.phish_hits),
                len(ecx_result.domain_hits),
                len(ecx_result.ip_hits),
                len(ecx_result.report_phishing_hits),
            )
        elif ecx_result.query_count > 0:
            # Store even empty results so the report shows the section was queried
            result.ecx_enrichment = ecx_result
    except Exception as e:
        logger.warning("eCX enrichment failed: %s", e)


def _run_ecx_wallet_enrichment(result: InvestigationResult) -> None:
    """Cross-reference extracted wallets against eCX cryptocurrency-addresses.

    Appends crypto hits to the existing ``ecx_enrichment`` on the result.
    """
    from ssi.osint.ecrimex import enrich_wallets_from_ecx

    try:
        wallet_hits = enrich_wallets_from_ecx(result.wallets)
        if wallet_hits:
            from ssi.models.ecx import ECXEnrichmentResult

            if result.ecx_enrichment is None:
                result.ecx_enrichment = ECXEnrichmentResult()

            # Merge crypto hits into the enrichment result
            for records in wallet_hits.values():
                result.ecx_enrichment.crypto_hits.extend(records)
            result.ecx_enrichment.total_hits += sum(len(r) for r in wallet_hits.values())
            result.ecx_enrichment.query_count += len(result.wallets)
            logger.info(
                "eCX wallet enrichment: %d/%d addresses had community hits",
                len(wallet_hits),
                len(result.wallets),
            )
    except Exception as e:
        logger.warning("eCX wallet enrichment failed: %s", e)


def _run_ecx_submission(scan_id: str, result: Any) -> None:
    """Submit investigation findings to eCX via the governance service (Phase 2).

    This function is non-blocking — all errors are caught and logged so that
    a submission failure never affects the investigation outcome.  The APWG
    data-sharing agreement gate inside :class:`~ssi.ecx.submission.ECXSubmissionService`
    is the primary safety check; this function just wires the call.

    Args:
        scan_id: The scan identifier used to link submission records.
        result: The completed :class:`~ssi.models.investigation.InvestigationResult`.
    """
    try:
        from ssi.ecx.submission import get_submission_service

        service = get_submission_service()
        if service is None:
            return  # Submission disabled or misconfigured — already logged inside factory

        case_id: str | None = getattr(result, "case_id", None)
        rows = service.process_investigation(scan_id, case_id, result)
        if rows:
            submitted = sum(1 for r in rows if r.get("status") == "submitted")
            queued = sum(1 for r in rows if r.get("status") == "queued")
            logger.info(
                "eCX Phase 2: %d indicators processed — %d submitted, %d queued for review",
                len(rows),
                submitted,
                queued,
            )
            # Attach submission records to the investigation result so callers and
            # reports can surface Phase 2 status without an extra store look-up.
            if hasattr(result, "ecx_submissions"):
                result.ecx_submissions = rows
    except Exception:
        logger.warning("eCX submission pipeline failed for scan %s", scan_id, exc_info=True)


def _domain_slug(url: str, max_length: int = 60) -> str:
    """Extract a filesystem-safe slug from a URL's hostname.

    Examples:
        ``https://example.com/page`` → ``example-com``
        ``http://sub.evil-site.co.uk/phish`` → ``sub-evil-site-co-uk``

    Returns an empty string if the hostname cannot be parsed.
    """
    try:
        # Ensure scheme is present so urlparse works reliably
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "https://" + url
        hostname = urlparse(url).hostname or ""
    except Exception:
        return ""

    # Replace dots and non-alphanumeric chars with hyphens, collapse runs
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", hostname).strip("-").lower()
    return slug[:max_length] if slug else ""
