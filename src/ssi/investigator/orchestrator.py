"""Top-level investigation orchestrator.

Coordinates passive and active recon phases and produces an ``InvestigationResult``.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ssi.models.investigation import DownloadArtifact, InvestigationResult, InvestigationStatus
from ssi.monitoring import CostTracker

if TYPE_CHECKING:
    from ssi.browser.capture import PageSnapshot
    from ssi.models.agent import AgentSession
    from ssi.models.investigation import FraudTaxonomyResult
    from ssi.osint.dns_lookup import DNSRecords
    from ssi.osint.geoip_lookup import GeoIPInfo
    from ssi.osint.ssl_inspect import SSLInfo
    from ssi.osint.whois_lookup import WHOISRecord

logger = logging.getLogger(__name__)


def run_investigation(
    url: str,
    output_dir: Path,
    passive_only: bool = True,
    skip_whois: bool = False,
    skip_screenshot: bool = False,
    skip_virustotal: bool = False,
    skip_urlscan: bool = False,
    report_format: str = "json",
) -> InvestigationResult:
    """Execute a full (or passive-only) investigation against *url*.

    Args:
        url: The suspicious URL to investigate.
        output_dir: Directory where evidence artifacts are written.
        passive_only: When True, skip AI-agent active interaction.
        skip_whois: Skip WHOIS/RDAP lookup.
        skip_screenshot: Skip Playwright screenshot capture.
        skip_virustotal: Skip VirusTotal API check.
        skip_urlscan: Skip urlscan.io check.
        report_format: Output format — ``json``, ``markdown``, or ``both``.

    Returns:
        An ``InvestigationResult`` populated with all collected intelligence.
    """

    start = time.monotonic()
    result = InvestigationResult(url=url, passive_only=passive_only)
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
            scan_type = "passive" if passive_only else "full"
            scan_id = scan_store.create_scan(
                url=url,
                scan_type=scan_type,
                domain=domain_slug,
                metadata={"output_dir": str(inv_dir), "investigation_id": str(result.investigation_id)},
            )
            logger.debug("Created scan record %s", scan_id)
        except Exception:
            logger.warning("Failed to initialise scan store — results will not be persisted", exc_info=True)
            scan_store = None

    site_result = None  # Populated if active interaction runs

    try:
        # --- Pre-flight: Domain resolution check ----------------------------
        domain_resolves = _check_domain_resolution(url)
        if not domain_resolves:
            result.warnings.append(
                f"Domain does not resolve (NXDOMAIN). The domain may be unregistered, "
                f"expired, or taken down. WHOIS, DNS, SSL, and GeoIP data will be unavailable."
            )
            logger.warning("Domain does not resolve — OSINT data will be limited")

        # --- Phase 1: Passive Reconnaissance --------------------------------
        logger.info("Phase 1: Passive recon for %s", url)

        if not skip_whois:
            result.whois = _run_whois(url)
            if cost_tracker:
                cost_tracker.record_api_call("whois")

        result.dns = _run_dns(url)
        if cost_tracker:
            cost_tracker.record_api_call("dns")

        result.ssl = _run_ssl(url)
        if cost_tracker:
            cost_tracker.record_api_call("ssl")

        result.geoip = _run_geoip(result.dns)
        if cost_tracker:
            cost_tracker.record_api_call("geoip")

        if not skip_screenshot:
            result.page_snapshot = _run_browser_capture(url, inv_dir)

            # Collect passive-capture downloads
            if result.page_snapshot and result.page_snapshot.captured_downloads:
                result.downloads.extend(
                    _to_download_artifacts(result.page_snapshot.captured_downloads)
                )

        if not skip_virustotal:
            _run_virustotal(url, result)
            if cost_tracker:
                cost_tracker.record_api_call("virustotal")

        if not skip_urlscan:
            _run_urlscan(url, result)
            if cost_tracker:
                cost_tracker.record_api_call("urlscan")

        # --- Phase 2: Active Interaction (AI Agent) -------------------------
        if not passive_only:
            logger.info("Phase 2: Active interaction via AI agent")
            agent_session = _run_agent_interaction(url, inv_dir)
            if agent_session:
                result.agent_steps = [step.to_dict() if hasattr(step, "to_dict") else {} for step in []]
                # Store raw agent session metrics on the result
                result.token_usage = (
                    agent_session.metrics.total_input_tokens + agent_session.metrics.total_output_tokens
                )
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
                    result.downloads.extend(
                        _to_download_artifacts(agent_session.captured_downloads)
                    )

        # --- Phase 2.5: HAR Analysis ----------------------------------------
        _run_har_analysis(result)

        # --- Phase 2.6: Wallet Extraction -----------------------------------
        _extract_wallets(result, url)

        # --- Phase 3: Classification & Evidence Packaging -------------------
        logger.info("Phase 3: Classification & evidence packaging")
        _run_classification(result)

        result.status = InvestigationStatus.COMPLETED
        result.success = True

    except Exception as e:
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
    result.completed_at = datetime.now(timezone.utc)
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

    # Persist results to the scan store
    if scan_store and scan_id:
        try:
            scan_store.persist_investigation(scan_id, result, site_result=site_result)
        except Exception:
            logger.warning("Failed to persist scan %s to store", scan_id, exc_info=True)

    return result


# ---------------------------------------------------------------------------
# Pre-flight check
# ---------------------------------------------------------------------------


def _check_domain_resolution(url: str) -> bool:
    """Return True if the domain in *url* resolves to at least one A/AAAA record."""
    import socket
    from urllib.parse import urlparse

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
    from urllib.parse import urlparse

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
    if result.page_snapshot:
        if result.page_snapshot.dom_snapshot_path:
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


def _run_classification(result: InvestigationResult) -> None:
    """Classify the investigation using the five-axis fraud taxonomy."""
    from ssi.classification.classifier import FraudTaxonomyResult, classify_investigation

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


def _taxonomy_to_model(taxonomy: "FraudTaxonomyResult") -> FraudTaxonomyResult:
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
    _DESCRIPTIONS: dict[str, str] = {
        "investigation.json": "Complete investigation result in structured JSON",
        "report.md": "Human-readable investigation report (Markdown)",
        "leo_evidence_report.md": "Law enforcement evidence summary report",
        "stix_bundle.json": "Threat indicators in STIX 2.1 format",
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
                            description=_DESCRIPTIONS.get(file_path.name, ""),
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
                collected_at=datetime.now(timezone.utc).isoformat(),
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


def _run_agent_interaction(url: str, output_dir: Path) -> AgentSession | None:
    """Launch the AI browser agent for active site interaction.

    Returns:
        An ``AgentSession`` or ``None`` if the agent cannot start.
    """
    from ssi.browser.agent import BrowserAgent
    from ssi.browser.llm_client import AgentLLMClient

    try:
        llm = AgentLLMClient.from_settings()
        if not llm.check_connectivity():
            logger.warning("Ollama not available — skipping active interaction")
            return None

        agent = BrowserAgent(llm_client=llm, output_dir=output_dir / "agent")
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
