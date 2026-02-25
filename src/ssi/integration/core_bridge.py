"""Bridge between SSI investigation results and i4g core platform.

This module translates SSI's ``InvestigationResult`` into the data
structures expected by core's case management, evidence storage, and
dossier/LEO report pipeline.  It communicates with the core API over
HTTP so the two systems remain independently deployable.

Usage (local/dev)::

    from ssi.integration.core_bridge import CoreBridge

    bridge = CoreBridge(core_api_url="http://localhost:8000")
    case_id = bridge.push_investigation(result)

Usage (Cloud Run)::

    bridge = CoreBridge()  # reads SSI_INTEGRATION__CORE_API_URL env var
    case_id = bridge.push_investigation(result)
"""

from __future__ import annotations

import logging
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from ssi.models.investigation import InvestigationResult

logger = logging.getLogger(__name__)


def _get_oidc_token(audience: str) -> str | None:
    """Fetch an OIDC identity token for IAP-protected service auth.

    Uses the default application credentials (service account on GCP,
    ``gcloud auth`` locally).  Returns ``None`` when not running on GCP
    or when credentials are unavailable — callers should treat this as a
    soft failure so local-dev keeps working without Google libs.

    Args:
        audience: The IAP OAuth client ID used as the token audience.

    Returns:
        The identity token string, or ``None`` on failure.
    """
    try:
        from google.auth.transport.requests import Request
        from google.oauth2 import id_token

        auth_req = Request()
        return id_token.fetch_id_token(auth_req, audience)
    except Exception as exc:
        logger.debug("Could not fetch OIDC token for audience %s: %s", audience, exc)
        return None


class CoreBridge:
    """Push SSI investigation results into the i4g core platform.

    Translates investigation evidence into core API calls:
    - Creates a case record
    - Attaches evidence artifacts (screenshots, HAR, DOM, etc.)
    - Stores the taxonomy classification
    - Extracts entities (IOCs) and links them to the case
    - Optionally triggers dossier generation

    Args:
        core_api_url: Base URL of the i4g core API.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        core_api_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        if core_api_url is None:
            from ssi.settings import get_settings

            settings = get_settings()
            core_api_url = getattr(getattr(settings, "integration", None), "core_api_url", None)
            if not core_api_url:
                core_api_url = "http://localhost:8000"

        self.core_api_url = core_api_url.rstrip("/")
        self.timeout = timeout
        headers = self._build_auth_headers()
        self._client = httpx.Client(base_url=self.core_api_url, timeout=self.timeout, headers=headers)

    def _build_auth_headers(self) -> dict[str, str]:
        """Build authentication headers for the core API.

        Follows the same pattern as the i4g-console's ``getIapHeaders()``:

        1. **OIDC identity token** (``Authorization: Bearer``) with the
           IAP OAuth client ID as audience — IAP verifies this at the
           load-balancer before forwarding to Cloud Run.
        2. **API key** (``X-API-KEY``) — fallback for core's app-level
           ``require_token`` when IAP injects its own JWT.

        For localhost URLs both layers are skipped so local dev works
        without configuration.

        Returns:
            Header dict with auth credentials for the target environment.
        """
        from ssi.settings import get_settings

        settings = get_settings()
        integration = getattr(settings, "integration", None)
        api_key = getattr(integration, "core_api_key", "")
        iap_audience = getattr(integration, "iap_audience", "")
        headers: dict[str, str] = {}

        if self.core_api_url.startswith("http://"):
            return headers

        # App-level auth (X-API-KEY) — accepted by core's require_token.
        if api_key:
            headers["X-API-KEY"] = api_key

        # IAP auth (OIDC Bearer with IAP client ID as audience).
        if iap_audience:
            token = _get_oidc_token(iap_audience)
            if token:
                headers["Authorization"] = f"Bearer {token}"
                logger.debug("OIDC token injected (audience=%s) for IAP auth", iap_audience)
            else:
                logger.warning("Could not obtain OIDC token for IAP audience %s", iap_audience)
        else:
            logger.warning("No iap_audience configured — IAP will reject the request")

        return headers

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def push_investigation(
        self,
        result: InvestigationResult,
        *,
        dataset: str = "ssi",
        trigger_dossier: bool = False,
    ) -> str:
        """Push a complete SSI investigation into core.

        Steps:
            1. Create a case record.
            2. Attach evidence artifacts.
            3. Store taxonomy classification on the case.
            4. Create entity records for threat indicators.
            5. Create wallet indicators for harvested crypto addresses.
            6. Create OSINT-derived entities (domains, IPs, registrants).
            7. Optionally queue dossier generation.

        Args:
            result: Completed SSI investigation.
            dataset: Dataset label for the case (default ``"ssi"``).
            trigger_dossier: When True, queue a dossier job for the case.

        Returns:
            The ``case_id`` assigned by the core platform.
        """
        case_id = self._create_case(result, dataset=dataset)
        logger.info("Created case %s for investigation %s", case_id, result.investigation_id)

        self._attach_evidence(case_id, result)
        self._store_classification(case_id, result)
        self._create_entities(case_id, result)
        self._create_wallet_indicators(case_id, result, dataset=dataset)
        self._create_osint_entities(case_id, result)

        if trigger_dossier:
            self._trigger_dossier(case_id, result)

        return case_id

    def health_check(self) -> bool:
        """Check if the core API is reachable."""
        try:
            resp = self._client.get("/health")
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    # ------------------------------------------------------------------
    # Case management
    # ------------------------------------------------------------------

    @staticmethod
    def _build_title(result: InvestigationResult) -> str:
        """Build a human-readable case title from investigation results."""
        from urllib.parse import urlparse

        # Extract domain from URL
        try:
            domain = urlparse(result.url).netloc or result.url
        except Exception:
            domain = result.url
        # Strip www. prefix for cleaner display
        if domain.startswith("www."):
            domain = domain[4:]

        # Extract classification intent if available
        intent_label = ""
        if result.taxonomy_result and result.taxonomy_result.intent:
            top_intent = result.taxonomy_result.intent[0]
            if top_intent.label:
                intent_label = top_intent.label.replace("INTENT.", "").replace("_", " ").title()
        elif result.classification and result.classification.intent:
            intent_label = result.classification.intent.replace("_", " ").title()

        # Build title: "Investment Scam — example.com" or "Investigation — example.com"
        prefix = intent_label if intent_label else "Investigation"
        return f"{prefix} — {domain}"

    def _create_case(self, result: InvestigationResult, *, dataset: str) -> str:
        """Create a case record in the core platform."""
        title = self._build_title(result)
        payload: dict[str, Any] = {
            "dataset": dataset,
            "source_type": "ssi_investigation",
            "source_url": result.url,
            "title": title,
            "metadata": {
                "title": title,
                "ssi_investigation_id": str(result.investigation_id),
                "scan_type": result.scan_type if isinstance(result.scan_type, str) else result.scan_type.value,
                "passive_only": result.passive_only,
                "started_at": result.started_at.isoformat() if result.started_at else None,
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "duration_seconds": result.duration_seconds,
            },
        }

        # Include classification if available
        if result.taxonomy_result:
            payload["classification_result"] = result.taxonomy_result.model_dump(mode="json")
            payload["risk_score"] = result.taxonomy_result.risk_score

        resp = self._client.post("/cases", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("caseId", data.get("case_id", data.get("id", str(uuid4()))))

    # ------------------------------------------------------------------
    # Evidence attachment
    # ------------------------------------------------------------------

    def _attach_evidence(self, case_id: str, result: InvestigationResult) -> None:
        """Upload evidence artifacts to the core evidence store."""
        inv_dir = Path(result.output_path) if result.output_path else None
        if not inv_dir or not inv_dir.is_dir():
            logger.warning("No output directory found for evidence attachment")
            return

        # Attach key artifacts
        _PRIORITY_FILES = [
            "investigation.json",
            "report.md",
            "leo_evidence_report.md",
            "stix_bundle.json",
            "evidence.zip",
        ]

        for fname in _PRIORITY_FILES:
            fpath = inv_dir / fname
            if fpath.is_file():
                self._upload_evidence_file(case_id, fpath)

        # Attach screenshots and HAR files from subdirectories
        for pattern in ("*.png", "*.har", "*.html"):
            for fpath in inv_dir.rglob(pattern):
                if fpath.is_file():
                    self._upload_evidence_file(case_id, fpath)

    def _upload_evidence_file(self, case_id: str, file_path: Path) -> None:
        """Upload a single evidence file to the core API."""
        mime_type, _ = mimetypes.guess_type(file_path.name)
        try:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, mime_type or "application/octet-stream")}
                resp = self._client.post(
                    f"/cases/{case_id}/evidence",
                    files=files,
                )
                resp.raise_for_status()
                logger.debug("Attached %s to case %s", file_path.name, case_id)
        except httpx.HTTPError as e:
            logger.warning("Failed to attach %s to case %s: %s", file_path.name, case_id, e)

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _store_classification(self, case_id: str, result: InvestigationResult) -> None:
        """Store the fraud taxonomy classification on the case."""
        if not result.taxonomy_result:
            return

        payload = {
            "classification_result": result.taxonomy_result.model_dump(mode="json"),
            "classification_status": "completed",
            "risk_score": result.taxonomy_result.risk_score,
        }
        try:
            resp = self._client.patch(f"/cases/{case_id}", json=payload)
            resp.raise_for_status()
            logger.info("Stored classification on case %s (risk_score=%.1f)", case_id, result.taxonomy_result.risk_score)
        except httpx.HTTPError as e:
            logger.warning("Failed to store classification on case %s: %s", case_id, e)

    # ------------------------------------------------------------------
    # Entity extraction (IOCs → entities + indicators)
    # ------------------------------------------------------------------

    def _create_entities(self, case_id: str, result: InvestigationResult) -> None:
        """Create entity and indicator records from threat indicators."""
        if not result.threat_indicators:
            return

        entities: list[dict[str, Any]] = []
        for ti in result.threat_indicators:
            entity_type = _IOC_TYPE_TO_ENTITY.get(ti.indicator_type, "other")
            entities.append(
                {
                    "entity_type": entity_type,
                    "canonical_value": ti.value,
                    "raw_value": ti.value,
                    "confidence": 0.9,
                    "metadata": {"source": ti.source, "context": ti.context},
                }
            )

        try:
            resp = self._client.post(f"/cases/{case_id}/entities/batch", json={"entities": entities})
            resp.raise_for_status()
            logger.info("Created %d entities on case %s", len(entities), case_id)
        except httpx.HTTPError as e:
            logger.warning("Failed to create entities on case %s: %s", case_id, e)

    # ------------------------------------------------------------------
    # Wallet indicators (crypto_wallet IOCs)
    # ------------------------------------------------------------------

    def _create_wallet_indicators(
        self,
        case_id: str,
        result: InvestigationResult,
        *,
        dataset: str = "ssi",
    ) -> None:
        """Create indicator records for harvested wallet addresses.

        Each wallet is stored as an indicator with category ``crypto_wallet``
        and a matching entity of type ``crypto_wallet``.
        """
        # Access wallets from agent_steps or from the result's threat indicators
        # that are typed as crypto_wallet.
        wallets: list[dict[str, Any]] = []

        # Prefer direct wallet data if available on the result
        if hasattr(result, "wallets") and result.wallets:
            wallets = [
                w.model_dump(mode="json") if hasattr(w, "model_dump") else w
                for w in result.wallets
            ]
        else:
            # Fall back to threat indicators with crypto_wallet type
            if result.threat_indicators:
                for ti in result.threat_indicators:
                    if ti.indicator_type == "crypto_wallet":
                        wallets.append(
                            {
                                "wallet_address": ti.value,
                                "token_symbol": ti.context or "UNKNOWN",
                                "network_short": "",
                                "source": ti.source,
                                "confidence": 0.9,
                            }
                        )

        if not wallets:
            return

        indicators: list[dict[str, Any]] = []
        for w in wallets:
            addr = w.get("wallet_address", "")
            if not addr:
                continue
            token = w.get("token_symbol", "UNKNOWN")
            network = w.get("network_short", "")
            indicators.append(
                {
                    "category": "crypto_wallet",
                    "type": f"{token}/{network}" if network else token,
                    "number": addr,
                    "status": "active",
                    "confidence": w.get("confidence", 0.9),
                    "dataset": dataset,
                    "metadata": {
                        "token_symbol": token,
                        "network_short": network,
                        "source": w.get("source", ""),
                        "token_label": w.get("token_label", ""),
                        "network_label": w.get("network_label", ""),
                    },
                }
            )

        if not indicators:
            return

        try:
            resp = self._client.post(
                f"/cases/{case_id}/indicators/batch",
                json={"indicators": indicators},
            )
            resp.raise_for_status()
            logger.info("Created %d wallet indicators on case %s", len(indicators), case_id)
        except httpx.HTTPError as e:
            logger.warning("Failed to create wallet indicators on case %s: %s", case_id, e)

    # ------------------------------------------------------------------
    # OSINT-derived entities (domains, IPs, registrants)
    # ------------------------------------------------------------------

    def _create_osint_entities(self, case_id: str, result: InvestigationResult) -> None:
        """Create entity records from OSINT reconnaissance data.

        Extracts domains, IP addresses, and registrant information from
        the passive recon results (WHOIS, DNS, SSL, GeoIP).
        """
        entities: list[dict[str, Any]] = []

        # Domain entity from the target URL
        if result.url:
            from urllib.parse import urlparse

            parsed = urlparse(result.url if "://" in result.url else f"https://{result.url}")
            hostname = parsed.hostname
            if hostname:
                entities.append(
                    {
                        "entity_type": "domain",
                        "canonical_value": hostname,
                        "raw_value": result.url,
                        "confidence": 1.0,
                        "metadata": {"source": "target_url"},
                    }
                )

        # IP addresses from DNS / GeoIP
        if result.dns:
            for record_type in ("a_records", "aaaa_records"):
                records = getattr(result.dns, record_type, []) or []
                for ip_addr in records:
                    if isinstance(ip_addr, str):
                        entities.append(
                            {
                                "entity_type": "ip_address",
                                "canonical_value": ip_addr,
                                "raw_value": ip_addr,
                                "confidence": 1.0,
                                "metadata": {"source": "dns", "record_type": record_type},
                            }
                        )

        if result.geoip and hasattr(result.geoip, "ip") and result.geoip.ip:
            # Avoid duplicate if already captured via DNS
            ip_entity_exists = any(
                e["canonical_value"] == result.geoip.ip for e in entities if e["entity_type"] == "ip_address"
            )
            if not ip_entity_exists:
                entities.append(
                    {
                        "entity_type": "ip_address",
                        "canonical_value": result.geoip.ip,
                        "raw_value": result.geoip.ip,
                        "confidence": 1.0,
                        "metadata": {
                            "source": "geoip",
                            "asn": getattr(result.geoip, "asn", None),
                            "country": getattr(result.geoip, "country", None),
                        },
                    }
                )

        # Registrant info from WHOIS
        if result.whois:
            registrant_name = getattr(result.whois, "registrant_name", None) or getattr(
                result.whois, "registrant", None
            )
            registrant_email = getattr(result.whois, "registrant_email", None)
            registrar = getattr(result.whois, "registrar", None)

            if registrant_name and registrant_name.lower() not in ("redacted", "privacy", "n/a", ""):
                entities.append(
                    {
                        "entity_type": "person",
                        "canonical_value": registrant_name,
                        "raw_value": registrant_name,
                        "confidence": 0.7,
                        "metadata": {"source": "whois", "role": "registrant"},
                    }
                )
            if registrant_email and "@" in registrant_email:
                entities.append(
                    {
                        "entity_type": "email",
                        "canonical_value": registrant_email.lower(),
                        "raw_value": registrant_email,
                        "confidence": 0.7,
                        "metadata": {"source": "whois", "role": "registrant"},
                    }
                )
            if registrar:
                entities.append(
                    {
                        "entity_type": "organization",
                        "canonical_value": registrar,
                        "raw_value": registrar,
                        "confidence": 0.9,
                        "metadata": {"source": "whois", "role": "registrar"},
                    }
                )

        if not entities:
            return

        try:
            resp = self._client.post(f"/cases/{case_id}/entities/batch", json={"entities": entities})
            resp.raise_for_status()
            logger.info("Created %d OSINT entities on case %s", len(entities), case_id)
        except httpx.HTTPError as e:
            logger.warning("Failed to create OSINT entities on case %s: %s", case_id, e)

    # ------------------------------------------------------------------
    # Dossier / LEO report trigger
    # ------------------------------------------------------------------

    def _trigger_dossier(self, case_id: str, result: InvestigationResult) -> None:
        """Queue a dossier generation job for the case."""
        payload = {
            "case_ids": [case_id],
            "priority": "normal",
            "metadata": {
                "source": "ssi",
                "investigation_id": str(result.investigation_id),
                "target_url": result.url,
            },
        }
        try:
            resp = self._client.post("/dossier/queue", json=payload)
            resp.raise_for_status()
            logger.info("Queued dossier generation for case %s", case_id)
        except httpx.HTTPError as e:
            logger.warning("Failed to trigger dossier for case %s: %s", case_id, e)


# IOC type → entity type mapping for core platform
_IOC_TYPE_TO_ENTITY: dict[str, str] = {
    "ip": "ip_address",
    "ipv4": "ip_address",
    "ipv6": "ip_address",
    "domain": "domain",
    "email": "email",
    "url": "url",
    "crypto_wallet": "crypto_wallet",
    "phone": "phone",
    "sha256": "file_hash",
    "md5": "file_hash",
}
