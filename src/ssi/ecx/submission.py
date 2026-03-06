"""eCrimeX (eCX) Submission Service — Phase 2: Contribute.

Governs the submission of SSI investigation findings to the APWG eCrimeX
data clearinghouse with hybrid governance:

* High-confidence indicators (>= ``auto_submit_threshold``) are submitted
  automatically after investigation completes.
* Medium-confidence indicators (>= ``queue_threshold``) are queued for
  analyst review via :meth:`analyst_approve` / :meth:`analyst_reject`.
* Low-confidence indicators are skipped.

Safety gates
------------
**Both** ``SSI_ECX__SUBMISSION_ENABLED=true`` **and**
``SSI_ECX__SUBMISSION_AGREEMENT_SIGNED=true`` must be set before any data
leaves SSI.  A single env-var flip cannot trigger live submissions — the
APWG data-sharing agreement flag is a deliberate second gate.

Until the agreement is executed, ``process_investigation()`` logs a warning
and returns an empty list on each call regardless of other settings.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse
from uuid import uuid4

if TYPE_CHECKING:
    from ssi.osint.ecrimex import ECXClient
    from ssi.store.scan_store import ScanStore

logger = logging.getLogger(__name__)

# eCX module path constants
_MODULE_PHISH = "phish"
_MODULE_DOMAIN = "malicious-domain"
_MODULE_IP = "malicious-ip"
_MODULE_CRYPTO = "cryptocurrency-addresses"


class ECXSubmissionService:
    """Submit SSI investigation findings to eCrimeX with governance gating.

    Args:
        client: Authenticated :class:`~ssi.osint.ecrimex.ECXClient`.
        store: :class:`~ssi.store.scan_store.ScanStore` for submission records.
    """

    def __init__(self, client: ECXClient, store: ScanStore) -> None:
        self._client = client
        self._store = store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_investigation(
        self,
        scan_id: str,
        case_id: str | None,
        result: Any,
    ) -> list[dict[str, Any]]:
        """Route investigation indicators through the submission governance policy.

        This is the primary entry point called by the orchestrator after an
        investigation persists.  All submission failures are caught and logged
        — they must never propagate back to block the investigation result.

        Safety gates:
            Returns immediately with an empty list unless *both*
            ``submission_enabled`` and ``submission_agreement_signed`` are
            ``True`` in settings.

        Args:
            scan_id: SSI scan identifier.
            case_id: Core case ID (may be ``None`` for standalone scans).
            result: :class:`~ssi.models.investigation.InvestigationResult`
                populated by the orchestrator.

        Returns:
            List of submission row dicts (one per indicator routed).
        """
        from ssi.settings import get_settings

        settings = get_settings().ecx

        if not settings.submission_enabled:
            logger.debug("eCX submission disabled (submission_enabled=false) — skipping")
            return []

        if not settings.submission_agreement_signed:
            logger.warning(
                "eCX submission_enabled=true but submission_agreement_signed=false — "
                "APWG data sharing agreement not yet confirmed. "
                "No indicator data will be transmitted to eCX. "
                "Set SSI_ECX__SUBMISSION_AGREEMENT_SIGNED=true after the agreement is executed."
            )
            return []

        auto_threshold = settings.auto_submit_threshold
        queue_threshold = settings.queue_threshold

        # Derive overall confidence from classification/taxonomy result.
        confidence = _extract_confidence(result)

        indicators = _extract_indicators(result)
        if not indicators:
            logger.debug("No submittable indicators found for scan %s", scan_id)
            return []

        rows: list[dict[str, Any]] = []
        for module, value, ind_confidence, extra in indicators:
            # Use the per-indicator confidence if available; otherwise the overall score.
            effective_confidence = ind_confidence if ind_confidence > 0 else confidence

            if effective_confidence >= auto_threshold:
                row = self._auto_submit(scan_id, case_id, module, value, effective_confidence, extra)
            elif effective_confidence >= queue_threshold:
                row = self._queue_for_review(scan_id, case_id, module, value, effective_confidence)
            else:
                logger.debug(
                    "Skipping indicator %s (%s) — confidence %d below queue threshold %d",
                    value,
                    module,
                    effective_confidence,
                    queue_threshold,
                )
                continue

            if row:
                rows.append(row)

        logger.info(
            "ECX submission governance: %d indicators processed for scan %s " "(%d auto-submit, %d queued, %d skipped)",
            len(indicators),
            scan_id,
            sum(1 for r in rows if r.get("status") == "submitted"),
            sum(1 for r in rows if r.get("status") == "queued"),
            len(indicators) - len(rows),
        )
        return rows

    def analyst_approve(
        self,
        submission_id: str,
        release_label: str,
        analyst: str,
    ) -> dict[str, Any] | None:
        """Approve a queued submission and transmit it to eCX.

        Args:
            submission_id: The queued submission to approve.
            release_label: eCX release classification label.
            analyst: Analyst identifier performing the approval.

        Returns:
            Updated submission row dict, or ``None`` if not found.
        """
        row = self._store.get_ecx_submission(submission_id)
        if row is None:
            logger.warning("analyst_approve: submission %s not found", submission_id)
            return None
        if row.get("status") != "queued":
            logger.warning(
                "analyst_approve: submission %s has status %r — expected 'queued'",
                submission_id,
                row.get("status"),
            )
            return None

        ecx_record_id, error = self._submit_with_dedup(
            module=row["ecx_module"],
            value=row["submitted_value"],
            confidence=row["confidence"],
            release_label=release_label,
        )
        now = datetime.now(UTC)
        if error:
            self._store.update_ecx_submission(
                submission_id,
                status="failed",
                error_message=error,
                submitted_by=analyst,
                submitted_at=now,
                release_label=release_label,
            )
        else:
            self._store.update_ecx_submission(
                submission_id,
                status="submitted",
                ecx_record_id=ecx_record_id,
                submitted_by=analyst,
                submitted_at=now,
                release_label=release_label,
                error_message=None,
            )
        return self._store.get_ecx_submission(submission_id)

    def analyst_reject(
        self,
        submission_id: str,
        analyst: str,
        reason: str = "",
    ) -> dict[str, Any] | None:
        """Reject a queued submission without transmitting to eCX.

        Args:
            submission_id: The queued submission to reject.
            analyst: Analyst identifier performing the rejection.
            reason: Optional rejection reason (stored in ``error_message``).

        Returns:
            Updated submission row dict, or ``None`` if not found.
        """
        row = self._store.get_ecx_submission(submission_id)
        if row is None:
            logger.warning("analyst_reject: submission %s not found", submission_id)
            return None
        if row.get("status") not in ("queued", "pending"):
            logger.warning(
                "analyst_reject: submission %s has status %r — expected queued/pending",
                submission_id,
                row.get("status"),
            )
            return None

        self._store.update_ecx_submission(
            submission_id,
            status="rejected",
            submitted_by=analyst,
            submitted_at=datetime.now(UTC),
            error_message=reason or "Rejected by analyst",
        )
        logger.info("Submission %s rejected by %s", submission_id, analyst)
        return self._store.get_ecx_submission(submission_id)

    def retract(self, submission_id: str, analyst: str) -> dict[str, Any] | None:
        """Retract a previously submitted eCX record.

        Calls ``update_record`` on the eCX API to set status ``"removed"``,
        then marks the local row as ``"retracted"``.

        Args:
            submission_id: The submitted record to retract.
            analyst: Analyst identifier performing the retraction.

        Returns:
            Updated submission row dict, or ``None`` if not found.
        """
        row = self._store.get_ecx_submission(submission_id)
        if row is None:
            logger.warning("retract: submission %s not found", submission_id)
            return None
        if row.get("status") != "submitted":
            logger.warning(
                "retract: submission %s has status %r — only 'submitted' records can be retracted",
                submission_id,
                row.get("status"),
            )
            return None

        ecx_record_id = row.get("ecx_record_id")
        ecx_module = row.get("ecx_module", "")
        error: str | None = None

        if ecx_record_id:
            try:
                self._client.update_record(ecx_module, ecx_record_id, status="removed")
                logger.info("Retracted eCX %s record %s (submission %s)", ecx_module, ecx_record_id, submission_id)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                logger.warning("Failed to retract eCX record %s: %s", ecx_record_id, error)

        self._store.update_ecx_submission(
            submission_id,
            status="retracted",
            submitted_by=analyst,
            error_message=error,
        )
        return self._store.get_ecx_submission(submission_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auto_submit(
        self,
        scan_id: str,
        case_id: str | None,
        module: str,
        value: str,
        confidence: int,
        extra: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Create a submission row and immediately transmit to eCX.

        Args:
            scan_id: SSI scan ID.
            case_id: Core case ID.
            module: eCX module path.
            value: Indicator value (URL / domain / IP / address).
            confidence: Confidence score 0–100.
            extra: Module-specific fields (brand, currency, classification, etc.).

        Returns:
            Submission row dict.
        """
        submission_id = str(uuid4())
        self._store.create_ecx_submission(
            submission_id=submission_id,
            scan_id=scan_id,
            case_id=case_id,
            ecx_module=module,
            submitted_value=value,
            confidence=confidence,
            status="pending",
            submitted_by="auto",
        )

        ecx_record_id, error = self._submit_with_dedup(
            module=module,
            value=value,
            confidence=confidence,
            release_label=extra.get("release_label", ""),
            **{k: v for k, v in extra.items() if k != "release_label"},
        )
        now = datetime.now(UTC)
        if error:
            self._store.update_ecx_submission(
                submission_id,
                status="failed",
                error_message=error,
                submitted_at=now,
            )
        else:
            self._store.update_ecx_submission(
                submission_id,
                status="submitted",
                ecx_record_id=ecx_record_id,
                submitted_at=now,
            )

        return self._store.get_ecx_submission(submission_id)

    def _queue_for_review(
        self,
        scan_id: str,
        case_id: str | None,
        module: str,
        value: str,
        confidence: int,
    ) -> dict[str, Any] | None:
        """Create a queued submission row pending analyst review.

        Args:
            scan_id: SSI scan ID.
            case_id: Core case ID.
            module: eCX module path.
            value: Indicator value.
            confidence: Confidence score 0–100.

        Returns:
            Submission row dict.
        """
        submission_id = str(uuid4())
        self._store.create_ecx_submission(
            submission_id=submission_id,
            scan_id=scan_id,
            case_id=case_id,
            ecx_module=module,
            submitted_value=value,
            confidence=confidence,
            status="queued",
            submitted_by="",
        )
        logger.info("Queued eCX submission %s (%s %s) for analyst review", submission_id, module, value[:60])
        return self._store.get_ecx_submission(submission_id)

    def _submit_with_dedup(
        self,
        module: str,
        value: str,
        confidence: int,
        release_label: str = "",
        **extra: Any,
    ) -> tuple[int | None, str | None]:
        """Submit to eCX, updating an existing record if one is found.

        Searches eCX for an existing record before posting.  If found and
        the existing confidence is lower, updates it; otherwise submits a new
        record.

        Args:
            module: eCX module path.
            value: Indicator value.
            confidence: Confidence score.
            release_label: Optional release label (phish module).
            **extra: Additional module-specific keyword arguments.

        Returns:
            Tuple of ``(ecx_record_id, error_message)``.  On success
            ``error_message`` is ``None``; on failure ``ecx_record_id`` is
            ``None``.
        """
        try:
            # Check for existing eCX record to avoid duplicates
            existing_id: int | None = self._find_existing(module, value)
            if existing_id:
                self._client.update_record(module, existing_id, confidence=confidence)
                logger.info("Updated existing eCX %s record %s (confidence=%d)", module, existing_id, confidence)
                return existing_id, None

            # New submission
            if module == _MODULE_PHISH:
                ecx_id = self._client.submit_phish(
                    url=value,
                    confidence=confidence,
                    brand=extra.get("brand", ""),
                    ip=extra.get("ip"),
                )
            elif module == _MODULE_CRYPTO:
                ecx_id = self._client.submit_crypto(
                    address=value,
                    currency=extra.get("currency", ""),
                    confidence=confidence,
                    crime_category=extra.get("crime_category", "fraud"),
                    site_link=extra.get("site_link", ""),
                    procedure=extra.get("procedure", ""),
                )
            elif module == _MODULE_DOMAIN:
                ecx_id = self._client.submit_domain(
                    domain=value,
                    classification=extra.get("classification", "phishing"),
                    confidence=confidence,
                )
            elif module == _MODULE_IP:
                ecx_id = self._client.submit_ip(
                    ip=value,
                    confidence=confidence,
                    description=extra.get("description", ""),
                )
            else:
                return None, f"Unsupported eCX module: {module}"

            logger.info("Submitted to eCX %s → record ID %s (confidence=%d)", module, ecx_id, confidence)
            return ecx_id, None

        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            logger.warning("eCX submission failed (%s %s): %s", module, value[:60], msg)
            return None, msg

    def _find_existing(self, module: str, value: str) -> int | None:
        """Search eCX for an existing record matching *value*.

        Returns the eCX record ID if found, otherwise ``None``.  Errors
        during the search are silently swallowed so a failed lookup never
        blocks the submission path.

        Args:
            module: eCX module path.
            value: Indicator value to search for.

        Returns:
            eCX record ID or ``None``.
        """
        try:
            if module == _MODULE_PHISH:
                hits = self._client.search_phish(value, limit=1)
                return hits[0].id if hits else None
            if module == _MODULE_DOMAIN:
                hits = self._client.search_domain(value, limit=1)
                return hits[0].id if hits else None
            if module == _MODULE_IP:
                hits = self._client.search_ip(value, limit=1)
                return hits[0].id if hits else None
            if module == _MODULE_CRYPTO:
                hits = self._client.search_crypto(value, limit=1)
                return hits[0].id if hits else None
        except Exception:
            logger.debug("eCX dedup search failed for %s %s — proceeding with new submission", module, value[:60])
        return None


# ---------------------------------------------------------------------------
# Indicator extraction helpers
# ---------------------------------------------------------------------------


def _extract_confidence(result: Any) -> int:
    """Derive a 0–100 integer confidence from an investigation result.

    Uses ``taxonomy_result.risk_score`` when available (already 0–100),
    otherwise falls back to ``classification.confidence * 100``.

    Args:
        result: :class:`~ssi.models.investigation.InvestigationResult`.

    Returns:
        Integer confidence score 0–100.
    """
    if result.taxonomy_result and result.taxonomy_result.risk_score > 0:
        return int(result.taxonomy_result.risk_score)
    if result.classification and result.classification.confidence > 0:
        return int(result.classification.confidence * 100)
    return 0


def _extract_domain(url: str) -> str:
    """Parse the hostname from a URL string."""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _extract_indicators(
    result: Any,
) -> list[tuple[str, str, int, dict[str, Any]]]:
    """Extract submittable indicators from an investigation result.

    Returns a list of ``(module, value, indicator_confidence, extra_kwargs)``
    tuples for each indicator discovered during the investigation.

    Indicators:
        phish — the target URL (if the site was classified as phishing)
        malicious-domain — the site's hostname
        malicious-ip — the primary hosting IP (if resolved)
        cryptocurrency-addresses — each harvested wallet address

    Args:
        result: :class:`~ssi.models.investigation.InvestigationResult`.

    Returns:
        List of ``(module, value, confidence, extra)`` tuples.
    """
    from ssi.osint.ecrimex import load_currency_map

    indicators: list[tuple[str, str, int, dict[str, Any]]] = []
    url = result.url or ""
    if not url:
        return indicators

    domain = _extract_domain(url)

    # Phish submission — only when the investigation produced a valid classification
    scam_type = ""
    brand = ""
    if result.classification:
        scam_type = result.classification.scam_type or ""
        brand = result.brand_impersonation or ""
    elif result.taxonomy_result:
        # Derive scam type from top intent label
        intents = result.taxonomy_result.intent or []
        scam_type = intents[0].label if intents else ""

    if url and scam_type:
        ip_list: list[str] = []
        if result.dns and result.dns.a:
            ip_list = result.dns.a[:3]  # First 3 IPs only
        indicators.append(
            (
                _MODULE_PHISH,
                url,
                0,  # Use overall confidence
                {"brand": brand, "ip": ip_list or None},
            )
        )

    # Malicious domain
    if domain:
        indicators.append(
            (
                _MODULE_DOMAIN,
                domain,
                0,  # Use overall confidence
                {"classification": scam_type or "phishing"},
            )
        )

    # Malicious IP — primary hosting IP
    if result.dns and result.dns.a:
        primary_ip = result.dns.a[0]
        description = f"Hosting IP for scam site {domain}" if domain else "Scam site hosting IP"
        indicators.append((_MODULE_IP, primary_ip, 0, {"description": description}))

    # Cryptocurrency addresses
    currency_map = load_currency_map()
    for wallet in result.wallets or []:
        address = wallet.wallet_address if hasattr(wallet, "wallet_address") else str(wallet)
        if not address:
            continue
        token_symbol = (wallet.token_symbol if hasattr(wallet, "token_symbol") else "").upper()
        ecx_currency = currency_map.get(token_symbol, token_symbol)
        # Wallet confidence is 0.0–1.0; scale to 0–100
        wallet_conf = int((wallet.confidence if hasattr(wallet, "confidence") else 0) * 100)
        indicators.append(
            (
                _MODULE_CRYPTO,
                address,
                wallet_conf,
                {
                    "currency": ecx_currency,
                    "crime_category": "fraud",
                    "site_link": url,
                    "procedure": f"Extracted by SSI from {domain}" if domain else "Extracted by SSI",
                },
            )
        )

    return indicators


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def get_submission_service() -> ECXSubmissionService | None:
    """Return a configured :class:`ECXSubmissionService` or ``None``.

    Returns ``None`` when eCX is disabled, the API key is missing, or the
    submission gates are not satisfied.  Uses the module-level ECX client
    singleton so the same httpx session is reused.

    Returns:
        A ready-to-use service instance, or ``None``.
    """
    from ssi.osint.ecrimex import get_client
    from ssi.settings import get_settings
    from ssi.store import build_scan_store

    settings = get_settings().ecx
    if not settings.submission_enabled:
        return None

    client = get_client()
    if client is None:
        return None

    store = build_scan_store()
    return ECXSubmissionService(client=client, store=store)
