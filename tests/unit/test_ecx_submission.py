"""Unit tests for the eCrimeX Phase 2 submission service.

Covers:
- Safety gates: both flags must be true; single-flag flip is blocked
- Threshold routing: auto-submit vs queue vs skip
- Deduplication: existing eCX record → update instead of POST
- analyst_approve / analyst_reject / retract flows
- _extract_confidence helper
- _extract_indicators helper
- get_submission_service factory (disabled by default)
- Field mapping: SSI result fields → eCX submission request bodies (2C)
- End-to-end: orchestrator populates result.ecx_submissions (2D)
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ssi.ecx.submission import (
    ECXSubmissionService,
    _extract_confidence,
    _extract_domain,
    _extract_indicators,
    get_submission_service,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_settings(
    submission_enabled: bool = True,
    submission_agreement_signed: bool = True,
    auto_submit_threshold: int = 80,
    queue_threshold: int = 50,
) -> MagicMock:
    """Build a mock settings.ecx object."""
    ecx = MagicMock()
    ecx.submission_enabled = submission_enabled
    ecx.submission_agreement_signed = submission_agreement_signed
    ecx.auto_submit_threshold = auto_submit_threshold
    ecx.queue_threshold = queue_threshold
    settings = MagicMock()
    settings.ecx = ecx
    return settings


def _make_result(
    url: str = "https://fake-bank.example.com/login",
    confidence: float = 0.9,
    scam_type: str = "phishing",
    brand: str = "ExampleBank",
    dns_a: list[str] | None = None,
    wallets: list[Any] | None = None,
) -> SimpleNamespace:
    """Build a minimal investigation result namespace."""
    classification = SimpleNamespace(confidence=confidence, scam_type=scam_type)
    dns = SimpleNamespace(a=dns_a or ["1.2.3.4"]) if dns_a is not False else None
    return SimpleNamespace(
        url=url,
        classification=classification,
        taxonomy_result=None,
        brand_impersonation=brand,
        dns=dns,
        wallets=wallets or [],
        success=True,
    )


def _make_wallet(address: str, token_symbol: str = "ETH", confidence: float = 0.85) -> SimpleNamespace:
    return SimpleNamespace(wallet_address=address, token_symbol=token_symbol, confidence=confidence)


@pytest.fixture()
def mock_client() -> MagicMock:
    """A mock ECXClient that returns deterministic record IDs."""
    client = MagicMock()
    client.submit_phish.return_value = 1001
    client.submit_domain.return_value = 1002
    client.submit_ip.return_value = 1003
    client.submit_crypto.return_value = 1004
    client.update_record.return_value = None
    client.search_phish.return_value = []
    client.search_domain.return_value = []
    client.search_ip.return_value = []
    client.search_crypto.return_value = []
    return client


@pytest.fixture()
def store() -> MagicMock:
    """A mock ScanStore that tracks created/updated submissions."""
    store_ = MagicMock()
    _rows: dict[str, dict[str, Any]] = {}

    def _create(**kwargs: Any) -> str:
        sid = kwargs["submission_id"]
        _rows[sid] = dict(kwargs)
        return sid

    def _update(submission_id: str, **fields: Any) -> None:
        if submission_id in _rows:
            _rows[submission_id].update(fields)

    def _get(submission_id: str) -> dict[str, Any] | None:
        return _rows.get(submission_id)

    def _list(**kwargs: Any) -> list[dict[str, Any]]:
        return list(_rows.values())

    store_.create_ecx_submission.side_effect = _create
    store_.update_ecx_submission.side_effect = _update
    store_.get_ecx_submission.side_effect = _get
    store_.list_ecx_submissions.side_effect = _list
    return store_


@pytest.fixture()
def service(mock_client: MagicMock, store: MagicMock) -> ECXSubmissionService:
    """A fully functional ECXSubmissionService with mocked dependencies."""
    return ECXSubmissionService(client=mock_client, store=store)


# ---------------------------------------------------------------------------
# Safety gate tests
# ---------------------------------------------------------------------------


class TestSafetyGates:
    """Both submission_enabled AND submission_agreement_signed must be True."""

    def test_both_disabled_returns_empty(self, service: ECXSubmissionService) -> None:
        """When both flags are false, no data is transmitted."""
        settings = _make_settings(submission_enabled=False, submission_agreement_signed=False)
        result = _make_result()
        with patch("ssi.settings.get_settings", return_value=settings):
            rows = service.process_investigation("scan-1", "case-1", result)
        assert rows == []
        service._client.submit_phish.assert_not_called()

    def test_submission_enabled_but_agreement_not_signed(
        self, service: ECXSubmissionService, caplog: pytest.LogCaptureFixture
    ) -> None:
        """submission_enabled=true without the agreement flag → warning + no transmission."""
        settings = _make_settings(submission_enabled=True, submission_agreement_signed=False)
        result = _make_result()
        with (
            patch("ssi.settings.get_settings", return_value=settings),
            caplog.at_level(logging.WARNING, logger="ssi.ecx.submission"),
        ):
            rows = service.process_investigation("scan-2", "case-2", result)
        assert rows == []
        service._client.submit_phish.assert_not_called()
        assert "submission_agreement_signed=false" in caplog.text

    def test_agreement_signed_but_submission_disabled(self, service: ECXSubmissionService) -> None:
        """submission_agreement_signed=true alone is insufficient."""
        settings = _make_settings(submission_enabled=False, submission_agreement_signed=True)
        result = _make_result()
        with patch("ssi.settings.get_settings", return_value=settings):
            rows = service.process_investigation("scan-3", "case-3", result)
        assert rows == []
        service._client.submit_phish.assert_not_called()

    def test_both_enabled_processes_indicators(self, service: ECXSubmissionService) -> None:
        """When both flags are true, indicators are processed."""
        settings = _make_settings(submission_enabled=True, submission_agreement_signed=True)
        result = _make_result(confidence=0.90)  # 90 >= auto_submit_threshold=80
        with patch("ssi.settings.get_settings", return_value=settings):
            rows = service.process_investigation("scan-4", "case-4", result)
        assert len(rows) > 0
        # At minimum phish + domain + IP should be submitted
        assert service._client.submit_phish.call_count >= 1


# ---------------------------------------------------------------------------
# Threshold routing
# ---------------------------------------------------------------------------


class TestThresholdRouting:
    """Test that confidence scores route correctly to auto-submit, queue, or skip."""

    def _run(
        self,
        service: ECXSubmissionService,
        confidence_pct: int,
        auto_threshold: int = 80,
        queue_threshold: int = 50,
    ) -> list[dict[str, Any]]:
        """Helper: run process_investigation with given confidence and thresholds."""
        # confidence_pct is 0–100 from taxonomy; we pass via classification (0–1 scale)
        settings = _make_settings(
            auto_submit_threshold=auto_threshold,
            queue_threshold=queue_threshold,
        )
        # Use a taxonomy_result to supply the score directly
        result = _make_result()
        result.taxonomy_result = SimpleNamespace(risk_score=confidence_pct, intent=[])
        result.classification = None
        with patch("ssi.settings.get_settings", return_value=settings):
            return service.process_investigation("scan-route", "case-route", result)

    def test_high_confidence_auto_submits(self, service: ECXSubmissionService) -> None:
        """Score >= auto_threshold → status 'submitted' via direct API call.

        The result has classification=None so phish is skipped (requires scam_type),
        but domain and IP indicators are always extracted and should be auto-submitted.
        """
        rows = self._run(service, confidence_pct=90)
        statuses = {r["status"] for r in rows}
        assert "submitted" in statuses
        # Domain + IP are always submitted when URL and DNS are present
        assert service._client.submit_domain.call_count >= 1 or service._client.submit_ip.call_count >= 1

    def test_medium_confidence_queues(self, service: ECXSubmissionService) -> None:
        """Score between queue_threshold and auto_threshold → status 'queued'."""
        rows = self._run(service, confidence_pct=60)
        statuses = {r["status"] for r in rows}
        assert "queued" in statuses
        service._client.submit_phish.assert_not_called()

    def test_low_confidence_skips(self, service: ECXSubmissionService) -> None:
        """Score below queue_threshold → no rows created, no API call."""
        rows = self._run(service, confidence_pct=30)
        assert rows == []
        service._client.submit_phish.assert_not_called()

    def test_exactly_auto_threshold_is_auto_submitted(self, service: ECXSubmissionService) -> None:
        """Score == auto_threshold is auto-submitted (>=), not queued."""
        rows = self._run(service, confidence_pct=80, auto_threshold=80)
        statuses = {r["status"] for r in rows}
        assert "submitted" in statuses

    def test_exactly_queue_threshold_is_queued(self, service: ECXSubmissionService) -> None:
        """Score == queue_threshold (below auto) is queued (>=), not skipped."""
        rows = self._run(service, confidence_pct=50, auto_threshold=80, queue_threshold=50)
        statuses = {r["status"] for r in rows}
        assert "queued" in statuses


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    """Existing eCX records should trigger update instead of duplicate POST."""

    def test_existing_phish_triggers_update(self, service: ECXSubmissionService) -> None:
        """If search_phish returns a hit, submit_phish is NOT called; update_record IS."""
        existing = MagicMock()
        existing.id = 999
        service._client.search_phish.return_value = [existing]

        settings = _make_settings()
        result = _make_result(confidence=0.90)
        with patch("ssi.settings.get_settings", return_value=settings):
            rows = service.process_investigation("scan-dedup", "case-dedup", result)

        # At least the phish indicator should trigger an update
        service._client.submit_phish.assert_not_called()
        service._client.update_record.assert_called()
        # The submitted phish row should have eCX ID 999
        phish_rows = [r for r in rows if r.get("ecx_module") == "phish"]
        assert phish_rows[0]["ecx_record_id"] == 999

    def test_no_existing_record_creates_new(self, service: ECXSubmissionService) -> None:
        """When search returns empty, a new POST is made."""
        service._client.search_phish.return_value = []
        settings = _make_settings()
        result = _make_result(confidence=0.90)
        with patch("ssi.settings.get_settings", return_value=settings):
            rows = service.process_investigation("scan-new", "case-new", result)
        service._client.submit_phish.assert_called_once()
        phish_rows = [r for r in rows if r.get("ecx_module") == "phish"]
        assert phish_rows[0]["ecx_record_id"] == 1001  # from mock fixture


# ---------------------------------------------------------------------------
# Analyst approval / rejection
# ---------------------------------------------------------------------------


class TestAnalystWorkflow:
    """Governance actions on queued submissions."""

    def _create_queued(self, store: MagicMock) -> str:
        """Insert a queued submission directly into the mock store."""
        sid = "test-queued-submission-id"
        store.create_ecx_submission(
            submission_id=sid,
            scan_id="scan-analytic",
            case_id="case-analytic",
            ecx_module="phish",
            submitted_value="https://scam.example.com",
            confidence=65,
            release_label="",
            status="queued",
            submitted_by="",
        )
        return sid

    def test_approve_queued_submission(
        self, service: ECXSubmissionService, store: MagicMock, mock_client: MagicMock
    ) -> None:
        """Approving a queued submission transmits to eCX and sets status='submitted'."""
        sid = self._create_queued(store)
        mock_client.search_phish.return_value = []
        mock_client.submit_phish.return_value = 2000

        updated = service.analyst_approve(sid, release_label="AMBER", analyst="analyst@example.com")

        assert updated is not None
        assert updated["status"] == "submitted"
        assert updated["ecx_record_id"] == 2000
        assert updated["submitted_by"] == "analyst@example.com"
        assert updated["release_label"] == "AMBER"

    def test_approve_nonexistent_returns_none(self, service: ECXSubmissionService) -> None:
        """Approving an unknown ID returns None and does not crash."""
        result = service.analyst_approve("does-not-exist", release_label="", analyst="analyst")
        assert result is None

    def test_approve_already_submitted_returns_none(self, service: ECXSubmissionService, store: MagicMock) -> None:
        """Cannot approve a record that is already submitted (wrong state)."""
        sid = "already-submitted"
        store.create_ecx_submission(
            submission_id=sid,
            scan_id="s",
            case_id="c",
            ecx_module="phish",
            submitted_value="https://scam.example.com",
            confidence=90,
            release_label="",
            status="submitted",
            submitted_by="auto",
        )
        result = service.analyst_approve(sid, release_label="AMBER", analyst="analyst")
        assert result is None

    def test_reject_queued_submission(self, service: ECXSubmissionService, store: MagicMock) -> None:
        """Rejecting marks the row 'rejected' without calling the eCX API."""
        sid = self._create_queued(store)
        updated = service.analyst_reject(sid, analyst="reviewer", reason="False positive")

        assert updated is not None
        assert updated["status"] == "rejected"
        assert updated["error_message"] == "False positive"
        service._client.submit_phish.assert_not_called()

    def test_reject_nonexistent_returns_none(self, service: ECXSubmissionService) -> None:
        result = service.analyst_reject("ghost-id", analyst="reviewer")
        assert result is None


# ---------------------------------------------------------------------------
# Retraction
# ---------------------------------------------------------------------------


class TestRetraction:
    def _create_submitted(self, store: MagicMock) -> str:
        sid = "retract-test-id"
        store.create_ecx_submission(
            submission_id=sid,
            scan_id="scan-ret",
            case_id="case-ret",
            ecx_module="phish",
            submitted_value="https://retract.example.com",
            confidence=88,
            release_label="",
            status="submitted",
            submitted_by="auto",
        )
        # Simulate that the store also has the eCX record ID set
        store.update_ecx_submission(sid, ecx_record_id=5555)
        return sid

    def test_retract_submitted_record(
        self, service: ECXSubmissionService, store: MagicMock, mock_client: MagicMock
    ) -> None:
        """Retracting a submitted record calls update_record('removed') and marks 'retracted'."""
        sid = self._create_submitted(store)
        updated = service.retract(sid, analyst="senior-analyst")

        assert updated is not None
        assert updated["status"] == "retracted"
        mock_client.update_record.assert_called_once_with("phish", 5555, status="removed")

    def test_retract_queued_record_returns_none(self, service: ECXSubmissionService, store: MagicMock) -> None:
        """Cannot retract a record that has not been submitted yet."""
        sid = "queued-record"
        store.create_ecx_submission(
            submission_id=sid,
            scan_id="s",
            case_id="c",
            ecx_module="phish",
            submitted_value="https://q.example.com",
            confidence=60,
            release_label="",
            status="queued",
            submitted_by="",
        )
        result = service.retract(sid, analyst="analyst")
        assert result is None

    def test_retract_api_error_still_marks_retracted(
        self, service: ECXSubmissionService, store: MagicMock, mock_client: MagicMock
    ) -> None:
        """If the eCX API call fails we still mark the local record 'retracted'."""
        sid = self._create_submitted(store)
        mock_client.update_record.side_effect = Exception("Network timeout")

        updated = service.retract(sid, analyst="analyst")

        assert updated is not None
        assert updated["status"] == "retracted"
        assert updated["error_message"] is not None


# ---------------------------------------------------------------------------
# _extract_confidence helper
# ---------------------------------------------------------------------------


class TestExtractConfidence:
    def test_uses_taxonomy_risk_score(self) -> None:
        result = SimpleNamespace(
            taxonomy_result=SimpleNamespace(risk_score=73, intent=[]),
            classification=SimpleNamespace(confidence=0.90, scam_type="phishing"),
        )
        assert _extract_confidence(result) == 73

    def test_falls_back_to_classification(self) -> None:
        result = SimpleNamespace(
            taxonomy_result=None,
            classification=SimpleNamespace(confidence=0.85, scam_type="phishing"),
        )
        assert _extract_confidence(result) == 85

    def test_zero_taxonomy_falls_back(self) -> None:
        result = SimpleNamespace(
            taxonomy_result=SimpleNamespace(risk_score=0, intent=[]),
            classification=SimpleNamespace(confidence=0.72, scam_type="phishing"),
        )
        assert _extract_confidence(result) == 72

    def test_no_classification_returns_zero(self) -> None:
        result = SimpleNamespace(taxonomy_result=None, classification=None)
        assert _extract_confidence(result) == 0


# ---------------------------------------------------------------------------
# _extract_domain helper
# ---------------------------------------------------------------------------


class TestExtractDomain:
    def test_standard_https_url(self) -> None:
        assert _extract_domain("https://fake-bank.example.com/login") == "fake-bank.example.com"

    def test_bare_domain(self) -> None:
        assert _extract_domain("http://scam.io") == "scam.io"

    def test_empty_string(self) -> None:
        assert _extract_domain("") == ""


# ---------------------------------------------------------------------------
# _extract_indicators helper
# ---------------------------------------------------------------------------


class TestExtractIndicators:
    def test_phishing_result_produces_phish_domain_ip(self) -> None:
        result = _make_result(
            url="https://phish.example.com/steal",
            confidence=0.9,
            scam_type="phishing",
            brand="BigBank",
            dns_a=["10.0.0.1", "10.0.0.2"],
        )
        with patch("ssi.osint.ecrimex.load_currency_map", return_value={}):
            indicators = _extract_indicators(result)

        modules = [m for m, *_ in indicators]
        assert "phish" in modules
        assert "malicious-domain" in modules
        assert "malicious-ip" in modules

    def test_wallet_produces_crypto_indicator(self) -> None:
        wallet = _make_wallet("0xABCDEF1234567890", token_symbol="ETH", confidence=0.88)
        result = _make_result(wallets=[wallet])
        with patch(
            "ssi.osint.ecrimex.load_currency_map",
            return_value={"ETH": "Ethereum"},
        ):
            indicators = _extract_indicators(result)

        crypto = [item for item in indicators if item[0] == "cryptocurrency-addresses"]
        assert len(crypto) == 1
        _, address, conf, extra = crypto[0]
        assert address == "0xABCDEF1234567890"
        assert conf == 88  # 0.88 * 100
        assert extra["currency"] == "Ethereum"

    def test_no_url_returns_empty(self) -> None:
        result = _make_result(url="")
        with patch("ssi.osint.ecrimex.load_currency_map", return_value={}):
            indicators = _extract_indicators(result)
        assert indicators == []

    def test_no_dns_skips_ip_indicator(self) -> None:
        result = _make_result(dns_a=False)  # dns=None via _make_result logic
        with patch("ssi.osint.ecrimex.load_currency_map", return_value={}):
            indicators = _extract_indicators(result)
        modules = [m for m, *_ in indicators]
        assert "malicious-ip" not in modules


# ---------------------------------------------------------------------------
# get_submission_service factory
# ---------------------------------------------------------------------------


class TestGetSubmissionService:
    def test_returns_none_when_disabled(self) -> None:
        settings = _make_settings(submission_enabled=False)
        with patch("ssi.settings.get_settings", return_value=settings):
            # The factory checks submission_enabled before building the service
            result = get_submission_service()
        assert result is None

    def test_returns_service_when_enabled(self) -> None:
        settings = _make_settings(submission_enabled=True, submission_agreement_signed=True)
        mock_ecx = MagicMock()
        mock_store = MagicMock()
        with (
            patch("ssi.settings.get_settings", return_value=settings),
            patch("ssi.osint.ecrimex.get_client", return_value=mock_ecx),
            patch("ssi.store.build_scan_store", return_value=mock_store),
        ):
            result = get_submission_service()
        assert isinstance(result, ECXSubmissionService)


# ---------------------------------------------------------------------------
# Field mapping tests (2C)
# ---------------------------------------------------------------------------
# Verify that _submit_with_dedup passes the correct SSI-to-eCX field translations
# when submitting phish, crypto, and domain indicators.


class TestFieldMapping:
    """ECX field mapping: SSI investigation data → eCX submission request bodies."""

    def _make_service(self, mock_client: MagicMock, mock_store: MagicMock) -> ECXSubmissionService:
        """Build a service backed by mock client and store."""
        mock_store.create_ecx_submission.return_value = "sub-1"
        mock_store.get_ecx_submission.return_value = {
            "submission_id": "sub-1",
            "ecx_module": "phish",
            "submitted_value": "https://evil.com",
            "confidence": 85,
            "status": "submitted",
            "ecx_record_id": 101,
        }
        return ECXSubmissionService(client=mock_client, store=mock_store)

    def test_phish_submission_uses_brand_and_ip(self, mock_client: MagicMock) -> None:
        """_submit_with_dedup for phish should pass brand and ip to submit_phish."""
        mock_store = MagicMock()
        service = self._make_service(mock_client, mock_store)
        mock_client.search_phish.return_value = []
        mock_client.submit_phish.return_value = 55

        service._submit_with_dedup(
            module="phish",
            value="https://evil.com",
            confidence=85,
            brand="ExampleBank",
            ip=["1.2.3.4"],
        )

        mock_client.submit_phish.assert_called_once_with(
            url="https://evil.com",
            confidence=85,
            brand="ExampleBank",
            ip=["1.2.3.4"],
        )

    def test_crypto_submission_maps_currency_to_ecx_code(self, mock_client: MagicMock) -> None:
        """_submit_with_dedup for crypto must pass the eCX currency code and crime_category."""
        mock_store = MagicMock()
        service = self._make_service(mock_client, mock_store)
        mock_client.search_crypto.return_value = []
        mock_client.submit_crypto.return_value = 66

        service._submit_with_dedup(
            module="cryptocurrency-addresses",
            value="bc1qfake",
            confidence=90,
            currency="bitcoin",
            crime_category="fraud",
            site_link="https://evil.com",
        )

        mock_client.submit_crypto.assert_called_once_with(
            address="bc1qfake",
            currency="bitcoin",
            confidence=90,
            crime_category="fraud",
            site_link="https://evil.com",
            procedure="",
        )

    def test_domain_submission_uses_classification(self, mock_client: MagicMock) -> None:
        """_submit_with_dedup for domain should forward classification to submit_domain."""
        mock_store = MagicMock()
        service = self._make_service(mock_client, mock_store)
        mock_client.search_domain.return_value = []
        mock_client.submit_domain.return_value = 77

        service._submit_with_dedup(
            module="malicious-domain",
            value="evil.com",
            confidence=80,
            classification="phishing",
        )

        mock_client.submit_domain.assert_called_once_with(
            domain="evil.com",
            classification="phishing",
            confidence=80,
        )

    def test_ip_submission_passes_description(self, mock_client: MagicMock) -> None:
        """_submit_with_dedup for IP should pass description to submit_ip."""
        mock_store = MagicMock()
        service = self._make_service(mock_client, mock_store)
        mock_client.search_ip.return_value = []
        mock_client.submit_ip.return_value = 88

        service._submit_with_dedup(
            module="malicious-ip",
            value="5.5.5.5",
            confidence=70,
            description="Hosting phishing page",
        )

        mock_client.submit_ip.assert_called_once_with(
            ip="5.5.5.5",
            confidence=70,
            description="Hosting phishing page",
        )

    def test_existing_record_triggers_update_not_post(self, mock_client: MagicMock) -> None:
        """When eCX already has a record, _submit_with_dedup should update, not POST."""
        from ssi.models.ecx import ECXPhishRecord

        mock_store = MagicMock()
        service = self._make_service(mock_client, mock_store)
        existing = ECXPhishRecord(id=42, url="https://evil.com", confidence=60)
        mock_client.search_phish.return_value = [existing]

        record_id, error = service._submit_with_dedup(
            module="phish",
            value="https://evil.com",
            confidence=85,
        )

        assert error is None
        assert record_id == 42
        mock_client.update_record.assert_called_once_with("phish", 42, confidence=85)
        mock_client.submit_phish.assert_not_called()


# ---------------------------------------------------------------------------
# End-to-end orchestrator integration (2D)
# ---------------------------------------------------------------------------


class TestOrchestratorPopulatesEcxSubmissions:
    """_run_ecx_submission should write back to result.ecx_submissions (2D)."""

    def test_submission_rows_attached_to_result(self) -> None:
        """After _run_ecx_submission runs, result.ecx_submissions should contain the rows."""
        from ssi.investigator.orchestrator import _run_ecx_submission

        rows = [
            {"submission_id": "sub-1", "ecx_module": "phish", "status": "submitted"},
        ]
        mock_service = MagicMock()
        mock_service.process_investigation.return_value = rows

        result = _make_result()
        result.ecx_submissions = []

        with patch("ssi.ecx.submission.get_submission_service", return_value=mock_service):
            _run_ecx_submission("scan-1", result)

        assert result.ecx_submissions == rows

    def test_submission_failure_does_not_raise(self) -> None:
        """A crash inside _run_ecx_submission should be swallowed — never propagate."""
        from ssi.investigator.orchestrator import _run_ecx_submission

        mock_service = MagicMock()
        mock_service.process_investigation.side_effect = RuntimeError("boom")

        result = _make_result()
        result.ecx_submissions = []

        with patch("ssi.ecx.submission.get_submission_service", return_value=mock_service):
            _run_ecx_submission("scan-1", result)

        assert result.ecx_submissions == []

    def test_no_rows_leaves_ecx_submissions_empty(self) -> None:
        """When process_investigation returns [], ecx_submissions should stay empty."""
        from ssi.investigator.orchestrator import _run_ecx_submission

        mock_service = MagicMock()
        mock_service.process_investigation.return_value = []

        result = _make_result()
        result.ecx_submissions = []

        with patch("ssi.ecx.submission.get_submission_service", return_value=mock_service):
            _run_ecx_submission("scan-1", result)

        assert result.ecx_submissions == []
