"""eCrimeX sandbox integration tests.

These tests hit the live eCX sandbox API and require a valid API key.
Run with::

    SSI_ECX__API_KEY="your-key" pytest tests/integration/test_ecx_sandbox.py -v

All tests are marked with ``@pytest.mark.ecx_sandbox`` so they can be
selected or excluded with ``-m ecx_sandbox`` / ``-m "not ecx_sandbox"``.

Note: The eCX API may return 403 or 405 for modules your key does not
have access to. Tests that call individual search methods treat HTTP errors
as "module not accessible" and skip with a warning rather than failing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
import pytest

from ssi.models.ecx import ECXCryptoRecord, ECXEnrichmentResult, ECXMalDomainRecord, ECXMalIPRecord, ECXPhishRecord
from ssi.osint.ecrimex import ECXClient, enrich_from_ecx

logger = logging.getLogger(__name__)

# Skip the entire module if no API key is set
_API_KEY = os.environ.get("SSI_ECX__API_KEY", "")
pytestmark = [
    pytest.mark.ecx_sandbox,
    pytest.mark.skipif(not _API_KEY, reason="SSI_ECX__API_KEY not set — skipping eCX sandbox tests"),
]

# Well-known test values likely to return results in the sandbox.
_TEST_PHISH_URL = "paypal.com"
_TEST_DOMAIN = "paypal.com"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ecx_client() -> ECXClient:
    """Build an ECXClient from environment variables."""
    return ECXClient(
        api_key=_API_KEY,
        base_url=os.environ.get("SSI_ECX__BASE_URL", "https://api.ecrimex.net"),
        attribution=os.environ.get("SSI_ECX__ATTRIBUTION", "i4g-ssi-test"),
        timeout=float(os.environ.get("SSI_ECX__TIMEOUT", "15")),
    )


# ---------------------------------------------------------------------------
# Helper: call a search method, tolerate module-access HTTP errors
# ---------------------------------------------------------------------------


def _try_search(callable_fn: Any, *args: Any) -> list[Any] | None:
    """Attempt a search; return results or None if the module is inaccessible."""
    try:
        return callable_fn(*args)
    except httpx.HTTPStatusError as exc:
        logger.warning("Module not accessible (%s) — %s", exc.response.status_code, exc.request.url)
        return None


# ---------------------------------------------------------------------------
# Client search methods — smoke tests against live API
# ---------------------------------------------------------------------------


class TestECXClientSandbox:
    """Smoke tests that verify the client can talk to the sandbox API.

    If a module returns an HTTP error (e.g. 403/405 for modules your
    key lacks access to), the test skips — it only fails on unexpected
    Python errors or malformed response parsing.
    """

    def test_search_phish(self, ecx_client: ECXClient) -> None:
        """search_phish should return a list of ECXPhishRecord (or module not accessible)."""
        results = _try_search(ecx_client.search_phish, _TEST_PHISH_URL, 3)
        if results is None:
            pytest.skip("phish module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], ECXPhishRecord)
            assert results[0].id is not None

    def test_search_domain(self, ecx_client: ECXClient) -> None:
        """search_domain should return a list of ECXMalDomainRecord."""
        results = _try_search(ecx_client.search_domain, _TEST_DOMAIN, 3)
        if results is None:
            pytest.skip("malicious-domain module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], ECXMalDomainRecord)

    def test_search_ip(self, ecx_client: ECXClient) -> None:
        """search_ip should return a list (possibly empty)."""
        results = _try_search(ecx_client.search_ip, "1.2.3.4", 3)
        if results is None:
            pytest.skip("malicious-ip module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], ECXMalIPRecord)

    def test_search_crypto(self, ecx_client: ECXClient) -> None:
        """search_crypto should return a list (possibly empty)."""
        results = _try_search(ecx_client.search_crypto, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", 3)
        if results is None:
            pytest.skip("cryptocurrency-addresses module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], ECXCryptoRecord)

    def test_search_report_phishing(self, ecx_client: ECXClient) -> None:
        """search_report_phishing should return a list of dicts."""
        results = _try_search(ecx_client.search_report_phishing, _TEST_PHISH_URL, 3)
        if results is None:
            pytest.skip("report-phishing module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], dict)

    def test_search_phish_empty(self, ecx_client: ECXClient) -> None:
        """Searching for a nonsense URL should return an empty list."""
        results = _try_search(ecx_client.search_phish, "xyzzy-no-such-url-99999.invalid", 3)
        if results is None:
            pytest.skip("phish module not accessible with this API key")
        assert isinstance(results, list)
        assert len(results) == 0


# ---------------------------------------------------------------------------
# Enrichment pipeline — end-to-end against live API
# ---------------------------------------------------------------------------


class TestEnrichmentPipelineSandbox:
    """Verify the enrichment pipeline works end-to-end with the sandbox.

    The pipeline uses _safe_query() internally, so individual module
    errors are caught — the enrichment completes even if some modules
    return HTTP errors.
    """

    def test_enrich_from_ecx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """enrich_from_ecx should aggregate results from available modules."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", _API_KEY)

        result = enrich_from_ecx(
            url=f"https://{_TEST_PHISH_URL}/login",
            domain=_TEST_DOMAIN,
            ip=None,
        )
        assert isinstance(result, ECXEnrichmentResult)
        assert result.query_count >= 1
        assert result.query_duration_ms > 0

    def test_enrich_from_ecx_with_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """enrich_from_ecx with IP should query one extra module."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", _API_KEY)

        result = enrich_from_ecx(
            url=f"https://{_TEST_PHISH_URL}/login",
            domain=_TEST_DOMAIN,
            ip="1.2.3.4",
        )
        assert isinstance(result, ECXEnrichmentResult)
        # With IP, should query 4 modules (phish + domain + ip + report-phishing)
        assert result.query_count == 4


# ---------------------------------------------------------------------------
# Cache round-trip — persist + retrieve
# ---------------------------------------------------------------------------


class TestCacheRoundTripSandbox:
    """Verify cache persistence works with live enrichment data."""

    def test_cache_round_trip(self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cache should persist enrichment results and retrieve them."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", _API_KEY)

        from ssi.store.scan_store import ScanStore

        store = ScanStore(db_path=tmp_path / "sandbox_cache.db")
        scan_id = store.create_scan(url=f"https://{_TEST_PHISH_URL}", domain=_TEST_DOMAIN)

        # Get live enrichment data
        result = enrich_from_ecx(
            url=f"https://{_TEST_PHISH_URL}/login",
            domain=_TEST_DOMAIN,
            ip=None,
        )

        if result.has_hits:
            count = store.cache_ecx_enrichments(scan_id, result, cache_ttl_hours=1)
            assert count > 0

            rows = store.get_ecx_enrichments(scan_id)
            assert len(rows) == count
            assert rows[0]["scan_id"] == scan_id
        else:
            # No hits from sandbox — cache should still work with zero rows
            count = store.cache_ecx_enrichments(scan_id, result, cache_ttl_hours=1)
            assert count == 0


# ---------------------------------------------------------------------------
# Submission service — end-to-end against live sandbox API
# ---------------------------------------------------------------------------


_SUBMISSION_ENABLED = (
    os.environ.get("SSI_ECX__SUBMISSION_ENABLED", "").lower() == "true"
    and os.environ.get("SSI_ECX__SUBMISSION_AGREEMENT_SIGNED", "").lower() == "true"
)

# Use a recognisable sentinel URL so sandbox submissions are easy to identify.
_SANDBOX_SUBMIT_URL = "https://sandbox-test-i4g-ssi.invalid/phish"
_SANDBOX_SUBMIT_DOMAIN = "sandbox-test-i4g-ssi.invalid"
_SANDBOX_SUBMIT_CRYPTO = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"


@pytest.fixture(scope="module")
def submission_store(tmp_path_factory: pytest.TempPathFactory) -> Any:
    """Temporary ScanStore for submission tests."""
    from ssi.store.scan_store import ScanStore

    db = tmp_path_factory.mktemp("ecx_submit") / "submit_test.db"
    return ScanStore(db_path=db)


@pytest.fixture(scope="module")
def submission_service(ecx_client: ECXClient, submission_store: Any) -> Any:
    """ECXSubmissionService wired to the sandbox client and a temporary store."""
    from ssi.ecx.submission import ECXSubmissionService

    return ECXSubmissionService(client=ecx_client, store=submission_store)


class TestECXSubmissionSandbox:
    """Verify submission flows against the live eCX sandbox.

    All tests require *both* ``SSI_ECX__SUBMISSION_ENABLED=true`` and
    ``SSI_ECX__SUBMISSION_AGREEMENT_SIGNED=true`` as an extra safety gate.
    When these are unset the tests skip so they never accidentally run in a
    non-submission environment.

    Run them explicitly::

        SSI_ECX__API_KEY="..." \\
        SSI_ECX__SUBMISSION_ENABLED=true \\
        SSI_ECX__SUBMISSION_AGREEMENT_SIGNED=true \\
        pytest tests/integration/test_ecx_sandbox.py::TestECXSubmissionSandbox -v
    """

    pytestmark = pytest.mark.skipif(
        not _SUBMISSION_ENABLED,
        reason=(
            "Submission safety gates not set — "
            "SSI_ECX__SUBMISSION_ENABLED and SSI_ECX__SUBMISSION_AGREEMENT_SIGNED "
            "must both be 'true' to run submission tests"
        ),
    )

    def test_submit_phish_and_verify(
        self, ecx_client: ECXClient, submission_store: Any, submission_service: Any
    ) -> None:
        """Submit a phish indicator and verify the returned eCX record ID."""
        from uuid import uuid4

        scan_id = str(uuid4())
        submission_id = str(uuid4())

        submission_store.create_ecx_submission(
            submission_id=submission_id,
            scan_id=scan_id,
            case_id=None,
            ecx_module="phish",
            submitted_value=_SANDBOX_SUBMIT_URL,
            confidence=75,
            status="queued",
        )

        row = submission_service.analyst_approve(
            submission_id=submission_id,
            release_label="WHITE",
            analyst="test-analyst",
        )

        assert row is not None, "analyst_approve returned None"
        if row["status"] == "submitted":
            assert row["ecx_record_id"] is not None
            logger.info("Phish submission eCX record ID: %s", row["ecx_record_id"])
        else:
            # Module may not be accessible to this key → treat as skip
            pytest.skip(f"Phish submission not accepted: {row.get('error_message')}")

    def test_submit_crypto_and_verify(
        self, ecx_client: ECXClient, submission_store: Any, submission_service: Any
    ) -> None:
        """Submit a crypto indicator via analyst_approve and check the eCX record ID."""
        from uuid import uuid4

        scan_id = str(uuid4())
        submission_id = str(uuid4())

        submission_store.create_ecx_submission(
            submission_id=submission_id,
            scan_id=scan_id,
            case_id=None,
            ecx_module="cryptocurrency-addresses",
            submitted_value=_SANDBOX_SUBMIT_CRYPTO,
            confidence=80,
            status="queued",
        )

        row = submission_service.analyst_approve(
            submission_id=submission_id,
            release_label="WHITE",
            analyst="test-analyst",
        )

        assert row is not None
        if row["status"] == "submitted":
            assert row["ecx_record_id"] is not None
            logger.info("Crypto submission eCX record ID: %s", row["ecx_record_id"])
        else:
            pytest.skip(f"Crypto submission not accepted: {row.get('error_message')}")

    def test_update_record(self, ecx_client: ECXClient, submission_store: Any, submission_service: Any) -> None:
        """Submit a phish, then update its confidence via the eCX API."""
        from uuid import uuid4

        scan_id = str(uuid4())
        submission_id = str(uuid4())

        submission_store.create_ecx_submission(
            submission_id=submission_id,
            scan_id=scan_id,
            case_id=None,
            ecx_module="phish",
            submitted_value=_SANDBOX_SUBMIT_URL + "/update",
            confidence=60,
            status="queued",
        )

        row = submission_service.analyst_approve(
            submission_id=submission_id,
            release_label="WHITE",
            analyst="update-tester",
        )
        if row is None or row.get("status") != "submitted":
            pytest.skip("Phish module not accessible — can't test update_record")

        record_id = row["ecx_record_id"]
        assert record_id is not None

        # Should not raise
        ecx_client.update_record("phish", int(record_id), confidence=70)
        logger.info("update_record succeeded for phish record %s", record_id)

    def test_add_note(self, ecx_client: ECXClient, submission_store: Any, submission_service: Any) -> None:
        """Submit a phish then append a note to the eCX record."""
        from uuid import uuid4

        scan_id = str(uuid4())
        submission_id = str(uuid4())

        submission_store.create_ecx_submission(
            submission_id=submission_id,
            scan_id=scan_id,
            case_id=None,
            ecx_module="phish",
            submitted_value=_SANDBOX_SUBMIT_URL + "/note",
            confidence=65,
            status="queued",
        )

        row = submission_service.analyst_approve(
            submission_id=submission_id,
            release_label="WHITE",
            analyst="note-tester",
        )
        if row is None or row.get("status") != "submitted":
            pytest.skip("Phish module not accessible — can't test add_note")

        record_id = row["ecx_record_id"]
        # Should not raise
        ecx_client.add_note("phish", int(record_id), "Automated sandbox test note from i4g-ssi")
        logger.info("add_note succeeded for phish record %s", record_id)

    def test_dedup_existing(self, ecx_client: ECXClient, submission_store: Any, submission_service: Any) -> None:
        """Submit the same URL twice — the second should detect an existing record (dedup)."""
        from uuid import uuid4

        url = _SANDBOX_SUBMIT_URL + "/dedup"
        scan_id_1, scan_id_2 = str(uuid4()), str(uuid4())
        sub_id_1, sub_id_2 = str(uuid4()), str(uuid4())

        for submission_id, scan_id in [(sub_id_1, scan_id_1), (sub_id_2, scan_id_2)]:
            submission_store.create_ecx_submission(
                submission_id=submission_id,
                scan_id=scan_id,
                case_id=None,
                ecx_module="phish",
                submitted_value=url,
                confidence=70,
                status="queued",
            )

        row1 = submission_service.analyst_approve(sub_id_1, "WHITE", "dedup-tester")
        if row1 is None or row1.get("status") != "submitted":
            pytest.skip("Phish module not accessible — can't test dedup")

        ecx_id_1 = row1["ecx_record_id"]

        # Second submission of the same URL — dedup logic should reuse existing record.
        row2 = submission_service.analyst_approve(sub_id_2, "WHITE", "dedup-tester")

        assert row2 is not None
        if row2.get("status") == "submitted":
            # Dedup: both should reference the same eCX record
            assert row2["ecx_record_id"] == ecx_id_1, (
                f"Expected dedup to reuse eCX record {ecx_id_1}, " f"got {row2['ecx_record_id']}"
            )
            logger.info("Dedup confirmed: both submissions reference eCX record %s", ecx_id_1)
        elif row2.get("status") == "failed":
            # Dedup may manifest as a 409 / duplicate error rather than a clean reuse
            assert row2.get("error_message") is not None
            logger.info("Dedup detected as API error (expected): %s", row2.get("error_message"))
        else:
            pytest.fail(f"Unexpected second submission status: {row2.get('status')}")

    def test_analyst_reject(self, submission_store: Any, submission_service: Any) -> None:
        """Reject a queued submission — no eCX API call should occur."""
        from uuid import uuid4

        submission_id = str(uuid4())
        submission_store.create_ecx_submission(
            submission_id=submission_id,
            scan_id=str(uuid4()),
            case_id=None,
            ecx_module="phish",
            submitted_value="https://reject-test.invalid/phish",
            confidence=55,
            status="queued",
        )

        row = submission_service.analyst_reject(
            submission_id=submission_id,
            analyst="reject-tester",
            reason="Sandbox reject test — not a real phish",
        )

        assert row is not None
        assert row["status"] == "rejected"
        assert row["submitted_by"] == "reject-tester"
        logger.info("analyst_reject confirmed for submission %s", submission_id)

    def test_retract(self, ecx_client: ECXClient, submission_store: Any, submission_service: Any) -> None:
        """Submit a phish, then retract it via the eCX API."""
        from uuid import uuid4

        submission_id = str(uuid4())
        submission_store.create_ecx_submission(
            submission_id=submission_id,
            scan_id=str(uuid4()),
            case_id=None,
            ecx_module="phish",
            submitted_value=_SANDBOX_SUBMIT_URL + "/retract",
            confidence=72,
            status="queued",
        )

        row = submission_service.analyst_approve(submission_id, "WHITE", "retract-tester")
        if row is None or row.get("status") != "submitted":
            pytest.skip("Phish module not accessible — can't test retract")

        retracted = submission_service.retract(submission_id, "retract-tester")
        assert retracted is not None
        assert retracted["status"] == "retracted"
        logger.info("retract confirmed for submission %s (eCX %s)", submission_id, row["ecx_record_id"])
