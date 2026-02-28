"""Unit tests for the investigation orchestrator.

Focuses on the scan-store create / skip-create branching logic:
when ``investigation_id`` is provided (Cloud Run Job path), the
orchestrator must reuse the pre-created scan row rather than calling
``create_scan()`` (which would cause an IntegrityError on the
duplicate primary key).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from ssi.models.investigation import InvestigationResult, InvestigationStatus, ScanType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stub_settings(persist: bool = True) -> MagicMock:
    """Return a mock ``Settings`` object with scan persistence toggled."""
    settings = MagicMock()
    settings.storage.persist_scans = persist
    settings.cost.enabled = False
    return settings


def _build_mock_scan_store() -> MagicMock:
    """Return a mock ``ScanStore`` with a working ``create_scan``."""
    store = MagicMock()
    store.create_scan.return_value = str(uuid4())
    return store


# ---------------------------------------------------------------------------
# Patches applied to every test in this module.
#
# We only need to exercise the scan-creation branch (lines ~120-150 of
# orchestrator.py).  All later investigation phases are stubbed out by
# raising ``StopIteration`` immediately after the scan store init so we
# don't need to mock dozens of OSINT helpers.
# ---------------------------------------------------------------------------


_ORCHESTRATOR_MODULE = "ssi.investigator.orchestrator"


class TestScanCreationBranch:
    """Verify the investigation_id → create_scan gating logic."""

    @patch(f"{_ORCHESTRATOR_MODULE}._check_domain_resolution", return_value=True)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_whois", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_dns", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_ssl", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_geoip", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_browser_capture", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_virustotal")
    @patch(f"{_ORCHESTRATOR_MODULE}._run_urlscan")
    def test_create_scan_called_when_no_investigation_id(
        self,
        _mock_urlscan: MagicMock,
        _mock_vt: MagicMock,
        _mock_capture: MagicMock,
        _mock_geoip: MagicMock,
        _mock_ssl: MagicMock,
        _mock_dns: MagicMock,
        _mock_whois: MagicMock,
        _mock_domain: MagicMock,
        tmp_path: Path,
    ) -> None:
        """When investigation_id is None, create_scan() MUST be called."""
        mock_store = _build_mock_scan_store()
        mock_settings = _stub_settings(persist=True)

        with (
            patch("ssi.settings.get_settings", return_value=mock_settings),
            patch("ssi.store.build_scan_store", return_value=mock_store),
        ):
            from ssi.investigator.orchestrator import run_investigation

            result = run_investigation(
                url="https://scam.example.com",
                output_dir=tmp_path,
                scan_type="passive",
                skip_whois=True,
                skip_screenshot=True,
                skip_virustotal=True,
                skip_urlscan=True,
                investigation_id=None,
            )

        mock_store.create_scan.assert_called_once()
        call_kwargs = mock_store.create_scan.call_args
        assert "scam.example.com" in str(call_kwargs)

    @patch(f"{_ORCHESTRATOR_MODULE}._check_domain_resolution", return_value=True)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_whois", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_dns", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_ssl", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_geoip", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_browser_capture", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_virustotal")
    @patch(f"{_ORCHESTRATOR_MODULE}._run_urlscan")
    def test_create_scan_skipped_when_investigation_id_provided(
        self,
        _mock_urlscan: MagicMock,
        _mock_vt: MagicMock,
        _mock_capture: MagicMock,
        _mock_geoip: MagicMock,
        _mock_ssl: MagicMock,
        _mock_dns: MagicMock,
        _mock_whois: MagicMock,
        _mock_domain: MagicMock,
        tmp_path: Path,
    ) -> None:
        """When investigation_id IS provided, create_scan() must NOT be called.

        This is the Cloud Run Job path: core pre-creates the ``site_scans``
        row at trigger time and passes the scan_id to the job via
        ``SSI_JOB__SCAN_ID``.  Calling ``create_scan()`` again would raise
        an IntegrityError on the duplicate primary key.
        """
        pre_assigned_id = str(uuid4())
        mock_store = _build_mock_scan_store()
        mock_settings = _stub_settings(persist=True)

        with (
            patch("ssi.settings.get_settings", return_value=mock_settings),
            patch("ssi.store.build_scan_store", return_value=mock_store),
        ):
            from ssi.investigator.orchestrator import run_investigation

            result = run_investigation(
                url="https://scam.example.com",
                output_dir=tmp_path,
                scan_type="passive",
                skip_whois=True,
                skip_screenshot=True,
                skip_virustotal=True,
                skip_urlscan=True,
                investigation_id=pre_assigned_id,
            )

        mock_store.create_scan.assert_not_called()
        assert str(result.investigation_id) == pre_assigned_id

    @patch(f"{_ORCHESTRATOR_MODULE}._check_domain_resolution", return_value=True)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_whois", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_dns", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_ssl", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_geoip", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_browser_capture", return_value=None)
    @patch(f"{_ORCHESTRATOR_MODULE}._run_virustotal")
    @patch(f"{_ORCHESTRATOR_MODULE}._run_urlscan")
    def test_persist_not_called_when_persistence_disabled(
        self,
        _mock_urlscan: MagicMock,
        _mock_vt: MagicMock,
        _mock_capture: MagicMock,
        _mock_geoip: MagicMock,
        _mock_ssl: MagicMock,
        _mock_dns: MagicMock,
        _mock_whois: MagicMock,
        _mock_domain: MagicMock,
        tmp_path: Path,
    ) -> None:
        """When persist_scans is False, no scan store is initialised."""
        mock_settings = _stub_settings(persist=False)

        with (
            patch("ssi.settings.get_settings", return_value=mock_settings),
            patch("ssi.store.build_scan_store") as mock_build,
        ):
            from ssi.investigator.orchestrator import run_investigation

            run_investigation(
                url="https://scam.example.com",
                output_dir=tmp_path,
                scan_type="passive",
                skip_whois=True,
                skip_screenshot=True,
                skip_virustotal=True,
                skip_urlscan=True,
            )

        mock_build.assert_not_called()
