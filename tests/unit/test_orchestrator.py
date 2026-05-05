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
    @patch(f"{_ORCHESTRATOR_MODULE}._run_google_osint")
    def test_create_scan_called_when_no_investigation_id(
        self,
        _mock_google_osint: MagicMock,
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

            run_investigation(
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
    @patch(f"{_ORCHESTRATOR_MODULE}._run_google_osint")
    def test_create_scan_skipped_when_investigation_id_provided(
        self,
        _mock_google_osint: MagicMock,
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

        This is the service trigger path: core pre-creates the ``site_scans``
        row at trigger time and passes the scan_id in the request body.
        Calling ``create_scan()`` again would raise an IntegrityError on the
        duplicate primary key.
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
    @patch(f"{_ORCHESTRATOR_MODULE}._run_google_osint")
    def test_persist_not_called_when_persistence_disabled(
        self,
        _mock_google_osint: MagicMock,
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


def test_run_google_osint_triggers_scrapers():
    """Verify that _run_google_osint triggers the scrapers when emails or drive links are found."""
    from ssi.investigator.orchestrator import _run_google_osint
    from ssi.models.investigation import InvestigationResult, PageSnapshot

    # Create a result with some text containing an email and a drive link
    result = InvestigationResult(url="https://scam.example.com", scan_type="passive", passive_only=True)
    result.page_snapshot = PageSnapshot(url="https://scam.example.com")
    result.page_snapshot.dom_snapshot_path = "non_existent_file.html"  # This will fail gracefully

    # We add text via agent_steps since that's easy to mock without a file
    result.agent_steps = [
        {"reasoning": "Found test@example.com here"},
        {"value": "Check out drive.google.com/file/d/test_drive_id123/view"},
    ]

    with (
        patch("ssi.osint.google.people.GooglePeopleScraper.resolve_email") as mock_people,
        patch("ssi.osint.google.maps.GoogleMapsScraper.get_location_data") as mock_maps,
        patch("ssi.osint.google.drive.GoogleDriveScraper.resolve_file") as mock_drive,
        patch("ssi.osint.google.auth.GoogleAuthManager.get_auth_headers", return_value={}),
    ):

        async def dummy_people(*args, **kwargs):
            return {"email": "test@example.com", "gaia_id": "gaia123"}

        async def dummy_maps(*args, **kwargs):
            return {"locations": []}

        async def dummy_drive(*args, **kwargs):
            return {"file_id": "test_drive_id123", "metadata": {}}

        mock_people.side_effect = dummy_people
        mock_maps.side_effect = dummy_maps
        mock_drive.side_effect = dummy_drive

        _run_google_osint(result)

        mock_people.assert_called_once_with("test@example.com")
        mock_maps.assert_called_once_with("gaia123")
        mock_drive.assert_called_once_with("test_drive_id123")
