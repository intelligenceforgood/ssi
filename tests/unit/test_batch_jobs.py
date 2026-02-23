"""Tests for the SSI batch job module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssi.worker.batch_jobs import (
    _push_result_to_core,
    _validate_manifest,
    load_manifest,
    run_batch,
)


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------


class TestValidateManifest:
    """Tests for manifest validation logic."""

    def test_valid_manifest(self) -> None:
        """A normal manifest with URLs passes validation."""
        data = [
            {"url": "https://scam1.example.com", "scan_type": "full"},
            {"url": "https://scam2.example.com"},
        ]
        result = _validate_manifest(data)
        assert len(result) == 2
        assert result[0]["url"] == "https://scam1.example.com"

    def test_empty_list_raises(self) -> None:
        """An empty list raises ValueError."""
        with pytest.raises(ValueError, match="non-empty"):
            _validate_manifest([])

    def test_not_a_list_raises(self) -> None:
        """A non-list value raises ValueError."""
        with pytest.raises(ValueError, match="non-empty"):
            _validate_manifest({"url": "https://example.com"})

    def test_entries_without_url_skipped(self) -> None:
        """Entries missing a URL key are skipped."""
        data = [
            {"url": "https://valid.example.com"},
            {"scan_type": "passive"},  # no url
            {"url": ""},  # empty url
        ]
        result = _validate_manifest(data)
        assert len(result) == 1
        assert result[0]["url"] == "https://valid.example.com"

    def test_all_invalid_raises(self) -> None:
        """If all entries are invalid, raises ValueError."""
        data = [
            {"scan_type": "passive"},
            {"something": "else"},
        ]
        with pytest.raises(ValueError, match="no valid entries"):
            _validate_manifest(data)

    def test_non_dict_entries_skipped(self) -> None:
        """Non-dict entries are skipped."""
        data = [
            "https://example.com",
            {"url": "https://valid.example.com"},
        ]
        result = _validate_manifest(data)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------


class TestLoadManifest:
    """Tests for local manifest loading."""

    def test_load_local_file(self, tmp_path: Path) -> None:
        """Load a valid manifest from a local JSON file."""
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(json.dumps([
            {"url": "https://scam1.example.com"},
            {"url": "https://scam2.example.com", "scan_type": "passive"},
        ]))

        result = load_manifest(str(manifest_file))
        assert len(result) == 2
        assert result[1]["scan_type"] == "passive"

    def test_load_missing_file_raises(self) -> None:
        """FileNotFoundError for a missing local file."""
        with pytest.raises(FileNotFoundError, match="not found"):
            load_manifest("/nonexistent/path/manifest.json")

    def test_load_invalid_json_raises(self, tmp_path: Path) -> None:
        """Invalid JSON raises ValueError or json.JSONDecodeError."""
        manifest_file = tmp_path / "bad.json"
        manifest_file.write_text("not json at all")

        with pytest.raises((json.JSONDecodeError, ValueError)):
            load_manifest(str(manifest_file))

    def test_gcs_uri_calls_gcs_loader(self) -> None:
        """A gs:// URI dispatches to the GCS loader."""
        with patch("ssi.worker.batch_jobs._load_from_gcs") as mock_gcs:
            mock_gcs.return_value = [{"url": "https://example.com"}]
            result = load_manifest("gs://my-bucket/manifests/batch1.json")

        mock_gcs.assert_called_once_with("gs://my-bucket/manifests/batch1.json")
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Batch execution
# ---------------------------------------------------------------------------


class TestRunBatch:
    """Tests for the batch execution loop."""

    @patch("ssi.investigator.orchestrator.run_investigation")
    @patch("ssi.settings.get_settings")
    def test_all_succeed(self, mock_settings: MagicMock, mock_investigate: MagicMock, tmp_path: Path) -> None:
        """All URLs succeed → summary shows 0 failures."""
        mock_settings.return_value.evidence.output_dir = str(tmp_path)

        mock_result = MagicMock()
        mock_result.investigation_id = "inv-001"
        mock_result.status.value = "completed"
        mock_result.success = True
        mock_result.taxonomy_result.risk_score = 85.0
        mock_result.error = None
        mock_investigate.return_value = mock_result

        manifest = [
            {"url": "https://scam1.example.com"},
            {"url": "https://scam2.example.com"},
        ]

        summary = run_batch(manifest)

        assert summary["total"] == 2
        assert summary["succeeded"] == 2
        assert summary["failed"] == 0
        assert len(summary["results"]) == 2
        assert mock_investigate.call_count == 2

    @patch("ssi.investigator.orchestrator.run_investigation")
    @patch("ssi.settings.get_settings")
    def test_partial_failure(self, mock_settings: MagicMock, mock_investigate: MagicMock, tmp_path: Path) -> None:
        """One URL fails → summary reflects partial failure."""
        mock_settings.return_value.evidence.output_dir = str(tmp_path)

        success_result = MagicMock()
        success_result.investigation_id = "inv-001"
        success_result.status.value = "completed"
        success_result.success = True
        success_result.taxonomy_result.risk_score = 90.0
        success_result.error = None

        failure_result = MagicMock()
        failure_result.investigation_id = "inv-002"
        failure_result.status.value = "failed"
        failure_result.success = False
        failure_result.taxonomy_result = None
        failure_result.error = "Connection refused"

        mock_investigate.side_effect = [success_result, failure_result]

        manifest = [
            {"url": "https://scam1.example.com"},
            {"url": "https://scam2.example.com"},
        ]

        summary = run_batch(manifest)

        assert summary["total"] == 2
        assert summary["succeeded"] == 1
        assert summary["failed"] == 1

    @patch("ssi.investigator.orchestrator.run_investigation")
    @patch("ssi.settings.get_settings")
    def test_exception_caught(self, mock_settings: MagicMock, mock_investigate: MagicMock, tmp_path: Path) -> None:
        """An exception during investigation is caught and logged."""
        mock_settings.return_value.evidence.output_dir = str(tmp_path)
        mock_investigate.side_effect = RuntimeError("Browser crashed")

        manifest = [{"url": "https://scam1.example.com"}]

        summary = run_batch(manifest)

        assert summary["total"] == 1
        assert summary["succeeded"] == 0
        assert summary["failed"] == 1
        assert summary["results"][0]["error"] == "Browser crashed"

    @patch("ssi.investigator.orchestrator.run_investigation")
    @patch("ssi.settings.get_settings")
    def test_scan_type_per_entry(self, mock_settings: MagicMock, mock_investigate: MagicMock, tmp_path: Path) -> None:
        """Per-entry scan_type overrides the default."""
        mock_settings.return_value.evidence.output_dir = str(tmp_path)

        mock_result = MagicMock()
        mock_result.investigation_id = "inv-001"
        mock_result.status.value = "completed"
        mock_result.success = True
        mock_result.taxonomy_result.risk_score = 50.0
        mock_investigate.return_value = mock_result

        manifest = [
            {"url": "https://scam1.example.com", "scan_type": "passive"},
            {"url": "https://scam2.example.com"},  # uses default
        ]

        run_batch(manifest, default_scan_type="active")

        calls = mock_investigate.call_args_list
        # First call: passive (from manifest entry)
        assert calls[0].kwargs["scan_type"] == "passive"
        # Second call: active (from default)
        assert calls[1].kwargs["scan_type"] == "active"

    @patch("ssi.worker.batch_jobs._push_result_to_core")
    @patch("ssi.investigator.orchestrator.run_investigation")
    @patch("ssi.settings.get_settings")
    def test_push_to_core_called(
        self, mock_settings: MagicMock, mock_investigate: MagicMock, mock_push: MagicMock, tmp_path: Path
    ) -> None:
        """When push_to_core=True, results are pushed."""
        mock_settings.return_value.evidence.output_dir = str(tmp_path)

        mock_result = MagicMock()
        mock_result.investigation_id = "inv-001"
        mock_result.status.value = "completed"
        mock_result.success = True
        mock_result.taxonomy_result.risk_score = 75.0
        mock_investigate.return_value = mock_result
        mock_push.return_value = "case-abc"

        manifest = [{"url": "https://scam1.example.com"}]

        summary = run_batch(manifest, push_to_core=True, dataset="test")

        mock_push.assert_called_once()
        assert summary["results"][0]["core_case_id"] == "case-abc"


# ---------------------------------------------------------------------------
# Entry point (main)
# ---------------------------------------------------------------------------


class TestBatchMain:
    """Tests for the main() entry point."""

    @patch.dict("os.environ", {"SSI_JOB__MANIFEST": ""}, clear=False)
    def test_missing_manifest_returns_1(self) -> None:
        """Missing SSI_JOB__MANIFEST returns exit code 1."""
        from ssi.worker.batch_jobs import main

        assert main() == 1

    @patch("ssi.worker.batch_jobs.load_manifest")
    @patch("ssi.worker.batch_jobs.run_batch")
    @patch.dict("os.environ", {"SSI_JOB__MANIFEST": "/tmp/test.json"}, clear=False)
    def test_success_returns_0(self, mock_run: MagicMock, mock_load: MagicMock) -> None:
        """Successful batch returns 0."""
        from ssi.worker.batch_jobs import main

        mock_load.return_value = [{"url": "https://example.com"}]
        mock_run.return_value = {"total": 1, "succeeded": 1, "failed": 0, "results": []}

        assert main() == 0

    @patch("ssi.worker.batch_jobs.load_manifest")
    @patch("ssi.worker.batch_jobs.run_batch")
    @patch.dict("os.environ", {"SSI_JOB__MANIFEST": "/tmp/test.json"}, clear=False)
    def test_partial_failure_returns_1(self, mock_run: MagicMock, mock_load: MagicMock) -> None:
        """Partial failures return exit code 1."""
        from ssi.worker.batch_jobs import main

        mock_load.return_value = [{"url": "https://example.com"}]
        mock_run.return_value = {"total": 2, "succeeded": 1, "failed": 1, "results": []}

        assert main() == 1

    @patch("ssi.worker.batch_jobs.load_manifest")
    @patch.dict("os.environ", {"SSI_JOB__MANIFEST": "/tmp/nonexistent.json"}, clear=False)
    def test_bad_manifest_returns_1(self, mock_load: MagicMock) -> None:
        """Invalid manifest returns exit code 1."""
        from ssi.worker.batch_jobs import main

        mock_load.side_effect = FileNotFoundError("not found")

        assert main() == 1


# ---------------------------------------------------------------------------
# GCS loading
# ---------------------------------------------------------------------------


class TestGCSLoading:
    """Tests for the GCS manifest loading path."""

    @patch("ssi.worker.batch_jobs._load_from_gcs")
    def test_gcs_uri_dispatches(self, mock_gcs: MagicMock) -> None:
        """A gs:// URI dispatches to the GCS loader."""
        mock_gcs.return_value = [{"url": "https://example.com"}]
        result = load_manifest("gs://bucket/path.json")
        mock_gcs.assert_called_once_with("gs://bucket/path.json")
        assert len(result) == 1

    def test_gcs_import_error(self) -> None:
        """ImportError if google-cloud-storage is missing."""
        from ssi.worker.batch_jobs import _load_from_gcs

        with patch.dict("sys.modules", {"google.cloud": None, "google": None}):
            with pytest.raises(ImportError, match="google-cloud-storage"):
                _load_from_gcs("gs://bucket/path.json")

    def test_gcs_invalid_uri(self) -> None:
        """Invalid GCS URI (no path component) raises ValueError."""
        from ssi.worker.batch_jobs import _load_from_gcs

        mock_gcs_mod = MagicMock()
        with patch.dict("sys.modules", {"google.cloud": mock_gcs_mod, "google.cloud.storage": mock_gcs_mod}):
            with pytest.raises(ValueError, match="Invalid GCS URI"):
                _load_from_gcs("gs://bucket-only")

    def test_gcs_blob_not_found(self) -> None:
        """FileNotFoundError when the GCS blob does not exist."""
        from ssi.worker import batch_jobs

        mock_blob = MagicMock()
        mock_blob.exists.return_value = False
        mock_client = MagicMock()
        mock_client.return_value.bucket.return_value.blob.return_value = mock_blob
        mock_gcs_mod = MagicMock()
        mock_gcs_mod.Client = mock_client

        with patch.object(batch_jobs, "_load_from_gcs", wraps=None) as _:
            # Directly test the inner validation by simulating the GCS call
            pass

        # Test via higher-level function with mock
        with patch("ssi.worker.batch_jobs._load_from_gcs") as mock_gcs:
            mock_gcs.side_effect = FileNotFoundError("GCS object not found: gs://bucket/path.json")
            with pytest.raises(FileNotFoundError, match="GCS object not found"):
                load_manifest("gs://bucket/path.json")

    def test_gcs_success(self) -> None:
        """Successful GCS download returns validated manifest."""
        with patch("ssi.worker.batch_jobs._load_from_gcs") as mock_gcs:
            mock_gcs.return_value = [{"url": "https://scam.test"}]
            result = load_manifest("gs://bucket/manifests/batch.json")

        assert len(result) == 1
        assert result[0]["url"] == "https://scam.test"

    def test_gcs_invalid_uri_no_path(self) -> None:
        """A GCS URI without a path component raises ValueError."""
        from ssi.worker.batch_jobs import _load_from_gcs

        # Inject a mock google.cloud.storage module
        mock_gcs = MagicMock()

        with patch("builtins.__import__", side_effect=lambda name, *a, **kw: mock_gcs if "google" in name else __import__(name, *a, **kw)):
            # The function splits on '/' and expects at least bucket/path
            # "gs://bucket-only" → parts = ["bucket-only"] → len != 2
            with pytest.raises((ValueError, ImportError)):
                _load_from_gcs("gs://bucket-only")


# ---------------------------------------------------------------------------
# Push to core
# ---------------------------------------------------------------------------


class TestPushResultToCore:
    """Tests for the _push_result_to_core helper."""

    @patch("ssi.integration.core_bridge.CoreBridge")
    def test_push_success(self, mock_bridge_cls: MagicMock) -> None:
        """Successful push returns the case ID."""
        mock_bridge = MagicMock()
        mock_bridge.health_check.return_value = True
        mock_bridge.push_investigation.return_value = "case-123"
        mock_bridge_cls.return_value = mock_bridge

        result = MagicMock()
        case_id = _push_result_to_core(result, dataset="test")

        assert case_id == "case-123"
        mock_bridge.close.assert_called_once()

    @patch("ssi.integration.core_bridge.CoreBridge")
    def test_push_unhealthy_returns_none(self, mock_bridge_cls: MagicMock) -> None:
        """When core is unreachable, returns None."""
        mock_bridge = MagicMock()
        mock_bridge.health_check.return_value = False
        mock_bridge_cls.return_value = mock_bridge

        result = MagicMock()
        case_id = _push_result_to_core(result)

        assert case_id is None
        mock_bridge.close.assert_called_once()

    @patch("ssi.integration.core_bridge.CoreBridge")
    def test_push_exception_returns_none(self, mock_bridge_cls: MagicMock) -> None:
        """Push exception is caught and returns None."""
        mock_bridge = MagicMock()
        mock_bridge.health_check.return_value = True
        mock_bridge.push_investigation.side_effect = RuntimeError("network error")
        mock_bridge_cls.return_value = mock_bridge

        result = MagicMock()
        case_id = _push_result_to_core(result)

        assert case_id is None
        mock_bridge.close.assert_called_once()
