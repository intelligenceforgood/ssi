"""Tests for the SSI batch manifest loading utilities.

Tests cover:
- Manifest validation (validate_manifest).
- Local file loading (load_manifest with filesystem paths).
- GCS URI dispatching (load_manifest with gs:// URIs).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssi.worker.batch import _load_from_gcs, load_manifest, validate_manifest

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
        result = validate_manifest(data)
        assert len(result) == 2
        assert result[0]["url"] == "https://scam1.example.com"

    def test_empty_list_raises(self) -> None:
        """An empty list raises ValueError."""
        with pytest.raises(ValueError, match="non-empty"):
            validate_manifest([])

    def test_not_a_list_raises(self) -> None:
        """A non-list value raises ValueError."""
        with pytest.raises(ValueError, match="non-empty"):
            validate_manifest({"url": "https://example.com"})

    def test_entries_without_url_skipped(self) -> None:
        """Entries missing a URL key are skipped."""
        data = [
            {"url": "https://valid.example.com"},
            {"scan_type": "passive"},  # no url
            {"url": ""},  # empty url
        ]
        result = validate_manifest(data)
        assert len(result) == 1
        assert result[0]["url"] == "https://valid.example.com"

    def test_all_invalid_raises(self) -> None:
        """If all entries are invalid, raises ValueError."""
        data = [
            {"scan_type": "passive"},
            {"something": "else"},
        ]
        with pytest.raises(ValueError, match="no valid entries"):
            validate_manifest(data)

    def test_non_dict_entries_skipped(self) -> None:
        """Non-dict entries are skipped."""
        data = [
            "https://example.com",
            {"url": "https://valid.example.com"},
        ]
        result = validate_manifest(data)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------


class TestLoadManifest:
    """Tests for local manifest loading."""

    def test_load_local_file(self, tmp_path: Path) -> None:
        """Load a valid manifest from a local JSON file."""
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(
            json.dumps(
                [
                    {"url": "https://scam1.example.com"},
                    {"url": "https://scam2.example.com", "scan_type": "passive"},
                ]
            )
        )

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
        with patch("ssi.worker.batch._load_from_gcs") as mock_gcs:
            mock_gcs.return_value = [{"url": "https://example.com"}]
            result = load_manifest("gs://my-bucket/manifests/batch1.json")

        mock_gcs.assert_called_once_with("gs://my-bucket/manifests/batch1.json")
        assert len(result) == 1


# ---------------------------------------------------------------------------
# GCS loading
# ---------------------------------------------------------------------------


class TestGCSLoading:
    """Tests for the GCS manifest loading path."""

    @patch("ssi.worker.batch._load_from_gcs")
    def test_gcs_uri_dispatches(self, mock_gcs: MagicMock) -> None:
        """A gs:// URI dispatches to the GCS loader."""
        mock_gcs.return_value = [{"url": "https://example.com"}]
        result = load_manifest("gs://bucket/path.json")
        mock_gcs.assert_called_once_with("gs://bucket/path.json")
        assert len(result) == 1

    def test_gcs_import_error(self) -> None:
        """ImportError if google-cloud-storage is missing."""
        with (
            patch.dict("sys.modules", {"google.cloud": None, "google": None}),
            pytest.raises(ImportError, match="google-cloud-storage"),
        ):
            _load_from_gcs("gs://bucket/path.json")

    def test_gcs_invalid_uri(self) -> None:
        """Invalid GCS URI (no path component) raises ValueError."""
        mock_gcs_mod = MagicMock()
        with (
            patch.dict("sys.modules", {"google.cloud": mock_gcs_mod, "google.cloud.storage": mock_gcs_mod}),
            pytest.raises(ValueError, match="Invalid GCS URI"),
        ):
            _load_from_gcs("gs://bucket-only")

    @patch("ssi.worker.batch._load_from_gcs")
    def test_gcs_not_found_raises(self, mock_gcs: MagicMock) -> None:
        """FileNotFoundError when the GCS blob does not exist."""
        mock_gcs.side_effect = FileNotFoundError("GCS object not found: gs://bucket/path.json")
        with pytest.raises(FileNotFoundError, match="GCS object not found"):
            load_manifest("gs://bucket/path.json")

    def test_gcs_success(self) -> None:
        """Successful GCS download returns validated manifest."""
        with patch("ssi.worker.batch._load_from_gcs") as mock_gcs:
            mock_gcs.return_value = [{"url": "https://scam.test"}]
            result = load_manifest("gs://bucket/manifests/batch.json")

        assert len(result) == 1
        assert result[0]["url"] == "https://scam.test"
