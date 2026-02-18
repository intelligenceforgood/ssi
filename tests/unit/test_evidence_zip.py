"""Unit tests for evidence ZIP packaging."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from ssi.investigator.orchestrator import _create_evidence_zip
from ssi.models.investigation import InvestigationResult, InvestigationStatus


@pytest.fixture()
def populated_inv_dir(tmp_path) -> tuple[InvestigationResult, Path]:
    """Create a populated investigation directory with sample artifacts."""
    inv_dir = tmp_path / "inv_001"
    inv_dir.mkdir()

    # Create sample artifacts
    (inv_dir / "investigation.json").write_text('{"url": "https://example.com"}')
    (inv_dir / "screenshot.png").write_bytes(b"\x89PNG" + b"\x00" * 100)
    (inv_dir / "dom.html").write_text("<html><body>test</body></html>")

    sub = inv_dir / "downloads"
    sub.mkdir()
    (sub / "payload.bin").write_bytes(b"\x00\x01\x02" * 50)

    result = InvestigationResult(
        url="https://example.com",
        status=InvestigationStatus.COMPLETED,
        success=True,
        duration_seconds=3.0,
    )
    return result, inv_dir


class TestCreateEvidenceZip:
    """Tests for evidence ZIP creation."""

    def test_zip_created(self, populated_inv_dir):
        result, inv_dir = populated_inv_dir
        _create_evidence_zip(result, inv_dir)

        zip_path = inv_dir / "evidence.zip"
        assert zip_path.exists()
        assert result.evidence_zip_path == str(zip_path)

    def test_zip_contains_all_files(self, populated_inv_dir):
        result, inv_dir = populated_inv_dir
        _create_evidence_zip(result, inv_dir)

        with zipfile.ZipFile(inv_dir / "evidence.zip", "r") as zf:
            names = zf.namelist()

        assert "investigation.json" in names
        assert "screenshot.png" in names
        assert "dom.html" in names
        assert "downloads/payload.bin" in names
        assert "manifest.json" in names

    def test_zip_does_not_contain_itself(self, populated_inv_dir):
        result, inv_dir = populated_inv_dir
        _create_evidence_zip(result, inv_dir)

        with zipfile.ZipFile(inv_dir / "evidence.zip", "r") as zf:
            names = zf.namelist()

        assert "evidence.zip" not in names

    def test_manifest_has_hashes(self, populated_inv_dir):
        result, inv_dir = populated_inv_dir
        _create_evidence_zip(result, inv_dir)

        with zipfile.ZipFile(inv_dir / "evidence.zip", "r") as zf:
            manifest = json.loads(zf.read("manifest.json"))

        assert manifest["target_url"] == "https://example.com"
        assert len(manifest["artifacts"]) >= 3

        for entry in manifest["artifacts"]:
            assert "sha256" in entry
            assert len(entry["sha256"]) == 64  # SHA-256 hex length
            assert "size_bytes" in entry
            assert entry["size_bytes"] > 0

    def test_empty_dir(self, tmp_path):
        inv_dir = tmp_path / "empty_inv"
        inv_dir.mkdir()

        result = InvestigationResult(
            url="https://example.com",
            status=InvestigationStatus.COMPLETED,
        )
        _create_evidence_zip(result, inv_dir)

        with zipfile.ZipFile(inv_dir / "evidence.zip", "r") as zf:
            names = zf.namelist()

        # Only manifest should be present
        assert names == ["manifest.json"]


class TestChainOfCustodyInZip:
    """Tests for chain-of-custody metadata in evidence ZIP."""

    def test_chain_of_custody_populated(self, populated_inv_dir):
        result, inv_dir = populated_inv_dir
        _create_evidence_zip(result, inv_dir)

        assert result.chain_of_custody is not None
        coc = result.chain_of_custody
        assert coc.investigation_id == str(result.investigation_id)
        assert coc.target_url == "https://example.com"
        assert coc.hash_algorithm == "SHA-256"
        assert coc.total_artifacts >= 3
        assert coc.total_size_bytes > 0

    def test_package_sha256_set(self, populated_inv_dir):
        result, inv_dir = populated_inv_dir
        _create_evidence_zip(result, inv_dir)

        assert result.chain_of_custody is not None
        assert result.chain_of_custody.package_sha256 != ""
        assert len(result.chain_of_custody.package_sha256) == 64

    def test_manifest_is_chain_of_custody(self, populated_inv_dir):
        """manifest.json in ZIP should be a full ChainOfCustody model dump."""
        result, inv_dir = populated_inv_dir
        _create_evidence_zip(result, inv_dir)

        with zipfile.ZipFile(inv_dir / "evidence.zip", "r") as zf:
            manifest = json.loads(zf.read("manifest.json"))

        assert "investigation_id" in manifest
        assert "target_url" in manifest
        assert "collected_at" in manifest
        assert "hash_algorithm" in manifest
        assert "artifacts" in manifest
        assert "legal_notice" in manifest
        assert manifest["target_url"] == "https://example.com"

    def test_artifacts_have_descriptions(self, populated_inv_dir):
        """Known files should have descriptions from the description map."""
        result, inv_dir = populated_inv_dir
        _create_evidence_zip(result, inv_dir)

        with zipfile.ZipFile(inv_dir / "evidence.zip", "r") as zf:
            manifest = json.loads(zf.read("manifest.json"))

        inv_art = next((a for a in manifest["artifacts"] if a["file"] == "investigation.json"), None)
        assert inv_art is not None
        assert inv_art["description"] != ""
        assert inv_art["mime_type"] == "application/json"
