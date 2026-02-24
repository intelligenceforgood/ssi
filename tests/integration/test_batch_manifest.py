"""Batch mode test — Task 1.8 of SSI roadmap Phase 1.

Validates:
  - The batch manifest JSON structure is valid.
  - Every fixture referenced in the manifest exists.
  - Batch investigation can be invoked programmatically against the manifest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Generator
from unittest.mock import patch

import pytest

from ssi.osint.dns_lookup import DNSRecords
from ssi.osint.geoip_lookup import GeoIPInfo
from ssi.osint.ssl_inspect import SSLInfo
from ssi.osint.whois_lookup import WHOISRecord

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
SCAM_SITES_DIR = FIXTURES_DIR / "scam_sites"
BATCH_MANIFEST_PATH = FIXTURES_DIR / "batch_manifest.json"


# ---------------------------------------------------------------------------
# OSINT stubs
# ---------------------------------------------------------------------------

_FAKE_WHOIS = WHOISRecord(
    domain="batch.scam.test",
    registrar="NameCheap",
    creation_date="2026-01-01",
    expiration_date="2027-01-01",
    name_servers=["ns1.namecheap.com"],
)
_FAKE_DNS = DNSRecords(a=["93.184.216.34"], ns=["ns1.namecheap.com"])
_FAKE_SSL = SSLInfo(subject="CN=batch.scam.test", issuer="CN=R3", is_valid=True, is_self_signed=False)
_FAKE_GEOIP = GeoIPInfo(ip="93.184.216.34", country="US", org="AS15169 Google LLC")


# ---------------------------------------------------------------------------
# Manifest structure tests
# ---------------------------------------------------------------------------


class TestBatchManifestStructure:
    """Validate the batch test manifest JSON file."""

    @pytest.fixture()
    def manifest(self) -> dict[str, Any]:
        """Load the batch manifest."""
        assert BATCH_MANIFEST_PATH.exists(), f"Batch manifest not found: {BATCH_MANIFEST_PATH}"
        return json.loads(BATCH_MANIFEST_PATH.read_text())

    def test_manifest_has_required_keys(self, manifest: dict[str, Any]) -> None:
        """Manifest has name, description, scan_type, and urls list."""
        assert "name" in manifest
        assert "description" in manifest
        assert "scan_type" in manifest
        assert "urls" in manifest
        assert isinstance(manifest["urls"], list)

    def test_manifest_has_minimum_urls(self, manifest: dict[str, Any]) -> None:
        """Manifest includes at least 20 URLs (matching Phase 1 target)."""
        assert len(manifest["urls"]) >= 20

    def test_all_urls_have_required_fields(self, manifest: dict[str, Any]) -> None:
        """Each URL entry has url, label, fixture, and expected_category."""
        for entry in manifest["urls"]:
            assert "url" in entry, f"Missing 'url' in: {entry}"
            assert "label" in entry, f"Missing 'label' in: {entry}"
            assert "fixture" in entry, f"Missing 'fixture' in: {entry}"
            assert "expected_category" in entry, f"Missing 'expected_category' in: {entry}"
            assert entry["url"].startswith("https://"), f"URL must use HTTPS: {entry['url']}"

    def test_all_fixture_files_exist(self, manifest: dict[str, Any]) -> None:
        """Every fixture file referenced in the manifest exists on disk."""
        missing: list[str] = []
        for entry in manifest["urls"]:
            fixture_path = SCAM_SITES_DIR / entry["fixture"]
            if not fixture_path.exists():
                missing.append(entry["fixture"])
        assert missing == [], f"Missing fixture files: {missing}"

    def test_labels_are_unique(self, manifest: dict[str, Any]) -> None:
        """All labels in the manifest are unique."""
        labels = [e["label"] for e in manifest["urls"]]
        assert len(labels) == len(set(labels)), f"Duplicate labels: {[l for l in labels if labels.count(l) > 1]}"

    def test_expected_categories_valid(self, manifest: dict[str, Any]) -> None:
        """Expected categories use the INTENT.* taxonomy format."""
        for entry in manifest["urls"]:
            cat = entry["expected_category"]
            assert cat.startswith("INTENT."), (
                f"Category '{cat}' for '{entry['label']}' does not match INTENT.* format"
            )


# ---------------------------------------------------------------------------
# Batch pipeline smoke test
# ---------------------------------------------------------------------------


class TestBatchPipelineSmoke:
    """Smoke test running multiple investigations from the batch manifest."""

    @pytest.fixture(autouse=True)
    def mock_osint(self) -> Generator[None, None, None]:
        """Apply all OSINT + store patches via context managers."""
        patches = [
            patch("ssi.investigator.orchestrator._check_domain_resolution", return_value=True),
            patch("ssi.investigator.orchestrator._run_whois", return_value=_FAKE_WHOIS),
            patch("ssi.investigator.orchestrator._run_dns", return_value=_FAKE_DNS),
            patch("ssi.investigator.orchestrator._run_ssl", return_value=_FAKE_SSL),
            patch("ssi.investigator.orchestrator._run_geoip", return_value=_FAKE_GEOIP),
            patch("ssi.investigator.orchestrator._run_browser_capture", return_value=None),
            patch("ssi.investigator.orchestrator._run_virustotal"),
            patch("ssi.investigator.orchestrator._run_urlscan"),
            # Mock the store builder at its origin so the in-function import resolves
            patch("ssi.store.build_scan_store", side_effect=Exception("skip")),
        ]
        for p in patches:
            p.start()
        yield
        patch.stopall()

    def test_first_three_manifest_urls(self, tmp_path: Path) -> None:
        """Run the first 3 URLs from the manifest as a quick batch smoke test."""
        from ssi.investigator.orchestrator import run_investigation

        manifest = json.loads(BATCH_MANIFEST_PATH.read_text())
        urls_to_test = manifest["urls"][:3]

        results: list[dict[str, Any]] = []
        for entry in urls_to_test:
            out_dir = tmp_path / entry["label"]
            out_dir.mkdir(parents=True, exist_ok=True)

            result = run_investigation(
                url=entry["url"],
                output_dir=out_dir,
                scan_type="passive",
                skip_screenshot=True,
            )
            results.append({
                "label": entry["label"],
                "success": result.success,
                "status": result.status.value,
            })

        # All 3 should complete
        for r in results:
            assert r["success"] is True, f"Failed for {r['label']}: status={r['status']}"
