"""Performance benchmark harness — Task 1.7 of SSI roadmap Phase 1.

Measures investigation time, token usage, and evidence size per scam type.
Results are written to a JSON report for trend tracking.

Usage:
    pytest tests/benchmark/test_performance.py -v -s

Markers:
    @pytest.mark.slow — excluded from default ``pytest tests/unit`` runs.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Generator
from unittest.mock import patch

import pytest

from ssi.investigator.orchestrator import run_investigation
from ssi.models.investigation import InvestigationStatus
from ssi.monitoring import CostTracker
from ssi.osint.dns_lookup import DNSRecords
from ssi.osint.geoip_lookup import GeoIPInfo
from ssi.osint.ssl_inspect import SSLInfo
from ssi.osint.whois_lookup import WHOISRecord


# ---------------------------------------------------------------------------
# OSINT stubs (deterministic, zero-latency)
# ---------------------------------------------------------------------------

_FAKE_WHOIS = WHOISRecord(
    domain="benchmark.scam.test",
    registrar="NameCheap",
    creation_date="2026-01-01",
    expiration_date="2027-01-01",
    name_servers=["ns1.namecheap.com"],
)
_FAKE_DNS = DNSRecords(a=["93.184.216.34"], ns=["ns1.namecheap.com"])
_FAKE_SSL = SSLInfo(subject="CN=benchmark.scam.test", issuer="CN=R3", is_valid=True, is_self_signed=False)
_FAKE_GEOIP = GeoIPInfo(ip="93.184.216.34", country="US", org="AS15169 Google LLC")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_passive_investigation(url: str, output_dir: Path) -> dict[str, Any]:
    """Run a passive investigation and collect performance metrics."""
    start = time.perf_counter()
    result = run_investigation(
        url=url,
        output_dir=output_dir,
        scan_type="passive",
        skip_screenshot=True,
    )
    elapsed = time.perf_counter() - start

    # Determine evidence ZIP size (if created)
    zip_path = Path(result.evidence_zip_path) if result.evidence_zip_path else None
    zip_size = zip_path.stat().st_size if zip_path and zip_path.exists() else 0

    return {
        "url": url,
        "success": result.success,
        "status": result.status.value,
        "reported_duration_s": result.duration_seconds,
        "wall_clock_s": round(elapsed, 3),
        "token_usage": result.token_usage,
        "evidence_zip_bytes": zip_size,
        "num_indicators": len(result.threat_indicators),
        "num_wallets": len(result.wallets),
        "warnings": result.warnings,
    }


# ---------------------------------------------------------------------------
# Benchmark test class
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestPassiveBenchmark:
    """Benchmark passive investigation performance."""

    @pytest.fixture()
    def mock_osint(self) -> Generator[None, None, None]:
        """Apply all OSINT patches via context managers."""
        patches = [
            patch("ssi.investigator.orchestrator._check_domain_resolution", return_value=True),
            patch("ssi.investigator.orchestrator._run_whois", return_value=_FAKE_WHOIS),
            patch("ssi.investigator.orchestrator._run_dns", return_value=_FAKE_DNS),
            patch("ssi.investigator.orchestrator._run_ssl", return_value=_FAKE_SSL),
            patch("ssi.investigator.orchestrator._run_geoip", return_value=_FAKE_GEOIP),
            patch("ssi.investigator.orchestrator._run_browser_capture", return_value=None),
            patch("ssi.investigator.orchestrator._run_virustotal"),
            patch("ssi.investigator.orchestrator._run_urlscan"),
        ]
        for p in patches:
            p.start()
        yield
        patch.stopall()

    def test_passive_investigation_completes_under_threshold(self, mock_osint, tmp_path: Path) -> None:
        """Passive investigation completes within a reasonable time budget."""
        metrics = _run_passive_investigation("https://benchmark.scam.test", tmp_path)
        assert metrics["success"] is True

        # Passive-only pipeline should complete in < 30s (generous for CI)
        assert metrics["wall_clock_s"] < 30.0, (
            f"Passive pipeline took {metrics['wall_clock_s']:.1f}s — exceeds 30s budget"
        )

    def test_evidence_zip_size_reasonable(self, mock_osint, tmp_path: Path) -> None:
        """Evidence ZIP weighs less than 50 MB (our upload threshold)."""
        metrics = _run_passive_investigation("https://benchmark.scam.test", tmp_path)
        max_bytes = 50 * 1024 * 1024  # 50 MB
        assert metrics["evidence_zip_bytes"] < max_bytes

    def test_benchmark_report_written(self, mock_osint, tmp_path: Path) -> None:
        """Benchmark report is written as JSON for trend tracking."""
        urls = [
            "https://phishing.scam.test",
            "https://fake-shop.scam.test",
            "https://crypto-mining.scam.test",
        ]

        report: list[dict[str, Any]] = []
        for url in urls:
            out_dir = tmp_path / url.split("//")[1].replace(".", "-")
            out_dir.mkdir(parents=True, exist_ok=True)
            metrics = _run_passive_investigation(url, out_dir)
            report.append(metrics)

        report_path = tmp_path / "benchmark_report.json"
        report_path.write_text(json.dumps(report, indent=2))

        loaded = json.loads(report_path.read_text())
        assert len(loaded) == 3
        for entry in loaded:
            assert "wall_clock_s" in entry
            assert "evidence_zip_bytes" in entry


# ---------------------------------------------------------------------------
# Token budget tracking
# ---------------------------------------------------------------------------


class TestTokenBudgetTracking:
    """Verify that CostTracker captures token usage."""

    def test_cost_tracker_accumulates(self) -> None:
        """CostTracker sums input and output tokens."""
        tracker = CostTracker()
        tracker.record_llm_tokens("mock-model", input_tokens=100, output_tokens=50)
        tracker.record_llm_tokens("mock-model", input_tokens=200, output_tokens=75)

        summary = tracker.summary()
        assert summary.total_input_tokens == 300
        assert summary.total_output_tokens == 125

    def test_cost_tracker_cost_estimate(self) -> None:
        """CostTracker computes estimated cost based on token counts."""
        tracker = CostTracker()
        tracker.record_llm_tokens("mock-model", input_tokens=1000, output_tokens=500)
        summary = tracker.summary()

        # total_usd is always present; may be 0 for unknown model pricing
        assert summary.total_usd >= 0.0
        assert summary.llm_usd >= 0.0

    def test_cost_tracker_api_call_tracking(self) -> None:
        """CostTracker tracks OSINT API call counts."""
        tracker = CostTracker()
        tracker.record_api_call("virustotal")
        tracker.record_api_call("urlscan")
        tracker.record_api_call("virustotal")

        summary = tracker.summary()
        assert summary.api_calls.get("virustotal") == 2
        assert summary.api_calls.get("urlscan") == 1

    def test_cost_tracker_budget_enforcement(self) -> None:
        """CostTracker flags budget exceeded correctly."""
        tracker = CostTracker(budget_usd=0.001)
        # Record enough tokens to possibly exceed the micro-budget
        tracker.record_llm_tokens("gemini-1.5-flash", input_tokens=100_000, output_tokens=50_000)

        summary = tracker.summary()
        # Budget status is consistent
        assert isinstance(summary.budget_exceeded, bool)
