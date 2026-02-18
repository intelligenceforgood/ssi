#!/usr/bin/env python3
"""Phase 0 Research Spike — Smoke test for the AI browser agent.

Runs the agent against a set of test URLs (safe, controlled sites) to
validate that the LLM can:
  1. Observe page structure via DOM extraction
  2. Fill forms with synthetic PII
  3. Navigate multi-step flows
  4. Measure token usage and latency per interaction

Usage:
    conda run -n i4g-ssi python scripts/phase0_smoke.py
    conda run -n i4g-ssi python scripts/phase0_smoke.py --url "https://httpbin.org/forms/post"
    conda run -n i4g-ssi python scripts/phase0_smoke.py --passive-only  # DOM extraction only, no LLM

Prerequisites:
    - Ollama running locally with llama3.3 pulled:
        ollama pull llama3.3
        ollama serve
    - Playwright browsers installed:
        playwright install chromium
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# Ensure the source tree is importable when run from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rich.console import Console
from rich.table import Table

from ssi.browser.dom_extractor import extract_page_observation
from ssi.browser.llm_client import AgentLLMClient
from ssi.identity.vault import IdentityVault

console = Console()

# ---- Safe test URLs -------------------------------------------------------
# These are legitimate sites with forms, suitable for smoke-testing the
# agent's ability to observe and (optionally) interact with page elements.

TEST_URLS = [
    {
        "url": "https://httpbin.org/forms/post",
        "description": "Simple form with text fields (Customer name, size, toppings, delivery time)",
        "expected": "Agent should identify and fill form fields",
    },
    {
        "url": "https://the-internet.herokuapp.com/login",
        "description": "Login form with username/password fields",
        "expected": "Agent should type credentials and submit",
    },
    {
        "url": "https://the-internet.herokuapp.com/forgot_password",
        "description": "Single email input + submit",
        "expected": "Agent should type email and submit",
    },
    {
        "url": "https://demoqa.com/text-box",
        "description": "Multi-field form (name, email, current/permanent address)",
        "expected": "Agent should fill all fields and submit",
    },
    {
        "url": "https://demoqa.com/automation-practice-form",
        "description": "Complex registration form with many field types",
        "expected": "Agent should fill most fields (may skip file upload)",
    },
]


def run_dom_extraction_test(url: str, output_dir: Path) -> dict:
    """Test DOM extraction only (no LLM) — validates Playwright + extractor."""
    from playwright.sync_api import sync_playwright

    from ssi.settings import get_settings

    settings = get_settings()
    result = {"url": url, "success": False, "elements": 0, "text_length": 0, "error": ""}

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=settings.browser.headless)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=settings.browser.timeout_ms)

            obs = extract_page_observation(page, output_dir, step_number=0)
            result["elements"] = len(obs.interactive_elements)
            result["text_length"] = len(obs.visible_text)
            result["title"] = obs.title
            result["success"] = result["elements"] > 0

            # Save the DOM summary for inspection
            summary_path = output_dir / "dom_summary.txt"
            summary_path.write_text(obs.dom_summary)
            result["dom_summary_path"] = str(summary_path)

            browser.close()
    except Exception as e:
        result["error"] = str(e)

    return result


def run_agent_test(url: str, output_dir: Path, max_steps: int = 10) -> dict:
    """Run the full agent loop against a URL and measure metrics."""
    from ssi.browser.agent import BrowserAgent

    result = {
        "url": url,
        "success": False,
        "steps": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "duration_ms": 0,
        "actions": [],
        "pii_submitted": [],
        "termination": "",
        "error": "",
    }

    try:
        llm = AgentLLMClient.from_settings()
        if not llm.check_connectivity():
            result["error"] = "Ollama not available"
            return result

        vault = IdentityVault()
        identity = vault.generate()

        agent = BrowserAgent(
            llm_client=llm,
            identity=identity,
            max_steps=max_steps,
            output_dir=output_dir,
        )

        session = agent.run(url)
        llm.close()

        result["success"] = session.metrics.completed_successfully
        result["steps"] = session.metrics.total_steps
        result["input_tokens"] = session.metrics.total_input_tokens
        result["output_tokens"] = session.metrics.total_output_tokens
        result["total_tokens"] = session.metrics.total_input_tokens + session.metrics.total_output_tokens
        result["duration_ms"] = round(session.metrics.total_duration_ms, 1)
        result["termination"] = session.metrics.termination_reason
        result["pii_submitted"] = session.pii_fields_submitted
        result["actions"] = [
            f"{s.action.action_type.value}({s.action.element_index or ''})"
            for s in session.steps
        ]
        result["pages_visited"] = session.pages_visited

    except Exception as e:
        result["error"] = str(e)

    return result


def main():
    parser = argparse.ArgumentParser(description="Phase 0 smoke test for SSI browser agent")
    parser.add_argument("--url", help="Test a single URL instead of the default set")
    parser.add_argument("--passive-only", action="store_true", help="Run DOM extraction only (no LLM)")
    parser.add_argument("--max-steps", type=int, default=10, help="Max agent steps per URL")
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/evidence/phase0_smoke",
        help="Output directory for artifacts",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    output_base = Path(args.output_dir)
    output_base.mkdir(parents=True, exist_ok=True)

    urls = [{"url": args.url, "description": "User-provided URL", "expected": "N/A"}] if args.url else TEST_URLS

    console.print(f"\n[bold]SSI Phase 0 Smoke Test[/bold] — {len(urls)} URL(s)")
    console.print(f"Mode: {'Passive (DOM only)' if args.passive_only else 'Active (LLM agent)'}")
    console.print(f"Output: {output_base}\n")

    results = []

    for i, test_case in enumerate(urls):
        url = test_case["url"]
        desc = test_case["description"]
        url_dir = output_base / f"test_{i:02d}"
        url_dir.mkdir(parents=True, exist_ok=True)

        console.print(f"[bold cyan]({i + 1}/{len(urls)})[/bold cyan] {url}")
        console.print(f"  Description: {desc}")

        start = time.time()
        if args.passive_only:
            result = run_dom_extraction_test(url, url_dir)
        else:
            result = run_agent_test(url, url_dir, max_steps=args.max_steps)
        elapsed = time.time() - start

        result["elapsed_sec"] = round(elapsed, 1)
        result["description"] = desc
        results.append(result)

        # Print inline result
        status = "[green]PASS[/green]" if result["success"] else "[red]FAIL[/red]"
        console.print(f"  Result: {status}")
        if result.get("error"):
            console.print(f"  Error: [red]{result['error']}[/red]")
        if not args.passive_only and result.get("steps"):
            console.print(
                f"  Steps: {result['steps']} | Tokens: {result['total_tokens']} | "
                f"Duration: {result['duration_ms']}ms | Termination: {result['termination']}"
            )
            if result.get("pii_submitted"):
                console.print(f"  PII submitted: {', '.join(result['pii_submitted'])}")
            if result.get("actions"):
                console.print(f"  Actions: {' → '.join(result['actions'])}")
        elif args.passive_only:
            console.print(
                f"  Elements: {result.get('elements', 0)} | "
                f"Text: {result.get('text_length', 0)} chars | "
                f"Time: {result['elapsed_sec']}s"
            )
        console.print()

    # Summary table
    console.print("\n[bold]Summary[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("URL", max_width=40)
    table.add_column("Status")
    if args.passive_only:
        table.add_column("Elements", justify="right")
        table.add_column("Time (s)", justify="right")
    else:
        table.add_column("Steps", justify="right")
        table.add_column("Tokens", justify="right")
        table.add_column("Duration (ms)", justify="right")
        table.add_column("PII Fields")
        table.add_column("Termination")

    for r in results:
        status = "[green]PASS[/green]" if r["success"] else "[red]FAIL[/red]"
        short_url = r["url"][:38] + "…" if len(r["url"]) > 40 else r["url"]
        if args.passive_only:
            table.add_row(short_url, status, str(r.get("elements", 0)), str(r["elapsed_sec"]))
        else:
            table.add_row(
                short_url,
                status,
                str(r.get("steps", 0)),
                str(r.get("total_tokens", 0)),
                str(r.get("duration_ms", 0)),
                str(len(r.get("pii_submitted", []))),
                r.get("termination", "")[:25],
            )

    console.print(table)

    # Go/no-go summary
    passed = sum(1 for r in results if r["success"])
    total = len(results)
    ratio = passed / total if total else 0
    console.print(f"\n[bold]Pass rate: {passed}/{total} ({ratio:.0%})[/bold]")

    if not args.passive_only:
        total_tokens = sum(r.get("total_tokens", 0) for r in results)
        total_steps = sum(r.get("steps", 0) for r in results)
        avg_tokens = total_tokens / total_steps if total_steps else 0
        console.print(f"Total tokens across all tests: {total_tokens}")
        console.print(f"Average tokens per step: {avg_tokens:.0f}")

    if ratio >= 0.6:
        console.print("\n[bold green]✓ GO — Agent reliability meets Phase 0 threshold (≥60%)[/bold green]")
    else:
        console.print("\n[bold red]✗ NO-GO — Agent reliability below Phase 0 threshold (<60%)[/bold red]")

    # Save results JSON
    results_path = output_base / "phase0_results.json"
    results_path.write_text(json.dumps(results, indent=2, default=str))
    console.print(f"\nDetailed results: {results_path}")


if __name__ == "__main__":
    main()
