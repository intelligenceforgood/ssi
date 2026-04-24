#!/usr/bin/env python3
"""Sprint 0 merklemap spike probe.

Streams merklemap SSE for a configurable duration and reports:

- domains/sec (sampled every 30 s + overall)
- total events
- first-parse failure sample (if any)
- reconnect events

Usage (30-minute sample with the dev key):

    export SSI_PROVIDERS__MERKLEMAP__API_KEY=<key>   # or read from settings.local.toml
    python scripts/spike_merklemap.py --duration-minutes 30 --out data/reports/spikes/merklemap.json

This script is intentionally standalone (no SSI imports) so it can run with a bare
`python` interpreter and minimal deps (`httpx`). It does NOT write to the core /
ssi databases and is safe to run against the live feed.

See: copilot/.github/shared/phishdestroy-provider-gating.instructions.md
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:  # pragma: no cover
    print("httpx required: pip install httpx", file=sys.stderr)
    sys.exit(2)


DEFAULT_URL = (
    "https://api.merklemap.com/live-domains?no_throttle=true"
    # <!-- spike-update --> confirmed from merklemap-cli/src/lib.rs tail() @ 550cb04aa633c000724c339ada085c59444d5b78
)


@dataclass
class SpikeStats:
    started_at: str
    ended_at: str | None = None
    total_events: int = 0
    parse_failures: int = 0
    first_parse_failure_sample: str | None = None
    reconnects: int = 0
    window_samples: list[dict[str, Any]] = field(default_factory=list)  # [{t, events}]
    domains_per_sec_overall: float = 0.0
    domains_per_sec_p95_window: float = 0.0


def resolve_api_key(cli_key: str | None) -> str:
    if cli_key:
        return cli_key
    for env in ("SSI_PROVIDERS__MERKLEMAP__API_KEY", "I4G_PROVIDERS__MERKLEMAP__API_KEY", "MERKLEMAP_API_KEY"):
        if os.environ.get(env):
            return os.environ[env]
    print(
        "No API key. Set SSI_PROVIDERS__MERKLEMAP__API_KEY or pass --api-key.",
        file=sys.stderr,
    )
    sys.exit(2)


def run(url: str, api_key: str, duration_s: int, window_s: int = 30) -> SpikeStats:
    stats = SpikeStats(started_at=datetime.now(UTC).isoformat())
    start = time.monotonic()
    end = start + duration_s
    window_start = start
    window_events = 0

    stop = False

    def _stop(*_: Any) -> None:  # pragma: no cover
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop)

    headers = {"Authorization": f"Bearer {api_key}", "Accept": "text/event-stream"}

    while not stop and time.monotonic() < end:
        try:
            with httpx.stream("GET", url, headers=headers, timeout=None) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if stop or time.monotonic() >= end:
                        break
                    if not line or not line.startswith("data:"):
                        continue
                    payload = line[len("data:") :].strip()
                    try:
                        json.loads(payload)
                    except json.JSONDecodeError:
                        stats.parse_failures += 1
                        if stats.first_parse_failure_sample is None:
                            stats.first_parse_failure_sample = payload[:500]
                        continue
                    stats.total_events += 1
                    window_events += 1

                    now = time.monotonic()
                    if now - window_start >= window_s:
                        stats.window_samples.append({"t_offset_s": round(now - start, 1), "events": window_events})
                        window_events = 0
                        window_start = now
        except (httpx.HTTPError, httpx.StreamError) as exc:
            stats.reconnects += 1
            print(f"[reconnect] {exc!r}", file=sys.stderr)
            time.sleep(min(30, 2**stats.reconnects))

    elapsed = max(1.0, time.monotonic() - start)
    stats.ended_at = datetime.now(UTC).isoformat()
    stats.domains_per_sec_overall = round(stats.total_events / elapsed, 3)
    if stats.window_samples:
        rates = sorted(s["events"] / window_s for s in stats.window_samples)
        p95_idx = min(len(rates) - 1, int(0.95 * len(rates)))
        stats.domains_per_sec_p95_window = round(rates[p95_idx], 3)
    return stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--duration-minutes", type=float, default=30.0)
    ap.add_argument("--window-seconds", type=int, default=30)
    ap.add_argument("--out", type=Path, default=Path("data/reports/spikes/merklemap.json"))
    args = ap.parse_args()

    key = resolve_api_key(args.api_key)
    stats = run(args.url, key, int(args.duration_minutes * 60), args.window_seconds)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(asdict(stats), indent=2) + "\n")
    print(json.dumps(asdict(stats), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
