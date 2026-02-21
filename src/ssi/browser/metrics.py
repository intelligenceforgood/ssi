"""Lightweight per-site metrics for cost and strategy optimization.

Tracks which click/type strategies succeed, where LLM calls are spent,
how input tokens grow per call, and screenshot sizes.  Attached to
``SiteResult.metrics`` and saved in the existing JSON output.

Ported from AWH's ``metrics.py`` — identical API, no external dependencies.
"""

from __future__ import annotations


class MetricsCollector:
    """Collects per-site metrics during an agent run."""

    def __init__(self) -> None:
        self._click_strategies: dict[str, int] = {
            "css": 0,
            "js_text": 0,
            "zendriver": 0,
            "fuzzy": 0,
            "failed": 0,
        }
        self._type_strategies: dict[str, int] = {
            "css_verified": 0,
            "css_mismatch": 0,
            "textmatch_verified": 0,
            "js_setter_verified": 0,
            "fuzzy_verified": 0,
            "fuzzy_mismatch": 0,
            "failed": 0,
        }
        self._llm_calls_by_state: dict[str, dict[str, int]] = {}
        self._token_series: list[dict] = []
        self._call_counter: int = 0
        self._wasted_total: int = 0
        self._wasted_by_type: dict[str, int] = {}
        self._screenshot_sizes: list[int] = []
        self._state_timing: dict[str, dict] = {}
        self._dom_inspections: dict[str, dict[str, int]] = {}
        self._dom_overlays_removed: int = 0

    # ------------------------------------------------------------------
    # Recording helpers
    # ------------------------------------------------------------------

    def record_click(self, selector: str, strategy: str, success: bool, state: str) -> None:
        """Record which click strategy won (or failed)."""
        key = strategy if strategy in self._click_strategies else "failed"
        self._click_strategies[key] += 1

    def record_type(self, selector: str, strategy: str, verified: bool, state: str) -> None:
        """Record which type strategy won and whether it verified."""
        key = strategy if strategy in self._type_strategies else "failed"
        self._type_strategies[key] += 1

    def record_llm_call(
        self, state: str, input_tokens: int, output_tokens: int, action_type: str
    ) -> None:
        """Record per-call token counts and the action produced."""
        self._call_counter += 1

        entry = self._llm_calls_by_state.setdefault(
            state,
            {"calls": 0, "input_tokens": 0, "output_tokens": 0},
        )
        entry["calls"] += 1
        entry["input_tokens"] += input_tokens
        entry["output_tokens"] += output_tokens

        self._token_series.append(
            {
                "call": self._call_counter,
                "state": state,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "action": action_type,
            }
        )

    def record_state_timing(self, state: str, action_count: int, duration_s: float) -> None:
        """Record time and action count for a completed state."""
        existing = self._state_timing.get(state)
        if existing:
            existing["duration_s"] += round(duration_s, 2)
            existing["actions"] += action_count
        else:
            self._state_timing[state] = {
                "duration_s": round(duration_s, 2),
                "actions": action_count,
            }

    def record_screenshot(self, state: str, size_bytes: int) -> None:
        """Record screenshot size for token cost estimation."""
        self._screenshot_sizes.append(size_bytes)

    def record_wasted_action(self, state: str, action_type: str, reason: str) -> None:
        """Record a WAIT, failed click, or retry that burned an LLM call."""
        self._wasted_total += 1
        self._wasted_by_type[action_type] = self._wasted_by_type.get(action_type, 0) + 1

    def record_dom_inspection(self, state: str, outcome: str) -> None:
        """Record DOM inspection outcome: ``direct``, ``assisted``, or ``fallback``."""
        entry = self._dom_inspections.setdefault(
            state,
            {"direct": 0, "assisted": 0, "fallback": 0},
        )
        if outcome in entry:
            entry[outcome] += 1

    def record_overlay_dismissal(self, count: int) -> None:
        """Record overlay elements removed from the DOM."""
        self._dom_overlays_removed += count

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """Produce a summary dict suitable for JSON serialization."""
        ss = self._screenshot_sizes
        return {
            "click_strategies": dict(self._click_strategies),
            "type_strategies": dict(self._type_strategies),
            "llm_calls_by_state": {k: dict(v) for k, v in self._llm_calls_by_state.items()},
            "token_series": list(self._token_series),
            "wasted_actions": {
                "total": self._wasted_total,
                "by_type": dict(self._wasted_by_type),
            },
            "screenshot_sizes": {
                "avg_bytes": round(sum(ss) / len(ss)) if ss else 0,
                "max_bytes": max(ss) if ss else 0,
                "total_count": len(ss),
            },
            "state_timing": {k: dict(v) for k, v in self._state_timing.items()},
            "dom_inspection": {
                "by_state": {k: dict(v) for k, v in self._dom_inspections.items()},
                "llm_calls_saved": sum(v.get("direct", 0) for v in self._dom_inspections.values()),
                "overlays_removed": self._dom_overlays_removed,
            },
        }
