"""Per-investigation monitoring: cost tracking, event bus, and budget enforcement.

**Cost tracking** — tracks the estimated dollar cost of each investigation
phase (LLM tokens, OSINT API calls, browser session compute).

**Event bus** — decoupled event dispatch for CLI (JSONL), WebSocket (live UI),
and logging sinks. See ``ssi.monitoring.event_bus`` for details.

Usage (cost)::

    from ssi.monitoring import CostTracker

    tracker = CostTracker(budget_usd=0.25)
    tracker.record_llm_tokens(model="llama3.1", input_tokens=5000, output_tokens=1000)

Usage (event bus)::

    from ssi.monitoring.event_bus import EventBus, EventType, LoggingSink

    bus = EventBus(investigation_id="abc123")
    bus.add_sink(LoggingSink())
    await bus.emit(EventType.SITE_STARTED, {"url": "https://example.com"})
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field as PydanticField

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default cost rates (USD)
# ---------------------------------------------------------------------------

# LLM token costs per 1K tokens. Ollama/local is free, cloud models charged.
_LLM_COST_PER_1K_TOKENS: dict[str, dict[str, float]] = {
    # Local models — zero cost
    "ollama": {"input": 0.0, "output": 0.0},
    "llama3.1": {"input": 0.0, "output": 0.0},
    "llama3.2": {"input": 0.0, "output": 0.0},
    "mistral": {"input": 0.0, "output": 0.0},
    # Vertex AI / Google Cloud
    "gemini-1.5-flash": {"input": 0.000075, "output": 0.0003},
    "gemini-1.5-pro": {"input": 0.00125, "output": 0.005},
    "gemini-2.0-flash": {"input": 0.0001, "output": 0.0004},
    # OpenAI (if ever added)
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
}

# OSINT API call costs (estimated per call, some are quota-based)
_API_CALL_COSTS: dict[str, float] = {
    "virustotal": 0.0,  # Free tier: 500 lookups/day
    "urlscan": 0.0,  # Free tier: 1000 public scans/day
    "ipinfo": 0.0,  # Free tier: 50K lookups/month
    "whois": 0.0,  # python-whois: free (direct WHOIS queries)
    "dns": 0.0,  # dnspython: free (direct DNS queries)
    "ssl": 0.0,  # stdlib: free
}

# Cloud Run compute cost estimate (per vCPU-second)
_CLOUD_RUN_COST_PER_CPU_SECOND = 0.000024  # ~$0.0864/vCPU-hour
_CLOUD_RUN_COST_PER_GB_SECOND = 0.0000025  # ~$0.009/GiB-hour
_DEFAULT_VCPUS = 1
_DEFAULT_MEMORY_GB = 1


# ---------------------------------------------------------------------------
# Cost line items
# ---------------------------------------------------------------------------


@dataclass
class CostLineItem:
    """A single cost entry in the investigation ledger."""

    category: str  # "llm", "api", "compute", "other"
    label: str  # "llama3.1 input tokens", "virustotal lookup", "browser session"
    quantity: float = 0.0  # tokens, calls, seconds
    unit: str = ""  # "tokens", "calls", "seconds"
    unit_cost_usd: float = 0.0  # cost per unit
    total_cost_usd: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the line item to a plain dictionary."""
        return {
            "category": self.category,
            "label": self.label,
            "quantity": self.quantity,
            "unit": self.unit,
            "unit_cost_usd": self.unit_cost_usd,
            "total_cost_usd": round(self.total_cost_usd, 8),
        }


# ---------------------------------------------------------------------------
# Cost tracker
# ---------------------------------------------------------------------------


class CostSummary(BaseModel):
    """Aggregated cost summary for an investigation."""

    total_usd: float = 0.0
    llm_usd: float = 0.0
    api_usd: float = 0.0
    compute_usd: float = 0.0
    budget_usd: float = 0.0
    budget_remaining_usd: float = 0.0
    budget_exceeded: bool = False
    line_items: list[dict[str, Any]] = PydanticField(default_factory=list)

    # Token breakdown
    total_input_tokens: int = 0
    total_output_tokens: int = 0

    # API call breakdown
    api_calls: dict[str, int] = PydanticField(default_factory=dict)

    # Compute breakdown
    browser_seconds: float = 0.0


class CostTracker:
    """Track and enforce per-investigation cost budgets.

    Args:
        budget_usd: Maximum allowed cost in USD. Set to 0 for unlimited.
    """

    def __init__(self, budget_usd: float = 0.0) -> None:
        self._budget_usd = budget_usd
        self._items: list[CostLineItem] = []
        self._total_usd: float = 0.0
        self._llm_usd: float = 0.0
        self._api_usd: float = 0.0
        self._compute_usd: float = 0.0
        self._input_tokens: int = 0
        self._output_tokens: int = 0
        self._api_calls: dict[str, int] = {}
        self._browser_seconds: float = 0.0

    @property
    def total_cost_usd(self) -> float:
        """Total accumulated cost in USD."""
        return self._total_usd

    @property
    def budget_exceeded(self) -> bool:
        if self._budget_usd <= 0:
            return False
        return self._total_usd >= self._budget_usd

    @property
    def budget_remaining_usd(self) -> float:
        if self._budget_usd <= 0:
            return float("inf")
        return max(0.0, self._budget_usd - self._total_usd)

    def record_llm_tokens(
        self,
        model: str,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """Record LLM token usage and compute estimated cost.

        Args:
            model: Model name (used to look up per-token pricing).
            input_tokens: Number of input/prompt tokens.
            output_tokens: Number of output/completion tokens.
        """
        rates = _LLM_COST_PER_1K_TOKENS.get(model, _LLM_COST_PER_1K_TOKENS.get("ollama", {"input": 0, "output": 0}))
        input_cost = (input_tokens / 1000) * rates["input"]
        output_cost = (output_tokens / 1000) * rates["output"]
        total = input_cost + output_cost

        self._input_tokens += input_tokens
        self._output_tokens += output_tokens

        if input_tokens:
            item = CostLineItem(
                category="llm",
                label=f"{model} input tokens",
                quantity=input_tokens,
                unit="tokens",
                unit_cost_usd=rates["input"] / 1000,
                total_cost_usd=input_cost,
            )
            self._items.append(item)

        if output_tokens:
            item = CostLineItem(
                category="llm",
                label=f"{model} output tokens",
                quantity=output_tokens,
                unit="tokens",
                unit_cost_usd=rates["output"] / 1000,
                total_cost_usd=output_cost,
            )
            self._items.append(item)

        self._llm_usd += total
        self._total_usd += total

        if self.budget_exceeded:
            logger.warning(
                "Cost budget exceeded: $%.4f / $%.4f after LLM tokens",
                self._total_usd,
                self._budget_usd,
            )

    def record_api_call(self, service: str, *, cost_override: float | None = None) -> None:
        """Record an OSINT API call.

        Args:
            service: Service name (virustotal, urlscan, ipinfo, etc.).
            cost_override: Override the default per-call cost.
        """
        cost = cost_override if cost_override is not None else _API_CALL_COSTS.get(service, 0.0)
        self._api_calls[service] = self._api_calls.get(service, 0) + 1

        item = CostLineItem(
            category="api",
            label=f"{service} API call",
            quantity=1,
            unit="calls",
            unit_cost_usd=cost,
            total_cost_usd=cost,
        )
        self._items.append(item)
        self._api_usd += cost
        self._total_usd += cost

    def record_browser_seconds(self, seconds: float) -> None:
        """Record browser/compute session duration.

        Args:
            seconds: Duration of the browser session in seconds.
        """
        cpu_cost = seconds * _CLOUD_RUN_COST_PER_CPU_SECOND * _DEFAULT_VCPUS
        mem_cost = seconds * _CLOUD_RUN_COST_PER_GB_SECOND * _DEFAULT_MEMORY_GB
        total = cpu_cost + mem_cost
        self._browser_seconds += seconds

        item = CostLineItem(
            category="compute",
            label="Browser session (Cloud Run estimate)",
            quantity=seconds,
            unit="seconds",
            unit_cost_usd=_CLOUD_RUN_COST_PER_CPU_SECOND + _CLOUD_RUN_COST_PER_GB_SECOND,
            total_cost_usd=total,
        )
        self._items.append(item)
        self._compute_usd += total
        self._total_usd += total

    def summary(self) -> CostSummary:
        """Return an aggregated cost summary."""
        return CostSummary(
            total_usd=self._total_usd,
            llm_usd=self._llm_usd,
            api_usd=self._api_usd,
            compute_usd=self._compute_usd,
            budget_usd=self._budget_usd,
            budget_remaining_usd=max(0.0, self._budget_usd - self._total_usd) if self._budget_usd > 0 else 0.0,
            budget_exceeded=self.budget_exceeded,
            total_input_tokens=self._input_tokens,
            total_output_tokens=self._output_tokens,
            api_calls=dict(self._api_calls),
            browser_seconds=self._browser_seconds,
            line_items=[it.to_dict() for it in self._items],
        )
