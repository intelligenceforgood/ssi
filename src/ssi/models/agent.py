"""Models for the AI browser interaction agent.

Defines the observation → reasoning → action loop data structures
used during Phase 2 active site interaction.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import UUID, uuid4


class ActionType(str, Enum):
    """Browser actions the agent can perform."""

    CLICK = "click"
    TYPE = "type"
    SELECT = "select"
    SCROLL = "scroll"
    WAIT = "wait"
    NAVIGATE = "navigate"
    SUBMIT = "submit"
    SCREENSHOT = "screenshot"
    DONE = "done"
    FAIL = "fail"


@dataclass
class InteractiveElement:
    """A numbered interactive element extracted from the DOM."""

    index: int
    tag: str
    element_type: str = ""  # input type, button type, etc.
    name: str = ""
    label: str = ""
    placeholder: str = ""
    text: str = ""
    value: str = ""
    href: str = ""
    required: bool = False
    selector: str = ""  # CSS selector for Playwright


@dataclass
class PageObservation:
    """Snapshot of the current page state visible to the agent."""

    url: str
    title: str
    visible_text: str = ""
    interactive_elements: list[InteractiveElement] = field(default_factory=list)
    screenshot_path: str = ""
    dom_summary: str = ""


@dataclass
class AgentAction:
    """A single action decided by the LLM."""

    action_type: ActionType
    element_index: int | None = None  # Reference to InteractiveElement.index
    value: str = ""  # Text to type, URL to navigate, option to select
    reasoning: str = ""  # LLM's explanation for this action


@dataclass
class AgentStep:
    """A complete observe → reason → act cycle."""

    step_number: int
    observation: PageObservation
    action: AgentAction
    screenshot_before: str = ""
    screenshot_after: str = ""
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    error: str = ""


@dataclass
class AgentMetrics:
    """Token/latency metrics for a complete agent session."""

    total_steps: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_llm_latency_ms: float = 0.0
    total_browser_latency_ms: float = 0.0
    total_duration_ms: float = 0.0
    budget_remaining: int = 0
    completed_successfully: bool = False
    termination_reason: str = ""


@dataclass
class AgentSession:
    """Complete record of an AI agent interaction session."""

    session_id: UUID = field(default_factory=uuid4)
    url: str = ""
    steps: list[AgentStep] = field(default_factory=list)
    metrics: AgentMetrics = field(default_factory=AgentMetrics)
    identity_id: UUID | None = None
    pii_fields_submitted: list[str] = field(default_factory=list)
    pages_visited: list[str] = field(default_factory=list)
    captured_downloads: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize session to a JSON-friendly dict."""
        from dataclasses import asdict

        return asdict(self)
