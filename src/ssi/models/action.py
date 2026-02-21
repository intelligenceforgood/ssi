"""Action models for the zendriver-based active browser agent.

Defines the structured action types returned by the LLM (or DOM inspector)
and executed by the browser manager.
"""

from enum import Enum

from pydantic import BaseModel, field_validator


class ActionType(str, Enum):
    """Browser actions the active agent can perform."""

    CLICK = "click"
    TYPE = "type"
    SELECT = "select"
    KEY = "key"
    NAVIGATE = "navigate"
    SCROLL = "scroll"
    WAIT = "wait"
    DONE = "done"
    STUCK = "stuck"


class AgentAction(BaseModel):
    """Structured action returned by the LLM or DOM inspector.

    The agent returns one of these after each page analysis, telling
    the browser manager exactly what to do next.
    """

    action: ActionType
    selector: str = ""
    value: str = ""
    reasoning: str = ""
    confidence: float = 0.0

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        """Clamp confidence to [0.0, 1.0]."""
        return max(0.0, min(1.0, v))
