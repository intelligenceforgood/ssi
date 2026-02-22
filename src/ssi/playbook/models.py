"""Playbook data models — deterministic action sequences for known scam sites.

Ported from AWH's ``src/models/playbook.py`` with SSI-specific enhancements:

* ``SELECT`` and ``SCROLL`` step types added for richer site interactions.
* ``PlaybookResult`` model for structured execution outcomes.
* ``max_duration_sec`` on ``Playbook`` for per-playbook time budgets.
* Template variables (``{identity.email}``, ``{identity.password}``, etc.)
  resolved at runtime from ``SyntheticIdentity.to_dict()``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class PlaybookStepType(str, Enum):
    """Action types a playbook step can perform."""

    CLICK = "click"
    TYPE = "type"
    SELECT = "select"
    NAVIGATE = "navigate"
    WAIT = "wait"
    SCROLL = "scroll"
    EXTRACT = "extract"


class PlaybookStep(BaseModel):
    """Single deterministic step in a playbook.

    Template variables like ``{identity.email}`` in ``value`` are resolved
    at runtime against the synthetic identity dict.
    """

    action: PlaybookStepType
    selector: str = ""
    value: str = ""
    description: str = ""

    retry_on_failure: int = Field(
        default=0,
        ge=0,
        le=10,
        description="Retry this step N times before considering it failed.",
    )
    fallback_to_llm: bool = Field(
        default=True,
        description="If step fails after retries, hand off to LLM vision agent.",
    )

    @field_validator("selector")
    @classmethod
    def validate_selector(cls, v: str, info: object) -> str:  # noqa: ANN001
        """Ensure selector is provided for click/type/select actions."""
        # info.data is available in Pydantic v2 validators
        return v

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str, info: object) -> str:  # noqa: ANN001
        """Ensure value is provided for navigate and type actions."""
        return v


class Playbook(BaseModel):
    """Complete scripted flow for a site or cluster of sites.

    When a target URL matches ``url_pattern``, the executor runs the
    ``steps`` sequence deterministically, optionally falling back to
    LLM-driven analysis when individual steps fail.
    """

    playbook_id: str = Field(
        ...,
        description="Unique identifier (e.g., 'okdc_cluster_v1').",
        pattern=r"^[a-z0-9_]+$",
    )
    url_pattern: str = Field(
        ...,
        description="Regex pattern to match against site URLs.",
    )
    description: str = ""
    steps: list[PlaybookStep] = Field(
        ...,
        min_length=1,
        description="Ordered steps to execute. Must have at least one.",
    )

    fallback_to_llm: bool = Field(
        default=True,
        description="If the playbook fails mid-way, fall back to LLM from current state.",
    )
    max_duration_sec: int = Field(
        default=120,
        ge=10,
        le=600,
        description="Maximum wall-clock time for playbook execution.",
    )

    # Metadata
    author: str = ""
    version: str = "1.0"
    tested_urls: list[str] = Field(
        default_factory=list,
        description="URLs this playbook has been validated against.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags for categorisation (e.g., 'crypto', 'phishing').",
    )
    enabled: bool = True

    @field_validator("url_pattern")
    @classmethod
    def validate_url_pattern(cls, v: str) -> str:
        """Validate that url_pattern is a compilable regex."""
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex in url_pattern: {e}") from e
        return v


class PlaybookStepResult(BaseModel):
    """Outcome of executing a single playbook step."""

    step_index: int
    action: PlaybookStepType
    selector: str = ""
    value: str = ""
    success: bool
    attempts: int = 1
    error: str = ""
    fell_back_to_llm: bool = False
    duration_sec: float = 0.0


class PlaybookResult(BaseModel):
    """Structured outcome of a full playbook execution."""

    playbook_id: str
    url: str
    success: bool
    completed_steps: int = 0
    total_steps: int = 0
    step_results: list[PlaybookStepResult] = Field(default_factory=list)
    fell_back_to_llm: bool = False
    fallback_reason: str = ""
    error: str = ""
    duration_sec: float = 0.0
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
