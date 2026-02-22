"""Event bus — decouples the agent controller from consumers (CLI, WebSocket, logs).

Ported from AWH's ``web_ui/event_bus.py`` with SSI-specific improvements:

* Type-safe event types via ``EventType`` enum.
* Multiple sink pattern: a single bus emits to all registered
  ``EventSink`` implementations (JSONL file, WebSocket broadcaster, logger).
* Guidance request/response via asyncio queues (blocks the controller
  until a human or auto-handler responds).
* Interject support — user can inject guidance mid-step.
* Snapshot caching so new WebSocket clients receive the latest state immediately.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    """All event types emitted during an investigation."""

    # Lifecycle
    SITE_STARTED = "site_started"
    SITE_COMPLETED = "site_completed"

    # State machine
    STATE_CHANGED = "state_changed"

    # Browser / agent
    SCREENSHOT_UPDATE = "screenshot_update"
    ACTION_EXECUTED = "action_executed"
    WALLET_FOUND = "wallet_found"

    # Playbook
    PLAYBOOK_MATCHED = "playbook_matched"
    PLAYBOOK_COMPLETED = "playbook_completed"

    # Human interaction
    GUIDANCE_NEEDED = "guidance_needed"
    GUIDANCE_RECEIVED = "guidance_received"

    # Progress / info
    LOG = "log"
    PROGRESS = "progress"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Event payload model
# ---------------------------------------------------------------------------


class Event(BaseModel):
    """Structured event emitted by the event bus."""

    event_type: EventType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    investigation_id: str = ""
    data: dict[str, Any] = Field(default_factory=dict)

    def to_jsonl(self) -> str:
        """Serialize to a single JSON line (no trailing newline)."""
        return self.model_dump_json()


# ---------------------------------------------------------------------------
# Guidance models
# ---------------------------------------------------------------------------


class GuidanceAction(str, Enum):
    """Actions a human operator can request."""

    CLICK = "click"
    TYPE = "type"
    GOTO = "goto"
    SKIP = "skip"
    CONTINUE = "continue"


class GuidanceCommand(BaseModel):
    """Command from a human operator (via WebSocket or CLI)."""

    action: GuidanceAction
    value: str = ""
    reason: str = ""


# ---------------------------------------------------------------------------
# Sink protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class EventSink(Protocol):
    """Protocol for event consumers.

    Implementations may write to JSONL files, WebSocket connections,
    structured loggers, or in-memory buffers for testing.
    """

    async def handle_event(self, event: Event) -> None:
        """Process a single event."""
        ...


# ---------------------------------------------------------------------------
# Built-in sinks
# ---------------------------------------------------------------------------


class LoggingSink:
    """Emit events to the Python logger at DEBUG level."""

    def __init__(self, logger_name: str = "ssi.events") -> None:
        self._logger = logging.getLogger(logger_name)

    async def handle_event(self, event: Event) -> None:
        """Log the event."""
        self._logger.debug(
            "[%s] %s: %s",
            event.investigation_id or "?",
            event.event_type.value,
            json.dumps(event.data, default=str)[:200],
        )


class InMemorySink:
    """Collect events in a list — useful for testing."""

    def __init__(self) -> None:
        self.events: list[Event] = []

    async def handle_event(self, event: Event) -> None:
        """Append the event to the in-memory list."""
        self.events.append(event)

    def clear(self) -> None:
        """Clear all collected events."""
        self.events.clear()

    @property
    def count(self) -> int:
        """Return the number of collected events."""
        return len(self.events)


class JsonlSink:
    """Write events as JSONL lines to a file-like object.

    Works with ``sys.stdout``, ``sys.stderr``, or an open file handle.
    """

    def __init__(self, stream: Any) -> None:
        self._stream = stream

    async def handle_event(self, event: Event) -> None:
        """Write one JSON line to the stream."""
        self._stream.write(event.to_jsonl() + "\n")
        if hasattr(self._stream, "flush"):
            self._stream.flush()


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------


class EventBus:
    """Central event dispatcher for controller-to-consumer communication.

    The bus supports:

    * Multiple sinks (JSONL, WebSocket, logger) registered via ``add_sink``.
    * Guidance request/response via ``request_guidance`` / ``provide_guidance``.
    * Interject support — ``request_interject`` / ``check_interject``.
    * State snapshot caching for late-joining WebSocket clients.

    Args:
        investigation_id: Optional default investigation ID attached to all events.
    """

    def __init__(self, investigation_id: str = "") -> None:
        self._investigation_id = investigation_id
        self._sinks: list[EventSink] = []
        self._guidance_queue: asyncio.Queue[GuidanceCommand] = asyncio.Queue()
        self._interject_queue: asyncio.Queue[GuidanceCommand] = asyncio.Queue()

        # Snapshot for late-joining clients
        self._latest_screenshot_b64: str = ""
        self._latest_state: str = ""
        self._latest_url: str = ""
        self._started_at: float = time.monotonic()

    # ------------------------------------------------------------------
    # Sink management
    # ------------------------------------------------------------------

    def add_sink(self, sink: EventSink) -> None:
        """Register an event sink."""
        self._sinks.append(sink)

    def remove_sink(self, sink: EventSink) -> None:
        """Remove a previously registered sink."""
        self._sinks = [s for s in self._sinks if s is not sink]

    @property
    def sink_count(self) -> int:
        """Return the number of registered sinks."""
        return len(self._sinks)

    # ------------------------------------------------------------------
    # Emit
    # ------------------------------------------------------------------

    async def emit(self, event_type: EventType | str, data: dict[str, Any] | None = None) -> None:
        """Emit an event to all registered sinks.

        Args:
            event_type: The event type (``EventType`` enum or raw string).
            data: Optional payload data.
        """
        # Normalise string → enum
        if isinstance(event_type, str):
            try:
                event_type = EventType(event_type)
            except ValueError:
                event_type = EventType.LOG

        payload = data or {}

        # Update snapshot
        self._update_snapshot(event_type, payload)

        event = Event(
            event_type=event_type,
            investigation_id=self._investigation_id,
            data=payload,
        )

        for sink in self._sinks:
            try:
                await sink.handle_event(event)
            except Exception as exc:
                logger.warning("EventBus sink error (%s): %s", type(sink).__name__, exc)

    def _update_snapshot(self, event_type: EventType, data: dict[str, Any]) -> None:
        """Update internal snapshot cache."""
        if event_type == EventType.SCREENSHOT_UPDATE:
            self._latest_screenshot_b64 = data.get("screenshot_b64", "")
        elif event_type == EventType.STATE_CHANGED:
            self._latest_state = data.get("new_state", "")
        elif event_type == EventType.SITE_STARTED:
            self._latest_url = data.get("url", "")
            self._latest_state = "LOAD_SITE"
            self._started_at = time.monotonic()

    # ------------------------------------------------------------------
    # Guidance (blocking request/response)
    # ------------------------------------------------------------------

    async def request_guidance(
        self,
        *,
        site_url: str,
        state: str,
        actions_taken: int,
        threshold: int,
        screenshot_b64: str = "",
        page_text_snippet: str = "",
        suggested_actions: list[dict[str, Any]] | None = None,
        current_url: str = "",
    ) -> GuidanceCommand:
        """Emit ``GUIDANCE_NEEDED`` and block until a response arrives.

        Called by the agent controller when stuck. The response comes
        from a WebSocket client or the auto-skip handler.

        Returns:
            A ``GuidanceCommand`` with the operator's chosen action.
        """
        # Drain any stale guidance from a previous request
        while not self._guidance_queue.empty():
            try:
                self._guidance_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        await self.emit(
            EventType.GUIDANCE_NEEDED,
            {
                "site_url": site_url,
                "state": state,
                "actions_taken": actions_taken,
                "threshold": threshold,
                "screenshot_b64": screenshot_b64,
                "page_text_snippet": page_text_snippet[:500],
                "suggested_actions": suggested_actions or [],
                "current_url": current_url,
            },
        )

        logger.info("Awaiting guidance for %s (state=%s)", site_url, state)
        guidance = await self._guidance_queue.get()
        logger.info("Received guidance: %s", guidance.action.value)

        await self.emit(
            EventType.GUIDANCE_RECEIVED,
            {"action": guidance.action.value, "value": guidance.value, "reason": guidance.reason},
        )
        return guidance

    def provide_guidance(self, guidance: GuidanceCommand) -> None:
        """Submit a guidance response (called by WebSocket handler or CLI)."""
        self._guidance_queue.put_nowait(guidance)

    # ------------------------------------------------------------------
    # Interject (non-blocking mid-step override)
    # ------------------------------------------------------------------

    def request_interject(self, guidance: GuidanceCommand) -> None:
        """Inject guidance mid-step (called by the user via UI)."""
        self._interject_queue.put_nowait(guidance)
        logger.info("Interject requested: %s", guidance.action.value)

    def check_interject(self) -> GuidanceCommand | None:
        """Non-blocking check for pending interjections.

        Returns the latest interject command, or ``None``.
        """
        result: GuidanceCommand | None = None
        while True:
            try:
                result = self._interject_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        return result

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def get_snapshot(self) -> dict[str, Any]:
        """Return latest state for new WebSocket clients."""
        return {
            "screenshot_b64": self._latest_screenshot_b64,
            "state": self._latest_state,
            "url": self._latest_url,
            "uptime_sec": round(time.monotonic() - self._started_at, 1),
        }
