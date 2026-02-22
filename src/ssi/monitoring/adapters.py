"""Adapters that bridge the agent controller's ``EventCallback`` protocol to the event bus.

The ``AgentController`` uses a simple ``EventCallback.on_event(type, data)``
protocol defined in ``agent_controller.py``. This module provides an adapter
that forwards those calls to the shared ``EventBus`` so sinks (JSONL, WebSocket,
logger) receive events without changing the controller's interface.

Also provides a ``GuidanceAdapter`` that bridges ``GuidanceHandler`` to the event
bus for WebSocket-driven human guidance.
"""

from __future__ import annotations

import logging
from typing import Any

from ssi.monitoring.event_bus import EventBus, GuidanceCommand

logger = logging.getLogger(__name__)


class EventBusCallback:
    """Adapter: ``EventCallback`` protocol → ``EventBus``.

    Drop this into ``AgentController(event_callback=EventBusCallback(bus))``
    and all controller events flow through the event bus to registered sinks.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus

    async def on_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Forward a controller event to the event bus."""
        await self._bus.emit(event_type, data)


class GuidanceBusAdapter:
    """Adapter: ``GuidanceHandler`` protocol → ``EventBus``.

    When the agent controller requests guidance, this adapter delegates
    to the event bus's ``request_guidance`` method, which blocks until
    a WebSocket client or auto-handler responds.

    The response is translated back into the ``GuidanceResponse`` class
    expected by the controller.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus

    async def request_guidance(
        self,
        *,
        site_url: str,
        state: str,
        actions_taken: int,
        threshold: int,
        screenshot_b64: str,
        page_text_snippet: str,
        suggested_actions: list[dict[str, Any]],
        current_url: str,
    ) -> Any:
        """Request guidance via the event bus and translate to a GuidanceResponse.

        Returns:
            A ``GuidanceResponse`` compatible with the controller.
        """
        # Import here to avoid circular deps
        from ssi.browser.agent_controller import GuidanceResponse

        cmd: GuidanceCommand = await self._bus.request_guidance(
            site_url=site_url,
            state=state,
            actions_taken=actions_taken,
            threshold=threshold,
            screenshot_b64=screenshot_b64,
            page_text_snippet=page_text_snippet,
            suggested_actions=suggested_actions,
            current_url=current_url,
        )

        return GuidanceResponse(
            action=cmd.action.value,
            value=cmd.value,
            reason=cmd.reason,
        )
