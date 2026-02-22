"""WebSocket endpoints for live investigation monitoring and guidance.

Endpoints:

* ``/ws/monitor/{investigation_id}`` — read-only event stream (screenshots,
  state changes, actions, wallet finds, completion).
* ``/ws/guidance/{investigation_id}`` — bidirectional: server emits
  ``guidance_needed``; client sends ``GuidanceCommand`` JSON back.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from ssi.monitoring.event_bus import (
    Event,
    EventBus,
    EventSink,
    GuidanceCommand,
)

logger = logging.getLogger(__name__)

ws_router = APIRouter(tags=["websocket"])

# ---------------------------------------------------------------------------
# Global bus registry — maps investigation_id → EventBus
# Populated when an investigation starts, cleaned up on completion.
# ---------------------------------------------------------------------------

_active_buses: dict[str, EventBus] = {}


def register_bus(investigation_id: str, bus: EventBus) -> None:
    """Register an event bus for a running investigation."""
    _active_buses[investigation_id] = bus
    logger.info("Registered event bus for investigation %s", investigation_id)


def unregister_bus(investigation_id: str) -> None:
    """Unregister an event bus when the investigation completes."""
    _active_buses.pop(investigation_id, None)
    logger.info("Unregistered event bus for investigation %s", investigation_id)


def get_bus(investigation_id: str) -> EventBus | None:
    """Get the event bus for a running investigation, or None."""
    return _active_buses.get(investigation_id)


def list_active_investigations() -> list[str]:
    """Return IDs of all investigations with active event buses."""
    return list(_active_buses.keys())


# ---------------------------------------------------------------------------
# WebSocket sink — bridges events to a single WebSocket connection
# ---------------------------------------------------------------------------


class WebSocketSink(EventSink):
    """Forwards events to a WebSocket client."""

    def __init__(self, websocket: WebSocket) -> None:
        self._ws = websocket
        self._closed = False

    async def handle_event(self, event: Event) -> None:
        """Send event JSON to the WebSocket client."""
        if self._closed:
            return
        try:
            await self._ws.send_text(event.to_jsonl())
        except Exception:
            self._closed = True

    @property
    def closed(self) -> bool:
        """Whether the WebSocket connection has been closed."""
        return self._closed


# ---------------------------------------------------------------------------
# Monitor endpoint — read-only event stream
# ---------------------------------------------------------------------------


@ws_router.websocket("/ws/monitor/{investigation_id}")
async def ws_monitor(websocket: WebSocket, investigation_id: str) -> None:
    """Stream investigation events to a WebSocket client.

    The client receives JSON events as they happen. If the investigation
    is already running, the client first receives a snapshot of the current
    state, then live events going forward.
    """
    await websocket.accept()

    bus = get_bus(investigation_id)
    if bus is None:
        await websocket.send_json(
            {"error": "investigation_not_found", "investigation_id": investigation_id}
        )
        await websocket.close(code=4004, reason="Investigation not found or not running")
        return

    # Send current snapshot
    snapshot = bus.get_snapshot()
    await websocket.send_json({"type": "snapshot", "data": snapshot})

    # Register sink
    sink = WebSocketSink(websocket)
    bus.add_sink(sink)

    try:
        # Keep connection alive — wait for client disconnect
        while True:
            # Read pings/pongs or detect disconnect
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Client may send pings; ignore anything that isn't a close
                if msg == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send keepalive
                try:
                    await websocket.send_json({"type": "keepalive"})
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        bus.remove_sink(sink)
        logger.debug("Monitor client disconnected from %s", investigation_id)


# ---------------------------------------------------------------------------
# Guidance endpoint — bidirectional
# ---------------------------------------------------------------------------


@ws_router.websocket("/ws/guidance/{investigation_id}")
async def ws_guidance(websocket: WebSocket, investigation_id: str) -> None:
    """Bidirectional WebSocket for human guidance.

    The server emits ``guidance_needed`` events. The client responds with
    a JSON ``GuidanceCommand``:

        {"action": "click", "value": "#submit-btn", "reason": "Found submit button"}
        {"action": "skip", "reason": "Site looks dead"}
        {"action": "continue"}
        {"action": "goto", "value": "https://example.com/deposit"}
        {"action": "type", "value": "selector|text to type"}

    Interject support: the client can send a guidance command at any time
    (not just in response to ``guidance_needed``). This will be picked up
    by the controller on its next ``check_interject`` call.
    """
    await websocket.accept()

    bus = get_bus(investigation_id)
    if bus is None:
        await websocket.send_json(
            {"error": "investigation_not_found", "investigation_id": investigation_id}
        )
        await websocket.close(code=4004, reason="Investigation not found or not running")
        return

    # Send snapshot
    snapshot = bus.get_snapshot()
    await websocket.send_json({"type": "snapshot", "data": snapshot})

    # Register sink for events
    sink = WebSocketSink(websocket)
    bus.add_sink(sink)

    try:
        while True:
            raw = await websocket.receive_text()
            if raw == "ping":
                await websocket.send_text("pong")
                continue

            try:
                data = json.loads(raw)
                cmd = GuidanceCommand(**data)
            except (json.JSONDecodeError, ValidationError) as e:
                await websocket.send_json({"error": "invalid_command", "detail": str(e)})
                continue

            # Determine if this is a response to guidance_needed or an interject
            # If guidance queue is empty (no pending request), treat as interject
            if bus._guidance_queue.empty():
                bus.request_interject(cmd)
                await websocket.send_json({"type": "interject_ack", "action": cmd.action.value})
                logger.info("Interject from guidance WS: %s", cmd.action.value)
            else:
                bus.provide_guidance(cmd)
                await websocket.send_json({"type": "guidance_ack", "action": cmd.action.value})
                logger.info("Guidance provided via WS: %s", cmd.action.value)

    except WebSocketDisconnect:
        pass
    finally:
        bus.remove_sink(sink)
        logger.debug("Guidance client disconnected from %s", investigation_id)


