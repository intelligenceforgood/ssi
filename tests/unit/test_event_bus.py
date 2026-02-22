"""Unit tests for the event bus module (Phase 5B)."""

from __future__ import annotations

import asyncio
import json
from io import StringIO

import pytest

from ssi.monitoring.event_bus import (
    Event,
    EventBus,
    EventSink,
    EventType,
    GuidanceAction,
    GuidanceCommand,
    InMemorySink,
    JsonlSink,
    LoggingSink,
)


# ===================================================================
# Event model tests
# ===================================================================


class TestEvent:
    """Tests for the Event Pydantic model."""

    def test_create_event(self) -> None:
        """Event is created with all fields populated."""
        event = Event(
            event_type=EventType.SITE_STARTED,
            investigation_id="abc123",
            data={"url": "https://example.com"},
        )
        assert event.event_type == EventType.SITE_STARTED
        assert event.investigation_id == "abc123"
        assert event.data["url"] == "https://example.com"
        assert event.timestamp  # auto-set

    def test_event_to_jsonl(self) -> None:
        """to_jsonl produces valid JSON without newlines."""
        event = Event(event_type=EventType.LOG, data={"msg": "test"})
        line = event.to_jsonl()
        assert "\n" not in line
        parsed = json.loads(line)
        assert parsed["event_type"] == "log"
        assert parsed["data"]["msg"] == "test"

    def test_event_default_timestamp(self) -> None:
        """Events get an ISO timestamp by default."""
        event = Event(event_type=EventType.LOG)
        assert "T" in event.timestamp  # ISO format


# ===================================================================
# EventType enum tests
# ===================================================================


class TestEventType:
    """Tests for the EventType enum."""

    def test_all_event_types_are_strings(self) -> None:
        """All event types are valid strings."""
        for et in EventType:
            assert isinstance(et.value, str)
            assert len(et.value) > 0

    def test_expected_event_types_exist(self) -> None:
        """Core event types exist."""
        names = {et.value for et in EventType}
        expected = {
            "site_started",
            "site_completed",
            "state_changed",
            "screenshot_update",
            "action_executed",
            "wallet_found",
            "playbook_matched",
            "playbook_completed",
            "guidance_needed",
            "guidance_received",
            "log",
            "progress",
            "error",
        }
        assert expected.issubset(names)


# ===================================================================
# Guidance model tests
# ===================================================================


class TestGuidanceModels:
    """Tests for GuidanceAction and GuidanceCommand."""

    def test_guidance_action_values(self) -> None:
        """All guidance actions are valid."""
        assert GuidanceAction.CLICK.value == "click"
        assert GuidanceAction.SKIP.value == "skip"
        assert GuidanceAction.CONTINUE.value == "continue"

    def test_guidance_command_creation(self) -> None:
        """GuidanceCommand can be created with defaults."""
        cmd = GuidanceCommand(action=GuidanceAction.SKIP, reason="test")
        assert cmd.action == GuidanceAction.SKIP
        assert cmd.value == ""
        assert cmd.reason == "test"

    def test_guidance_command_from_dict(self) -> None:
        """GuidanceCommand can be created from a dict (WebSocket JSON)."""
        data = {"action": "click", "value": "#submit-btn", "reason": "found it"}
        cmd = GuidanceCommand(**data)
        assert cmd.action == GuidanceAction.CLICK
        assert cmd.value == "#submit-btn"


# ===================================================================
# Built-in sink tests
# ===================================================================


class TestInMemorySink:
    """Tests for the InMemorySink."""

    @pytest.mark.anyio
    async def test_collects_events(self) -> None:
        """InMemorySink stores events in order."""
        sink = InMemorySink()
        e1 = Event(event_type=EventType.LOG, data={"x": 1})
        e2 = Event(event_type=EventType.LOG, data={"x": 2})
        await sink.handle_event(e1)
        await sink.handle_event(e2)
        assert sink.count == 2
        assert sink.events[0].data["x"] == 1
        assert sink.events[1].data["x"] == 2

    @pytest.mark.anyio
    async def test_clear(self) -> None:
        """clear() empties the event list."""
        sink = InMemorySink()
        await sink.handle_event(Event(event_type=EventType.LOG))
        assert sink.count == 1
        sink.clear()
        assert sink.count == 0


class TestJsonlSink:
    """Tests for the JsonlSink."""

    @pytest.mark.anyio
    async def test_writes_jsonl_lines(self) -> None:
        """JsonlSink writes one JSON line per event."""
        buf = StringIO()
        sink = JsonlSink(buf)
        e = Event(event_type=EventType.SITE_STARTED, data={"url": "https://x.com"})
        await sink.handle_event(e)
        output = buf.getvalue()
        lines = output.strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["event_type"] == "site_started"

    @pytest.mark.anyio
    async def test_multiple_events(self) -> None:
        """Multiple events produce multiple lines."""
        buf = StringIO()
        sink = JsonlSink(buf)
        for _ in range(3):
            await sink.handle_event(Event(event_type=EventType.LOG))
        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 3


class TestLoggingSink:
    """Tests for the LoggingSink."""

    @pytest.mark.anyio
    async def test_does_not_raise(self) -> None:
        """LoggingSink handles events without error."""
        sink = LoggingSink()
        await sink.handle_event(Event(event_type=EventType.LOG, data={"msg": "test"}))
        # No exception = pass


# ===================================================================
# EventBus tests
# ===================================================================


class TestEventBus:
    """Tests for the EventBus core functionality."""

    @pytest.mark.anyio
    async def test_emit_to_single_sink(self) -> None:
        """Events flow to a registered sink."""
        bus = EventBus(investigation_id="test-1")
        sink = InMemorySink()
        bus.add_sink(sink)
        await bus.emit(EventType.SITE_STARTED, {"url": "https://x.com"})
        assert sink.count == 1
        assert sink.events[0].event_type == EventType.SITE_STARTED
        assert sink.events[0].investigation_id == "test-1"

    @pytest.mark.anyio
    async def test_emit_to_multiple_sinks(self) -> None:
        """Events are broadcast to all sinks."""
        bus = EventBus()
        s1 = InMemorySink()
        s2 = InMemorySink()
        bus.add_sink(s1)
        bus.add_sink(s2)
        await bus.emit(EventType.LOG, {"msg": "hello"})
        assert s1.count == 1
        assert s2.count == 1

    @pytest.mark.anyio
    async def test_remove_sink(self) -> None:
        """Removed sinks no longer receive events."""
        bus = EventBus()
        sink = InMemorySink()
        bus.add_sink(sink)
        await bus.emit(EventType.LOG)
        assert sink.count == 1
        bus.remove_sink(sink)
        await bus.emit(EventType.LOG)
        assert sink.count == 1  # No new event

    @pytest.mark.anyio
    async def test_emit_string_event_type(self) -> None:
        """String event types are normalized to EventType enum."""
        bus = EventBus()
        sink = InMemorySink()
        bus.add_sink(sink)
        await bus.emit("site_started", {"url": "test"})
        assert sink.events[0].event_type == EventType.SITE_STARTED

    @pytest.mark.anyio
    async def test_emit_unknown_string_becomes_log(self) -> None:
        """Unknown string event types become LOG."""
        bus = EventBus()
        sink = InMemorySink()
        bus.add_sink(sink)
        await bus.emit("some_unknown_type", {"info": "test"})
        assert sink.events[0].event_type == EventType.LOG

    @pytest.mark.anyio
    async def test_sink_error_does_not_propagate(self) -> None:
        """A failing sink doesn't stop other sinks from receiving events."""
        bus = EventBus()

        class BrokenSink:
            async def handle_event(self, event: Event) -> None:
                raise RuntimeError("boom")

        good_sink = InMemorySink()
        bus.add_sink(BrokenSink())  # type: ignore[arg-type]
        bus.add_sink(good_sink)
        await bus.emit(EventType.LOG, {"msg": "test"})
        assert good_sink.count == 1

    @pytest.mark.anyio
    async def test_sink_count(self) -> None:
        """sink_count reflects registered sinks."""
        bus = EventBus()
        assert bus.sink_count == 0
        s = InMemorySink()
        bus.add_sink(s)
        assert bus.sink_count == 1
        bus.remove_sink(s)
        assert bus.sink_count == 0


# ===================================================================
# Snapshot tests
# ===================================================================


class TestEventBusSnapshot:
    """Tests for the EventBus snapshot caching."""

    @pytest.mark.anyio
    async def test_snapshot_updates_on_site_started(self) -> None:
        """Snapshot captures URL and state after SITE_STARTED."""
        bus = EventBus()
        await bus.emit(EventType.SITE_STARTED, {"url": "https://scam.com"})
        snap = bus.get_snapshot()
        assert snap["url"] == "https://scam.com"
        assert snap["state"] == "LOAD_SITE"

    @pytest.mark.anyio
    async def test_snapshot_updates_on_state_changed(self) -> None:
        """Snapshot state updates on STATE_CHANGED."""
        bus = EventBus()
        await bus.emit(EventType.STATE_CHANGED, {"new_state": "FIND_REGISTER"})
        snap = bus.get_snapshot()
        assert snap["state"] == "FIND_REGISTER"

    @pytest.mark.anyio
    async def test_snapshot_updates_on_screenshot(self) -> None:
        """Snapshot screenshot updates on SCREENSHOT_UPDATE."""
        bus = EventBus()
        await bus.emit(EventType.SCREENSHOT_UPDATE, {"screenshot_b64": "base64data"})
        snap = bus.get_snapshot()
        assert snap["screenshot_b64"] == "base64data"

    @pytest.mark.anyio
    async def test_snapshot_has_uptime(self) -> None:
        """Snapshot includes uptime_sec."""
        bus = EventBus()
        snap = bus.get_snapshot()
        assert "uptime_sec" in snap
        assert snap["uptime_sec"] >= 0.0


# ===================================================================
# Guidance tests
# ===================================================================


class TestEventBusGuidance:
    """Tests for guidance request/response via the event bus."""

    @pytest.mark.anyio
    async def test_provide_guidance_unblocks_request(self) -> None:
        """provide_guidance unblocks a waiting request_guidance call."""
        bus = EventBus()
        sink = InMemorySink()
        bus.add_sink(sink)

        cmd = GuidanceCommand(action=GuidanceAction.SKIP, reason="test skip")

        async def provide_after_delay() -> None:
            await asyncio.sleep(0.05)
            bus.provide_guidance(cmd)

        task = asyncio.ensure_future(provide_after_delay())
        result = await bus.request_guidance(
            site_url="https://x.com",
            state="FILL_REGISTER",
            actions_taken=5,
            threshold=10,
        )
        await task

        assert result.action == GuidanceAction.SKIP
        assert result.reason == "test skip"

        # Should have emitted GUIDANCE_NEEDED and GUIDANCE_RECEIVED
        types = [e.event_type for e in sink.events]
        assert EventType.GUIDANCE_NEEDED in types
        assert EventType.GUIDANCE_RECEIVED in types

    @pytest.mark.anyio
    async def test_interject_returns_latest(self) -> None:
        """check_interject returns the latest interjection, or None."""
        bus = EventBus()
        assert bus.check_interject() is None

        cmd1 = GuidanceCommand(action=GuidanceAction.CLICK, value="#btn1")
        cmd2 = GuidanceCommand(action=GuidanceAction.GOTO, value="https://x.com")
        bus.request_interject(cmd1)
        bus.request_interject(cmd2)

        result = bus.check_interject()
        assert result is not None
        assert result.action == GuidanceAction.GOTO  # latest wins

        # Queue should now be empty
        assert bus.check_interject() is None


# ===================================================================
# Adapter tests
# ===================================================================


class TestEventBusCallback:
    """Tests for the EventBusCallback adapter."""

    @pytest.mark.anyio
    async def test_forwards_events(self) -> None:
        """EventBusCallback.on_event forwards to the bus."""
        from ssi.monitoring.adapters import EventBusCallback

        bus = EventBus()
        sink = InMemorySink()
        bus.add_sink(sink)

        cb = EventBusCallback(bus)
        await cb.on_event("site_started", {"url": "https://test.com"})

        assert sink.count == 1
        assert sink.events[0].event_type == EventType.SITE_STARTED

    @pytest.mark.anyio
    async def test_forwards_unknown_types(self) -> None:
        """Unknown event types are forwarded as LOG."""
        from ssi.monitoring.adapters import EventBusCallback

        bus = EventBus()
        sink = InMemorySink()
        bus.add_sink(sink)

        cb = EventBusCallback(bus)
        await cb.on_event("custom_event", {"detail": "something"})

        assert sink.count == 1
        assert sink.events[0].event_type == EventType.LOG
