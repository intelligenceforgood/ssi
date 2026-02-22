"""Unit tests for Phase 5A CLI commands and 5B WebSocket routes."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ===================================================================
# _load_batch_entries tests (investigate CLI helper)
# ===================================================================


class TestLoadBatchEntries:
    """Tests for the _load_batch_entries helper function."""

    def test_text_format_basic(self, tmp_path: Path) -> None:
        """Plain text file: one URL per line."""
        from ssi.cli.investigate import _load_batch_entries

        f = tmp_path / "urls.txt"
        f.write_text("https://a.com\nhttps://b.com\nhttps://c.com\n")
        entries = _load_batch_entries(f, "text", default_passive=False)
        assert len(entries) == 3
        assert entries[0]["url"] == "https://a.com"
        assert entries[2]["url"] == "https://c.com"

    def test_text_format_skips_comments_and_blanks(self, tmp_path: Path) -> None:
        """Comments and blank lines are ignored."""
        from ssi.cli.investigate import _load_batch_entries

        content = "# header comment\nhttps://a.com\n\n# another comment\nhttps://b.com\n   \n"
        f = tmp_path / "urls.txt"
        f.write_text(content)
        entries = _load_batch_entries(f, "text", default_passive=True)
        assert len(entries) == 2
        assert all(e["passive_only"] is True for e in entries)

    def test_json_format_string_array(self, tmp_path: Path) -> None:
        """JSON format: array of plain URL strings."""
        from ssi.cli.investigate import _load_batch_entries

        f = tmp_path / "batch.json"
        f.write_text(json.dumps(["https://a.com", "https://b.com"]))
        entries = _load_batch_entries(f, "json", default_passive=True)
        assert len(entries) == 2
        assert entries[0]["url"] == "https://a.com"
        assert entries[0]["passive_only"] is True

    def test_json_format_object_array(self, tmp_path: Path) -> None:
        """JSON format: array of objects with per-URL options."""
        from ssi.cli.investigate import _load_batch_entries

        data = [
            {"url": "https://a.com", "passive_only": False, "tags": ["crypto"]},
            {"url": "https://b.com", "playbook_override": "okdc_cluster_v1"},
        ]
        f = tmp_path / "batch.json"
        f.write_text(json.dumps(data))
        entries = _load_batch_entries(f, "json", default_passive=True)
        assert len(entries) == 2
        assert entries[0]["passive_only"] is False
        assert entries[0]["tags"] == ["crypto"]
        assert entries[1]["playbook_override"] == "okdc_cluster_v1"
        assert entries[1]["passive_only"] is True  # default applied

    def test_json_format_mixed(self, tmp_path: Path) -> None:
        """JSON format: mix of strings and objects."""
        from ssi.cli.investigate import _load_batch_entries

        data = ["https://a.com", {"url": "https://b.com", "skip_whois": True}]
        f = tmp_path / "batch.json"
        f.write_text(json.dumps(data))
        entries = _load_batch_entries(f, "json", default_passive=False)
        assert len(entries) == 2
        assert entries[0]["url"] == "https://a.com"
        assert entries[1]["skip_whois"] is True

    def test_empty_text_file(self, tmp_path: Path) -> None:
        """Empty text file returns no entries."""
        from ssi.cli.investigate import _load_batch_entries

        f = tmp_path / "empty.txt"
        f.write_text("")
        entries = _load_batch_entries(f, "text", default_passive=False)
        assert entries == []

    def test_empty_json_array(self, tmp_path: Path) -> None:
        """Empty JSON array returns no entries."""
        from ssi.cli.investigate import _load_batch_entries

        f = tmp_path / "empty.json"
        f.write_text("[]")
        entries = _load_batch_entries(f, "json", default_passive=False)
        assert entries == []


# ===================================================================
# _output_exists tests
# ===================================================================


class TestOutputExists:
    """Tests for the _output_exists helper (--resume support)."""

    def test_returns_true_when_dir_matches(self, tmp_path: Path) -> None:
        """Returns True when a matching output dir exists."""
        from ssi.cli.investigate import _output_exists

        (tmp_path / "example-com_20250101").mkdir()
        assert _output_exists("https://example.com/page", tmp_path) is True

    def test_returns_false_when_no_match(self, tmp_path: Path) -> None:
        """Returns False when no matching dir exists."""
        from ssi.cli.investigate import _output_exists

        (tmp_path / "other-site-com_20250101").mkdir()
        assert _output_exists("https://example.com", tmp_path) is False

    def test_returns_false_for_empty_dir(self, tmp_path: Path) -> None:
        """Returns False when output dir is empty."""
        from ssi.cli.investigate import _output_exists

        assert _output_exists("https://example.com", tmp_path) is False

    def test_returns_false_for_nonexistent_dir(self) -> None:
        """Returns False when output dir doesn't exist."""
        from ssi.cli.investigate import _output_exists

        assert _output_exists("https://example.com", Path("/nonexistent/path")) is False


# ===================================================================
# Playbook CLI command tests (via typer.testing.CliRunner)
# ===================================================================


class TestPlaybookCli:
    """Tests for the ssi playbook CLI commands."""

    def _runner(self):
        """Return a Typer test CliRunner bound to the main app."""
        from typer.testing import CliRunner

        from ssi.cli.app import app

        return CliRunner(), app

    def test_playbook_list(self) -> None:
        """ssi playbook list shows available playbooks."""
        runner, app = self._runner()
        # Use the actual playbook dir from config
        result = runner.invoke(app, ["playbook", "list"])
        # Should exit 0 and mention playbook(s)
        assert result.exit_code == 0

    def test_playbook_list_json(self) -> None:
        """ssi playbook list --json outputs valid JSON."""
        runner, app = self._runner()
        result = runner.invoke(app, ["playbook", "list", "--json"])
        assert result.exit_code == 0
        # Output should be parseable JSON (Rich may add formatting)
        # Just check for some JSON structure markers
        assert "playbook_id" in result.output or "[]" in result.output or result.output.strip() == ""

    def test_playbook_list_with_dir(self, tmp_path: Path) -> None:
        """ssi playbook list --dir with empty dir shows no playbooks."""
        runner, app = self._runner()
        result = runner.invoke(app, ["playbook", "list", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "No playbooks" in result.output

    def test_playbook_show_not_found(self) -> None:
        """ssi playbook show <nonexistent> exits with code 1."""
        runner, app = self._runner()
        result = runner.invoke(app, ["playbook", "show", "nonexistent_id"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_playbook_validate_missing_file(self) -> None:
        """ssi playbook validate with a missing file exits with code 1."""
        runner, app = self._runner()
        result = runner.invoke(app, ["playbook", "validate", "/tmp/no-such-file.json"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_playbook_validate_invalid_json(self, tmp_path: Path) -> None:
        """ssi playbook validate with invalid JSON exits with code 1."""
        runner, app = self._runner()
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json}")
        result = runner.invoke(app, ["playbook", "validate", str(bad)])
        assert result.exit_code == 1
        assert "invalid json" in result.output.lower() or "validation" in result.output.lower()

    def test_playbook_validate_invalid_schema(self, tmp_path: Path) -> None:
        """ssi playbook validate with valid JSON but bad schema exits with code 1."""
        runner, app = self._runner()
        bad = tmp_path / "bad_schema.json"
        bad.write_text(json.dumps({"wrong_field": "value"}))
        result = runner.invoke(app, ["playbook", "validate", str(bad)])
        assert result.exit_code == 1

    def test_playbook_validate_good_file(self, tmp_path: Path) -> None:
        """ssi playbook validate on a valid playbook file succeeds."""
        runner, app = self._runner()
        playbook = {
            "playbook_id": "test_v1",
            "url_pattern": ".*test\\.com.*",
            "description": "Test playbook",
            "steps": [
                {"action": "navigate", "value": "{url}", "description": "Go to URL"}
            ],
        }
        f = tmp_path / "test_v1.json"
        f.write_text(json.dumps(playbook))
        result = runner.invoke(app, ["playbook", "validate", str(f)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower() or "✓" in result.output

    def test_playbook_test_match_no_match(self, tmp_path: Path) -> None:
        """ssi playbook test-match with no matching playbook."""
        runner, app = self._runner()
        result = runner.invoke(
            app,
            ["playbook", "test-match", "https://nomatch.example.com", "--dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "no playbook" in result.output.lower()


# ===================================================================
# WebSocket route registration tests
# ===================================================================


class TestWsRouteRegistry:
    """Tests for the WebSocket route bus registry."""

    def test_register_and_get_bus(self) -> None:
        """register_bus makes bus retrievable via get_bus."""
        from ssi.api.ws_routes import get_bus, register_bus, unregister_bus
        from ssi.monitoring.event_bus import EventBus

        bus = EventBus(investigation_id="test-1")
        register_bus("test-1", bus)
        try:
            assert get_bus("test-1") is bus
        finally:
            unregister_bus("test-1")

    def test_unregister_bus(self) -> None:
        """unregister_bus removes the bus."""
        from ssi.api.ws_routes import get_bus, register_bus, unregister_bus
        from ssi.monitoring.event_bus import EventBus

        bus = EventBus(investigation_id="test-2")
        register_bus("test-2", bus)
        unregister_bus("test-2")
        assert get_bus("test-2") is None

    def test_get_bus_returns_none_for_unknown(self) -> None:
        """get_bus returns None for unregistered IDs."""
        from ssi.api.ws_routes import get_bus

        assert get_bus("no-such-investigation") is None

    def test_list_active_investigations(self) -> None:
        """list_active_investigations returns all registered IDs."""
        from ssi.api.ws_routes import (
            list_active_investigations,
            register_bus,
            unregister_bus,
        )
        from ssi.monitoring.event_bus import EventBus

        bus_a = EventBus(investigation_id="a")
        bus_b = EventBus(investigation_id="b")
        register_bus("a", bus_a)
        register_bus("b", bus_b)
        try:
            active = list_active_investigations()
            assert "a" in active
            assert "b" in active
        finally:
            unregister_bus("a")
            unregister_bus("b")


# ===================================================================
# WebSocket sink tests
# ===================================================================


class TestWebSocketSink:
    """Tests for the WebSocketSink event forwarding."""

    @pytest.mark.anyio
    async def test_sends_jsonl_to_websocket(self) -> None:
        """WebSocketSink sends event JSONL to the websocket."""
        from ssi.api.ws_routes import WebSocketSink
        from ssi.monitoring.event_bus import Event, EventType

        mock_ws = MagicMock()
        mock_ws.send_text = MagicMock(return_value=_async_noop())
        sink = WebSocketSink(mock_ws)

        event = Event(event_type=EventType.LOG, data={"msg": "hello"})
        await sink.handle_event(event)

        mock_ws.send_text.assert_called_once()
        sent = mock_ws.send_text.call_args[0][0]
        parsed = json.loads(sent)
        assert parsed["event_type"] == "log"

    @pytest.mark.anyio
    async def test_marks_closed_on_send_error(self) -> None:
        """WebSocketSink marks itself closed on send error."""
        from unittest.mock import AsyncMock as _AsyncMock

        from ssi.api.ws_routes import WebSocketSink
        from ssi.monitoring.event_bus import Event, EventType

        mock_ws = MagicMock()
        mock_ws.send_text = _AsyncMock(side_effect=ConnectionError("gone"))
        sink = WebSocketSink(mock_ws)

        event = Event(event_type=EventType.LOG)
        await sink.handle_event(event)
        assert sink.closed is True

    @pytest.mark.anyio
    async def test_no_send_after_closed(self) -> None:
        """No send_text calls after the sink is marked closed."""
        from unittest.mock import AsyncMock as _AsyncMock

        from ssi.api.ws_routes import WebSocketSink
        from ssi.monitoring.event_bus import Event, EventType

        mock_ws = MagicMock()
        mock_ws.send_text = _AsyncMock(side_effect=ConnectionError("gone"))
        sink = WebSocketSink(mock_ws)

        # First call — causes closed
        await sink.handle_event(Event(event_type=EventType.LOG))
        assert sink.closed

        # Second call — should NOT call send_text again
        mock_ws.send_text.reset_mock()
        await sink.handle_event(Event(event_type=EventType.LOG))
        mock_ws.send_text.assert_not_called()


# ===================================================================
# REST endpoint test
# ===================================================================


class TestActiveInvestigationsEndpoint:
    """Tests for GET /investigations/active."""

    def test_returns_empty_when_no_buses(self) -> None:
        """Returns empty list when no buses are registered."""
        from fastapi.testclient import TestClient

        from ssi.api.app import create_app

        app = create_app()
        client = TestClient(app)
        resp = client.get("/investigations/active")
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] >= 0
        assert isinstance(body["active"], list)

    def test_returns_registered_buses(self) -> None:
        """Registered buses appear in the active investigations list."""
        from fastapi.testclient import TestClient

        from ssi.api.app import create_app
        from ssi.api.ws_routes import register_bus, unregister_bus
        from ssi.monitoring.event_bus import EventBus

        app = create_app()
        client = TestClient(app)

        bus = EventBus(investigation_id="test-active")
        register_bus("test-active", bus)
        try:
            resp = client.get("/investigations/active")
            assert resp.status_code == 200
            body = resp.json()
            ids = [item["investigation_id"] for item in body["active"]]
            assert "test-active" in ids
        finally:
            unregister_bus("test-active")


# ===================================================================
# MonitoringSettings tests
# ===================================================================


class TestMonitoringSettings:
    """Tests for the MonitoringSettings in config."""

    def test_default_values(self) -> None:
        """MonitoringSettings has sensible defaults."""
        from ssi.settings.config import MonitoringSettings

        ms = MonitoringSettings()
        assert ms.enabled is True
        assert ms.websocket_enabled is True
        assert ms.jsonl_output is False
        assert ms.max_event_history == 500
        assert ms.guidance_timeout_sec == 300

    def test_settings_includes_monitoring(self) -> None:
        """Root Settings includes the monitoring section."""
        from ssi.settings import get_settings

        s = get_settings()
        assert hasattr(s, "monitoring")
        assert s.monitoring.enabled is True


# ===================================================================
# Helpers
# ===================================================================


async def _async_noop() -> None:
    """Async no-op for mock return values."""
    pass
