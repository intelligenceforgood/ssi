"""Unit tests for the guidance poll handler and relay — Phase 3C.

Tests cover:
* ``GuidancePollHandler.request_guidance`` — poll + timeout behaviour.
* ``GuidancePollRelay`` — background polling and EventBus integration.

HTTP calls to core are mocked via ``httpx.AsyncClient``.

Note: Uses ``asyncio.run()`` wrappers since pytest-asyncio is not
available in the SSI test environment.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from ssi.monitoring.event_bus import EventBus, GuidanceAction, GuidanceCommand

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_client(
    get_return: MagicMock | None = None,
    get_side_effect: Exception | None = None,
    post_return: MagicMock | None = None,
) -> AsyncMock:
    """Build a mock httpx.AsyncClient with async context manager support.

    Args:
        get_return: Response mock for GET requests.
        get_side_effect: Exception to raise on GET.
        post_return: Response mock for POST requests.

    Returns:
        Configured AsyncMock.
    """
    mock_client = AsyncMock()
    if get_side_effect:
        mock_client.get.side_effect = get_side_effect
    elif get_return:
        mock_client.get.return_value = get_return
    if post_return:
        mock_client.post.return_value = post_return
    else:
        ack = MagicMock()
        ack.is_success = True
        mock_client.post.return_value = ack
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


def _make_response(commands: list[dict]) -> MagicMock:
    """Build a mock HTTP response with guidance commands.

    Args:
        commands: List of command dicts.

    Returns:
        Configured MagicMock.
    """
    resp = MagicMock()
    resp.is_success = True
    resp.status_code = 200
    resp.json.return_value = {"commands": commands}
    return resp


# ---------------------------------------------------------------------------
# GuidancePollHandler tests
# ---------------------------------------------------------------------------


class TestGuidancePollHandler:
    """Tests for the HTTP-based GuidanceHandler implementation."""

    def test_request_guidance_returns_on_command(self) -> None:
        """Handler returns GuidanceResponse when a command is available."""
        from ssi.monitoring.guidance_poll_handler import GuidancePollHandler

        handler = GuidancePollHandler(
            core_api_url="http://core:8000",
            scan_id="scan-001",
            timeout_seconds=10,
            poll_interval=0.1,
        )

        resp = _make_response(
            [
                {"id": "cmd-001", "action": "click", "value": "#submit", "reason": "Found button"},
            ]
        )
        mock_client = _make_mock_client(get_return=resp)

        async def _run() -> object:
            with patch("ssi.monitoring.guidance_poll_handler.httpx.AsyncClient", return_value=mock_client):
                return await handler.request_guidance(
                    site_url="https://example.com",
                    state="NAVIGATING",
                    actions_taken=3,
                    threshold=5,
                    screenshot_b64="",
                    page_text_snippet="",
                    suggested_actions=[],
                    current_url="https://example.com",
                )

        result = asyncio.run(_run())
        assert result.action == "click"  # type: ignore[union-attr]
        assert result.value == "#submit"  # type: ignore[union-attr]
        assert result.reason == "Found button"  # type: ignore[union-attr]

    def test_request_guidance_timeout_returns_continue(self) -> None:
        """Handler returns auto-continue after timeout."""
        from ssi.monitoring.guidance_poll_handler import GuidancePollHandler

        handler = GuidancePollHandler(
            core_api_url="http://core:8000",
            scan_id="scan-001",
            timeout_seconds=0.2,
            poll_interval=0.05,
        )

        empty_resp = _make_response([])
        mock_client = _make_mock_client(get_return=empty_resp)

        async def _run() -> object:
            with patch("ssi.monitoring.guidance_poll_handler.httpx.AsyncClient", return_value=mock_client):
                return await handler.request_guidance(
                    site_url="https://example.com",
                    state="STUCK",
                    actions_taken=10,
                    threshold=5,
                    screenshot_b64="",
                    page_text_snippet="",
                    suggested_actions=[],
                    current_url="https://example.com",
                )

        from ssi.browser.agent_controller import HumanAction

        result = asyncio.run(_run())
        assert result.action == HumanAction.CONTINUE  # type: ignore[union-attr]
        assert "auto-continuing" in result.reason.lower()  # type: ignore[union-attr]

    def test_uses_core_events_url_when_set(self) -> None:
        """Handler uses core_events_url (direct Cloud Run) when set."""
        from ssi.monitoring.guidance_poll_handler import GuidancePollHandler

        handler = GuidancePollHandler(
            core_api_url="http://core:8000",
            scan_id="scan-002",
            core_events_url="https://core-svc-direct.run.app",
            timeout_seconds=0.2,
            poll_interval=0.05,
        )

        assert "core-svc-direct.run.app" in handler._base_url

    def test_handles_poll_error_then_timeout(self) -> None:
        """Handler retries on transient errors and eventually times out."""
        from ssi.monitoring.guidance_poll_handler import GuidancePollHandler

        handler = GuidancePollHandler(
            core_api_url="http://core:8000",
            scan_id="scan-003",
            timeout_seconds=0.2,
            poll_interval=0.05,
        )

        mock_client = _make_mock_client(get_side_effect=Exception("Connection refused"))

        async def _run() -> object:
            with patch("ssi.monitoring.guidance_poll_handler.httpx.AsyncClient", return_value=mock_client):
                return await handler.request_guidance(
                    site_url="https://example.com",
                    state="STUCK",
                    actions_taken=10,
                    threshold=5,
                    screenshot_b64="",
                    page_text_snippet="",
                    suggested_actions=[],
                    current_url="https://example.com",
                )

        from ssi.browser.agent_controller import HumanAction

        result = asyncio.run(_run())
        assert result.action == HumanAction.CONTINUE  # type: ignore[union-attr]

    def test_build_headers_with_api_key(self) -> None:
        """Handler includes X-API-KEY when configured."""
        from ssi.monitoring.guidance_poll_handler import GuidancePollHandler

        handler = GuidancePollHandler(
            core_api_url="http://core:8000",
            scan_id="scan-004",
            core_api_key="test-key",
        )
        headers = handler._build_headers()
        assert headers["X-API-KEY"] == "test-key"


# ---------------------------------------------------------------------------
# GuidancePollRelay tests
# ---------------------------------------------------------------------------


class TestGuidancePollRelay:
    """Tests for the background EventBus relay."""

    def test_relay_feeds_command_to_bus(self) -> None:
        """Relay polls core and delivers command via bus.provide_guidance()."""
        from ssi.monitoring.guidance_poll_handler import GuidancePollRelay

        async def _run() -> GuidanceCommand | None:
            bus = EventBus(investigation_id="scan-relay-001")

            call_count = 0
            first_resp = _make_response(
                [
                    {"id": "cmd-r1", "action": "goto", "value": "https://target.com", "reason": "Navigate"},
                ]
            )
            empty_resp = _make_response([])

            async def _mock_get(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                return first_resp if call_count == 1 else empty_resp

            mock_client = _make_mock_client(get_return=empty_resp)
            mock_client.get = _mock_get

            relay = GuidancePollRelay(
                bus=bus,
                core_api_url="http://core:8000",
                scan_id="scan-relay-001",
                poll_interval=0.05,
            )

            with patch("ssi.monitoring.guidance_poll_handler.httpx.AsyncClient", return_value=mock_client):
                relay.start()
                await asyncio.sleep(0.3)
                relay.stop()

            if not bus._guidance_queue.empty():
                return bus._guidance_queue.get_nowait()
            return None

        cmd = asyncio.run(_run())
        assert cmd is not None
        assert cmd.action == GuidanceAction.GOTO
        assert cmd.value == "https://target.com"

    def test_relay_stop_cancels_task(self) -> None:
        """Calling stop() cancels the background task."""
        from ssi.monitoring.guidance_poll_handler import GuidancePollRelay

        async def _run() -> bool:
            bus = EventBus(investigation_id="scan-stop-001")
            empty_resp = _make_response([])
            mock_client = _make_mock_client(get_return=empty_resp)

            relay = GuidancePollRelay(
                bus=bus,
                core_api_url="http://core:8000",
                scan_id="scan-stop-001",
                poll_interval=0.1,
            )

            with patch("ssi.monitoring.guidance_poll_handler.httpx.AsyncClient", return_value=mock_client):
                relay.start()
                assert relay._task is not None
                assert not relay._task.done()
                relay.stop()
                await asyncio.sleep(0.2)
                return relay._task.done()

        done = asyncio.run(_run())
        assert done

    def test_relay_acknowledges_consumed_commands(self) -> None:
        """Relay acknowledges commands after delivering them to the bus."""
        from ssi.monitoring.guidance_poll_handler import GuidancePollRelay

        async def _run() -> bool:
            bus = EventBus(investigation_id="scan-ack-001")

            call_count = 0
            first_resp = _make_response(
                [
                    {"id": "cmd-ack", "action": "skip", "value": "", "reason": "Dead site"},
                ]
            )
            empty_resp = _make_response([])

            async def _mock_get(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                return first_resp if call_count == 1 else empty_resp

            ack_resp = MagicMock()
            ack_resp.is_success = True
            mock_client = _make_mock_client(get_return=empty_resp, post_return=ack_resp)
            mock_client.get = _mock_get

            relay = GuidancePollRelay(
                bus=bus,
                core_api_url="http://core:8000",
                scan_id="scan-ack-001",
                poll_interval=0.05,
            )

            with patch("ssi.monitoring.guidance_poll_handler.httpx.AsyncClient", return_value=mock_client):
                relay.start()
                await asyncio.sleep(0.3)
                relay.stop()

            # Verify ACK was called
            mock_client.post.assert_called()
            ack_call_url = str(mock_client.post.call_args)
            return "cmd-ack" in ack_call_url

        ack_called = asyncio.run(_run())
        assert ack_called
