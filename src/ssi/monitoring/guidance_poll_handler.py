"""HTTP-based guidance handler — polls core for analyst commands (Phase 3C).

In cloud deployments, analysts submit guidance commands via the UI which
are stored in core's ``ssi_guidance_commands`` table.  This handler polls
``GET /events/ssi/{scan_id}/guidance/pending`` at a configurable interval
and feeds received commands to the ``EventBus`` guidance queue.

Two classes are provided:

``GuidancePollHandler``
    Implements the ``GuidanceHandler`` protocol from ``agent_controller.py``
    so it can be used as a drop-in replacement for ``AutoSkipGuidance`` or
    the local WebSocket-based handler.  Blocks on ``request_guidance()``
    until a command arrives or timeout elapses.

``GuidancePollRelay``
    Background async task that continuously polls core for pending
    guidance commands and feeds them into an ``EventBus`` via
    ``provide_guidance()`` or ``request_interject()``.  Attached by
    ``trigger_investigate()`` when cloud guidance is enabled.

Usage (handler — for AgentController)::

    handler = GuidancePollHandler(
        core_api_url="https://core-svc-xxx-uc.a.run.app",
        scan_id="abc123",
        timeout_seconds=300,
    )
    controller = AgentController(guidance_handler=handler, ...)

Usage (relay — for EventBus)::

    relay = GuidancePollRelay(
        bus=event_bus,
        core_api_url="https://core-svc-xxx-uc.a.run.app",
        scan_id="abc123",
    )
    relay.start()          # launches background asyncio task
    ...
    relay.stop()           # cancels when investigation ends

When no guidance arrives within ``timeout_seconds``, the handler returns
an auto-continue response so the investigation doesn't hang indefinitely.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from ssi.monitoring.event_bus import EventBus

logger = logging.getLogger(__name__)


class GuidancePollHandler:
    """Polls core API for analyst guidance commands.

    Implements the ``GuidanceHandler`` protocol from ``agent_controller.py``:
    - ``request_guidance(...)`` → blocks until a command arrives or timeout.

    Args:
        core_api_url: Base URL of the core API (or direct Cloud Run URL).
        scan_id: The SSI investigation scan ID.
        core_api_key: Optional API key for auth.
        core_events_url: Direct Cloud Run URL (bypasses IAP).
        timeout_seconds: Max seconds to wait for guidance before auto-continue.
        poll_interval: Seconds between polls.
    """

    def __init__(
        self,
        *,
        core_api_url: str,
        scan_id: str,
        core_api_key: str = "",
        core_events_url: str = "",
        timeout_seconds: float = 300.0,
        poll_interval: float = 2.0,
    ) -> None:
        base = core_events_url.rstrip("/") if core_events_url else core_api_url.rstrip("/")
        self._base_url = base
        self._scan_id = scan_id
        self._core_api_key = core_api_key
        self._core_events_url = core_events_url.rstrip("/") if core_events_url else ""
        self._timeout_seconds = timeout_seconds
        self._poll_interval = poll_interval

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
        """Poll core for pending guidance commands.

        Blocks until a command is received or ``timeout_seconds`` elapses.
        On timeout, returns an auto-continue response.

        Args:
            site_url: The site URL being investigated.
            state: Current agent state.
            actions_taken: Number of actions taken in current state.
            threshold: Action threshold for stuck detection.
            screenshot_b64: Current screenshot as base64.
            page_text_snippet: Visible page text snippet.
            suggested_actions: AI-suggested next actions.
            current_url: Current browser URL.

        Returns:
            A ``GuidanceResponse``-compatible object.
        """
        from ssi.browser.agent_controller import GuidanceResponse, HumanAction

        logger.info(
            "Polling core for guidance: scan=%s state=%s url=%s (timeout=%ds)",
            self._scan_id,
            state,
            site_url,
            self._timeout_seconds,
        )

        start = time.monotonic()
        pending_url = f"{self._base_url}/events/ssi/{self._scan_id}/guidance/pending"

        while True:
            elapsed = time.monotonic() - start
            if elapsed >= self._timeout_seconds:
                logger.warning(
                    "Guidance timeout after %.0fs for scan %s — auto-continuing",
                    elapsed,
                    self._scan_id,
                )
                return GuidanceResponse(
                    action=HumanAction.CONTINUE,
                    reason=f"No analyst guidance received within {self._timeout_seconds}s — auto-continuing",
                )

            try:
                headers = self._build_headers()
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(pending_url, headers=headers)

                if resp.is_success:
                    data = resp.json()
                    commands = data.get("commands", [])
                    if commands:
                        cmd = commands[0]  # Take oldest pending command
                        cmd_id = cmd.get("id", "")
                        action = cmd.get("action", "continue")
                        value = cmd.get("value", "")
                        reason = cmd.get("reason", "")

                        # Acknowledge the command
                        await self._acknowledge(cmd_id)

                        logger.info(
                            "Received guidance from analyst: action=%s value=%s id=%s",
                            action,
                            value[:50] if value else "",
                            cmd_id,
                        )
                        return GuidanceResponse(action=action, value=value, reason=reason)
                else:
                    logger.warning(
                        "Guidance poll returned %s for scan %s",
                        resp.status_code,
                        self._scan_id,
                    )
            except Exception as exc:
                logger.warning(
                    "Guidance poll failed for scan %s: %s",
                    self._scan_id,
                    exc,
                )

            await asyncio.sleep(self._poll_interval)

    async def _acknowledge(self, command_id: str) -> None:
        """Acknowledge a guidance command after consuming it.

        Args:
            command_id: The guidance command row ID.
        """
        if not command_id:
            return
        ack_url = f"{self._base_url}/events/ssi/{self._scan_id}/guidance/{command_id}/ack"
        try:
            headers = self._build_headers()
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(ack_url, headers=headers)
                if not resp.is_success:
                    logger.warning("Guidance ACK returned %s for %s", resp.status_code, command_id)
        except Exception as exc:
            logger.warning("Guidance ACK failed for %s: %s", command_id, exc)

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for core API requests.

        Uses the same auth strategy as ``HttpEventSink``: OIDC token for
        direct Cloud Run access, or API key for local/LB access.

        Returns:
            Headers dict.
        """
        if self._core_events_url:
            try:
                import google.auth.transport.requests  # type: ignore[import-untyped]
                import google.oauth2.id_token  # type: ignore[import-untyped]

                req = google.auth.transport.requests.Request()
                token = google.oauth2.id_token.fetch_id_token(req, audience=self._core_events_url)
                headers: dict[str, str] = {"Authorization": f"Bearer {token}"}
                if self._core_api_key:
                    headers["X-API-KEY"] = self._core_api_key
                return headers
            except Exception as exc:
                logger.warning("Could not acquire OIDC token for guidance poll: %s", exc)

        if self._core_api_key:
            return {"X-API-KEY": self._core_api_key}

        return {}


# ---------------------------------------------------------------------------
# GuidancePollRelay — background EventBus feeder
# ---------------------------------------------------------------------------


class GuidancePollRelay:
    """Background async task that polls core for guidance commands and relays them to EventBus.

    Unlike ``GuidancePollHandler`` (which blocks inside ``request_guidance``),
    this relay runs continuously in the background and feeds any received
    commands into the bus:

    * If the bus has a pending ``request_guidance()`` call (i.e. the guidance
      queue is being awaited), the command is delivered via ``provide_guidance()``.
    * Otherwise, the command is injected via ``request_interject()`` so it
      can be picked up by the next ``check_interject()`` call.

    The relay should be ``start()``-ed after the EventBus is created and
    ``stop()``-ped when the investigation ends (or let it cancel naturally
    when the event loop shuts down).

    Args:
        bus: The investigation's EventBus instance.
        core_api_url: Base URL of the core API.
        scan_id: SSI investigation scan ID.
        core_api_key: Optional API key for auth.
        core_events_url: Direct Cloud Run URL (bypasses IAP).
        poll_interval: Seconds between polls.
    """

    def __init__(
        self,
        *,
        bus: EventBus,
        core_api_url: str,
        scan_id: str,
        core_api_key: str = "",
        core_events_url: str = "",
        poll_interval: float = 2.0,
    ) -> None:
        self._bus = bus
        base = core_events_url.rstrip("/") if core_events_url else core_api_url.rstrip("/")
        self._base_url = base
        self._scan_id = scan_id
        self._core_api_key = core_api_key
        self._core_events_url = core_events_url.rstrip("/") if core_events_url else ""
        self._poll_interval = poll_interval
        self._task: asyncio.Task[None] | None = None
        self._stopped = False

    def start(self) -> None:
        """Launch the polling loop as an asyncio task on the current event loop."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.warning("No running event loop — GuidancePollRelay not started")
            return
        self._task = loop.create_task(self._poll_loop(), name=f"guidance-relay-{self._scan_id}")
        logger.info("GuidancePollRelay started for scan %s", self._scan_id)

    def stop(self) -> None:
        """Cancel the polling task."""
        self._stopped = True
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("GuidancePollRelay stopped for scan %s", self._scan_id)

    async def _poll_loop(self) -> None:
        """Continuously poll core for pending guidance commands."""
        from ssi.monitoring.event_bus import GuidanceAction, GuidanceCommand

        pending_url = f"{self._base_url}/events/ssi/{self._scan_id}/guidance/pending"

        while not self._stopped:
            try:
                headers = self._build_headers()
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(pending_url, headers=headers)

                if resp.is_success:
                    data = resp.json()
                    commands = data.get("commands", [])
                    for cmd_data in commands:
                        cmd_id = cmd_data.get("id", "")
                        action_str = cmd_data.get("action", "continue")
                        value = cmd_data.get("value", "")
                        reason = cmd_data.get("reason", "")

                        try:
                            action = GuidanceAction(action_str)
                        except ValueError:
                            action = GuidanceAction.CONTINUE

                        guidance_cmd = GuidanceCommand(action=action, value=value, reason=reason)

                        # Always deliver via provide_guidance(). If the agent
                        # is blocking on request_guidance(), this unblocks it.
                        # If not, the command sits in the queue and will be
                        # consumed by the next request_guidance() call.  The
                        # request_guidance() method drains stale commands
                        # before emitting GUIDANCE_NEEDED, so there is no
                        # risk of delivering a stale command to the wrong
                        # request.  For interject-style delivery a future
                        # enhancement can check whether request_guidance is
                        # actively waiting.
                        self._bus.provide_guidance(guidance_cmd)

                        logger.info(
                            "Relayed guidance command: action=%s value=%s id=%s",
                            action_str,
                            value[:50] if value else "",
                            cmd_id,
                        )

                        # Acknowledge the command
                        await self._acknowledge(cmd_id)
                elif resp.status_code != 404:
                    logger.warning(
                        "Guidance relay poll returned %s for scan %s",
                        resp.status_code,
                        self._scan_id,
                    )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Guidance relay poll failed for scan %s: %s", self._scan_id, exc)

            try:
                await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                break

        logger.debug("GuidancePollRelay loop exited for scan %s", self._scan_id)

    async def _acknowledge(self, command_id: str) -> None:
        """Acknowledge a guidance command after consuming it.

        Args:
            command_id: The guidance command row ID.
        """
        if not command_id:
            return
        ack_url = f"{self._base_url}/events/ssi/{self._scan_id}/guidance/{command_id}/ack"
        try:
            headers = self._build_headers()
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(ack_url, headers=headers)
                if not resp.is_success:
                    logger.warning("Guidance relay ACK returned %s for %s", resp.status_code, command_id)
        except Exception as exc:
            logger.warning("Guidance relay ACK failed for %s: %s", command_id, exc)

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for core API requests.

        Uses the same auth strategy as ``HttpEventSink``: OIDC token for
        direct Cloud Run access, or API key for local/LB access.

        Returns:
            Headers dict.
        """
        if self._core_events_url:
            try:
                import google.auth.transport.requests  # type: ignore[import-untyped]
                import google.oauth2.id_token  # type: ignore[import-untyped]

                req = google.auth.transport.requests.Request()
                token = google.oauth2.id_token.fetch_id_token(req, audience=self._core_events_url)
                headers: dict[str, str] = {"Authorization": f"Bearer {token}"}
                if self._core_api_key:
                    headers["X-API-KEY"] = self._core_api_key
                return headers
            except Exception as exc:
                logger.warning("Could not acquire OIDC token for guidance relay: %s", exc)

        if self._core_api_key:
            return {"X-API-KEY": self._core_api_key}

        return {}
