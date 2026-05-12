"""Sec-Gemini enrichment provider.

Wraps the ``sec-gemini`` Python SDK to run a targeted security analysis
session against the Sec-Gemini cloud agent.  Designed to be called as a
single async function from the SSI orchestrator's Phase 1 pipeline.

The provider:
1. Creates a Sec-Gemini session.
2. Uploads SSI's existing OSINT as context (to avoid redundant lookups).
3. Sends a focused investigation prompt.
4. Streams and collects agent responses.
5. Parses the response into a structured ``SecGeminiAnalysis``.
6. Cleans up the session.

All errors are caught and logged — failures never propagate to the caller.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from ssi.providers.sec_gemini.models import SecGeminiAnalysis
from ssi.providers.sec_gemini.parser import parse_sec_gemini_response
from ssi.providers.sec_gemini.prompts import build_investigation_prompt

logger = logging.getLogger(__name__)


class SecGeminiProvider:
    """Optional enrichment provider using Google's Sec-Gemini SDK.

    Args:
        api_key: Sec-Gemini API key from ``secgemini.google/keys``.
        timeout_seconds: Maximum wall-clock time to wait for the agent
            to finish.  Sec-Gemini sessions are non-deterministic; the
            agent may take 30s–5min depending on the target.
        disable_logging: When ``True``, instructs Sec-Gemini not to log
            session data server-side (privacy mode).
    """

    def __init__(
        self,
        api_key: str,
        timeout_seconds: int = 180,
        disable_logging: bool = False,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._disable_logging = disable_logging

    async def analyze_domain(
        self,
        url: str,
        existing_osint: dict[str, Any],
    ) -> SecGeminiAnalysis:
        """Run domain security analysis via Sec-Gemini.

        Creates a session, uploads context, sends the investigation prompt,
        and collects the streamed response.

        Args:
            url: Target URL being investigated.
            existing_osint: Dict of SSI's existing OSINT results (WHOIS,
                DNS, SSL, GeoIP, threat indicators) to provide as context
                and avoid redundant lookups.

        Returns:
            Structured ``SecGeminiAnalysis`` result.

        Raises:
            No exceptions — all errors are caught and returned as an empty
            ``SecGeminiAnalysis`` with error details in ``raw_agent_response``.
        """
        try:
            from sec_gemini import SecGemini  # noqa: F811 — import guarded for optional dep
        except ImportError:
            logger.warning("sec-gemini package is not installed. Install with: " "pip install sec-gemini")
            return SecGeminiAnalysis(
                raw_agent_response="ERROR: sec-gemini package not installed",
            )

        start = time.monotonic()

        try:
            async with SecGemini(api_key=self._api_key) as client:
                session = await client.sessions.create()
                logger.info("Sec-Gemini session created: %s", session.id)

                try:
                    # Upload existing OSINT as context file
                    context_json = json.dumps(existing_osint, indent=2, default=str)
                    await session.files.upload(
                        file_path=_write_temp_context(context_json),
                        content_type="application/json",
                    )

                    # Build and send the investigation prompt
                    prompt = build_investigation_prompt(url, existing_osint)
                    await session.prompt(prompt)

                    # Stream and collect results with timeout
                    result = await asyncio.wait_for(
                        self._collect_results(session),
                        timeout=self._timeout,
                    )
                    result.session_id = session.id
                    result.duration_seconds = time.monotonic() - start

                    logger.info(
                        "Sec-Gemini analysis complete: session=%s duration=%.1fs " "indicators=%d risk_adj=%.1f",
                        session.id,
                        result.duration_seconds,
                        len(result.threat_indicators),
                        result.risk_adjustment,
                    )
                    return result

                finally:
                    # Always clean up the session
                    try:
                        await session.delete()
                        logger.debug("Sec-Gemini session %s deleted", session.id)
                    except Exception:
                        logger.debug("Failed to delete Sec-Gemini session %s", session.id, exc_info=True)

        except TimeoutError:
            elapsed = time.monotonic() - start
            logger.warning("Sec-Gemini session timed out after %.1fs", elapsed)
            return SecGeminiAnalysis(
                raw_agent_response=f"ERROR: Session timed out after {elapsed:.0f}s",
                duration_seconds=elapsed,
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            logger.warning("Sec-Gemini analysis failed: %s", exc)
            return SecGeminiAnalysis(
                raw_agent_response=f"ERROR: {type(exc).__name__}: {exc}",
                duration_seconds=elapsed,
            )

    async def _collect_results(self, session: Any) -> SecGeminiAnalysis:
        """Stream agent messages and parse the final response.

        Collects all ``MESSAGE_TYPE_RESPONSE`` messages from the agent's
        stream and concatenates them into a single response for parsing.
        """
        responses: list[str] = []

        async for msg in session.messages.stream():
            msg_type = msg.get("message_type", "")

            if msg_type == "MESSAGE_TYPE_RESPONSE":
                content = msg.get("content", "")
                if content:
                    responses.append(content)
                    logger.debug("Sec-Gemini response chunk: %d chars", len(content))

            elif msg_type == "MESSAGE_TYPE_THOUGHT":
                thought = msg.get("content", "")
                if thought:
                    logger.debug("Sec-Gemini thought: %s", thought[:200])

            elif msg_type == "MESSAGE_TYPE_TOOL_CALL":
                title = msg.get("title", "unknown tool")
                logger.debug("Sec-Gemini tool call: %s", title)

        combined = "\n".join(responses)
        return parse_sec_gemini_response(combined)


def _write_temp_context(content: str) -> str:
    """Write context JSON to a temporary file and return its path.

    The file is created in the system temp directory and will be cleaned
    up by the OS.  Sec-Gemini's ``session.files.upload()`` requires a
    file path, not a bytes object.
    """
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".json", prefix="ssi_osint_ctx_")
    try:
        with open(fd, "w") as f:
            f.write(content)
    except Exception:
        import os

        os.close(fd)
        raise
    return path
