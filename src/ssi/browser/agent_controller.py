"""Agent Controller — state machine that orchestrates scam site investigation.

Drives the zendriver-powered browser through each state using vision-based
LLM analysis (screenshot + page text → LLM → structured action).

Ported from AWH's ``controller.py`` with these SSI adaptations:

* ``IdentityVault`` replaces the MCP Faker server.
* ``MetricsCollector`` replaces the standalone metrics module.
* ``GuidanceHandler`` protocol replaces console-based human interaction.
* Screenshots saved to a local ``Path`` instead of Azure Blob Storage.
* No MCP or EventBus dependencies — pure async Python.
* Settings from ``ssi.settings.get_settings()`` instead of flat config.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ssi.browser.dom_inspector import DOMInspector
from ssi.browser.metrics import MetricsCollector
from ssi.browser.page_analyzer import PageAnalyzer
from ssi.browser.zen_manager import ZenBrowserManager
from ssi.identity.vault import IdentityVault
from ssi.models.action import ActionType, AgentAction
from ssi.models.results import SiteResult, SiteStatus, WalletEntry
from ssi.models.states import (
    AgentState,
    MILESTONE_SCREENSHOT_STATES,
    STATE_TRANSITIONS,
    TERMINAL_STATES,
)
from ssi.settings import get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocols for extensibility
# ---------------------------------------------------------------------------


class HumanAction:
    """Action types a human operator can take."""

    SKIP = "skip"
    CLICK = "click"
    TYPE = "type"
    GOTO = "goto"
    CONTINUE = "continue"


@runtime_checkable
class GuidanceHandler(Protocol):
    """Protocol for human-in-the-loop guidance.

    Implementations may be a web UI, CLI prompt, or automated fallback.
    The controller calls ``request_guidance`` when stuck and applies the
    returned guidance.
    """

    async def request_guidance(
        self,
        *,
        site_url: str,
        state: str,
        actions_taken: int,
        threshold: int,
        screenshot_b64: str,
        page_text_snippet: str,
        suggested_actions: list[dict],
        current_url: str,
    ) -> GuidanceResponse:
        """Request guidance from the human operator."""
        ...


@runtime_checkable
class EventCallback(Protocol):
    """Optional event callback for monitoring agent progress.

    Implementations receive events as the agent progresses through states.
    """

    async def on_event(self, event_type: str, data: dict[str, Any]) -> None:
        ...


class GuidanceResponse:
    """Response from a human operator."""

    __slots__ = ("action", "value", "reason")

    def __init__(self, action: str = HumanAction.CONTINUE, value: str = "", reason: str = "") -> None:
        self.action = action
        self.value = value
        self.reason = reason


class AutoSkipGuidance:
    """Default guidance handler that skips the site when stuck.

    Useful for fully automated runs where no human is available.
    """

    async def request_guidance(
        self,
        *,
        site_url: str,
        state: str,
        actions_taken: int,
        threshold: int,
        screenshot_b64: str,
        page_text_snippet: str,
        suggested_actions: list[dict],
        current_url: str,
    ) -> GuidanceResponse:
        """Return an auto-skip guidance response when no human handler is available."""
        logger.warning("Auto-skipping %s in state %s (no human handler)", site_url, state)
        return GuidanceResponse(action=HumanAction.SKIP, reason="No human handler — auto-skip")


# ---------------------------------------------------------------------------
# Screenshot helper (simple local-file approach)
# ---------------------------------------------------------------------------


class ScreenshotStore:
    """Saves screenshots to a local directory, tracking paths for SiteResult."""

    def __init__(self, output_dir: Path, site_id: str, run_id: str) -> None:
        self._dir = output_dir / run_id / site_id
        self._dir.mkdir(parents=True, exist_ok=True)
        self.paths: list[str] = []

    async def capture_milestone(self, b64_png: str, label: str) -> str:
        """Save a milestone screenshot and return its file path."""
        return self._save(b64_png, f"milestone_{label}.png")

    async def capture_error(self, b64_png: str) -> str:
        """Save an error screenshot and return its file path."""
        return self._save(b64_png, "error.png")

    async def capture_stuck(self, b64_png: str) -> str:
        """Save a stuck-state screenshot and return its file path."""
        return self._save(b64_png, f"stuck_{int(time.time())}.png")

    def _save(self, b64_png: str, filename: str) -> str:
        """Decode a base64 PNG and write it to the screenshot directory."""
        path = self._dir / filename
        path.write_bytes(base64.b64decode(b64_png))
        rel = str(path)
        self.paths.append(rel)
        return rel


# ---------------------------------------------------------------------------
# States where DOM inspection runs before the LLM call
# ---------------------------------------------------------------------------

_DOM_INSPECTABLE_STATES = {
    AgentState.FIND_REGISTER,
    AgentState.NAVIGATE_DEPOSIT,
    AgentState.CHECK_EMAIL_VERIFICATION,
}

_STATE_SCAN_TYPE: dict[AgentState, str] = {
    AgentState.FIND_REGISTER: "find_register",
    AgentState.NAVIGATE_DEPOSIT: "navigate_deposit",
    AgentState.CHECK_EMAIL_VERIFICATION: "check_email",
}


def _should_include_screenshot(
    state: AgentState, actions_in_state: int, js_wallets_found: bool
) -> bool:
    """Decide whether to send a screenshot with the current LLM call.

    Text-only mode skips the image block for states where page text + extra_context
    already capture all the information the LLM needs.
    """
    if state == AgentState.CHECK_EMAIL_VERIFICATION:
        return False
    if state == AgentState.SUBMIT_REGISTER and actions_in_state > 0:
        return False
    if state == AgentState.EXTRACT_WALLETS and js_wallets_found:
        return False
    return True


# ---------------------------------------------------------------------------
# Agent Controller
# ---------------------------------------------------------------------------


class AgentController:
    """State machine controller for a single site investigation.

    Args:
        run_id: Unique identifier for this batch run.
        output_dir: Local directory for screenshots and artifacts.
        guidance_handler: Human-in-the-loop handler (default: auto-skip).
        event_callback: Optional event sink for monitoring.
        page_analyzer: Optional pre-configured PageAnalyzer.
    """

    def __init__(
        self,
        run_id: str,
        output_dir: Path | None = None,
        guidance_handler: GuidanceHandler | None = None,
        event_callback: EventCallback | None = None,
        page_analyzer: PageAnalyzer | None = None,
    ) -> None:
        settings = get_settings()
        self._settings = settings
        self._run_id = run_id
        self._output_dir = output_dir or Path("data/evidence/screenshots")

        self._browser = ZenBrowserManager()
        self._analyzer = page_analyzer or PageAnalyzer()
        self._dom_inspector = DOMInspector()
        self._identity_vault = IdentityVault()
        self._guidance = guidance_handler or AutoSkipGuidance()
        self._event_cb = event_callback

        # Per-site state (reset in process_site)
        self._state = AgentState.INIT
        self._actions_in_state = 0
        self._total_actions = 0
        self._last_actions: list[str] = []
        self._identity: dict | None = None
        self._consecutive_noop_scrolls: int = 0
        self._type_mismatches: list[str] = []
        self._blank_page_retries: int = 0
        self._last_screenshot_hash: str = ""
        self._consecutive_dupes: int = 0
        self._recent_action_log: list[dict] = []
        self._js_wallets_found: bool = False
        self._last_password_used: str = ""
        self._skip_dom_direct: bool = False
        self._human_instruction: str = ""
        self._metrics = MetricsCollector()
        self._state_entered_at: float = 0.0
        self._pre_llm_wallets: list[WalletEntry] = []

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def process_site(self, url: str, site_id: str = "unknown") -> SiteResult:
        """Process a single scam site end-to-end.

        Args:
            url: The scam site URL to investigate.
            site_id: Optional identifier for the site.

        Returns:
            A ``SiteResult`` with status, wallets found, and screenshot paths.
        """
        agent_cfg = self._settings.agent

        result = SiteResult(
            site_url=url,
            site_id=site_id,
            run_id=self._run_id,
            status=SiteStatus.IN_PROGRESS,
            started_at=datetime.now(timezone.utc),
        )

        screenshots = ScreenshotStore(self._output_dir, site_id, self._run_id)

        try:
            await self._browser.start()
            self._analyzer.reset_conversation()
            self._metrics = MetricsCollector()
            self._state = AgentState.LOAD_SITE
            self._state_entered_at = time.monotonic()
            self._actions_in_state = 0
            self._total_actions = 0
            self._last_actions = []
            self._identity = None
            self._consecutive_noop_scrolls = 0
            self._type_mismatches = []
            self._blank_page_retries = 0
            self._last_screenshot_hash = ""
            self._consecutive_dupes = 0
            self._recent_action_log = []
            self._js_wallets_found = False
            self._last_password_used = ""
            self._skip_dom_direct = False
            self._human_instruction = ""
            self._pre_llm_wallets = []

            await self._emit("site_started", {"url": url, "site_id": site_id, "run_id": self._run_id})

            while self._state not in TERMINAL_STATES:
                if self._total_actions >= agent_cfg.max_actions_per_site:
                    logger.warning("Max actions reached (%d) for %s", agent_cfg.max_actions_per_site, url)
                    result.status = SiteStatus.NEEDS_MANUAL_REVIEW
                    result.error_message = f"Exceeded max actions ({agent_cfg.max_actions_per_site})"
                    break

                action = await self._step(url, result, screenshots)
                self._total_actions += 1
                result.actions_taken = self._total_actions

                if action is None:
                    continue

        except Exception as e:
            logger.exception("Unhandled error processing %s", url)
            result.status = SiteStatus.ERROR
            result.error_message = str(e)
            try:
                ss = await self._browser.screenshot_base64_full_res()
                await screenshots.capture_error(ss)
            except Exception as ss_err:
                logger.warning("Failed to capture error screenshot: %s", ss_err)

        finally:
            await self._browser.stop()
            result.screenshots = screenshots.paths
            if result.status == SiteStatus.IN_PROGRESS:
                logger.warning("Site %s ended IN_PROGRESS — marking NEEDS_MANUAL_REVIEW", url)
                result.status = SiteStatus.NEEDS_MANUAL_REVIEW
            result.completed_at = datetime.now(timezone.utc)

            # Populate token usage from the analyzer
            usage = self._analyzer.usage
            result.llm_calls = usage.api_calls
            result.input_tokens = usage.input_tokens
            result.output_tokens = usage.output_tokens
            result.metrics = self._metrics.summary()

            await self._emit(
                "site_completed",
                {
                    "url": url,
                    "site_id": site_id,
                    "status": result.status.value,
                    "wallets": len(result.wallets),
                    "actions": result.actions_taken,
                },
            )

        logger.info(
            "Site %s: status=%s wallets=%d actions=%d (%d LLM calls, %d in + %d out tokens)",
            url,
            result.status.value,
            len(result.wallets),
            result.actions_taken,
            result.llm_calls,
            result.input_tokens,
            result.output_tokens,
        )
        return result

    # ------------------------------------------------------------------
    # Step (one iteration of the main loop)
    # ------------------------------------------------------------------

    async def _step(
        self,
        url: str,
        result: SiteResult,
        screenshots: ScreenshotStore,
    ) -> AgentAction | None:
        """Execute one step of the state machine."""
        agent_cfg = self._settings.agent

        # --- Check for stuck state ---
        threshold = agent_cfg.stuck_thresholds.get(
            self._state.value, agent_cfg.stuck_thresholds.get("DEFAULT", 15)
        )
        if self._actions_in_state >= threshold:
            guidance = await self._handle_stuck(url, result, screenshots)
            if guidance is None:
                return None
            self._actions_in_state = 0
            self._skip_dom_direct = True
            return None

        # --- Handle LOAD_SITE state (no LLM needed) ---
        if self._state == AgentState.LOAD_SITE:
            success = await self._browser.navigate(url)
            if not success:
                result.status = SiteStatus.ERROR
                result.error_message = "Failed to load site"
                self._state = AgentState.ERROR
                return None

            if agent_cfg.overlay_dismiss_enabled:
                removed = await self._browser.dismiss_overlays()
                if removed:
                    self._metrics.record_overlay_dismissal(removed)

            ss = await self._browser.screenshot_base64_full_res()
            await screenshots.capture_milestone(ss, "initial_load")
            await self._transition(AgentState.FIND_REGISTER)
            return None

        # --- For all other states: vision-based LLM analysis ---
        screenshot_b64 = await self._browser.screenshot_base64()
        page_text = await self._browser.get_page_text()
        page_url = await self._browser.get_page_url()

        # --- Pre-LLM blank page detection ---
        screenshot_bytes = int(len(screenshot_b64) * 3 / 4)
        is_blank = len(page_text.strip()) < 20 and screenshot_bytes < 5000
        if is_blank:
            self._blank_page_retries += 1
            logger.info(
                "Blank page in %s (attempt %d, text=%d, img=%d bytes)",
                self._state.value, self._blank_page_retries,
                len(page_text.strip()), screenshot_bytes,
            )
            self._metrics.record_wasted_action(
                self._state.value, "blank_page",
                f"text={len(page_text.strip())} img={screenshot_bytes}",
            )

            # NAVIGATE_DEPOSIT early-abort
            if self._state == AgentState.NAVIGATE_DEPOSIT and self._blank_page_retries >= 2:
                logger.warning("Deposit page blank after %d retries — aborting", self._blank_page_retries)
                result.status = SiteStatus.BROKEN_DEPOSIT_PAGE
                result.notes = "Deposit page blank/broken after multiple retries"
                self._state = AgentState.SKIPPED
                return None

            max_retries = agent_cfg.blank_page_max_retries.get(
                self._state.value, agent_cfg.blank_page_max_retries.get("DEFAULT", 3)
            )
            if self._blank_page_retries <= max_retries:
                wait_secs = min(2.0 + self._blank_page_retries, 5.0)
                logger.info("Blank page retry %d/%d — waiting %.0fs", self._blank_page_retries, max_retries, wait_secs)
                await self._browser.wait(wait_secs)
                self._actions_in_state += 1
                return None
        else:
            self._blank_page_retries = 0

        # --- Snapshot hash dedup: skip LLM if page hasn't changed ---
        screenshot_hash = hashlib.md5(screenshot_b64.encode("utf-8")).hexdigest()
        if screenshot_hash == self._last_screenshot_hash:
            self._consecutive_dupes += 1
            logger.info(
                "Duplicate screenshot in %s (hash=%s, streak=%d)",
                self._state.value, screenshot_hash[:8], self._consecutive_dupes,
            )
            self._metrics.record_wasted_action(
                self._state.value, "duplicate_screenshot", f"hash={screenshot_hash[:12]}",
            )
            if self._consecutive_dupes >= 5:
                self._actions_in_state = threshold  # Force stuck
            else:
                await self._browser.wait(2.0)
                self._actions_in_state += 1
            return None
        self._last_screenshot_hash = screenshot_hash
        self._consecutive_dupes = 0

        extra_context = await self._build_state_context()

        # Scroll-stuck hint
        if self._consecutive_noop_scrolls >= 2:
            extra_context += (
                "\n\nIMPORTANT: The page cannot scroll further — the scroll position "
                "has not changed for the last several scroll attempts. Try a different "
                "approach (click a link, navigate, or signal 'done' if you have all the info)."
            )

        # DOM error messages
        dom_errors = await self._browser.get_visible_errors()
        if dom_errors:
            error_lines = "\n".join(f'- "{e}"' for e in dom_errors)
            fields_all_filled = (
                self._state == AgentState.SUBMIT_REGISTER
                and "FORM FIELD STATUS" in extra_context
                and "EMPTY" not in extra_context
            )
            if fields_all_filled:
                extra_context += (
                    f"\n\nFORM ERRORS DETECTED ON PAGE (likely stale):\n{error_lines}\n"
                    "These error messages may be stale from a previous submission attempt. "
                    "The FORM FIELD STATUS above shows all fields are filled — "
                    "click the submit/register button to re-attempt submission."
                )
            else:
                extra_context += (
                    f"\n\nFORM ERRORS DETECTED ON PAGE:\n{error_lines}\n"
                    "Act on these errors — fix the problematic fields before trying to submit again."
                )

        # Type mismatch warnings
        if self._type_mismatches:
            mismatch_lines = "\n".join(f"- {m}" for m in self._type_mismatches)
            extra_context += (
                f"\n\nTYPE VERIFICATION WARNINGS:\n{mismatch_lines}\n"
                "These fields may not have accepted the typed value. "
                "Try clicking the field first, clearing it, then retyping."
            )

        # Human instruction (consumed once)
        if self._human_instruction:
            extra_context += (
                f"\n\nHUMAN OPERATOR INSTRUCTION: {self._human_instruction}\n"
                "Follow this instruction from the human operator."
            )
            logger.info("Injecting human instruction: %s", self._human_instruction)
            self._human_instruction = ""

        await self._emit("screenshot_update", {"screenshot_b64": screenshot_b64})

        # Capture milestone on state entry (full-res for human review)
        if self._actions_in_state == 0 and self._state in MILESTONE_SCREENSHOT_STATES:
            milestone_ss = await self._browser.screenshot_base64_full_res()
            await screenshots.capture_milestone(milestone_ss, self._state.value.lower())

        # --- DOM Inspection: pre-LLM detection ---
        if self._skip_dom_direct:
            self._skip_dom_direct = False
            logger.info("Skipping DOM direct (post-guidance cooldown)")
        elif agent_cfg.dom_inspection_enabled and self._state in _DOM_INSPECTABLE_STATES:
            dom_action, extra_context = await self._try_dom_inspection(extra_context)
            if dom_action is not None:
                self._actions_in_state += 1
                action_sig = f"{dom_action.action}:{dom_action.selector}:{dom_action.value}"
                self._last_actions.append(action_sig)
                if len(self._last_actions) > agent_cfg.max_repeated_actions:
                    self._last_actions = self._last_actions[-agent_cfg.max_repeated_actions:]
                if (
                    len(self._last_actions) >= agent_cfg.max_repeated_actions
                    and len(set(self._last_actions)) == 1
                ):
                    logger.warning("DOM direct: %d repeated actions — triggering stuck", agent_cfg.max_repeated_actions)
                    self._actions_in_state = threshold
                await self._emit(
                    "action_executed",
                    {
                        "action": dom_action.action.value,
                        "selector": dom_action.selector,
                        "value": dom_action.value,
                        "reasoning": dom_action.reasoning,
                        "confidence": dom_action.confidence,
                    },
                )
                await self._execute_action(dom_action, url, result, screenshots)
                return dom_action

        # --- JS-based coin extraction before first LLM call in EXTRACT_WALLETS ---
        if self._state == AgentState.EXTRACT_WALLETS and self._actions_in_state == 0:
            js_wallets = await self._try_js_wallet_extraction(url, result)
            if js_wallets:
                self._js_wallets_found = True
                wallet_summary = ", ".join(
                    f"{w.token_symbol} ({w.wallet_address[:12]}...)" for w in js_wallets
                )
                extra_context += (
                    f"\n\nJS PRE-EXTRACTION found {len(js_wallets)} wallet addresses: "
                    f"{wallet_summary}. "
                    "IMPORTANT: You MUST re-list ALL wallet addresses in your 'done' response "
                    "with complete data — include token_label, token_symbol, network_label, "
                    "network_short, and wallet_address for each."
                )

        # --- Batch path for FILL_REGISTER (first entry only) ---
        if self._state == AgentState.FILL_REGISTER and self._actions_in_state == 0:
            return await self._step_fill_register_batch(
                url, result, screenshots,
                screenshot_b64, page_text, page_url, extra_context,
            )

        # --- Text-only mode for select states ---
        include_screenshot = _should_include_screenshot(
            self._state, self._actions_in_state, self._js_wallets_found,
        )

        action = await self._analyzer.analyze_page(
            screenshot_b64=screenshot_b64,
            state=self._state.value,
            page_text=page_text,
            page_url=page_url,
            extra_context=extra_context,
            include_screenshot=include_screenshot,
        )

        # --- Record metrics ---
        if self._analyzer.last_call_result:
            self._metrics.record_llm_call(
                state=self._state.value,
                input_tokens=self._analyzer.last_call_result.input_tokens,
                output_tokens=self._analyzer.last_call_result.output_tokens,
                action_type=action.action.value,
            )
        self._metrics.record_screenshot(
            state=self._state.value,
            size_bytes=int(len(screenshot_b64) * 3 / 4),
        )
        if action.action in (ActionType.WAIT, ActionType.STUCK):
            self._metrics.record_wasted_action(
                self._state.value, action.action.value, action.reasoning[:100],
            )

        self._actions_in_state += 1

        await self._emit(
            "action_executed",
            {
                "action": action.action.value,
                "selector": action.selector,
                "value": action.value,
                "reasoning": action.reasoning,
                "confidence": action.confidence,
            },
        )

        # --- Check for repeated actions ---
        action_sig = f"{action.action}:{action.selector}:{action.value}"
        self._last_actions.append(action_sig)
        if len(self._last_actions) > agent_cfg.max_repeated_actions:
            self._last_actions = self._last_actions[-agent_cfg.max_repeated_actions:]
        if (
            len(self._last_actions) >= agent_cfg.max_repeated_actions
            and len(set(self._last_actions)) == 1
        ):
            logger.warning("Detected %d repeated actions — triggering stuck", agent_cfg.max_repeated_actions)
            self._actions_in_state = threshold
            return action

        # --- Execute the action ---
        await self._execute_action(action, url, result, screenshots)
        return action

    # ------------------------------------------------------------------
    # Action execution
    # ------------------------------------------------------------------

    async def _execute_action(
        self,
        action: AgentAction,
        url: str,
        result: SiteResult,
        screenshots: ScreenshotStore,
    ) -> None:
        """Execute a single action returned by the LLM or DOM inspector."""
        log_entry: dict[str, Any] = {
            "action": action.action.value,
            "selector": action.selector[:80] if action.selector else "",
            "value": action.value[:60] if action.value else "",
            "reasoning": action.reasoning[:80] if action.reasoning else "",
            "success": True,
        }

        try:
            if action.action == ActionType.CLICK:
                success = await self._browser.click(action.selector)
                self._metrics.record_click(
                    selector=action.selector,
                    strategy=self._browser.last_click_strategy,
                    success=success,
                    state=self._state.value,
                )
                if not success:
                    logger.warning("Click failed: %s", action.selector)
                    self._metrics.record_wasted_action(
                        self._state.value, "failed_click", f"selector: {action.selector[:80]}",
                    )
                    self._last_screenshot_hash = ""
                    log_entry["success"] = False
                else:
                    await asyncio.sleep(2)
                if self._state == AgentState.SUBMIT_REGISTER:
                    await self._browser.scroll_to_top()

            elif action.action == ActionType.TYPE:
                success, actual_value = await self._browser.type_text(action.selector, action.value)
                self._metrics.record_type(
                    selector=action.selector,
                    strategy=self._browser.last_type_strategy,
                    verified=(success and actual_value == action.value),
                    state=self._state.value,
                )
                sel_lower = action.selector.lower()
                if success and "password" in sel_lower and "confirm" not in sel_lower:
                    self._last_password_used = action.value
                if not success:
                    logger.warning("Type failed: %s", action.selector)
                    self._last_screenshot_hash = ""
                    log_entry["success"] = False
                elif actual_value != action.value:
                    mismatch_msg = (
                        f'Field "{action.selector}" was set to "{action.value}" '
                        f'but contains "{actual_value}" — value may not have been accepted.'
                    )
                    self._type_mismatches.append(mismatch_msg)
                    logger.warning("Type mismatch: %s", mismatch_msg)
                else:
                    self._type_mismatches = [
                        m for m in self._type_mismatches
                        if f'Field "{action.selector}"' not in m
                    ]

            elif action.action == ActionType.SELECT:
                success = await self._browser.select_option(action.selector, action.value)
                if not success:
                    logger.warning("Select failed: %s", action.selector)
                    self._last_screenshot_hash = ""

            elif action.action == ActionType.KEY:
                key_name = action.value or action.selector
                success = await self._browser.press_key(key_name)
                if not success:
                    logger.warning("Key press failed: %s", key_name)
                    self._last_screenshot_hash = ""

            elif action.action == ActionType.NAVIGATE:
                success = await self._browser.navigate(action.value)
                if not success:
                    logger.warning("Navigate failed: %s", action.value)
                    self._last_screenshot_hash = ""

            elif action.action == ActionType.SCROLL:
                try:
                    pixels = int(action.value) if action.value else 500
                except ValueError:
                    pixels = 500
                pos_before = await self._browser.get_scroll_position()
                await self._browser.scroll_down(pixels)
                pos_after = await self._browser.get_scroll_position()
                if pos_after == pos_before:
                    self._consecutive_noop_scrolls += 1
                    logger.info("Noop scroll (%d consecutive)", self._consecutive_noop_scrolls)
                else:
                    self._consecutive_noop_scrolls = 0

            elif action.action == ActionType.WAIT:
                try:
                    seconds = float(action.value) if action.value else 2.0
                except ValueError:
                    seconds = 2.0
                await self._browser.wait(min(seconds, 10.0))

            elif action.action == ActionType.DONE:
                await self._handle_done(action, url, result, screenshots)

            elif action.action == ActionType.STUCK:
                await self._handle_stuck_action(action, url, result, screenshots)

        finally:
            self._recent_action_log.append(log_entry)
            if len(self._recent_action_log) > 5:
                self._recent_action_log = self._recent_action_log[-5:]

    # ------------------------------------------------------------------
    # DONE handler
    # ------------------------------------------------------------------

    async def _handle_done(
        self,
        action: AgentAction,
        url: str,
        result: SiteResult,
        screenshots: ScreenshotStore,
    ) -> None:
        """Handle the DONE action — state transition or wallet extraction."""

        if self._state == AgentState.EXTRACT_WALLETS:
            # LLM wallet data supersedes JS/opportunistic entries for matching addresses
            if action.value and result.wallets:
                logger.info("LLM wallet data — merging with %d existing", len(result.wallets))
                self._pre_llm_wallets = list(result.wallets)
                result.wallets.clear()
            else:
                self._pre_llm_wallets = []

            if action.value:
                try:
                    wallets_raw = json.loads(action.value)
                    if isinstance(wallets_raw, dict):
                        for key in ("wallets", "data", "addresses"):
                            if key in wallets_raw and isinstance(wallets_raw[key], list):
                                wallets_raw = wallets_raw[key]
                                break
                        else:
                            logger.warning("LLM dict but no wallet key: %s", list(wallets_raw.keys()))
                            wallets_raw = []
                    if isinstance(wallets_raw, list):
                        for w in wallets_raw:
                            try:
                                addr = w.get("wallet_address", "").strip()
                                if not addr:
                                    logger.warning("Skipping wallet with empty address from %s", url)
                                    continue
                                entry = WalletEntry(
                                    site_url=url,
                                    token_label=w.get("token_label", ""),
                                    token_symbol=w.get("token_symbol", ""),
                                    network_label=w.get("network_label", ""),
                                    network_short=w.get("network_short", ""),
                                    wallet_address=addr,
                                    run_id=self._run_id,
                                    source="llm",
                                    confidence=1.0 if w.get("network_short") else 0.7,
                                )
                                result.wallets.append(entry)
                                logger.info(
                                    "Wallet: %s %s — %s...",
                                    entry.token_symbol, entry.network_short,
                                    entry.wallet_address[:20],
                                )
                            except Exception as e:
                                logger.warning("Bad wallet entry %s: %s", w, e)
                except json.JSONDecodeError as e:
                    logger.error("Failed to parse wallet JSON: %s — %s", e, action.value[:200])

            # Preserve pre-LLM wallets not covered by LLM output
            if self._pre_llm_wallets:
                llm_addresses = {w.wallet_address for w in result.wallets}
                for pw in self._pre_llm_wallets:
                    if pw.wallet_address not in llm_addresses:
                        result.wallets.append(pw)
                        logger.info("Preserved opportunistic wallet: %s...", pw.wallet_address[:20])

            if not result.wallets:
                logger.warning("EXTRACT_WALLETS completed with ZERO wallets for %s", url)

            ss = await self._browser.screenshot_base64_full_res()
            await screenshots.capture_milestone(ss, f"wallets_{len(result.wallets)}")
            await self._transition(AgentState.COMPLETE)

        elif self._state == AgentState.FIND_REGISTER:
            await self._transition(AgentState.FILL_REGISTER)

        elif self._state == AgentState.FILL_REGISTER:
            await self._transition(AgentState.SUBMIT_REGISTER)

        elif self._state == AgentState.SUBMIT_REGISTER:
            await self._probe_for_visible_wallet(url, result)
            await self._transition(AgentState.CHECK_EMAIL_VERIFICATION)

        elif self._state == AgentState.CHECK_EMAIL_VERIFICATION:
            await self._probe_for_visible_wallet(url, result)
            await self._transition(AgentState.NAVIGATE_DEPOSIT)

        elif self._state == AgentState.NAVIGATE_DEPOSIT:
            await self._probe_for_visible_wallet(url, result)
            await self._transition(AgentState.EXTRACT_WALLETS)

        else:
            await self._transition(AgentState.COMPLETE)

    # ------------------------------------------------------------------
    # STUCK handlers
    # ------------------------------------------------------------------

    async def _handle_stuck_action(
        self,
        action: AgentAction,
        url: str,
        result: SiteResult,
        screenshots: ScreenshotStore,
    ) -> None:
        """Handle an explicit STUCK action from the LLM."""
        reasoning_lower = action.reasoning.lower()

        if "email verification" in reasoning_lower:
            result.status = SiteStatus.EMAIL_VERIFICATION_REQUIRED
            result.notes = action.reasoning
            logger.warning("Email verification required for %s", url)
            ss = await self._browser.screenshot_base64_full_res()
            await screenshots.capture_milestone(ss, "email_verification")
            self._state = AgentState.SKIPPED

        elif "referral" in reasoning_lower or "invitation code" in reasoning_lower:
            result.notes = action.reasoning
            logger.warning("Referral code required for %s", url)
            ss = await self._browser.screenshot_base64_full_res()
            await screenshots.capture_milestone(ss, "referral_code_required")

            referral_suggestions = [
                {"label": "Skip site", "action": "skip", "value": "", "description": "Referral code required"},
                {"label": "I have a code", "action": "type", "value": "", "description": "Type: field_selector|code"},
            ]
            guidance = await self._guidance.request_guidance(
                site_url=url,
                state=self._state.value,
                actions_taken=self._actions_in_state,
                threshold=0,
                screenshot_b64=ss,
                page_text_snippet=f"REFERRAL CODE NEEDED: {action.reasoning}",
                suggested_actions=referral_suggestions,
                current_url=await self._browser.get_page_url(),
            )

            if guidance.action == HumanAction.SKIP:
                result.status = SiteStatus.REFERRAL_CODE_REQUIRED
                result.skip_reason = guidance.reason or "Referral code required"
                self._state = AgentState.SKIPPED
            elif guidance.action == HumanAction.TYPE:
                field, _, text = guidance.value.partition("|")
                success, actual = await self._browser.type_text(field, text)
                if not success:
                    logger.error("Guided TYPE failed for field '%s'", field)
                elif actual != text:
                    logger.warning("Guided TYPE mismatch '%s': expected=%r actual=%r", field, text, actual)
            else:
                ss2 = await self._browser.screenshot_base64()
                llm_action = await self._analyzer.analyze_with_human_guidance(
                    screenshot_b64=ss2,
                    state=self._state.value,
                    human_instruction=guidance.value or "continue",
                    page_url=await self._browser.get_page_url(),
                )
                await self._execute_action(llm_action, url, result, screenshots)
        else:
            await self._handle_stuck(url, result, screenshots)
            self._actions_in_state = 0

    async def _handle_stuck(
        self,
        url: str,
        result: SiteResult,
        screenshots: ScreenshotStore,
    ) -> str | None:
        """Handle stuck detection (threshold-based) — request human guidance."""
        agent_cfg = self._settings.agent
        threshold = agent_cfg.stuck_thresholds.get(
            self._state.value, agent_cfg.stuck_thresholds.get("DEFAULT", 15)
        )

        ss = ""
        try:
            ss = await self._browser.screenshot_base64_full_res()
            await screenshots.capture_stuck(ss)
        except Exception as ss_err:
            logger.warning("Failed to capture stuck screenshot: %s", ss_err)

        page_text = await self._browser.get_page_text()
        stuck_context = self._build_stuck_context(page_text)
        suggested_actions = self._build_suggested_actions()
        current_url = await self._browser.get_page_url()

        guidance = await self._guidance.request_guidance(
            site_url=url,
            state=self._state.value,
            actions_taken=self._actions_in_state,
            threshold=threshold,
            screenshot_b64=ss,
            page_text_snippet=stuck_context,
            suggested_actions=suggested_actions,
            current_url=current_url,
        )

        return await self._apply_guidance(guidance, url, result, screenshots)

    async def _apply_guidance(
        self,
        guidance: GuidanceResponse,
        url: str,
        result: SiteResult,
        screenshots: ScreenshotStore,
    ) -> str | None:
        """Apply a GuidanceResponse (shared by stuck handling and interject)."""
        if guidance.action == HumanAction.SKIP:
            result.status = SiteStatus.SKIPPED
            result.skip_reason = guidance.reason
            self._state = AgentState.SKIPPED
            logger.info("Skipped %s: %s", url, guidance.reason)
            return None

        elif guidance.action == HumanAction.CLICK:
            direct = await self._browser.click(guidance.value)
            if direct:
                logger.info("Guided click succeeded: %s", guidance.value)
            else:
                logger.info("Direct click failed, falling back to LLM: %s", guidance.value)
                ss = await self._browser.screenshot_base64()
                llm_action = await self._analyzer.analyze_with_human_guidance(
                    screenshot_b64=ss,
                    state=self._state.value,
                    human_instruction=f"Click: {guidance.value}",
                    page_url=await self._browser.get_page_url(),
                )
                await self._execute_action(llm_action, url, result, screenshots)
            return "guided"

        elif guidance.action == HumanAction.TYPE:
            field, _, text = guidance.value.partition("|")
            success, actual = await self._browser.type_text(field, text)
            if not success:
                logger.error("Guided TYPE failed for '%s'", field)
            elif actual != text:
                logger.warning("Guided TYPE mismatch '%s': expected=%r actual=%r", field, text, actual)
            return "guided"

        elif guidance.action == HumanAction.GOTO:
            success = await self._browser.navigate(guidance.value)
            if not success:
                logger.error("Guided GOTO failed: %s", guidance.value)
            return "guided"

        elif guidance.action == HumanAction.CONTINUE:
            if guidance.value:
                self._human_instruction = guidance.value
                logger.info("CONTINUE with instruction: %s", guidance.value)
            return "continue"

        return None

    # ------------------------------------------------------------------
    # Batch fill
    # ------------------------------------------------------------------

    async def _step_fill_register_batch(
        self,
        url: str,
        result: SiteResult,
        screenshots: ScreenshotStore,
        screenshot_b64: str,
        page_text: str,
        page_url: str,
        extra_context: str,
    ) -> AgentAction | None:
        """Execute FILL_REGISTER using batch API: all fields in 1 call + 1 verification."""
        batch_actions = await self._analyzer.analyze_page_batch(
            screenshot_b64=screenshot_b64,
            state=self._state.value,
            page_text=page_text,
            page_url=page_url,
            extra_context=extra_context,
        )

        if self._analyzer.last_call_result:
            self._metrics.record_llm_call(
                state=self._state.value,
                input_tokens=self._analyzer.last_call_result.input_tokens,
                output_tokens=self._analyzer.last_call_result.output_tokens,
                action_type="batch_fill",
            )
        self._metrics.record_screenshot(
            state=self._state.value,
            size_bytes=int(len(screenshot_b64) * 3 / 4),
        )

        # Graceful degradation: if batch returns STUCK, fall to single-action mode
        if len(batch_actions) == 1 and batch_actions[0].action == ActionType.STUCK:
            logger.warning("FILL_REGISTER batch STUCK (%s) — single-action fallback", batch_actions[0].reasoning)
            action = await self._analyzer.analyze_page(
                screenshot_b64=screenshot_b64,
                state=self._state.value,
                page_text=page_text,
                page_url=page_url,
                extra_context=extra_context,
            )
            if self._analyzer.last_call_result:
                self._metrics.record_llm_call(
                    state=self._state.value,
                    input_tokens=self._analyzer.last_call_result.input_tokens,
                    output_tokens=self._analyzer.last_call_result.output_tokens,
                    action_type=action.action.value,
                )
            self._actions_in_state += 1
            self._total_actions += 1
            await self._execute_action(action, url, result, screenshots)
            return action

        # Execute all batch fill actions
        logger.info("FILL_REGISTER batch: executing %d actions", len(batch_actions))
        for i, batch_action in enumerate(batch_actions):
            logger.info("Batch %d/%d: %s → '%s'", i + 1, len(batch_actions), batch_action.selector[:50], (batch_action.value or "")[:40])
            await self._execute_action(batch_action, url, result, screenshots)
            self._actions_in_state += 1
            self._total_actions += 1

        # Verification: scroll to top, screenshot, and check for errors
        await self._browser.scroll_to_top()
        await asyncio.sleep(1)
        verify_ss = await self._browser.screenshot_base64()
        verify_text = await self._browser.get_page_text()
        verify_url = await self._browser.get_page_url()

        filled_summary = "; ".join(
            f"{a.selector[:30]}='{(a.value or '')[:20]}'"
            for a in batch_actions
            if a.action == ActionType.TYPE
        )
        verify_context = extra_context
        if filled_summary:
            verify_context += (
                f"\n\nBATCH FILL COMPLETED: Fields filled: {filled_summary}. "
                "Check for validation errors or missing fields. "
                "If everything looks good, signal 'done' to proceed to submission. "
                "Do NOT click the submit button — just signal 'done'."
            )

        verify_action = await self._analyzer.analyze_page(
            screenshot_b64=verify_ss,
            state=self._state.value,
            page_text=verify_text,
            page_url=verify_url,
            extra_context=verify_context,
        )

        if self._analyzer.last_call_result:
            self._metrics.record_llm_call(
                state=self._state.value,
                input_tokens=self._analyzer.last_call_result.input_tokens,
                output_tokens=self._analyzer.last_call_result.output_tokens,
                action_type=verify_action.action.value,
            )
        self._metrics.record_screenshot(
            state=self._state.value,
            size_bytes=int(len(verify_ss) * 3 / 4),
        )

        self._actions_in_state += 1
        self._total_actions += 1

        await self._execute_action(verify_action, url, result, screenshots)
        return verify_action

    # ------------------------------------------------------------------
    # DOM Inspection
    # ------------------------------------------------------------------

    async def _try_dom_inspection(self, extra_context: str) -> tuple[AgentAction | None, str]:
        """Pre-LLM DOM inspection hook.

        Returns ``(direct_action, updated_extra_context)``.
        ``direct_action`` is non-None when DOM confidence >= direct threshold.
        """
        scan_type = _STATE_SCAN_TYPE.get(self._state)
        if not scan_type:
            return None, extra_context

        t0 = time.monotonic()
        scan_data = await self._browser.run_dom_scan(scan_type)
        scan_ms = (time.monotonic() - t0) * 1000

        if not scan_data:
            logger.debug("DOM scan empty for %s", self._state.value)
            return None, extra_context

        inspection = self._dom_inspector.inspect(self._state.value, scan_data, scan_ms)

        self._metrics.record_dom_inspection(state=self._state.value, outcome=inspection.outcome)

        if inspection.outcome == "direct" and inspection.direct_action is not None:
            logger.info(
                "DOM direct [%s] conf=%d: %s → '%s' (%.0fms)",
                self._state.value, inspection.confidence,
                inspection.direct_action.action.value,
                inspection.direct_action.selector[:60], scan_ms,
            )
            return inspection.direct_action, extra_context

        if inspection.outcome == "assisted" and inspection.context_summary:
            logger.info(
                "DOM assisted [%s] conf=%d — injecting %d chars (%.0fms)",
                self._state.value, inspection.confidence,
                len(inspection.context_summary), scan_ms,
            )
            extra_context += f"\n\n{inspection.context_summary}"
            return None, extra_context

        logger.debug("DOM fallback [%s] conf=%d (%.0fms)", self._state.value, inspection.confidence, scan_ms)
        return None, extra_context

    # ------------------------------------------------------------------
    # Wallet extraction helpers
    # ------------------------------------------------------------------

    async def _probe_for_visible_wallet(self, url: str, result: SiteResult) -> None:
        """Opportunistic wallet capture during state transitions."""
        try:
            address = await self._browser.extract_wallet_address()
            if address and address not in {w.wallet_address for w in result.wallets}:
                entry = WalletEntry(
                    site_url=url,
                    token_label="", token_symbol="",
                    network_label="", network_short="",
                    wallet_address=address,
                    run_id=self._run_id,
                    source="opportunistic",
                    confidence=0.3,
                )
                result.wallets.append(entry)
                logger.info("Opportunistic wallet (%s): %s...", self._state.value, address[:20])
        except Exception as e:
            logger.debug("Opportunistic wallet probe failed: %s", e)

    async def _try_js_wallet_extraction(self, url: str, result: SiteResult) -> list[WalletEntry]:
        """JS-based wallet extraction by discovering and clicking coin options."""
        wallets_found: list[WalletEntry] = []

        # Extract any wallet already visible
        current_address = await self._browser.extract_wallet_address()
        if current_address and current_address not in {w.wallet_address for w in result.wallets}:
            entry = WalletEntry(
                site_url=url, token_label="", token_symbol="",
                network_label="", network_short="",
                wallet_address=current_address, run_id=self._run_id,
                source="js", confidence=0.5,
            )
            wallets_found.append(entry)
            result.wallets.append(entry)
            logger.info("JS pre-extracted visible wallet: %s...", current_address[:20])

        # Discover coin tabs/buttons
        discovered = await self._browser.discover_crypto_selectors()
        if not discovered:
            if wallets_found:
                logger.info("JS discovery: nothing extra — %d from pre-extraction", len(wallets_found))
            else:
                logger.info("JS discovery: nothing found — LLM will handle extraction")
            return wallets_found

        logger.info("JS discovery: %d options — extracting", len(discovered))

        for option in discovered:
            clicked = await self._browser.click_crypto_option(option)
            if not clicked:
                continue
            await self._browser.wait(1.5)

            address = await self._browser.extract_wallet_address()
            seen = {w.wallet_address for w in result.wallets} | {w.wallet_address for w in wallets_found}
            if address and address not in seen:
                entry = WalletEntry(
                    site_url=url,
                    token_label=option.get("label", ""),
                    token_symbol=option.get("symbol", ""),
                    network_label="", network_short="",
                    wallet_address=address, run_id=self._run_id,
                    source="js", confidence=0.5,
                )
                wallets_found.append(entry)
                result.wallets.append(entry)
                logger.info("JS wallet: %s — %s...", entry.token_symbol, entry.wallet_address[:20])

        logger.info("JS extraction complete: %d wallets", len(wallets_found))
        return wallets_found

    # ------------------------------------------------------------------
    # State context builder
    # ------------------------------------------------------------------

    async def _build_state_context(self) -> str:
        """Build extra context for the LLM based on the current state."""
        parts: list[str] = []

        if self._state in (AgentState.FILL_REGISTER, AgentState.SUBMIT_REGISTER):
            if not self._identity:
                identity_obj = self._identity_vault.generate()
                self._identity = identity_obj.to_dict()

            if self._identity:
                # In SUBMIT_REGISTER with a tracked password, omit password_variants
                if self._state == AgentState.SUBMIT_REGISTER and self._last_password_used:
                    identity_display = {
                        k: v for k, v in self._identity.items() if k != "password_variants"
                    }
                else:
                    identity_display = self._identity
                parts.append(
                    "Use this identity to fill the registration form:\n"
                    + json.dumps(identity_display, indent=2)
                    + "\n\nPASSWORD SELECTION — read each field's placeholder text:\n"
                    "- Default: use 'default' variant when no specific format is indicated\n"
                    "- Placeholder says 'digits only' or 'N digits' → use digits_8 or digits_12\n"
                    "- Placeholder says max length (e.g., '7-15 characters') → use simple_10\n"
                    "- Error after submission says specific requirements → switch variant\n"
                    "IMPORTANT: Different password fields may have DIFFERENT requirements. "
                    "Check EACH field's placeholder independently.\n"
                    "Use the SAME password for password + confirm password pairs."
                )

            if self._state == AgentState.FILL_REGISTER:
                parts.append(
                    "WORKFLOW: Type directly into visible fields — do NOT click fields before typing, "
                    "do NOT scroll to survey the form. Fill what you can see, then signal 'done'. "
                    "If a referral/invitation code is REQUIRED and cannot be left blank, "
                    "respond with action 'stuck' and include 'referral code' in your reasoning."
                )

            if self._state == AgentState.SUBMIT_REGISTER:
                if self._last_password_used:
                    parts.append(
                        f"PASSWORD FOR THIS REGISTRATION: {self._last_password_used}\n"
                        "Use this EXACT password for login password and confirm field. "
                        "Do NOT switch variant unless an error explicitly says format is wrong."
                    )
                field_status = await self._browser.get_form_field_values()
                if field_status:
                    parts.append(field_status)
                    parts.append(
                        "IMPORTANT: Field status above shows ACTUAL DOM values. "
                        "Fields with values are already filled — do NOT re-type them. "
                        "Only fill fields marked EMPTY or [DEFAULT - needs selection]. "
                        "If ALL fields are EMPTY, the form cleared on failure — re-fill everything.\n"
                        "SELECTOR TIP: If a field has an opaque ID (e.g., el-id-*), use "
                        'placeholder text: input[placeholder="..."]'
                    )

        if self._state == AgentState.EXTRACT_WALLETS:
            parts.append(
                "Extract ALL cryptocurrency wallet addresses visible on this page. "
                "If there are tabs/buttons for different cryptos (BTC, ETH, USDT, etc.), "
                "click each to reveal its wallet address. Include token name/symbol and network. "
                "When done, use action 'done' with wallet data as JSON in 'value'."
            )

        if self._state == AgentState.CHECK_EMAIL_VERIFICATION:
            parts.append(
                "Check if the site requires email verification. "
                "Look for messages about checking email, verification links, or confirmation codes. "
                "If email verification IS required, respond with action 'stuck' and explain. "
                "If no verification needed (dashboard visible, can navigate), signal 'done'."
            )

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Stuck context helpers
    # ------------------------------------------------------------------

    def _build_stuck_context(self, page_text: str = "") -> str:
        """Build context summary for human guidance when agent is stuck."""
        objectives = {
            "FIND_REGISTER": "Finding the registration page/form",
            "FILL_REGISTER": "Filling registration form fields",
            "SUBMIT_REGISTER": "Submitting the registration form",
            "CHECK_EMAIL_VERIFICATION": "Checking for email verification",
            "NAVIGATE_DEPOSIT": "Finding the deposit/invest page",
            "EXTRACT_WALLETS": "Extracting cryptocurrency wallet addresses",
        }
        parts: list[str] = []

        objective = objectives.get(self._state.value, self._state.value)
        parts.append(f"OBJECTIVE: {objective}")

        if self._recent_action_log:
            parts.append("RECENT ACTIONS:")
            for entry in self._recent_action_log[-5:]:
                status = "OK" if entry.get("success", True) else "FAILED"
                line = f"  [{status}] {entry['action']}"
                if entry.get("selector"):
                    line += f" → {entry['selector']}"
                if entry.get("reasoning"):
                    line += f" ({entry['reasoning']})"
                parts.append(line)

        if self._type_mismatches:
            parts.append("UNRESOLVED TYPE ISSUES:")
            for m in self._type_mismatches:
                parts.append(f"  {m}")

        if page_text:
            parts.append(f"PAGE TEXT: {page_text[:500]}")

        return "\n".join(parts)

    def _build_suggested_actions(self) -> list[dict]:
        """Build state-aware suggested guidance actions for the human operator."""
        suggestions: list[dict] = []
        is_blank = self._blank_page_retries > 0

        if is_blank:
            suggestions.append({
                "label": "Wait longer", "action": "continue", "value": "",
                "description": "Page may still be loading",
            })

        if self._state == AgentState.FIND_REGISTER:
            if is_blank:
                suggestions.append({"label": "Reload page", "action": "goto", "value": "__current_url__", "description": "Reload the current page"})
            else:
                suggestions.append({"label": "Click Register/Sign Up", "action": "click", "value": "Register", "description": "Click a visible register link"})
                suggestions.append({"label": "Go to /register", "action": "goto", "value": "/register", "description": "Navigate to /register"})

        elif self._state == AgentState.FILL_REGISTER:
            if self._type_mismatches:
                suggestions.append({"label": "Retry form fill", "action": "continue", "value": "", "description": "Clear mismatched fields and retry"})
            suggestions.append({"label": "Change password", "action": "continue", "value": "", "description": "Password may not meet requirements"})
            suggestions.append({"label": "Skip optional fields", "action": "continue", "value": "", "description": "Submit with only required fields"})

        elif self._state == AgentState.SUBMIT_REGISTER:
            suggestions.append({"label": "Fix password", "action": "continue", "value": "", "description": "Password format may be wrong"})
            suggestions.append({"label": "Fix email/username", "action": "continue", "value": "", "description": "Email or username may be invalid"})
            suggestions.append({"label": "Click submit", "action": "click", "value": "Submit", "description": "Try clicking submit button"})

        elif self._state == AgentState.NAVIGATE_DEPOSIT:
            suggestions.append({"label": "Click Deposit", "action": "click", "value": "Deposit", "description": "Click a visible deposit button"})
            suggestions.append({"label": "Go to /deposit", "action": "goto", "value": "/deposit", "description": "Navigate to /deposit"})

        elif self._state == AgentState.EXTRACT_WALLETS:
            suggestions.append({"label": "Click next crypto tab", "action": "continue", "value": "", "description": "More crypto tabs may be available"})
            suggestions.append({"label": "All wallets found", "action": "continue", "value": "", "description": "No more wallets — proceed"})

        if not any(s["label"] == "Wait longer" for s in suggestions):
            suggestions.insert(0, {"label": "Continue", "action": "continue", "value": "", "description": "Let agent retry"})

        return suggestions

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    async def _transition(self, new_state: AgentState) -> None:
        """Transition to a new state, resetting per-state counters."""
        agent_cfg = self._settings.agent
        allowed = STATE_TRANSITIONS.get(self._state, [])

        if allowed and new_state not in allowed and new_state not in TERMINAL_STATES:
            logger.warning(
                "Non-standard transition: %s → %s (allowed: %s)",
                self._state.value, new_state.value, [s.value for s in allowed],
            )
        old_state = self._state.value

        # Record state timing
        if self._state_entered_at > 0:
            duration = time.monotonic() - self._state_entered_at
            self._metrics.record_state_timing(old_state, self._actions_in_state, duration)

        logger.info("State: %s → %s", old_state, new_state.value)
        self._state = new_state
        self._state_entered_at = time.monotonic()
        self._actions_in_state = 0
        self._last_actions = []
        self._consecutive_noop_scrolls = 0
        self._type_mismatches = []
        self._blank_page_retries = 0
        self._last_screenshot_hash = ""
        self._consecutive_dupes = 0
        self._js_wallets_found = False
        self._skip_dom_direct = False
        # NOTE: do NOT reset _human_instruction — may persist across transitions

        # Dismiss overlays on state entry
        if agent_cfg.overlay_dismiss_enabled and new_state not in TERMINAL_STATES:
            removed = await self._browser.dismiss_overlays()
            if removed:
                self._metrics.record_overlay_dismissal(removed)

        await self._emit("state_changed", {"old_state": old_state, "new_state": new_state.value})

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    async def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event to the optional callback."""
        if self._event_cb:
            try:
                await self._event_cb.on_event(event_type, data)
            except Exception as e:
                logger.debug("Event callback error (%s): %s", event_type, e)
