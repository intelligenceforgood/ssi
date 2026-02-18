"""AI browser interaction agent.

The core agent loop: observe page → ask LLM → execute action → record step.
This is the Phase 0 research-spike deliverable — validating that an LLM
can reliably navigate scam site funnels via Playwright.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ssi.browser.actions import execute_action
from ssi.browser.dom_extractor import extract_page_observation
from ssi.browser.downloads import DownloadInterceptor
from ssi.browser.llm_client import AgentLLMClient
from ssi.identity.vault import IdentityVault, SyntheticIdentity
from ssi.models.agent import (
    ActionType,
    AgentMetrics,
    AgentSession,
    AgentStep,
)

logger = logging.getLogger(__name__)

# Terminal action types that end the agent loop
_TERMINAL_ACTIONS = {ActionType.DONE, ActionType.FAIL}

# Default budget / limits
_DEFAULT_MAX_STEPS = 20
_DEFAULT_TOKEN_BUDGET = 50_000


class BrowserAgent:
    """LLM-powered browser interaction agent.

    Navigates a target URL using Playwright, making decisions via an
    Ollama LLM at each step.  Records every observation and action for
    forensic evidence.

    Args:
        llm_client: Configured LLM client for action decisions.
        identity: Synthetic identity for form filling.
        max_steps: Maximum number of interaction steps.
        token_budget: Maximum total tokens (input + output) before stopping.
        output_dir: Directory for screenshots and session artifacts.
    """

    def __init__(
        self,
        llm_client: AgentLLMClient | None = None,
        identity: SyntheticIdentity | None = None,
        max_steps: int = _DEFAULT_MAX_STEPS,
        token_budget: int = _DEFAULT_TOKEN_BUDGET,
        output_dir: Path | None = None,
    ) -> None:
        from ssi.settings import get_settings

        settings = get_settings()

        self.llm = llm_client or AgentLLMClient.from_settings()
        self.identity = identity or IdentityVault(locale=settings.identity.default_locale).generate()
        self.max_steps = max_steps
        self.token_budget = token_budget or settings.llm.token_budget_per_session
        self.output_dir = output_dir

        self._session = AgentSession(identity_id=self.identity.identity_id)
        self._history: list[dict[str, str]] = []
        self._tokens_used = 0

    @property
    def session(self) -> AgentSession:
        """Return the current session record."""
        return self._session

    def run(self, url: str) -> AgentSession:
        """Execute the full agent loop against the target URL.

        Args:
            url: The suspicious URL to investigate interactively.

        Returns:
            An ``AgentSession`` recording all steps, metrics, and artifacts.
        """
        from playwright.sync_api import sync_playwright

        from ssi.browser.stealth import ProxyPool, apply_stealth_scripts, build_browser_profile
        from ssi.settings import get_settings

        settings = get_settings()
        self._session.url = url

        total_start = time.monotonic()

        # Ensure output directory exists
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        with sync_playwright() as pw:
            # Build stealth-aware browser profile
            proxy_pool = ProxyPool(settings.stealth.proxy_urls) if settings.stealth.proxy_urls else None
            har_path = str(self.output_dir / "agent_session.har") if (settings.browser.record_har and self.output_dir) else None
            video_dir = str(self.output_dir / "video") if (settings.browser.record_video and self.output_dir) else None

            profile = build_browser_profile(
                headless=settings.browser.headless,
                proxy_pool=proxy_pool,
                explicit_proxy=settings.browser.proxy or None,
                explicit_user_agent=settings.browser.user_agent or None,
                randomize_fingerprint=settings.stealth.randomize_fingerprint,
                record_har_path=har_path,
                record_video_dir=video_dir,
            )

            browser = pw.chromium.launch(**profile.launch_args)
            context = browser.new_context(**profile.context_args)
            page = context.new_page()

            # Apply anti-detection stealth scripts
            if settings.stealth.apply_stealth_scripts:
                apply_stealth_scripts(page)

            # Attach download interceptor for malware capture
            downloads_dir = self.output_dir / "downloads" if self.output_dir else Path("/tmp/ssi-downloads")
            self._download_interceptor = DownloadInterceptor(
                output_dir=downloads_dir,
                check_virustotal=bool(settings.osint.virustotal_api_key),
            )
            self._download_interceptor.attach(page)

            try:
                # Initial navigation
                logger.info("Agent navigating to %s", url)
                page.goto(url, wait_until="networkidle", timeout=settings.browser.timeout_ms)

                # Check for CAPTCHA before agent loop
                from ssi.browser.captcha import CaptchaStrategy, detect_captcha, handle_captcha

                captcha_detection = detect_captcha(page)
                if captcha_detection.detected:
                    logger.info("CAPTCHA detected: %s", captcha_detection.captcha_type.value)
                    captcha_strategy = CaptchaStrategy(settings.captcha.strategy)
                    captcha_result = handle_captcha(
                        page,
                        captcha_detection,
                        strategy=captcha_strategy,
                        wait_seconds=settings.captcha.wait_seconds,
                        screenshot_dir=self.output_dir,
                    )
                    if not captcha_result.bypassed:
                        logger.warning("CAPTCHA not bypassed — agent may encounter issues")

                self._session.pages_visited.append(page.url)

                # --- Main agent loop ---
                for step_num in range(self.max_steps):
                    step = self._execute_step(page, step_num)
                    self._session.steps.append(step)

                    # Track pages visited
                    current_url = page.url
                    if current_url not in self._session.pages_visited:
                        self._session.pages_visited.append(current_url)

                    # Check termination conditions
                    if step.action.action_type in _TERMINAL_ACTIONS:
                        logger.info(
                            "Agent terminated at step %d: %s — %s",
                            step_num,
                            step.action.action_type.value,
                            step.action.reasoning,
                        )
                        self._session.metrics.termination_reason = (
                            f"{step.action.action_type.value}: {step.action.reasoning}"
                        )
                        break

                    if self._tokens_used >= self.token_budget:
                        logger.warning("Token budget exhausted (%d/%d)", self._tokens_used, self.token_budget)
                        self._session.metrics.termination_reason = "token_budget_exhausted"
                        break

                    if step.error:
                        logger.warning("Step %d had error: %s", step_num, step.error)
                        # Continue — the agent can try to recover

                else:
                    self._session.metrics.termination_reason = "max_steps_reached"

            except Exception as e:
                logger.exception("Agent session failed: %s", e)
                self._session.metrics.termination_reason = f"exception: {e}"

            finally:
                # Capture downloads from interceptor
                if hasattr(self, "_download_interceptor"):
                    self._session.captured_downloads = [d.to_dict() for d in self._download_interceptor.downloads]
                context.close()
                browser.close()

        # Finalize metrics
        total_ms = (time.monotonic() - total_start) * 1000
        self._session.metrics = self._compute_metrics(total_ms)

        # Save session record
        if self.output_dir:
            self._save_session()

        return self._session

    def _execute_step(self, page, step_number: int) -> AgentStep:
        """Run a single observe → decide → act cycle.

        Args:
            page: Playwright page object.
            step_number: Current step counter.

        Returns:
            A populated ``AgentStep``.
        """
        step_start = time.monotonic()

        # 1. Observe the current page state
        observation = extract_page_observation(page, self.output_dir, step_number)

        # 2. Ask the LLM what to do
        llm_start = time.monotonic()
        try:
            llm_response = self.llm.decide_action(
                observation=observation,
                identity=self.identity,
                history=self._history,
            )
        except Exception as e:
            logger.error("LLM call failed at step %d: %s", step_number, e)
            from ssi.models.agent import AgentAction

            return AgentStep(
                step_number=step_number,
                observation=observation,
                action=AgentAction(action_type=ActionType.FAIL, reasoning=f"LLM error: {e}"),
                screenshot_before=observation.screenshot_path,
                error=str(e),
            )

        llm_ms = (time.monotonic() - llm_start) * 1000

        action = llm_response.action
        self._tokens_used += llm_response.input_tokens + llm_response.output_tokens

        # Update conversation history for context continuity
        self._history.append({"role": "user", "content": observation.dom_summary})
        self._history.append({"role": "assistant", "content": llm_response.raw_response})

        # Trim history to last 6 exchanges to manage context window
        if len(self._history) > 12:
            self._history = self._history[-12:]

        # 3. Execute the action
        browser_start = time.monotonic()
        exec_result = ""
        error = ""
        if action.action_type not in _TERMINAL_ACTIONS:
            try:
                exec_result = execute_action(page, action, observation.interactive_elements)
            except Exception as e:
                error = str(e)
                logger.warning("Action execution error at step %d: %s", step_number, e)
        browser_ms = (time.monotonic() - browser_start) * 1000

        # Track which PII fields were submitted
        if action.action_type == ActionType.TYPE and action.value:
            self._track_pii_submission(action.value)

        # Screenshot after action
        screenshot_after = ""
        if self.output_dir and action.action_type not in _TERMINAL_ACTIONS:
            try:
                after_path = self.output_dir / f"step_{step_number:03d}_after.png"
                page.screenshot(path=str(after_path), full_page=False)
                screenshot_after = str(after_path)
            except Exception:
                pass

        step_ms = (time.monotonic() - step_start) * 1000

        logger.info(
            "Step %d: %s (element=%s, value=%s) — LLM: %.0fms, Browser: %.0fms, Tokens: +%d/%d",
            step_number,
            action.action_type.value,
            action.element_index,
            action.value[:30] if action.value else "",
            llm_ms,
            browser_ms,
            llm_response.input_tokens + llm_response.output_tokens,
            self._tokens_used,
        )

        return AgentStep(
            step_number=step_number,
            observation=observation,
            action=action,
            screenshot_before=observation.screenshot_path,
            screenshot_after=screenshot_after,
            duration_ms=step_ms,
            input_tokens=llm_response.input_tokens,
            output_tokens=llm_response.output_tokens,
            error=error,
        )

    def _track_pii_submission(self, value: str) -> None:
        """Record which PII fields were typed into forms."""
        identity = self.identity
        pii_map = {
            identity.first_name: "first_name",
            identity.last_name: "last_name",
            identity.email: "email",
            identity.phone: "phone",
            identity.street_address: "street_address",
            identity.city: "city",
            identity.state: "state",
            identity.zip_code: "zip_code",
            identity.date_of_birth: "date_of_birth",
            identity.ssn: "ssn",
            identity.credit_card_number: "credit_card_number",
            identity.credit_card_cvv: "credit_card_cvv",
            identity.username: "username",
            identity.password: "password",
        }
        for pii_value, field_name in pii_map.items():
            if pii_value and pii_value in value and field_name not in self._session.pii_fields_submitted:
                self._session.pii_fields_submitted.append(field_name)

    def _compute_metrics(self, total_ms: float) -> AgentMetrics:
        """Aggregate metrics from all steps."""
        steps = self._session.steps
        completed = any(s.action.action_type == ActionType.DONE for s in steps)
        failed = any(s.action.action_type == ActionType.FAIL for s in steps)

        return AgentMetrics(
            total_steps=len(steps),
            total_input_tokens=sum(s.input_tokens for s in steps),
            total_output_tokens=sum(s.output_tokens for s in steps),
            total_llm_latency_ms=sum(s.duration_ms for s in steps),  # Approximate
            total_browser_latency_ms=0.0,  # Tracked separately if needed
            total_duration_ms=total_ms,
            budget_remaining=self.token_budget - self._tokens_used,
            completed_successfully=completed and not failed,
            termination_reason=self._session.metrics.termination_reason,
        )

    def _save_session(self) -> None:
        """Persist the session record to disk."""
        if not self.output_dir:
            return
        session_path = self.output_dir / "agent_session.json"
        try:
            # Convert dataclass tree to JSON-safe dict
            data = self._session.to_dict()
            # UUIDs need string conversion
            session_path.write_text(json.dumps(data, indent=2, default=str))
            logger.info("Agent session saved to %s", session_path)
        except Exception as e:
            logger.warning("Failed to save agent session: %s", e)
