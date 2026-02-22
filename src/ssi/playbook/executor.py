"""Playbook executor — run deterministic step sequences against the browser.

The executor takes a ``Playbook``, a ``ZenBrowserManager``, and a
``SyntheticIdentity`` and executes each step in order. Template variables
in step values (e.g., ``{identity.email}``) are resolved against the
identity dict before execution.

Features:

* **Per-step retry**: Each step declares ``retry_on_failure`` attempts.
* **LLM fallback**: If a step fails and ``fallback_to_llm`` is ``True``,
  control is handed back to the caller (typically ``AgentController``)
  to continue with vision-based LLM analysis.
* **Time budget**: The ``Playbook.max_duration_sec`` is enforced.
* **Template resolution**: ``{identity.*}`` and ``{password_variants.*}``
  placeholders are expanded from the synthetic identity.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone

from ssi.browser.zen_manager import ZenBrowserManager
from ssi.identity.vault import SyntheticIdentity
from ssi.playbook.models import (
    Playbook,
    PlaybookResult,
    PlaybookStep,
    PlaybookStepResult,
    PlaybookStepType,
)

logger = logging.getLogger(__name__)

# Regex for template variables: {identity.email}, {password_variants.digits_8}, etc.
_TEMPLATE_RE = re.compile(r"\{(\w+(?:\.\w+)*)\}")


def resolve_template(
    template: str,
    identity: SyntheticIdentity,
) -> str:
    """Resolve template variables in a string.

    Supported namespaces:

    * ``{identity.<field>}`` — any field on ``SyntheticIdentity``
    * ``{password_variants.<variant>}`` — e.g., ``{password_variants.digits_8}``

    Unresolved placeholders are left as-is and logged as warnings.

    Args:
        template: The string potentially containing ``{…}`` placeholders.
        identity: The synthetic identity to resolve against.

    Returns:
        The string with all resolvable placeholders replaced.
    """
    if "{" not in template:
        return template

    identity_dict = identity.to_dict()
    password_variants = identity_dict.get("password_variants", {})

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)

        # {identity.email} → identity_dict["email"]
        if key.startswith("identity."):
            field = key[len("identity."):]
            value = identity_dict.get(field)
            if value is not None:
                return str(value)
            logger.warning("Unresolved template variable: %s", key)
            return match.group(0)

        # {password_variants.digits_8} → password_variants["digits_8"]
        if key.startswith("password_variants."):
            variant = key[len("password_variants."):]
            value = password_variants.get(variant)
            if value is not None:
                return str(value)
            logger.warning("Unresolved password variant: %s", variant)
            return match.group(0)

        # Direct field lookup (shorthand: {email} → identity_dict["email"])
        value = identity_dict.get(key)
        if value is not None:
            return str(value)

        logger.warning("Unresolved template variable: %s", key)
        return match.group(0)

    return _TEMPLATE_RE.sub(_replace, template)


class PlaybookExecutor:
    """Executes a playbook's steps sequentially against the browser.

    Args:
        browser: The zendriver browser manager instance.
        identity: The synthetic identity for template variable resolution.
    """

    def __init__(
        self,
        browser: ZenBrowserManager,
        identity: SyntheticIdentity,
    ) -> None:
        self._browser = browser
        self._identity = identity

    async def execute(self, playbook: Playbook, url: str) -> PlaybookResult:
        """Execute all steps in the playbook.

        Args:
            playbook: The playbook to execute.
            url: The target site URL (for the result record).

        Returns:
            A ``PlaybookResult`` with per-step outcomes.
        """
        result = PlaybookResult(
            playbook_id=playbook.playbook_id,
            url=url,
            success=False,
            total_steps=len(playbook.steps),
            started_at=datetime.now(timezone.utc),
        )

        start_time = time.monotonic()
        deadline = start_time + playbook.max_duration_sec

        for idx, step in enumerate(playbook.steps):
            # --- Time budget check ---
            elapsed = time.monotonic() - start_time
            if time.monotonic() >= deadline:
                result.error = (
                    f"Time budget exceeded at step {idx + 1}/{len(playbook.steps)} "
                    f"after {elapsed:.1f}s (budget: {playbook.max_duration_sec}s)"
                )
                logger.warning("Playbook %s: %s", playbook.playbook_id, result.error)
                if playbook.fallback_to_llm:
                    result.fell_back_to_llm = True
                    result.fallback_reason = "Time budget exceeded"
                break

            # --- Resolve template variables ---
            resolved_value = resolve_template(step.value, self._identity)
            resolved_selector = resolve_template(step.selector, self._identity)

            # --- Execute step with retries ---
            step_result = await self._execute_step(
                idx, step, resolved_selector, resolved_value,
            )
            result.step_results.append(step_result)

            if step_result.success:
                result.completed_steps += 1
                continue

            # --- Step failed ---
            logger.warning(
                "Playbook %s: step %d/%d failed — %s %s: %s",
                playbook.playbook_id,
                idx + 1,
                len(playbook.steps),
                step.action.value,
                resolved_selector[:60],
                step_result.error,
            )

            if step.fallback_to_llm:
                result.fell_back_to_llm = True
                result.fallback_reason = (
                    f"Step {idx + 1} ({step.action.value} "
                    f"{resolved_selector[:40]}) failed: {step_result.error}"
                )
                logger.info(
                    "Playbook %s: falling back to LLM from step %d",
                    playbook.playbook_id,
                    idx + 1,
                )
                break

            # Step failed, no fallback — abort the playbook
            result.error = (
                f"Step {idx + 1} failed without fallback: "
                f"{step.action.value} {resolved_selector[:40]}"
            )
            break
        else:
            # All steps completed successfully
            result.success = True

        result.duration_sec = time.monotonic() - start_time
        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            "Playbook %s: %s (%d/%d steps in %.1fs)%s",
            playbook.playbook_id,
            "SUCCESS" if result.success else "FAILED",
            result.completed_steps,
            result.total_steps,
            result.duration_sec,
            " → LLM fallback" if result.fell_back_to_llm else "",
        )
        return result

    # ------------------------------------------------------------------
    # Step execution
    # ------------------------------------------------------------------

    async def _execute_step(
        self,
        index: int,
        step: PlaybookStep,
        selector: str,
        value: str,
    ) -> PlaybookStepResult:
        """Execute a single step with retry logic.

        Args:
            index: Zero-based step index.
            step: The playbook step definition.
            selector: Resolved CSS selector / text label.
            value: Resolved value (text to type, URL to navigate, etc.).

        Returns:
            A ``PlaybookStepResult`` recording success/failure and attempts.
        """
        max_attempts = 1 + step.retry_on_failure
        step_start = time.monotonic()
        last_error = ""

        for attempt in range(1, max_attempts + 1):
            try:
                success = await self._dispatch_action(step.action, selector, value)
                if success:
                    return PlaybookStepResult(
                        step_index=index,
                        action=step.action,
                        selector=selector,
                        value=_redact(value, step.action),
                        success=True,
                        attempts=attempt,
                        duration_sec=time.monotonic() - step_start,
                    )
                last_error = f"{step.action.value} returned False"
            except Exception as exc:
                last_error = str(exc)
                logger.debug(
                    "Step %d attempt %d/%d error: %s",
                    index + 1, attempt, max_attempts, exc,
                )

            # Wait before retry (progressive backoff: 1s, 2s, 3s, …)
            if attempt < max_attempts:
                await asyncio.sleep(min(attempt, 3))

        return PlaybookStepResult(
            step_index=index,
            action=step.action,
            selector=selector,
            value=_redact(value, step.action),
            success=False,
            attempts=max_attempts,
            error=last_error,
            duration_sec=time.monotonic() - step_start,
        )

    async def _dispatch_action(
        self,
        action: PlaybookStepType,
        selector: str,
        value: str,
    ) -> bool:
        """Dispatch a playbook step to the appropriate browser method.

        Args:
            action: The step action type.
            selector: CSS selector or text label.
            value: Action-specific value.

        Returns:
            ``True`` if the action succeeded.
        """
        if action == PlaybookStepType.CLICK:
            return await self._browser.click(selector)

        if action == PlaybookStepType.TYPE:
            success, _actual = await self._browser.type_text(selector, value)
            return success

        if action == PlaybookStepType.SELECT:
            return await self._browser.select_option(selector, value)

        if action == PlaybookStepType.NAVIGATE:
            return await self._browser.navigate(value)

        if action == PlaybookStepType.WAIT:
            try:
                seconds = float(value) if value else 2.0
            except ValueError:
                seconds = 2.0
            await self._browser.wait(min(seconds, 10.0))
            return True

        if action == PlaybookStepType.SCROLL:
            try:
                pixels = int(value) if value else 500
            except ValueError:
                pixels = 500
            await self._browser.scroll_down(pixels)
            return True

        if action == PlaybookStepType.EXTRACT:
            # Extract wallet addresses — always succeeds (may find 0 wallets)
            await self._browser.extract_wallet_address()
            return True

        logger.warning("Unknown playbook action: %s", action)
        return False


def _redact(value: str, action: PlaybookStepType) -> str:
    """Redact sensitive values (passwords, credit cards) in results.

    Args:
        value: The original value.
        action: The step action type.

    Returns:
        The value with sensitive content masked.
    """
    if not value:
        return value
    if action == PlaybookStepType.TYPE and len(value) > 4:
        # Simple heuristic: mask anything that looks like it could be PII typed in
        return value[:2] + "***" + value[-2:]
    return value
