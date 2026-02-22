"""Playwright action executor for the AI agent.

Translates ``AgentAction`` decisions into real browser interactions.
Each action is performed with realistic timing (random delays) to
reduce anti-bot detection risk.
"""

from __future__ import annotations

import logging
import random
import time
from typing import TYPE_CHECKING

from ssi.models.agent import ActionType, AgentAction, InteractiveElement

if TYPE_CHECKING:
    from playwright.sync_api import Page

logger = logging.getLogger(__name__)

# Realistic human-like typing delay range (ms per character)
_TYPE_DELAY_MIN = 30
_TYPE_DELAY_MAX = 90

# Pause before/after actions (ms)
_PRE_ACTION_DELAY = (200, 600)
_POST_ACTION_DELAY = (300, 800)


def execute_action(
    page: Page,
    action: AgentAction,
    elements: list[InteractiveElement],
) -> str:
    """Execute a single agent action on the Playwright page.

    Args:
        page: Playwright ``Page`` object.
        action: The action to execute.
        elements: List of interactive elements from the current observation.

    Returns:
        A short human-readable description of what happened.
    """
    if action.action_type in (ActionType.DONE, ActionType.FAIL):
        return f"Agent signalled: {action.action_type.value}"

    # Small pre-action delay for realism
    _human_delay(*_PRE_ACTION_DELAY)

    try:
        result = _dispatch_action(page, action, elements)
    except Exception as e:
        logger.warning("Action execution failed: %s", e)
        return f"ERROR: {e}"

    # Post-action delay + wait for network settle
    _human_delay(*_POST_ACTION_DELAY)
    try:
        page.wait_for_load_state("networkidle", timeout=10_000)
    except Exception:
        # Network may not fully settle — that's OK
        pass

    return result


def _dispatch_action(
    page,
    action: AgentAction,
    elements: list[InteractiveElement],
) -> str:
    """Route to the appropriate action handler."""
    handlers = {
        ActionType.CLICK: _do_click,
        ActionType.TYPE: _do_type,
        ActionType.SELECT: _do_select,
        ActionType.SCROLL: _do_scroll,
        ActionType.WAIT: _do_wait,
        ActionType.NAVIGATE: _do_navigate,
        ActionType.SUBMIT: _do_submit,
        ActionType.SCREENSHOT: _do_screenshot,
    }

    handler = handlers.get(action.action_type)
    if not handler:
        return f"No handler for action type: {action.action_type}"

    return handler(page, action, elements)


def _resolve_element(
    elements: list[InteractiveElement], index: int | None
) -> InteractiveElement | None:
    """Find the element matching the given index."""
    if index is None:
        return None
    for el in elements:
        if el.index == index:
            return el
    return None


def _do_click(page, action: AgentAction, elements: list[InteractiveElement]) -> str:
    """Click an interactive element."""
    el = _resolve_element(elements, action.element_index)
    if not el:
        return f"Cannot click: element index {action.element_index} not found"

    locator = page.locator(el.selector).first
    locator.scroll_into_view_if_needed(timeout=5000)
    locator.click(timeout=5000)
    desc = el.text or el.label or el.name or el.selector
    return f"Clicked [{el.index}] {el.tag} '{desc}'"


def _do_type(page, action: AgentAction, elements: list[InteractiveElement]) -> str:
    """Type text into an input field with human-like delays."""
    el = _resolve_element(elements, action.element_index)
    if not el:
        return f"Cannot type: element index {action.element_index} not found"

    locator = page.locator(el.selector).first
    locator.scroll_into_view_if_needed(timeout=5000)
    locator.click(timeout=5000)

    # Clear existing value first
    locator.fill("")
    # Type with realistic delay
    delay = random.randint(_TYPE_DELAY_MIN, _TYPE_DELAY_MAX)
    locator.type(action.value, delay=delay)

    label = el.label or el.name or el.placeholder or el.selector
    masked = _mask_value(action.value, el.element_type)
    return f"Typed '{masked}' into [{el.index}] {el.tag} '{label}'"


def _do_select(page, action: AgentAction, elements: list[InteractiveElement]) -> str:
    """Select an option from a <select> dropdown."""
    el = _resolve_element(elements, action.element_index)
    if not el:
        return f"Cannot select: element index {action.element_index} not found"

    locator = page.locator(el.selector).first
    locator.scroll_into_view_if_needed(timeout=5000)

    # Try selecting by value first, then by label
    try:
        locator.select_option(value=action.value, timeout=3000)
    except Exception:
        locator.select_option(label=action.value, timeout=3000)

    label = el.label or el.name or el.selector
    return f"Selected '{action.value}' in [{el.index}] {el.tag} '{label}'"


def _do_scroll(page, action: AgentAction, elements: list[InteractiveElement]) -> str:
    """Scroll the page."""
    direction = action.value.lower() if action.value else "down"
    distance = 400 if direction == "down" else -400
    page.evaluate(f"window.scrollBy(0, {distance})")
    return f"Scrolled {direction}"


def _do_wait(page, action: AgentAction, elements: list[InteractiveElement]) -> str:
    """Wait for a specified duration."""
    ms = 2000  # Default 2s wait
    if action.value and action.value.isdigit():
        ms = min(int(action.value), 10_000)  # Cap at 10s
    page.wait_for_timeout(ms)
    return f"Waited {ms}ms"


def _do_navigate(page, action: AgentAction, elements: list[InteractiveElement]) -> str:
    """Navigate to a new URL."""
    url = action.value
    if not url:
        return "Cannot navigate: no URL provided"
    if not url.startswith("http"):
        # Relative URL — resolve against current page
        from urllib.parse import urljoin

        url = urljoin(page.url, url)
    from ssi.browser.navigation import resilient_goto

    resilient_goto(page, url, timeout_ms=30_000)
    return f"Navigated to {url}"


def _do_submit(page, action: AgentAction, elements: list[InteractiveElement]) -> str:
    """Submit a form — either click a submit button or press Enter."""
    el = _resolve_element(elements, action.element_index)
    if el:
        locator = page.locator(el.selector).first
        locator.scroll_into_view_if_needed(timeout=5000)
        locator.click(timeout=5000)
        desc = el.text or el.label or el.name or "submit"
        return f"Submitted via [{el.index}] '{desc}'"

    # No specific element — try pressing Enter on the active element
    page.keyboard.press("Enter")
    return "Submitted via Enter key"


def _do_screenshot(page, action: AgentAction, elements: list[InteractiveElement]) -> str:
    """Take an additional screenshot (agent-requested)."""
    return "Screenshot captured (handled by agent loop)"


def _human_delay(min_ms: int, max_ms: int) -> None:
    """Introduce a random human-like delay."""
    time.sleep(random.randint(min_ms, max_ms) / 1000)


def _mask_value(value: str, field_type: str) -> str:
    """Mask sensitive values in log output."""
    sensitive_types = {"password", "ssn", "credit-card"}
    if field_type in sensitive_types or len(value) > 30:
        return value[:3] + "***"
    return value
