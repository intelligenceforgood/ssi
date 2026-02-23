"""Decision Cascade — formalized four-tier routing for the active agent.

Codifies the implicit decision tiers in ``AgentController._step()`` as
named constants and testable routing functions.  The cascade determines
whether an agent step uses a deterministic shortcut (DOM/JS) or
requires an LLM call (text-only or vision), and when to escalate to
human guidance.

Cascade tiers (evaluated top-to-bottom; first match wins):

    Tier 0 — Playbook           Deterministic script matched by URL pattern.
                                Runs before the main step loop (``_try_playbook``).
    Tier 1 — DOM Inspection     Pure-JS heuristic scoring of the live DOM.
                                Three confidence outcomes:
                                  ≥ 75 → *direct* action (zero LLM cost)
                                  ≥ 40 → *assisted* (context injected into LLM prompt)
                                  < 40 → *fallback* (full LLM vision analysis)
    Tier 2 — Text-only LLM     Page text + extra_context (no screenshot).
                                Used for states where the page structure is
                                predictable (CHECK_EMAIL, post-submit, wallets
                                after JS extraction).
    Tier 3 — Vision LLM        Full screenshot + page text + context sent to
                                a multimodal LLM.  Default tier for complex
                                navigation decisions.
    Tier 4 — Human Guidance     Escalation when the agent is stuck (exceeded
                                per-state stuck threshold).  Requests human
                                instructions via the ``GuidanceHandler`` protocol.

Pre-filters (skip LLM entirely):
    - Blank page detection: page_text < 20 chars AND screenshot < 5 KB → wait+retry.
    - Screenshot hash dedup: MD5 unchanged from last step → wait, no LLM.
    - JS wallet extraction: In ``EXTRACT_WALLETS``, JavaScript regex scan runs
      before the first LLM call to pre-populate wallet data.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ssi.browser.dom_inspector import DOMInspection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tier enumeration
# ---------------------------------------------------------------------------


class CascadeTier(str, enum.Enum):
    """Named tiers in the decision cascade, ordered by cost/complexity."""

    PLAYBOOK = "playbook"
    DOM_DIRECT = "dom_direct"
    DOM_ASSISTED = "dom_assisted"
    TEXT_ONLY_LLM = "text_only_llm"
    VISION_LLM = "vision_llm"
    HUMAN_GUIDANCE = "human_guidance"


# ---------------------------------------------------------------------------
# Pre-filter outcomes
# ---------------------------------------------------------------------------


class PreFilterOutcome(str, enum.Enum):
    """Outcomes from pre-filter checks that bypass the cascade entirely."""

    BLANK_PAGE = "blank_page"
    DUPLICATE_SCREENSHOT = "duplicate_screenshot"
    JS_EXTRACTION = "js_extraction"
    PROCEED = "proceed"


# ---------------------------------------------------------------------------
# Decision result
# ---------------------------------------------------------------------------


@dataclass
class CascadeDecision:
    """Result of cascade routing — which tier should handle this step."""

    tier: CascadeTier
    include_screenshot: bool = True
    extra_context: str = ""
    reason: str = ""


# ---------------------------------------------------------------------------
# Routing functions
# ---------------------------------------------------------------------------

# States where the DOM inspector is tried before the LLM.
DOM_INSPECTABLE_STATES: frozenset[str] = frozenset({
    "FIND_REGISTER",
    "NAVIGATE_DEPOSIT",
    "CHECK_EMAIL_VERIFICATION",
})

# States where screenshots are omitted (text-only mode).
TEXT_ONLY_STATES: frozenset[str] = frozenset({
    "CHECK_EMAIL_VERIFICATION",
})


def check_pre_filters(
    *,
    page_text: str,
    screenshot_size_bytes: int,
    screenshot_hash: str,
    last_screenshot_hash: str,
    consecutive_dupes: int,
    dupe_threshold: int = 5,
) -> PreFilterOutcome:
    """Evaluate pre-LLM filters to determine if the full cascade is needed.

    Args:
        page_text: Visible text on the page.
        screenshot_size_bytes: Estimated byte size of the screenshot.
        screenshot_hash: MD5 hash of the current screenshot.
        last_screenshot_hash: MD5 hash from the previous step.
        consecutive_dupes: Current run of duplicate screenshots.
        dupe_threshold: Dupe streak that forces stuck.

    Returns:
        A ``PreFilterOutcome`` indicating whether to skip or proceed.
    """
    # Blank page detection
    if len(page_text.strip()) < 20 and screenshot_size_bytes < 5000:
        return PreFilterOutcome.BLANK_PAGE

    # Screenshot hash dedup
    if screenshot_hash and screenshot_hash == last_screenshot_hash:
        return PreFilterOutcome.DUPLICATE_SCREENSHOT

    return PreFilterOutcome.PROCEED


def resolve_tier(
    *,
    state: str,
    dom_inspection: "DOMInspection | None" = None,
    dom_inspection_enabled: bool = True,
    actions_in_state: int = 0,
    js_wallets_found: bool = False,
    is_stuck: bool = False,
) -> CascadeDecision:
    """Determine which cascade tier should handle the current step.

    This function implements the core routing logic.  It does not
    execute any actions — it only decides which tier is appropriate.

    Args:
        state: Current agent state (e.g. ``"FIND_REGISTER"``).
        dom_inspection: Result from ``DOMInspector.inspect()`` if available.
        dom_inspection_enabled: Whether DOM inspection is active in settings.
        actions_in_state: Number of actions already taken in this state.
        js_wallets_found: Whether JS pre-extraction already found wallets.
        is_stuck: Whether the stuck threshold was exceeded.

    Returns:
        A ``CascadeDecision`` with the selected tier and metadata.
    """
    # Tier 4: Human guidance (stuck threshold exceeded)
    if is_stuck:
        return CascadeDecision(
            tier=CascadeTier.HUMAN_GUIDANCE,
            include_screenshot=True,
            reason=f"Stuck threshold exceeded in {state}",
        )

    # Tier 1: DOM Inspection
    if (
        dom_inspection_enabled
        and state in DOM_INSPECTABLE_STATES
        and dom_inspection is not None
    ):
        if dom_inspection.outcome == "direct" and dom_inspection.direct_action is not None:
            return CascadeDecision(
                tier=CascadeTier.DOM_DIRECT,
                include_screenshot=False,
                extra_context=dom_inspection.context_summary,
                reason=f"DOM direct action (confidence={dom_inspection.confidence})",
            )
        if dom_inspection.outcome == "assisted":
            return CascadeDecision(
                tier=CascadeTier.DOM_ASSISTED,
                include_screenshot=True,
                extra_context=dom_inspection.context_summary,
                reason=f"DOM assisted (confidence={dom_inspection.confidence})",
            )
        # fallback — proceed to LLM tier

    # Tier 2: Text-only LLM for eligible states
    if state in TEXT_ONLY_STATES:
        return CascadeDecision(
            tier=CascadeTier.TEXT_ONLY_LLM,
            include_screenshot=False,
            reason=f"Text-only state: {state}",
        )

    # SUBMIT_REGISTER text-only after first action
    if state == "SUBMIT_REGISTER" and actions_in_state > 0:
        return CascadeDecision(
            tier=CascadeTier.TEXT_ONLY_LLM,
            include_screenshot=False,
            reason="SUBMIT_REGISTER re-check (text-only after first action)",
        )

    # EXTRACT_WALLETS text-only when JS already found wallets
    if state == "EXTRACT_WALLETS" and js_wallets_found:
        return CascadeDecision(
            tier=CascadeTier.TEXT_ONLY_LLM,
            include_screenshot=False,
            reason="EXTRACT_WALLETS with JS pre-extraction results",
        )

    # Tier 3: Full vision LLM (default)
    return CascadeDecision(
        tier=CascadeTier.VISION_LLM,
        include_screenshot=True,
        reason=f"Full vision analysis for {state}",
    )
