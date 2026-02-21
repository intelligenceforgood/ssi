"""DOM Inspector — pure-Python confidence scoring for CDP DOM scan results.

Receives raw dicts from ``ZenBrowserManager.run_dom_scan()`` and produces
``DOMInspection`` results.  Has no async I/O — fully synchronous and testable.

Architecture::

    ZenBrowserManager  →  raw JS scan dict
    DOMInspector       →  DOMInspection (direct AgentAction *or* LLM context string)
    AgentController    →  routes to execute or injects into extra_context

Three-tier confidence system:

    ≥ ``dom_direct_threshold`` (75)   → execute AgentAction directly (zero LLM)
    ≥ ``dom_assisted_threshold`` (40) → inject context into LLM prompt
    < ``dom_assisted_threshold``      → full LLM fallback
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

from ssi.models.action import ActionType, AgentAction

logger = logging.getLogger(__name__)

_MAX_CONFIDENCE = 100


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class DOMSignal:
    """A single piece of evidence from the DOM with its weight."""

    source: str  # e.g., "registration_form_present", "register_link_found"
    weight: int  # Contribution to confidence score (0–100 cap)
    selector: str = ""
    value: str = ""


@dataclass
class DOMInspection:
    """Result of a DOM inspection pass for a single state."""

    state: str
    confidence: int  # 0–100
    outcome: Literal["direct", "assisted", "fallback"]
    signals: list[DOMSignal]
    direct_action: AgentAction | None  # Set when outcome == "direct"
    context_summary: str = ""  # Formatted string for extra_context injection
    scan_duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# State detectors
# ---------------------------------------------------------------------------


class FindRegisterDetector:
    """Detection layers for FIND_REGISTER state.

    Signals and weights:
      - Registration form present (password + email inputs): 60 pts
      - Link/button with register keyword: 40 pts
      - URL already contains /register, /signup: 25 pts
      - Modal dialog with form inputs: 20 pts
    """

    def detect(self, scan_data: dict) -> list[DOMSignal]:
        """Analyse DOM scan data and return weighted signals for register detection."""
        signals: list[DOMSignal] = []

        if scan_data.get("has_registration_form"):
            signals.append(
                DOMSignal(
                    source="registration_form_present",
                    weight=60,
                    selector=scan_data.get("form_selector", "form"),
                    value=scan_data.get("field_summary", ""),
                )
            )

        register_links = scan_data.get("register_links", [])
        if register_links:
            best = register_links[0]
            signals.append(
                DOMSignal(
                    source="register_link_found",
                    weight=40,
                    selector=best.get("selector", ""),
                    value=best.get("text", ""),
                )
            )

        if scan_data.get("url_is_register_page"):
            signals.append(
                DOMSignal(
                    source="url_pattern_match",
                    weight=25,
                    value=scan_data.get("current_url", ""),
                )
            )

        if scan_data.get("modal_has_form"):
            signals.append(
                DOMSignal(
                    source="modal_form_detected",
                    weight=20,
                    selector=scan_data.get("modal_selector", ""),
                )
            )

        return signals

    def build_action(self, signals: list[DOMSignal]) -> AgentAction | None:
        """Build a deterministic action from the collected signals."""
        # If form is present, signal DONE (proceed to FILL_REGISTER)
        for s in signals:
            if s.source == "registration_form_present":
                return AgentAction(
                    action=ActionType.DONE,
                    reasoning=f"DOM: Registration form detected ({s.value}). Proceeding to FILL_REGISTER.",
                    confidence=0.9,
                )

        # Click the register link (selector-based)
        for s in signals:
            if s.source == "register_link_found" and s.selector:
                return AgentAction(
                    action=ActionType.CLICK,
                    selector=s.selector,
                    reasoning=f"DOM: Register link found: '{s.value}'",
                    confidence=0.8,
                )

        # Register link found but no usable selector — use text as selector
        for s in signals:
            if s.source == "register_link_found" and s.value:
                return AgentAction(
                    action=ActionType.CLICK,
                    selector=s.value,
                    reasoning=f"DOM: Register link found (text match): '{s.value}'",
                    confidence=0.75,
                )

        return None


class NavigateDepositDetector:
    """Detection layers for NAVIGATE_DEPOSIT state.

    Signals and weights:
      - Deposit link/button with keyword: 40 pts
      - URL already contains /deposit, /recharge: 35 pts
      - CSS class matching: 20 pts
    """

    def detect(self, scan_data: dict) -> list[DOMSignal]:
        """Analyse DOM scan data and return weighted signals for deposit navigation."""
        signals: list[DOMSignal] = []

        deposit_links = scan_data.get("deposit_links", [])
        if deposit_links:
            best = deposit_links[0]
            signals.append(
                DOMSignal(
                    source="deposit_link_found",
                    weight=40,
                    selector=best.get("selector", ""),
                    value=best.get("text", ""),
                )
            )

        if scan_data.get("url_is_deposit_page"):
            signals.append(
                DOMSignal(
                    source="url_pattern_match",
                    weight=35,
                    value=scan_data.get("current_url", ""),
                )
            )

        if scan_data.get("deposit_class_match"):
            signals.append(
                DOMSignal(
                    source="css_class_match",
                    weight=20,
                    selector=scan_data.get("deposit_class_selector", ""),
                )
            )

        return signals

    def build_action(self, signals: list[DOMSignal]) -> AgentAction | None:
        """Build a deterministic action from the collected signals."""
        # If URL already indicates deposit page — don't click again (prevents loops).
        for s in signals:
            if s.source == "url_pattern_match":
                return AgentAction(
                    action=ActionType.DONE,
                    reasoning="DOM: Already on deposit page (URL pattern match).",
                    confidence=0.85,
                )

        # Click a visible deposit link (only if NOT already on the deposit page)
        for s in signals:
            if s.source == "deposit_link_found" and s.selector:
                return AgentAction(
                    action=ActionType.CLICK,
                    selector=s.selector,
                    reasoning=f"DOM: Deposit link found: '{s.value}'",
                    confidence=0.8,
                )

        for s in signals:
            if s.source == "deposit_link_found" and s.value:
                return AgentAction(
                    action=ActionType.CLICK,
                    selector=s.value,
                    reasoning=f"DOM: Deposit link found (text match): '{s.value}'",
                    confidence=0.75,
                )

        # CSS class match as last resort
        for s in signals:
            if s.source == "css_class_match" and s.selector:
                return AgentAction(
                    action=ActionType.CLICK,
                    selector=s.selector,
                    reasoning="DOM: Deposit element found via CSS class match",
                    confidence=0.6,
                )

        return None


class CheckEmailDetector:
    """Detection layers for CHECK_EMAIL_VERIFICATION state.

    This state is always zero-LLM — the detector always returns a definitive action.

    Decision logic:
      - Email verification text found → STUCK (email required)
      - Dashboard/account indicators → DONE (no verification needed)
      - URL verify pattern (weaker than page text) → STUCK
      - Ambiguous → DONE (default: proceed, per design spec)
    """

    def detect(self, scan_data: dict) -> list[DOMSignal]:
        """Analyse DOM scan data and return weighted signals for email verification detection."""
        signals: list[DOMSignal] = []

        if scan_data.get("email_verify_text_found"):
            signals.append(
                DOMSignal(
                    source="email_verify_text",
                    weight=80,
                    value=scan_data.get("email_verify_snippet", ""),
                )
            )

        if scan_data.get("dashboard_text_found"):
            signals.append(
                DOMSignal(
                    source="dashboard_text",
                    weight=60,
                    value=scan_data.get("dashboard_snippet", ""),
                )
            )

        if scan_data.get("url_is_verify_page"):
            signals.append(
                DOMSignal(
                    source="url_verify_pattern",
                    weight=40,
                )
            )

        return signals

    def build_action(self, signals: list[DOMSignal]) -> AgentAction | None:
        """Always returns an action — never ``None`` for CHECK_EMAIL."""
        # Email body text is the strongest signal
        for s in signals:
            if s.source == "email_verify_text":
                return AgentAction(
                    action=ActionType.STUCK,
                    reasoning=f"DOM: Email verification required. Text: '{s.value}'",
                    confidence=0.95,
                )

        # Dashboard text overrides URL patterns (URL can lag after redirect)
        for s in signals:
            if s.source == "dashboard_text":
                return AgentAction(
                    action=ActionType.DONE,
                    reasoning=f"DOM: Dashboard detected ({s.value}). No email verification.",
                    confidence=0.90,
                )

        # URL pattern is weaker — only use if no body text evidence
        for s in signals:
            if s.source == "url_verify_pattern":
                return AgentAction(
                    action=ActionType.STUCK,
                    reasoning="DOM: URL matches email verification pattern.",
                    confidence=0.85,
                )

        # Ambiguous — default to proceed
        return AgentAction(
            action=ActionType.DONE,
            reasoning="DOM: No email verification signals. Proceeding.",
            confidence=0.75,
        )


# ---------------------------------------------------------------------------
# Main coordinator
# ---------------------------------------------------------------------------


class DOMInspector:
    """Coordinates detectors, scores confidence, and routes outcomes.

    Configuration is read from ``ssi.settings.get_settings().agent`` at
    construction time so thresholds can be overridden via environment
    variables (``SSI_AGENT__DOM_DIRECT_THRESHOLD``, etc.).
    """

    def __init__(self) -> None:
        from ssi.settings import get_settings

        agent = get_settings().agent
        self._direct_threshold: int = agent.dom_direct_threshold
        self._assisted_threshold: int = agent.dom_assisted_threshold

        self._detectors: dict = {
            "FIND_REGISTER": FindRegisterDetector(),
            "NAVIGATE_DEPOSIT": NavigateDepositDetector(),
            "CHECK_EMAIL_VERIFICATION": CheckEmailDetector(),
        }

    def inspect(
        self, state: str, scan_data: dict, scan_duration_ms: float = 0.0
    ) -> DOMInspection:
        """Analyze raw scan data and return a ``DOMInspection`` result."""
        detector = self._detectors.get(state)
        if detector is None:
            return DOMInspection(
                state=state,
                confidence=0,
                outcome="fallback",
                signals=[],
                direct_action=None,
                scan_duration_ms=scan_duration_ms,
            )

        signals = detector.detect(scan_data)
        confidence = min(sum(s.weight for s in signals), _MAX_CONFIDENCE)

        # CHECK_EMAIL is always direct — deterministic answer, no LLM needed
        if state == "CHECK_EMAIL_VERIFICATION":
            direct_action = detector.build_action(signals)
            confidence = max(confidence, self._direct_threshold)
            outcome: Literal["direct", "assisted", "fallback"] = "direct"
        elif confidence >= self._direct_threshold:
            direct_action = detector.build_action(signals)
            outcome = "direct"
        elif confidence >= self._assisted_threshold:
            direct_action = None
            outcome = "assisted"
        else:
            direct_action = None
            outcome = "fallback"

        context_summary = self._format_context(state, confidence, signals)

        inspection = DOMInspection(
            state=state,
            confidence=confidence,
            outcome=outcome,
            signals=signals,
            direct_action=direct_action,
            context_summary=context_summary,
            scan_duration_ms=scan_duration_ms,
        )

        logger.info(
            "DOM inspection [%s]: confidence=%d outcome=%s signals=%d duration=%.0fms",
            state,
            confidence,
            outcome,
            len(signals),
            scan_duration_ms,
        )
        return inspection

    @staticmethod
    def _format_context(state: str, confidence: int, signals: list[DOMSignal]) -> str:
        """Format signals as text for ``extra_context`` injection into LLM."""
        if not signals:
            return ""
        lines = [f"DOM PRE-SCAN [{state}] confidence={confidence}/100:"]
        for s in signals:
            detail = f"selector='{s.selector}'" if s.selector else f"value='{s.value}'"
            lines.append(f"  - {s.source} (+{s.weight}pts): {detail}")
        return "\n".join(lines)
