"""Page Analyzer — uses LLM vision to analyze page screenshots and decide actions.

This is the "brain" of the active browser agent.  It receives a screenshot
plus context about the current state and returns a structured ``AgentAction``.

Ported from AWH's ``page_analyzer.py`` with the following adaptations:

* Uses SSI's pluggable ``LLMProvider`` (Gemini/Ollama) instead of Anthropic.
* Token-usage tracking is provider-agnostic (``LLMResult`` carries metrics).
* Conversation management preserved (rolling window + old-image stripping).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from ssi.llm.base import LLMProvider, LLMResult
from ssi.models.action import ActionType, AgentAction

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a web automation agent investigating confirmed cryptocurrency scam websites.
Your task is to navigate each site, register a throwaway account, find the deposit/invest section,
and extract all cryptocurrency wallet addresses shown.

You operate by analyzing screenshots of the current page and returning ONE structured action at a time.

## Current Objective by State

- LOAD_SITE: The page should be loading. Verify it loaded correctly.
- FIND_REGISTER: Find and navigate to the registration form. If you can already see a registration \
FORM with input fields (email, username, password), signal 'done' immediately to proceed to filling \
it out. If you only see a link or button to get to the registration page, click it.
- FILL_REGISTER: Fill the registration form using the provided identity data. DO NOT scroll to survey \
the form first — start filling fields that are currently visible, starting with the most important \
ones (email/username, password, confirm password). You can type directly into fields using their CSS \
selector — the system will handle clicking and focusing the field for you, so do NOT waste an action \
clicking a field before typing into it. If it is unclear which fields are required, fill the obvious \
ones (username/email, password, confirm password, name if present) and signal 'done' to attempt \
submission. The form's error messages will tell us what's missing. Skip fields that are clearly \
optional (wallet addresses, social media handles, referral codes without asterisks). If a form error \
after submission indicates password format requirements, adjust using the provided password variants.
  IMPORTANT — PASSWORD FIELDS: Before filling password fields, READ the placeholder text (shown in \
the field status as [placeholder: "..."]) — it often contains format requirements like "8-12 digits", \
"6 digits only", "Enter 6-digit password". Different password fields on the same form (login password \
vs fund/trading password) may have DIFFERENT requirements. Choose the appropriate password_variant \
for EACH field independently based on its placeholder hints.
- SUBMIT_REGISTER: Click the submit/register button on the form. After clicking, carefully check if \
any error messages, validation warnings, or alert banners appeared anywhere on the page (especially \
at the top). Common errors include: invalid email, weak password, missing required fields, username \
taken. If you see ANY error messages, do NOT signal 'done' — instead describe the error and take \
corrective action (fix the field that caused the error). IMPORTANT: Some forms clear all field values \
after a failed submission. Check the FORM FIELD STATUS in the context (if provided) to see which \
fields are actually filled vs empty — do NOT rely on the screenshot alone to distinguish filled \
values from placeholder text. Only fill fields that the FORM FIELD STATUS shows as EMPTY. Only \
signal 'done' when registration appears to have succeeded (page changed, dashboard loaded, success \
message, etc.).
- CHECK_EMAIL_VERIFICATION: Check if the site requires email verification. Look for messages like \
"verify your email", "check your inbox", "confirmation link".
- NAVIGATE_DEPOSIT: Find the deposit/invest/fund section. Look for text like "Deposit", "Invest", \
"Fund", "Top Up", "Add Funds", "Recharge", "Buy".
- EXTRACT_WALLETS: You are on or near the deposit page. Find and extract cryptocurrency wallet \
addresses. You may need to click through different cryptocurrency tabs/options to reveal each address.

## Response Format

Always respond with valid JSON matching this schema:
{
    "action": "click|type|select|key|navigate|scroll|wait|done|stuck",
    "selector": "CSS selector or text description of the element to interact with",
    "value": "text to type, option to select, URL to navigate to, or key name to press",
    "reasoning": "brief explanation of why you chose this action",
    "confidence": 0.0 to 1.0
}

## Rules

- Return exactly ONE action per response
- Fill core registration fields (email/username, password, confirm password, name). Skip clearly \
optional fields (wallet addresses, social media, referral codes). If unsure whether a field is \
required, skip it and let form validation reveal what's missing after submission.
- Do NOT click a field before typing into it — the type action handles focus automatically.
- Do NOT scroll to survey the form before filling it. Work with what is visible. You can scroll \
AFTER filling all visible fields to check for a submit button or additional required fields.
- When clicking buttons or links, prefer using the visible button text as the selector.
- If a security question is required, pick any answer and remember it.
- If you see cryptocurrency wallet addresses on screen, output them in the "value" field as JSON: \
[{"token_label": "...", "token_symbol": "...", "network_label": "...", "network_short": "...", \
"wallet_address": "..."}] and set action to "done" — the controller will handle recording them
- If you see an email verification requirement, set action to "stuck" with reasoning explaining it
- If a form explicitly rejects because a referral/invitation code is missing, set action to "stuck"
- If you truly cannot determine what to do, set action to "stuck"
- Use the "key" action to press keyboard keys (e.g., value "Escape" to close a dropdown)
- Be precise with selectors — use visible text content when CSS selectors aren't clear
"""

BATCH_FILL_ADDENDUM = """

## BATCH MODE — FILL_REGISTER

You are in batch mode. Instead of ONE action, return ALL form-fill actions needed
as a JSON array. Include "type", "select", and "click" (for checkboxes only) actions.
Do NOT include scroll, navigate, wait, or done actions.

Schema:
[
    {"action": "type", "selector": "CSS or description", "value": "text to enter", \
"reasoning": "brief reason", "confidence": 0.9},
    {"action": "select", "selector": "CSS or description", "value": "option to select", \
"reasoning": "brief reason", "confidence": 0.9},
    {"action": "click", "selector": "input[type='checkbox']", "value": "", \
"reasoning": "check terms checkbox", "confidence": 0.9}
]

Return the bare JSON array only. Fill all visible required fields in one response.
Skip clearly optional fields (wallet addresses, social media, referral codes).
Fill ALL visible <select> dropdowns — including currency, country, gender, etc.
Check any "I agree to terms/privacy" checkboxes by including a click action for them.
If password_variants are provided in the identity data, use the 'default' variant UNLESS the
field's placeholder text indicates specific requirements (e.g., "6 digits", "8-12 digits").
Read the placeholder text of EACH password field — different fields (login password, fund password,
trading password) may require different formats. Match each field to the appropriate variant:
- Placeholder says "digits" or "N digits" -> use digits_8 or digits_12
- Placeholder says specific length range -> use the variant that fits
- No specific hint -> use 'default'
"""


# ---------------------------------------------------------------------------
# Token tracking
# ---------------------------------------------------------------------------


@dataclass
class TokenUsage:
    """Accumulates token usage across multiple LLM calls for a single site.

    Provider-agnostic — consumes ``LLMResult`` from any backend.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    api_calls: int = 0
    total_latency_ms: float = 0.0

    def add(self, result: LLMResult) -> None:
        """Record token usage from an ``LLMResult``."""
        self.input_tokens += result.input_tokens
        self.output_tokens += result.output_tokens
        self.total_latency_ms += result.latency_ms
        self.api_calls += 1

    def reset(self) -> None:
        self.input_tokens = 0
        self.output_tokens = 0
        self.api_calls = 0
        self.total_latency_ms = 0.0

    def to_dict(self) -> dict:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "api_calls": self.api_calls,
            "total_latency_ms": round(self.total_latency_ms, 1),
        }


# ---------------------------------------------------------------------------
# Page Analyzer
# ---------------------------------------------------------------------------


class PageAnalyzer:
    """Sends screenshots to the LLM and returns structured navigation actions.

    Uses SSI's pluggable ``LLMProvider`` so the same code works with
    Gemini (primary) and Ollama (local dev).

    Args:
        llm: An ``LLMProvider`` that supports ``chat_with_images()``.
        max_context_messages: Rolling window size for conversation history.
        max_tokens: Max output tokens per LLM call.
    """

    def __init__(
        self,
        llm: LLMProvider | None = None,
        max_context_messages: int = 10,
        max_tokens: int = 4096,
    ) -> None:
        if llm is None:
            from ssi.llm.factory import create_llm_provider

            llm = create_llm_provider()
        self._llm = llm
        self._max_context_messages = max_context_messages
        self._max_tokens = max_tokens
        self._conversation: list[dict] = []
        self.usage = TokenUsage()
        self.last_call_result: LLMResult | None = None

    def reset_conversation(self) -> None:
        """Clear conversation history and token usage (call between sites)."""
        self._conversation = []
        self.usage.reset()
        self.last_call_result = None

    # ------------------------------------------------------------------
    # Single-action analysis
    # ------------------------------------------------------------------

    async def analyze_page(
        self,
        screenshot_b64: str,
        state: str,
        page_text: str = "",
        page_url: str = "",
        extra_context: str = "",
        include_screenshot: bool = True,
    ) -> AgentAction:
        """Analyze a page screenshot and return the next action.

        Args:
            screenshot_b64: Base64-encoded PNG screenshot.
            state: Current agent state (e.g., ``"NAVIGATE_DEPOSIT"``).
            page_text: Visible text content of the page (truncated).
            page_url: Current page URL.
            extra_context: Additional context (identity data, human guidance, etc.).
            include_screenshot: If False, omit the image (text-only mode).
        """
        content_parts: list[dict] = []

        if include_screenshot and screenshot_b64:
            content_parts.append(
                {"type": "image", "media_type": "image/png", "data": screenshot_b64}
            )

        text_context = f"Current state: {state}\nCurrent URL: {page_url}\n"
        if page_text:
            truncated = page_text[:3000] if len(page_text) > 3000 else page_text
            text_context += f"\nVisible page text:\n{truncated}\n"
        if extra_context:
            text_context += f"\n{extra_context}\n"
        text_context += "\nWhat is the next action? Respond with JSON only."

        content_parts.append({"type": "text", "text": text_context})

        # Build the user message
        user_msg = {"role": "user", "content": content_parts}
        self._conversation.append(user_msg)
        self._trim_conversation()

        # Build full message list with system prompt
        messages = [{"role": "system", "content": SYSTEM_PROMPT}] + self._conversation

        raw_text = None
        try:
            result = self._llm.chat_with_images(
                messages,
                max_tokens=self._max_tokens,
                json_mode=True,
            )
            self.usage.add(result)
            self.last_call_result = result

            logger.debug(
                "LLM call: in=%d out=%d latency=%.0fms (cumulative: in=%d out=%d)",
                result.input_tokens,
                result.output_tokens,
                result.latency_ms,
                self.usage.input_tokens,
                self.usage.output_tokens,
            )

            raw_text = result.content.strip()
            if not raw_text:
                logger.error("LLM returned empty response")
                self._conversation.pop()
                return AgentAction(
                    action=ActionType.STUCK,
                    reasoning="LLM returned empty response",
                )

            self._conversation.append({"role": "assistant", "content": raw_text})
            return self._parse_response(raw_text)

        except json.JSONDecodeError as e:
            logger.error("Failed to parse LLM response as JSON: %s", e)
            logger.error("Raw response: %s", raw_text[:500] if raw_text else "empty")
            # Clean up conversation
            while self._conversation and self._conversation[-1].get("role") != "user":
                self._conversation.pop()
            if self._conversation:
                self._conversation.pop()
            return AgentAction(
                action=ActionType.STUCK,
                reasoning=f"Failed to parse LLM response: {e}",
            )
        except NotImplementedError:
            logger.error(
                "LLM provider %s does not support multimodal chat",
                type(self._llm).__name__,
            )
            if self._conversation and self._conversation[-1].get("role") == "user":
                self._conversation.pop()
            return AgentAction(
                action=ActionType.STUCK,
                reasoning="LLM provider does not support vision",
            )
        except Exception as e:
            logger.error("Unexpected error in analyze_page: %s", e)
            if self._conversation and self._conversation[-1].get("role") == "user":
                self._conversation.pop()
            return AgentAction(
                action=ActionType.STUCK,
                reasoning=f"Unexpected error: {e}",
            )

    # ------------------------------------------------------------------
    # Human guidance re-analysis
    # ------------------------------------------------------------------

    async def analyze_with_human_guidance(
        self,
        screenshot_b64: str,
        state: str,
        human_instruction: str,
        page_url: str = "",
    ) -> AgentAction:
        """Re-analyze after receiving human guidance for a stuck state."""
        extra = (
            f"HUMAN OPERATOR GUIDANCE: {human_instruction}\n"
            "Follow the operator's instruction to proceed."
        )
        return await self.analyze_page(
            screenshot_b64=screenshot_b64,
            state=state,
            page_url=page_url,
            extra_context=extra,
        )

    # ------------------------------------------------------------------
    # Batch-mode analysis (FILL_REGISTER)
    # ------------------------------------------------------------------

    async def analyze_page_batch(
        self,
        screenshot_b64: str,
        state: str,
        page_text: str = "",
        page_url: str = "",
        extra_context: str = "",
    ) -> list[AgentAction]:
        """Analyze a FILL_REGISTER page and return ALL fill actions at once.

        One-shot call (NOT added to conversation history).
        Returns ``[STUCK]`` on any error so the caller can fall back to single-action mode.
        """
        content_parts: list[dict] = [
            {"type": "image", "media_type": "image/png", "data": screenshot_b64},
        ]

        text_context = f"Current state: {state}\nCurrent URL: {page_url}\n"
        if page_text:
            truncated = page_text[:3000] if len(page_text) > 3000 else page_text
            text_context += f"\nVisible page text:\n{truncated}\n"
        if extra_context:
            text_context += f"\n{extra_context}\n"
        text_context += (
            "\nReturn ALL form-fill actions as a JSON array. "
            "Only type and select actions for visible required fields."
        )
        content_parts.append({"type": "text", "text": text_context})

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT + BATCH_FILL_ADDENDUM},
            {"role": "user", "content": content_parts},
        ]

        raw_text = None
        try:
            result = self._llm.chat_with_images(
                messages,
                max_tokens=self._max_tokens,
                json_mode=True,
            )
            self.usage.add(result)
            self.last_call_result = result

            logger.debug(
                "Batch LLM call: in=%d out=%d latency=%.0fms",
                result.input_tokens,
                result.output_tokens,
                result.latency_ms,
            )

            raw_text = result.content.strip()
            if not raw_text:
                return [AgentAction(action=ActionType.STUCK, reasoning="Batch returned empty response")]

            return self._parse_batch_response(raw_text)

        except json.JSONDecodeError as e:
            logger.error("Batch JSON parse error: %s — raw: %s", e, (raw_text or "")[:500])
            return [AgentAction(action=ActionType.STUCK, reasoning=f"Batch JSON parse failed: {e}")]
        except Exception as e:
            logger.error("Unexpected error in analyze_page_batch: %s", e)
            return [AgentAction(action=ActionType.STUCK, reasoning=f"Unexpected batch error: {e}")]

    # ------------------------------------------------------------------
    # Conversation management
    # ------------------------------------------------------------------

    def _trim_conversation(self) -> None:
        """Keep a rolling window and strip old images to reduce token costs.

        1. Drops the oldest messages (rolling window).
        2. Strips image blocks from all but the last 2 user messages,
           replacing them with a text placeholder.  Saves ~60 % of
           per-call input tokens from re-sent old screenshots.
        """
        if len(self._conversation) > self._max_context_messages:
            self._conversation = self._conversation[-self._max_context_messages:]

        user_indices = [
            i for i, msg in enumerate(self._conversation) if msg.get("role") == "user"
        ]

        if len(user_indices) > 2:
            for idx in user_indices[:-2]:
                content = self._conversation[idx].get("content", [])
                if isinstance(content, list):
                    stripped = []
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "image":
                            stripped.append({"type": "text", "text": "[Previous screenshot omitted]"})
                        else:
                            stripped.append(block)
                    self._conversation[idx]["content"] = stripped

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, raw_text: str) -> AgentAction:
        """Parse the LLM's JSON response into an ``AgentAction``."""
        text = raw_text
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.strip()

        parsed = json.loads(text)

        # LLM sometimes returns value as a list/dict (e.g., wallet data).
        if "value" in parsed and not isinstance(parsed["value"], str):
            parsed["value"] = json.dumps(parsed["value"])

        action = AgentAction(**parsed)

        logger.info(
            "LLM action: %s (selector='%s', confidence=%.2f) — %s",
            action.action,
            action.selector[:80] if action.selector else "",
            action.confidence,
            action.reasoning,
        )
        return action

    def _parse_batch_response(self, raw_text: str) -> list[AgentAction]:
        """Parse a JSON array batch response into a list of ``AgentAction`` objects."""
        text = raw_text
        if text.startswith("```"):
            parts = text.split("```")
            if len(parts) >= 2:
                text = parts[1]
                if text.startswith("json"):
                    text = text[4:]
                text = text.strip()

        parsed = json.loads(text)

        # Handle accidental object wrapper: {"actions": [...]}
        if isinstance(parsed, dict):
            for key in ("actions", "fills", "fields"):
                if key in parsed and isinstance(parsed[key], list):
                    parsed = parsed[key]
                    break
            else:
                logger.warning(
                    "Batch response was dict with no recognized list key: %s",
                    list(parsed.keys()),
                )
                return [AgentAction(action=ActionType.STUCK, reasoning="Batch dict had no action list")]

        if not isinstance(parsed, list) or not parsed:
            return [AgentAction(action=ActionType.STUCK, reasoning="Batch was not a non-empty list")]

        actions: list[AgentAction] = []
        for item in parsed:
            try:
                action = AgentAction(**item)
                if action.action not in (ActionType.TYPE, ActionType.SELECT, ActionType.CLICK):
                    logger.warning("Batch contained non-fill action %s — skipping", action.action)
                    continue
                actions.append(action)
                logger.info(
                    "Batch action: %s → '%s' = '%s'",
                    action.action,
                    action.selector[:50] if action.selector else "",
                    (action.value or "")[:40],
                )
            except Exception as e:
                logger.warning("Skipping malformed batch item %s: %s", item, e)

        if not actions:
            return [AgentAction(action=ActionType.STUCK, reasoning="Batch produced no valid fill actions")]

        return actions
