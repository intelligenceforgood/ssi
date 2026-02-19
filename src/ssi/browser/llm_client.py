"""LLM client for the browser interaction agent.

Uses the pluggable ``ssi.llm`` provider layer so the agent works with
both local Ollama and cloud-hosted Gemini models.
Tracks token usage for budget enforcement and measurement.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from ssi.identity.vault import SyntheticIdentity
from ssi.llm.base import LLMProvider
from ssi.models.agent import ActionType, AgentAction, PageObservation

logger = logging.getLogger(__name__)

# ---- System prompt --------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an AI agent investigating a suspicious website for potential fraud.
Your goal is to walk through the site as a potential victim would, filling
out forms with synthetic (fake) PII, clicking through the funnel, and
documenting every step.

RULES:
1. Observe the page carefully — read visible text and interactive elements.
2. Decide the SINGLE best next action to advance through the funnel.
3. Fill form fields with the provided synthetic identity data.
4. Always submit forms after filling all visible fields.
5. If you reach a payment page, DO NOT submit real payment details — document
   what is requested and stop.
6. If the page asks for a CAPTCHA you cannot solve, respond with FAIL.
7. When you believe the funnel is complete (confirmation page, dead end,
   or no more meaningful actions), respond with DONE.
8. Never exceed {max_steps} total steps.

Respond ONLY with valid JSON matching this schema:
{{
  "reasoning": "<brief explanation of what you see and why you chose this action>",
  "action_type": "<one of: click, type, select, scroll, wait, navigate, submit, done, fail>",
  "element_index": <integer index of the target element, or null>,
  "value": "<text to type, option to select, URL to navigate to, or empty string>"
}}
"""

_IDENTITY_BLOCK = """\
--- Synthetic Identity (use this data when filling forms) ---
Name: {first_name} {last_name}
Email: {email}
Phone: {phone}
Address: {street_address}, {city}, {state} {zip_code}
DOB: {date_of_birth}
SSN: {ssn}
Credit Card: {credit_card_number} Exp: {credit_card_expiry} CVV: {credit_card_cvv}
Username: {username}
Password: {password}
"""


@dataclass
class LLMResponse:
    """Parsed LLM response with token tracking."""

    action: AgentAction
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    raw_response: str = ""


class AgentLLMClient:
    """LLM client for the browser interaction agent.

    Delegates to the pluggable ``LLMProvider`` abstraction so the same
    agent code works with Ollama, Gemini, or any future backend.

    Args:
        llm: An ``LLMProvider`` instance.  Defaults to one built from settings.
        max_steps: Maximum agent interaction steps.
    """

    def __init__(
        self,
        llm: LLMProvider | None = None,
        max_steps: int = 20,
    ) -> None:
        if llm is None:
            from ssi.llm.factory import create_llm_provider

            llm = create_llm_provider()
        self._llm = llm
        self.max_steps = max_steps
        self._system_prompt = _SYSTEM_PROMPT.format(max_steps=max_steps)

    @classmethod
    def from_settings(cls) -> "AgentLLMClient":
        """Create client from SSI settings."""
        from ssi.llm.factory import create_llm_provider

        return cls(llm=create_llm_provider(), max_steps=20)

    def decide_action(
        self,
        observation: PageObservation,
        identity: SyntheticIdentity,
        history: list[dict[str, str]] | None = None,
    ) -> LLMResponse:
        """Ask the LLM what action to take given the current page state.

        Args:
            observation: Current page observation with DOM summary.
            identity: Synthetic identity for form filling.
            history: Previous message exchanges for context continuity.

        Returns:
            Parsed ``LLMResponse`` with the decided action and token metrics.
        """
        messages = self._build_messages(observation, identity, history)

        result = self._llm.chat(messages, json_mode=True)

        action = self._parse_action(result.content)

        return LLMResponse(
            action=action,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            latency_ms=result.latency_ms,
            raw_response=result.content,
        )

    def check_connectivity(self) -> bool:
        """Verify the LLM provider is reachable and the model is available."""
        return self._llm.check_connectivity()

    def close(self) -> None:
        """Close the LLM provider."""
        self._llm.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_messages(
        self,
        observation: PageObservation,
        identity: SyntheticIdentity,
        history: list[dict[str, str]] | None,
    ) -> list[dict[str, str]]:
        """Assemble the chat message list for the LLM."""
        identity_block = _IDENTITY_BLOCK.format(
            first_name=identity.first_name,
            last_name=identity.last_name,
            email=identity.email,
            phone=identity.phone,
            street_address=identity.street_address,
            city=identity.city,
            state=identity.state,
            zip_code=identity.zip_code,
            date_of_birth=identity.date_of_birth,
            ssn=identity.ssn,
            credit_card_number=identity.credit_card_number,
            credit_card_expiry=identity.credit_card_expiry,
            credit_card_cvv=identity.credit_card_cvv,
            username=identity.username,
            password=identity.password,
        )

        messages: list[dict[str, str]] = [
            {"role": "system", "content": self._system_prompt + "\n\n" + identity_block},
        ]

        # Append conversation history
        if history:
            messages.extend(history)

        # Current observation as the new user message
        user_msg = (
            f"Step observation:\n\n{observation.dom_summary}\n\n"
            "What is the best next action? Respond with JSON only."
        )
        messages.append({"role": "user", "content": user_msg})

        return messages

    def _parse_action(self, content: str) -> AgentAction:
        """Parse the LLM's JSON response into an ``AgentAction``.

        Handles common LLM quirks: markdown code fences, extra text, etc.
        """
        # Strip markdown code fences if present
        content = content.strip()
        if content.startswith("```"):
            # Remove opening fence (```json or ```)
            content = content.split("\n", 1)[-1] if "\n" in content else content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response as JSON: %s", content[:200])
            return AgentAction(
                action_type=ActionType.FAIL,
                reasoning=f"LLM returned unparseable response: {content[:200]}",
            )

        # Map action_type string to enum
        action_str = data.get("action_type", "fail").lower().strip()
        try:
            action_type = ActionType(action_str)
        except ValueError:
            logger.warning("Unknown action type from LLM: %s", action_str)
            action_type = ActionType.FAIL

        return AgentAction(
            action_type=action_type,
            element_index=data.get("element_index"),
            value=data.get("value", ""),
            reasoning=data.get("reasoning", ""),
        )
