"""LLM client for the browser interaction agent.

Calls Ollama (or compatible endpoint) and returns structured actions.
Tracks token usage for budget enforcement and measurement.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

import httpx

from ssi.identity.vault import SyntheticIdentity
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
    """Thin client for calling an Ollama-compatible LLM.

    Uses Ollama's ``/api/chat`` endpoint directly for precise token
    counting.  Falls back to langchain-ollama if needed in the future.

    Args:
        base_url: Ollama base URL (e.g. ``http://localhost:11434``).
        model: Model name (e.g. ``llama3.3``).
        temperature: Sampling temperature.
        max_tokens: Maximum generation tokens per call.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.3",
        temperature: float = 0.1,
        max_tokens: int = 1024,
        max_steps: int = 20,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_steps = max_steps
        self._client = httpx.Client(timeout=120.0)
        self._system_prompt = _SYSTEM_PROMPT.format(max_steps=max_steps)

    @classmethod
    def from_settings(cls) -> "AgentLLMClient":
        """Create client from SSI settings."""
        from ssi.settings import get_settings

        s = get_settings()
        return cls(
            base_url=s.llm.ollama_base_url,
            model=s.llm.model,
            temperature=s.llm.temperature,
            max_tokens=s.llm.max_tokens,
            max_steps=20,
        )

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

        start = time.monotonic()
        raw = self._call_ollama(messages)
        latency_ms = (time.monotonic() - start) * 1000

        action = self._parse_action(raw.get("message", {}).get("content", ""))

        return LLMResponse(
            action=action,
            input_tokens=raw.get("prompt_eval_count", 0),
            output_tokens=raw.get("eval_count", 0),
            latency_ms=latency_ms,
            raw_response=raw.get("message", {}).get("content", ""),
        )

    def check_connectivity(self) -> bool:
        """Verify the Ollama server is reachable and the model is available."""
        try:
            resp = self._client.get(f"{self.base_url}/api/tags")
            if resp.status_code != 200:
                return False
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            # Check if any model name starts with our target (handles :latest tag)
            return any(m.startswith(self.model.split(":")[0]) for m in models)
        except Exception:
            return False

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

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

    def _call_ollama(self, messages: list[dict[str, str]]) -> dict:
        """Make a synchronous call to Ollama's chat endpoint."""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
            "format": "json",
        }

        try:
            resp = self._client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            logger.error("Ollama HTTP error: %s %s", e.response.status_code, e.response.text[:500])
            raise
        except httpx.ConnectError:
            logger.error("Cannot connect to Ollama at %s — is it running?", self.base_url)
            raise

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
