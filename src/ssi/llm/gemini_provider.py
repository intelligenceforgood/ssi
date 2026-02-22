"""Gemini LLM provider for SSI using the ``google-genai`` unified SDK.

Works with both backends:
- **Vertex AI** (default for cloud envs — uses ADC / service-account auth)
- **Google AI Studio** (API-key auth via ``SSI_LLM__GEMINI_API_KEY``)

The provider is selected at runtime via ``SSI_LLM__PROVIDER=gemini``.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from ssi.llm.base import LLMProvider, LLMResult

if TYPE_CHECKING:
    from google.genai import types

logger = logging.getLogger(__name__)


# Build the safety-settings list once — used by both chat() and chat_with_images().
def _safety_off() -> list["types.SafetySetting"]:
    """Return safety settings that disable all content filters.

    SSI is a fraud-analysis tool whose prompts inherently discuss scams,
    social-engineering, extortion, etc.  Disabling Gemini's safety
    filters prevents classification from being blocked.
    """
    from google.genai import types

    categories = [
        types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        types.HarmCategory.HARM_CATEGORY_HARASSMENT,
        types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
    ]
    return [
        types.SafetySetting(category=cat, threshold=types.HarmBlockThreshold.OFF)
        for cat in categories
    ]


class GeminiProvider(LLMProvider):
    """LLM provider backed by Google Gemini via the ``google-genai`` SDK.

    Uses Vertex AI (ADC) for authentication in Cloud Run, or
    Google AI Studio with an API key for local development.

    Args:
        model: Gemini model name (e.g. ``gemini-2.0-flash``).
        project: GCP project ID (Vertex AI only).
        location: GCP region (Vertex AI only, default ``us-central1``).
        temperature: Default sampling temperature.
        max_tokens: Default max output tokens.
    """

    def __init__(
        self,
        model: str = "gemini-2.0-flash",
        project: str = "",
        location: str = "us-central1",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        self.model_name = model
        self.project = project
        self.location = location
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._client = None
        self._init_client()

    def _init_client(self) -> None:
        """Initialize the ``google-genai`` client."""
        try:
            from google import genai

            self._client = genai.Client(
                vertexai=True,
                project=self.project,
                location=self.location,
            )
            logger.info(
                "Gemini provider initialized (google-genai): model=%s project=%s location=%s",
                self.model_name,
                self.project,
                self.location,
            )
        except Exception as e:
            logger.error("Failed to initialize Gemini provider: %s", e)
            raise

    # ------------------------------------------------------------------
    # Text chat
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        """Send a chat completion request to the Gemini model.

        Args:
            messages: Conversation history as a list of ``{"role": ..., "content": ...}`` dicts.
            temperature: Sampling temperature override (``None`` uses the instance default).
            max_tokens: Max output tokens override (``None`` uses the instance default).
            json_mode: When ``True``, request a JSON-formatted response.

        Returns:
            An ``LLMResult`` with the response content and token usage metrics.
        """
        from google.genai import types

        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens if max_tokens is not None else self.max_tokens

        # Extract system instruction and build content list.
        system_instruction = None
        contents: list[types.Content] = []

        for msg in messages:
            role = msg["role"]
            text = msg["content"]
            if role == "system":
                system_instruction = text
            elif role == "assistant":
                contents.append(types.Content(role="model", parts=[types.Part.from_text(text=text)]))
            else:
                contents.append(types.Content(role="user", parts=[types.Part.from_text(text=text)]))

        config = types.GenerateContentConfig(
            temperature=temp,
            max_output_tokens=tokens,
            safety_settings=_safety_off(),
            system_instruction=system_instruction,
            response_mime_type="application/json" if json_mode else None,
        )

        start = time.monotonic()
        try:
            response = self._client.models.generate_content(
                model=self.model_name,
                contents=contents,
                config=config,
            )
        except Exception as e:
            logger.error("Gemini API error: %s", e)
            raise

        return self._parse_response(response, time.monotonic() - start)

    # ------------------------------------------------------------------
    # Connectivity probe
    # ------------------------------------------------------------------

    def check_connectivity(self) -> bool:
        """Verify that Gemini is reachable with a minimal request."""
        from google.genai import types

        try:
            response = self._client.models.generate_content(
                model=self.model_name,
                contents="Say hello in one word.",
                config=types.GenerateContentConfig(max_output_tokens=10),
            )
            ok = bool(response.candidates)
            if ok:
                logger.info(
                    "Gemini connectivity OK: model=%s project=%s location=%s",
                    self.model_name,
                    self.project,
                    self.location,
                )
            else:
                logger.error(
                    "Gemini returned no candidates during connectivity check: "
                    "model=%s project=%s location=%s prompt_feedback=%s",
                    self.model_name,
                    self.project,
                    self.location,
                    getattr(response, "prompt_feedback", "N/A"),
                )
            return ok
        except Exception as e:
            logger.error(
                "Gemini connectivity check failed: model=%s project=%s location=%s error=%s",
                self.model_name,
                self.project,
                self.location,
                e,
            )
            return False

    # ------------------------------------------------------------------
    # Multimodal chat (text + images)
    # ------------------------------------------------------------------

    def chat_with_images(
        self,
        messages: list[dict],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        """Multimodal chat with inline base64 images.

        Accepts messages where ``content`` may be a list of parts::

            {"role": "user", "content": [
                {"type": "text", "text": "..."},
                {"type": "image", "media_type": "image/png", "data": "<b64>"},
            ]}
        """
        import base64

        from google.genai import types

        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens if max_tokens is not None else self.max_tokens

        system_instruction = None
        contents: list[types.Content] = []

        for msg in messages:
            role = msg["role"]
            raw_content = msg["content"]

            if role == "system":
                system_instruction = raw_content if isinstance(raw_content, str) else str(raw_content)
                continue

            gemini_role = "model" if role == "assistant" else "user"

            if isinstance(raw_content, str):
                contents.append(
                    types.Content(role=gemini_role, parts=[types.Part.from_text(text=raw_content)])
                )
                continue

            # Structured content parts (text + images)
            parts: list[types.Part] = []
            for part in raw_content:
                if part.get("type") == "text":
                    parts.append(types.Part.from_text(text=part["text"]))
                elif part.get("type") == "image":
                    image_bytes = base64.b64decode(part["data"])
                    media_type = part.get("media_type", "image/png")
                    parts.append(types.Part.from_bytes(data=image_bytes, mime_type=media_type))
            if parts:
                contents.append(types.Content(role=gemini_role, parts=parts))

        config = types.GenerateContentConfig(
            temperature=temp,
            max_output_tokens=tokens,
            safety_settings=_safety_off(),
            system_instruction=system_instruction,
            response_mime_type="application/json" if json_mode else None,
        )

        start = time.monotonic()
        try:
            response = self._client.models.generate_content(
                model=self.model_name,
                contents=contents,
                config=config,
            )
        except Exception as e:
            logger.error("Gemini multimodal API error: %s", e)
            raise

        return self._parse_response(response, time.monotonic() - start)

    # ------------------------------------------------------------------
    # Shared response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, response: "types.GenerateContentResponse", elapsed_s: float) -> LLMResult:
        """Extract text and usage from a ``GenerateContentResponse``."""
        latency_ms = elapsed_s * 1000

        usage = getattr(response, "usage_metadata", None)
        input_tokens = getattr(usage, "prompt_token_count", 0) if usage else 0
        output_tokens = getattr(usage, "candidates_token_count", 0) if usage else 0

        content_text = ""
        if response.candidates:
            candidate = response.candidates[0]
            finish_reason = getattr(candidate, "finish_reason", None)
            if finish_reason and str(finish_reason) not in ("STOP", "FinishReason.STOP", "1"):
                logger.warning(
                    "Gemini response finish_reason=%s (model=%s). Safety ratings: %s",
                    finish_reason,
                    self.model_name,
                    getattr(candidate, "safety_ratings", "N/A"),
                )
            if candidate.content and candidate.content.parts:
                content_text = candidate.content.parts[0].text
        else:
            block_reason = getattr(response, "prompt_feedback", None)
            logger.error(
                "Gemini returned no candidates (model=%s). Prompt feedback: %s",
                self.model_name,
                block_reason,
            )

        return LLMResult(
            content=content_text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            model=self.model_name,
            raw_response={"text": content_text},
        )
