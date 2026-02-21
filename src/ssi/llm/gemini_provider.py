"""Gemini (Google Generative AI / Vertex AI) LLM provider for SSI.

Uses the ``google-genai`` unified SDK which works with both:
- **Vertex AI** (``SSI_LLM__GEMINI_BACKEND=vertex``, default for cloud envs)
- **Google Generative AI** (``SSI_LLM__GEMINI_BACKEND=genai``, API-key auth)

The provider is selected at runtime based on ``SSI_LLM__PROVIDER=gemini``.
"""

from __future__ import annotations

import logging
import time

from ssi.llm.base import LLMProvider, LLMResult

logger = logging.getLogger(__name__)


class GeminiProvider(LLMProvider):
    """LLM provider backed by Google Gemini via the Vertex AI Python SDK.

    Uses ``google.cloud.aiplatform`` (Vertex AI) for authentication in
    Cloud Run, or ``google.generativeai`` for local development with an
    API key.

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
        """Initialize the Vertex AI generative model client."""
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel

            vertexai.init(project=self.project, location=self.location)
            self._client = GenerativeModel(self.model_name)
            logger.info(
                "Gemini provider initialized: model=%s project=%s location=%s",
                self.model_name,
                self.project,
                self.location,
            )
        except Exception as e:
            logger.error("Failed to initialize Gemini provider: %s", e)
            raise

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        from vertexai.generative_models import Content, GenerationConfig, HarmBlockThreshold, HarmCategory, Part

        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens if max_tokens is not None else self.max_tokens

        gen_config = GenerationConfig(
            temperature=temp,
            max_output_tokens=tokens,
        )
        if json_mode:
            gen_config = GenerationConfig(
                temperature=temp,
                max_output_tokens=tokens,
                response_mime_type="application/json",
            )

        # SSI is a fraud-analysis tool — prompts inherently discuss scams,
        # social-engineering, extortion, etc.  Disable Gemini's safety
        # filters so classification is not blocked.
        safety_settings = {
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
        }

        # Convert chat messages to Vertex AI format.
        # Gemini expects: system instruction separately, then alternating user/model.
        system_instruction = None
        contents: list[Content] = []

        for msg in messages:
            role = msg["role"]
            text = msg["content"]
            if role == "system":
                system_instruction = text
            elif role == "assistant":
                contents.append(Content(role="model", parts=[Part.from_text(text)]))
            else:
                contents.append(Content(role="user", parts=[Part.from_text(text)]))

        start = time.monotonic()
        try:
            # Re-create model with system instruction if provided
            if system_instruction:
                from vertexai.generative_models import GenerativeModel

                model = GenerativeModel(self.model_name, system_instruction=system_instruction)
            else:
                model = self._client

            response = model.generate_content(
                contents=contents,
                generation_config=gen_config,
                safety_settings=safety_settings,
            )
        except Exception as e:
            logger.error("Gemini API error: %s", e)
            raise

        latency_ms = (time.monotonic() - start) * 1000

        # Extract token usage from response metadata
        usage = getattr(response, "usage_metadata", None)
        input_tokens = getattr(usage, "prompt_token_count", 0) if usage else 0
        output_tokens = getattr(usage, "candidates_token_count", 0) if usage else 0

        content_text = ""
        if response.candidates:
            candidate = response.candidates[0]
            finish_reason = getattr(candidate, "finish_reason", None)
            if finish_reason and str(finish_reason) not in ("1", "FinishReason.STOP", "STOP"):
                logger.warning(
                    "Gemini response finish_reason=%s (model=%s). "
                    "Safety ratings: %s",
                    finish_reason,
                    self.model_name,
                    getattr(candidate, "safety_ratings", "N/A"),
                )
            if candidate.content and candidate.content.parts:
                content_text = candidate.content.parts[0].text
        else:
            # No candidates at all — likely a complete safety block
            block_reason = getattr(response, "prompt_feedback", None)
            logger.error(
                "Gemini returned no candidates (model=%s). "
                "Prompt feedback: %s",
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

    def check_connectivity(self) -> bool:
        """Verify that Gemini is reachable with a minimal request."""
        try:
            from vertexai.generative_models import GenerationConfig

            response = self._client.generate_content(
                "Say hello in one word.",
                generation_config=GenerationConfig(max_output_tokens=10),
            )
            return bool(response.candidates)
        except Exception as e:
            logger.warning("Gemini connectivity check failed: %s", e)
            return False

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

        from vertexai.generative_models import (
            Content,
            GenerationConfig,
            GenerativeModel,
            HarmBlockThreshold,
            HarmCategory,
            Part,
        )

        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens if max_tokens is not None else self.max_tokens

        gen_config = GenerationConfig(
            temperature=temp,
            max_output_tokens=tokens,
        )
        if json_mode:
            gen_config = GenerationConfig(
                temperature=temp,
                max_output_tokens=tokens,
                response_mime_type="application/json",
            )

        safety_settings = {
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
        }

        system_instruction = None
        contents: list[Content] = []

        for msg in messages:
            role = msg["role"]
            raw_content = msg["content"]

            if role == "system":
                system_instruction = raw_content if isinstance(raw_content, str) else str(raw_content)
                continue

            gemini_role = "model" if role == "assistant" else "user"

            if isinstance(raw_content, str):
                contents.append(Content(role=gemini_role, parts=[Part.from_text(raw_content)]))
                continue

            # Structured content parts (text + images)
            parts: list[Part] = []
            for part in raw_content:
                if part.get("type") == "text":
                    parts.append(Part.from_text(part["text"]))
                elif part.get("type") == "image":
                    image_bytes = base64.b64decode(part["data"])
                    media_type = part.get("media_type", "image/png")
                    parts.append(Part.from_data(data=image_bytes, mime_type=media_type))
            if parts:
                contents.append(Content(role=gemini_role, parts=parts))

        start = time.monotonic()
        try:
            if system_instruction:
                model = GenerativeModel(self.model_name, system_instruction=system_instruction)
            else:
                model = self._client

            response = model.generate_content(
                contents=contents,
                generation_config=gen_config,
                safety_settings=safety_settings,
            )
        except Exception as e:
            logger.error("Gemini multimodal API error: %s", e)
            raise

        latency_ms = (time.monotonic() - start) * 1000

        usage = getattr(response, "usage_metadata", None)
        input_tokens = getattr(usage, "prompt_token_count", 0) if usage else 0
        output_tokens = getattr(usage, "candidates_token_count", 0) if usage else 0

        content_text = ""
        if response.candidates:
            candidate = response.candidates[0]
            finish_reason = getattr(candidate, "finish_reason", None)
            if finish_reason and str(finish_reason) not in ("1", "FinishReason.STOP", "STOP"):
                logger.warning(
                    "Gemini multimodal finish_reason=%s (model=%s). Safety: %s",
                    finish_reason,
                    self.model_name,
                    getattr(candidate, "safety_ratings", "N/A"),
                )
            if candidate.content and candidate.content.parts:
                content_text = candidate.content.parts[0].text
        else:
            block_reason = getattr(response, "prompt_feedback", None)
            logger.error(
                "Gemini multimodal returned no candidates (model=%s). Prompt feedback: %s",
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
