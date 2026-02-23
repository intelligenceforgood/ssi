"""Ollama LLM provider for SSI — local/self-hosted models.

Supports both text-only and multimodal (vision) models.  When a vision
model is configured (e.g. ``gemma3``, ``llava``, ``qwen2-vl``), the
``chat_with_images()`` method sends base64-encoded images inline via
Ollama's native ``images`` message field.
"""

from __future__ import annotations

import logging
import time

import httpx

from ssi.llm.base import LLMProvider, LLMResult

logger = logging.getLogger(__name__)

# Models known to support vision (prefix match).  This is consulted by
# ``chat_with_images`` to decide whether to send images inline or fall
# back to text-only.  Extend this list as new multimodal Ollama models
# become available.
_VISION_MODEL_PREFIXES: tuple[str, ...] = (
    "gemma3",
    "llava",
    "llava-llama3",
    "llava-phi3",
    "bakllava",
    "qwen2-vl",
    "qwen3-vl",
    "moondream",
    "minicpm-v",
)


class OllamaProvider(LLMProvider):
    """LLM provider backed by a local Ollama server.

    Uses Ollama's ``/api/chat`` endpoint for precise token counting.
    Supports multimodal (vision) models via ``chat_with_images()`` when
    the configured model is in the known vision-capable list.

    Args:
        base_url: Ollama server URL (e.g. ``http://localhost:11434``).
        model: Model name (e.g. ``llama3.1`` for text, ``gemma3`` for vision).
        temperature: Default sampling temperature.
        max_tokens: Default max generation tokens.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.1",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._client = httpx.Client(timeout=120.0)

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        """Send a chat completion request to the local Ollama server.

        Args:
            messages: Conversation history as a list of ``{"role": ..., "content": ...}`` dicts.
            temperature: Sampling temperature override (``None`` uses the instance default).
            max_tokens: Max output tokens override (``None`` uses the instance default).
            json_mode: When ``True``, request a JSON-formatted response.

        Returns:
            An ``LLMResult`` with the response content and token usage metrics.
        """
        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens if max_tokens is not None else self.max_tokens

        payload: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temp,
                "num_predict": tokens,
            },
        }
        if json_mode:
            payload["format"] = "json"

        start = time.monotonic()
        try:
            resp = self._client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPStatusError as e:
            logger.error("Ollama HTTP error: %s %s", e.response.status_code, e.response.text[:500])
            raise
        except httpx.ConnectError:
            logger.error("Cannot connect to Ollama at %s — is it running?", self.base_url)
            raise

        latency_ms = (time.monotonic() - start) * 1000
        content = body.get("message", {}).get("content", "")

        return LLMResult(
            content=content,
            input_tokens=body.get("prompt_eval_count", 0),
            output_tokens=body.get("eval_count", 0),
            latency_ms=latency_ms,
            model=self.model,
            raw_response=body,
        )

    def check_connectivity(self) -> bool:
        """Return ``True`` if Ollama is reachable and the configured model is available."""
        try:
            resp = self._client.get(f"{self.base_url}/api/tags")
            if resp.status_code != 200:
                return False
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            return any(m.startswith(self.model.split(":")[0]) for m in models)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Vision support
    # ------------------------------------------------------------------

    @property
    def supports_vision(self) -> bool:
        """Return ``True`` if the configured model is known to support images."""
        model_lower = self.model.lower()
        return any(model_lower.startswith(prefix) for prefix in _VISION_MODEL_PREFIXES)

    def chat_with_images(
        self,
        messages: list[dict],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        """Send a multimodal chat request with inline base64 images.

        Accepts messages with structured content parts (same schema as the
        base class docstring).  Images are sent using Ollama's native
        ``images`` field on each message.

        If the configured model is not vision-capable, falls back to
        text-only by stripping images and calling ``chat()``.

        Args:
            messages: Chat messages — ``content`` may be a list of parts.
            temperature: Sampling temperature override.
            max_tokens: Max output tokens override.
            json_mode: When ``True``, request JSON-formatted output.

        Returns:
            An ``LLMResult`` with the generated text and token metrics.
        """
        if not self.supports_vision:
            logger.warning(
                "Model %s is not vision-capable; stripping images and falling back to text-only.",
                self.model,
            )
            text_messages = self._strip_images(messages)
            return self.chat(text_messages, temperature=temperature, max_tokens=max_tokens, json_mode=json_mode)

        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens if max_tokens is not None else self.max_tokens

        ollama_messages = self._convert_messages_for_ollama(messages)

        payload: dict = {
            "model": self.model,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": temp,
                "num_predict": tokens,
            },
        }
        if json_mode:
            payload["format"] = "json"

        start = time.monotonic()
        try:
            resp = self._client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPStatusError as e:
            logger.error("Ollama HTTP error: %s %s", e.response.status_code, e.response.text[:500])
            raise
        except httpx.ConnectError:
            logger.error("Cannot connect to Ollama at %s — is it running?", self.base_url)
            raise

        latency_ms = (time.monotonic() - start) * 1000
        content = body.get("message", {}).get("content", "")

        return LLMResult(
            content=content,
            input_tokens=body.get("prompt_eval_count", 0),
            output_tokens=body.get("eval_count", 0),
            latency_ms=latency_ms,
            model=self.model,
            raw_response=body,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _convert_messages_for_ollama(messages: list[dict]) -> list[dict]:
        """Convert structured content parts to Ollama's ``images`` format.

        Ollama expects images as a list of raw base64 strings under an
        ``images`` key on each message, rather than inline content blocks.
        """
        result: list[dict] = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content")

            if isinstance(content, str):
                result.append({"role": role, "content": content})
                continue

            # Structured content parts — extract text and images separately.
            text_parts: list[str] = []
            images: list[str] = []
            for part in content:
                if isinstance(part, dict):
                    if part.get("type") == "text":
                        text_parts.append(part["text"])
                    elif part.get("type") == "image":
                        images.append(part["data"])

            entry: dict = {"role": role, "content": "\n".join(text_parts)}
            if images:
                entry["images"] = images
            result.append(entry)

        return result

    @staticmethod
    def _strip_images(messages: list[dict]) -> list[dict[str, str]]:
        """Extract text-only content from messages that may have image parts."""
        text_messages: list[dict[str, str]] = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content")

            if isinstance(content, str):
                text_messages.append({"role": role, "content": content})
                continue

            text_parts = [
                part["text"]
                for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            ]
            text_messages.append({"role": role, "content": "\n".join(text_parts)})

        return text_messages

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()
