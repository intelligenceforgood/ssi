"""Ollama LLM provider for SSI — local/self-hosted models."""

from __future__ import annotations

import logging
import time

import httpx

from ssi.llm.base import LLMProvider, LLMResult

logger = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    """LLM provider backed by a local Ollama server.

    Uses Ollama's ``/api/chat`` endpoint for precise token counting.

    Args:
        base_url: Ollama server URL (e.g. ``http://localhost:11434``).
        model: Model name (e.g. ``llama3.1``).
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

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()
