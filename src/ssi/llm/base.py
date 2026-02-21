"""Abstract LLM provider interface for SSI."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field


@dataclass
class LLMResult:
    """Unified result from any LLM provider call."""

    content: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    model: str = ""
    raw_response: dict = field(default_factory=dict)


class LLMProvider(abc.ABC):
    """Abstract interface for LLM chat completions."""

    @abc.abstractmethod
    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        """Send a chat completion request and return the result.

        Args:
            messages: Chat messages in ``[{"role": ..., "content": ...}]`` format.
            temperature: Override sampling temperature.
            max_tokens: Override max generation tokens.
            json_mode: Request JSON-only output when supported.

        Returns:
            An ``LLMResult`` with the generated text and token metrics.
        """

    def chat_with_images(
        self,
        messages: list[dict],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        """Send a multimodal chat request with inline images.

        Messages may contain structured content parts::

            [
                {"role": "system", "content": "..."},
                {"role": "user", "content": [
                    {"type": "text", "text": "Describe this image"},
                    {"type": "image", "media_type": "image/png", "data": "<base64>"},
                ]},
            ]

        The default implementation raises ``NotImplementedError``.
        Override in providers that support vision (Gemini, Ollama w/ llava, etc.).
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support multimodal chat"
        )

    @abc.abstractmethod
    def check_connectivity(self) -> bool:
        """Return True if the provider is reachable and the model is available."""

    def close(self) -> None:
        """Clean up resources. Override if needed."""
