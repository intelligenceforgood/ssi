"""Factory for creating LLM provider instances from SSI settings."""

from __future__ import annotations

import logging

from ssi.llm.base import LLMProvider

logger = logging.getLogger(__name__)


def create_llm_provider(provider: str | None = None) -> LLMProvider:
    """Create an LLM provider from settings or an explicit provider name.

    The returned provider is automatically wrapped with
    ``RetryingLLMProvider`` for resilience against transient errors.

    Args:
        provider: Override provider name (``ollama`` or ``gemini``).
            If None, reads from ``get_settings().llm.provider``.

    Returns:
        A configured ``LLMProvider`` instance (with retry wrapper).

    Raises:
        ValueError: If the provider name is not recognized.
    """
    from ssi.settings import get_settings

    settings = get_settings()
    provider_name = (provider or settings.llm.provider).lower().strip()

    base: LLMProvider

    if provider_name == "ollama":
        from ssi.llm.ollama_provider import OllamaProvider

        base = OllamaProvider(
            base_url=settings.llm.ollama_base_url,
            model=settings.llm.model,
            temperature=settings.llm.temperature,
            max_tokens=settings.llm.max_tokens,
        )

    elif provider_name == "gemini":
        from ssi.llm.gemini_provider import GeminiProvider

        base = GeminiProvider(
            model=settings.llm.model,
            project=settings.llm.gcp_project,
            location=settings.llm.gcp_location,
            temperature=settings.llm.temperature,
            max_tokens=settings.llm.max_tokens,
        )

    else:
        raise ValueError(
            f"Unknown LLM provider: {provider_name!r}. "
            f"Supported: ollama, gemini"
        )

    # Wrap with retry logic for resilience
    from ssi.llm.retry import RetryingLLMProvider

    return RetryingLLMProvider(base, max_retries=3, base_delay=1.0)
