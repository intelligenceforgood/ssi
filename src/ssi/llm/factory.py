"""Factory for creating LLM provider instances from SSI settings."""

from __future__ import annotations

import logging

from ssi.llm.base import LLMProvider

logger = logging.getLogger(__name__)


def create_llm_provider(provider: str | None = None) -> LLMProvider:
    """Create an LLM provider from settings or an explicit provider name.

    Args:
        provider: Override provider name (``ollama`` or ``gemini``).
            If None, reads from ``get_settings().llm.provider``.

    Returns:
        A configured ``LLMProvider`` instance.

    Raises:
        ValueError: If the provider name is not recognized.
    """
    from ssi.settings import get_settings

    settings = get_settings()
    provider_name = (provider or settings.llm.provider).lower().strip()

    if provider_name == "ollama":
        from ssi.llm.ollama_provider import OllamaProvider

        return OllamaProvider(
            base_url=settings.llm.ollama_base_url,
            model=settings.llm.model,
            temperature=settings.llm.temperature,
            max_tokens=settings.llm.max_tokens,
        )

    if provider_name == "gemini":
        from ssi.llm.gemini_provider import GeminiProvider

        return GeminiProvider(
            model=settings.llm.model,
            project=settings.llm.gcp_project,
            location=settings.llm.gcp_location,
            temperature=settings.llm.temperature,
            max_tokens=settings.llm.max_tokens,
        )

    raise ValueError(
        f"Unknown LLM provider: {provider_name!r}. "
        f"Supported: ollama, gemini"
    )
