"""Factory for creating LLM provider instances from SSI settings.

Supports three flavours:

    create_llm_provider()           — primary model (default)
    create_llm_provider(role="cheap")  — cheap/fast model for routine states
    create_llm_provider(role="vision") — vision-capable model override (Ollama)

When ``role`` is ``"cheap"`` or ``"vision"`` but the corresponding setting
(``llm.cheap_model`` / ``llm.vision_model``) is empty, the primary model
is used as a transparent fallback.
"""

from __future__ import annotations

import logging

from ssi.llm.base import LLMProvider

logger = logging.getLogger(__name__)


def create_llm_provider(
    provider: str | None = None,
    *,
    role: str = "primary",
) -> LLMProvider:
    """Create an LLM provider from settings or an explicit provider name.

    The returned provider is automatically wrapped with
    ``RetryingLLMProvider`` for resilience against transient errors.

    Args:
        provider: Override provider name (``ollama`` or ``gemini``).
            If None, reads from ``get_settings().llm.provider``.
        role: Which model variant to use.  One of:
            ``"primary"`` — the default/expensive model.
            ``"cheap"`` — the lightweight model for routine agent states.
            ``"vision"`` — the vision-capable model (Ollama override).

    Returns:
        A configured ``LLMProvider`` instance (with retry wrapper).

    Raises:
        ValueError: If the provider name is not recognized.
    """
    from ssi.settings import get_settings

    settings = get_settings()
    provider_name = (provider or settings.llm.provider).lower().strip()

    # Resolve model name based on role
    model = _resolve_model(settings.llm, role)

    base: LLMProvider

    if provider_name == "ollama":
        from ssi.llm.ollama_provider import OllamaProvider

        base = OllamaProvider(
            base_url=settings.llm.ollama_base_url,
            model=model,
            temperature=settings.llm.temperature,
            max_tokens=settings.llm.max_tokens,
        )

    elif provider_name == "gemini":
        from ssi.llm.gemini_provider import GeminiProvider

        base = GeminiProvider(
            model=model,
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

    logger.info("Created LLM provider: provider=%s model=%s role=%s", provider_name, model, role)

    # Wrap with retry logic for resilience
    from ssi.llm.retry import RetryingLLMProvider

    return RetryingLLMProvider(base, max_retries=3, base_delay=1.0)


def _resolve_model(llm_settings: "LLMSettings", role: str) -> str:  # noqa: F821
    """Resolve the concrete model name for the given role.

    Falls back to the primary model when the role-specific setting is empty.

    Args:
        llm_settings: The ``LLMSettings`` instance.
        role: One of ``"primary"``, ``"cheap"``, ``"vision"``.

    Returns:
        The model name to use.
    """
    if role == "cheap" and llm_settings.cheap_model:
        return llm_settings.cheap_model
    if role == "vision" and llm_settings.vision_model:
        return llm_settings.vision_model
    return llm_settings.model
