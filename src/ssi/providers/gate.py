"""Provider gating primitive for quota-gated external API integrations.

Every PhishDestroy OSINT module that requires an external paid API
must use ``ProviderGate`` to guard its entry point — see
``copilot/.github/shared/phishdestroy-provider-gating.instructions.md §3``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

SkipReason = Literal["quota_gated", "auth_expired", "rate_limited", "disabled"]


@dataclass(frozen=True)
class SkippedResult:
    """Structured skip signal emitted when a provider is not active.

    Never raise an exception for a skipped provider — return this value
    so callers can distinguish "provider ran and found nothing" from
    "provider did not run".
    """

    provider: str
    reason: SkipReason
    detail: str = ""


@dataclass
class ProviderGate:
    """Gate for a single named external provider.

    Reads configuration exclusively from environment variables using the
    ``SSI_PROVIDERS__{NAME}__`` prefix.  This keeps provider credentials
    out of the TOML config tree and isolated from the settings loader.
    """

    name: str

    @property
    def env_prefix(self) -> str:
        """Return the env-var prefix for this provider (e.g. ``SSI_PROVIDERS__MERKLEMAP__``)."""
        return f"SSI_PROVIDERS__{self.name.upper()}__"

    @property
    def api_key(self) -> str:
        """Return the provider's API key from the environment, or empty string."""
        return os.environ.get(f"{self.env_prefix}API_KEY", "").strip()

    @property
    def enabled(self) -> bool:
        """Return ``True`` iff BOTH the ``ENABLED`` flag is truthy AND ``api_key`` is non-empty."""
        flag = os.environ.get(f"{self.env_prefix}ENABLED", "").strip().lower()
        _bool_true = {"1", "true", "yes", "on"}
        return flag in _bool_true and bool(self.api_key)

    def skip(self, reason: SkipReason, detail: str = "") -> SkippedResult:
        """Return a structured ``SkippedResult`` for this provider."""
        return SkippedResult(provider=self.name, reason=reason, detail=detail)
