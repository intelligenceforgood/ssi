"""Configuration loader for SSI using Pydantic settings.

Config precedence (highest wins):
  1. CLI flags (where applicable)
  2. Environment variables (SSI_* with __ for nesting)
  3. settings.local.toml
  4. settings.default.toml
"""

from __future__ import annotations

import os
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = Path(os.getenv("SSI_PROJECT_ROOT", _THIS_DIR.parents[2]))
CONFIG_DIR = PROJECT_ROOT / "config"

ENV_VAR_NAME = "SSI_ENV"
DEFAULT_ENV = "local"


def _resolve_env() -> str:
    return (os.getenv(ENV_VAR_NAME) or DEFAULT_ENV).strip()


def _load_toml(path: Path) -> dict[str, Any]:
    if path.is_file():
        with open(path, "rb") as f:
            return tomllib.load(f)
    return {}


# ---------------------------------------------------------------------------
# Section models
# ---------------------------------------------------------------------------


class LLMSettings(BaseSettings):
    """LLM provider configuration."""

    model_config = SettingsConfigDict(env_prefix="SSI_LLM__")

    provider: str = "ollama"
    model: str = "llama3.1"
    ollama_base_url: str = "http://localhost:11434"
    temperature: float = 0.1
    max_tokens: int = 4096
    token_budget_per_session: int = 50_000


class BrowserSettings(BaseSettings):
    """Playwright browser settings."""

    model_config = SettingsConfigDict(env_prefix="SSI_BROWSER__")

    headless: bool = True
    timeout_ms: int = 30_000
    user_agent: str = ""
    proxy: str = ""
    record_har: bool = True
    record_video: bool = False
    sandbox: bool = True


class OSINTSettings(BaseSettings):
    """OSINT API keys and configuration."""

    model_config = SettingsConfigDict(env_prefix="SSI_OSINT__")

    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    ipinfo_token: str = ""
    maxmind_license_key: str = ""
    whois_timeout_sec: int = 10
    dns_timeout_sec: int = 5


class EvidenceSettings(BaseSettings):
    """Evidence storage configuration."""

    model_config = SettingsConfigDict(env_prefix="SSI_EVIDENCE__")

    output_dir: str = "data/evidence"
    storage_backend: str = "local"
    gcs_bucket: str = ""
    gcs_prefix: str = "ssi/evidence"
    retain_days: int = 365


class IdentityVaultSettings(BaseSettings):
    """Synthetic identity vault configuration."""

    model_config = SettingsConfigDict(env_prefix="SSI_IDENTITY__")

    default_locale: str = "en_US"
    db_url: str = "sqlite:///data/identity_vault.db"
    rotate_per_session: bool = True


class StealthSettings(BaseSettings):
    """Anti-detection / stealth configuration."""

    model_config = SettingsConfigDict(env_prefix="SSI_STEALTH__")

    proxy_urls: list[str] = Field(default_factory=list)
    rotation_strategy: str = "round_robin"  # round_robin | random
    randomize_fingerprint: bool = True
    apply_stealth_scripts: bool = True


class CaptchaSettings(BaseSettings):
    """CAPTCHA detection and handling configuration."""

    model_config = SettingsConfigDict(env_prefix="SSI_CAPTCHA__")

    strategy: str = "skip"  # skip | wait | accessibility | solver
    solver_api_key: str = ""
    wait_seconds: int = 15
    screenshot_on_detect: bool = True


class CostSettings(BaseSettings):
    """Cost monitoring and budget enforcement."""

    model_config = SettingsConfigDict(env_prefix="SSI_COST__")

    budget_per_investigation_usd: float = 1.0
    warn_at_pct: int = 80
    enabled: bool = True


class FeedbackSettings(BaseSettings):
    """Investigation feedback loop configuration."""

    model_config = SettingsConfigDict(env_prefix="SSI_FEEDBACK__")

    db_path: str = "data/evidence/feedback.db"
    enabled: bool = True


class APISettings(BaseSettings):
    """API server configuration."""

    model_config = SettingsConfigDict(env_prefix="SSI_API__")

    host: str = "0.0.0.0"
    port: int = 8100
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]
    rate_limit_per_minute: int = 30
    require_auth: bool = False


class IntegrationSettings(BaseSettings):
    """Settings for integration with the i4g core platform."""

    model_config = SettingsConfigDict(env_prefix="SSI_INTEGRATION__")

    core_api_url: str = "http://localhost:8000"
    push_to_core: bool = False
    trigger_dossier: bool = False
    dataset: str = "ssi"


# ---------------------------------------------------------------------------
# Root settings
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    """Root SSI settings with nested sections."""

    model_config = SettingsConfigDict(
        env_prefix="SSI_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    env: str = Field(default_factory=_resolve_env)
    project_root: Path = Field(default=PROJECT_ROOT)
    debug: bool = False

    llm: LLMSettings = Field(default_factory=LLMSettings)
    browser: BrowserSettings = Field(default_factory=BrowserSettings)
    osint: OSINTSettings = Field(default_factory=OSINTSettings)
    evidence: EvidenceSettings = Field(default_factory=EvidenceSettings)
    identity: IdentityVaultSettings = Field(default_factory=IdentityVaultSettings)
    api: APISettings = Field(default_factory=APISettings)
    integration: IntegrationSettings = Field(default_factory=IntegrationSettings)
    stealth: StealthSettings = Field(default_factory=StealthSettings)
    captcha: CaptchaSettings = Field(default_factory=CaptchaSettings)
    cost: CostSettings = Field(default_factory=CostSettings)
    feedback: FeedbackSettings = Field(default_factory=FeedbackSettings)

    @model_validator(mode="before")
    @classmethod
    def _merge_toml_files(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Layer TOML config files before env var overrides."""
        defaults = _load_toml(CONFIG_DIR / "settings.default.toml")
        env_name = (values.get("env") or os.getenv(ENV_VAR_NAME) or DEFAULT_ENV).strip()
        env_overrides = _load_toml(CONFIG_DIR / f"settings.{env_name}.toml")
        local_overrides = _load_toml(CONFIG_DIR / "settings.local.toml")

        # Merge: defaults < env-specific < local < explicit values
        merged: dict[str, Any] = {}
        for layer in (defaults, env_overrides, local_overrides, values):
            for key, val in layer.items():
                if isinstance(val, dict) and isinstance(merged.get(key), dict):
                    merged[key] = {**merged[key], **val}
                else:
                    merged[key] = val
        return merged

    @model_validator(mode="after")
    def _resolve_paths(self) -> "Settings":
        """Normalize relative paths against project_root."""
        root = self.project_root
        if not Path(self.evidence.output_dir).is_absolute():
            self.evidence.output_dir = str(root / self.evidence.output_dir)
        if self.identity.db_url.startswith("sqlite:///") and not Path(
            self.identity.db_url.replace("sqlite:///", "")
        ).is_absolute():
            rel = self.identity.db_url.replace("sqlite:///", "")
            self.identity.db_url = f"sqlite:///{root / rel}"
        if not Path(self.feedback.db_path).is_absolute():
            self.feedback.db_path = str(root / self.feedback.db_path)
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton settings instance (cached)."""
    return Settings()
