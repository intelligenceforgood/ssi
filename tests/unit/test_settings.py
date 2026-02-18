"""Unit tests for SSI settings."""

from __future__ import annotations

import os


class TestSettings:
    def test_default_settings_load(self, monkeypatch):
        """Settings should load without any env overrides."""
        monkeypatch.delenv("SSI_ENV", raising=False)
        from ssi.settings import get_settings

        s = get_settings()
        assert s.env == "local"
        assert s.llm.provider == "ollama"

    def test_env_override(self, monkeypatch):
        """SSI_LLM__PROVIDER should override the default."""
        monkeypatch.setenv("SSI_LLM__PROVIDER", "vertex")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.llm.provider == "vertex"

    def test_paths_resolved_relative_to_project_root(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert os.path.isabs(s.evidence.output_dir)


class TestIdentityVault:
    def test_generate_identity(self):
        from ssi.identity.vault import IdentityVault

        vault = IdentityVault()
        identity = vault.generate()
        assert identity.first_name
        assert identity.last_name
        assert identity.email.endswith("@i4g-probe.net")
        assert identity.ssn.startswith("9")  # Invalid SSN range
        assert identity.credit_card_number == "4242424242424242"  # Stripe test BIN

    def test_batch_generation(self):
        from ssi.identity.vault import IdentityVault

        vault = IdentityVault()
        batch = vault.generate_batch(5)
        assert len(batch) == 5
        ids = {i.identity_id for i in batch}
        assert len(ids) == 5  # All unique
