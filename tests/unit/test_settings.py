"""Unit tests for SSI settings.

Covers default loading, env var overrides, dev profile, path resolution,
and validation for all 17 settings sections: llm, browser, zen_browser,
proxy, agent, osint, evidence, identity, api, integration, stealth,
captcha, cost, storage, feedback, playbook, monitoring.
"""

from __future__ import annotations

import os


class TestSettings:
    """Core settings loading and override mechanics."""

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

    def test_dev_profile_loads_gemini(self, monkeypatch):
        """SSI_ENV=dev should load settings.dev.toml with Gemini provider."""
        monkeypatch.setenv("SSI_ENV", "dev")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.env == "dev"
        assert s.llm.provider == "gemini"
        assert s.llm.model == "gemini-2.0-flash"
        assert s.llm.gcp_project == "i4g-dev"

    def test_dev_profile_gcs_evidence(self, monkeypatch):
        """Dev profile should enable GCS evidence storage."""
        monkeypatch.setenv("SSI_ENV", "dev")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.evidence.storage_backend == "gcs"
        assert s.evidence.gcs_bucket == "i4g-dev-ssi-evidence"
        assert s.evidence.gcs_prefix == "investigations"

    def test_dev_profile_sandbox_disabled(self, monkeypatch):
        """Dev profile should disable browser sandbox for Cloud Run."""
        monkeypatch.setenv("SSI_ENV", "dev")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.browser.sandbox is False

    def test_nested_env_var_override_double_underscore(self, monkeypatch):
        """Double-underscore nested env vars should override section fields."""
        monkeypatch.setenv("SSI_COST__BUDGET_PER_INVESTIGATION_USD", "5.0")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.cost.budget_per_investigation_usd == 5.0

    def test_multiple_section_overrides(self, monkeypatch):
        """Multiple env overrides across sections should all apply."""
        monkeypatch.setenv("SSI_API__PORT", "9999")
        monkeypatch.setenv("SSI_PROXY__ENABLED", "true")
        monkeypatch.setenv("SSI_MONITORING__WEBSOCKET_ENABLED", "false")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.api.port == 9999
        assert s.proxy.enabled is True
        assert s.monitoring.websocket_enabled is False


class TestLLMSettings:
    """LLM settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.llm.provider == "ollama"
        assert s.llm.temperature == 0.1
        assert s.llm.max_tokens == 4096
        assert s.llm.token_budget_per_session == 100_000
        assert s.llm.gcp_location == "us-central1"

    def test_gcp_project_override(self, monkeypatch):
        monkeypatch.setenv("SSI_LLM__GCP_PROJECT", "my-project")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.llm.gcp_project == "my-project"


class TestBrowserSettings:
    """Browser (Playwright) settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.browser.headless is True
        assert s.browser.timeout_ms == 30_000
        assert s.browser.sandbox is True
        assert s.browser.record_har is True
        assert s.browser.record_video is False


class TestZenBrowserSettings:
    """Zendriver browser settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.zen_browser.headless is True
        assert s.zen_browser.page_zoom == 0.75
        assert s.zen_browser.action_timeout == 15
        assert s.zen_browser.page_load_timeout == 45
        assert s.zen_browser.screenshot_resize_width == 1280
        assert s.zen_browser.screenshot_resize_height == 720

    def test_chrome_binary_override(self, monkeypatch):
        monkeypatch.setenv("SSI_ZEN_BROWSER__CHROME_BINARY", "/usr/bin/chromium")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.zen_browser.chrome_binary == "/usr/bin/chromium"


class TestProxySettings:
    """Proxy settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.proxy.enabled is False
        assert s.proxy.host == "gate.decodo.com"
        assert s.proxy.port == "10001"


class TestAgentSettings:
    """Agent (state machine) settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.agent.max_actions_per_site == 80
        assert s.agent.dom_inspection_enabled is True
        assert s.agent.dom_direct_threshold == 75
        assert s.agent.dom_assisted_threshold == 40
        assert s.agent.max_repeated_actions == 3

    def test_stuck_thresholds_dict(self):
        from ssi.settings.config import Settings

        s = Settings()
        thresholds = s.agent.stuck_thresholds
        assert thresholds["DEFAULT"] == 10
        assert thresholds["LOAD_SITE"] == 5
        assert thresholds["EXTRACT_WALLETS"] == 20
        assert len(thresholds) == 8

    def test_blank_page_max_retries_dict(self):
        from ssi.settings.config import Settings

        s = Settings()
        retries = s.agent.blank_page_max_retries
        assert retries["DEFAULT"] == 4
        assert retries["FIND_REGISTER"] == 8
        assert len(retries) == 3

    def test_cheap_model_states(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert "FILL_REGISTER" in s.agent.cheap_model_states
        assert "SUBMIT_REGISTER" in s.agent.cheap_model_states


class TestOSINTSettings:
    """OSINT settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.osint.whois_timeout_sec == 10
        assert s.osint.dns_timeout_sec == 5
        assert s.osint.virustotal_api_key == ""
        assert s.osint.ipinfo_token == ""

    def test_api_key_override(self, monkeypatch):
        monkeypatch.setenv("SSI_OSINT__VIRUSTOTAL_API_KEY", "test-key-123")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.osint.virustotal_api_key == "test-key-123"

    def test_ipinfo_token_override(self, monkeypatch):
        """SSI_OSINT__IPINFO_TOKEN should set the ipinfo.io API token."""
        monkeypatch.setenv("SSI_OSINT__IPINFO_TOKEN", "tok_test_abc123")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.osint.ipinfo_token == "tok_test_abc123"


class TestEvidenceSettings:
    """Evidence storage settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.evidence.storage_backend == "local"
        assert s.evidence.retain_days == 365
        assert os.path.isabs(s.evidence.output_dir)

    def test_gcs_override(self, monkeypatch):
        monkeypatch.setenv("SSI_EVIDENCE__STORAGE_BACKEND", "gcs")
        monkeypatch.setenv("SSI_EVIDENCE__GCS_BUCKET", "my-bucket")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.evidence.storage_backend == "gcs"
        assert s.evidence.gcs_bucket == "my-bucket"


class TestCostSettings:
    """Cost monitoring settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.cost.budget_per_investigation_usd == 1.0
        assert s.cost.warn_at_pct == 80
        assert s.cost.enabled is True


class TestStorageSettings:
    """Scan persistence settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.storage.backend == "sqlite"
        assert s.storage.persist_scans is True
        assert os.path.isabs(s.storage.sqlite_path)


class TestPlaybookSettings:
    """Playbook engine settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.playbook.enabled is True
        assert s.playbook.fallback_to_llm is True
        assert s.playbook.max_duration_sec == 120
        assert os.path.isabs(s.playbook.playbook_dir)


class TestMonitoringSettings:
    """Event bus and WebSocket monitoring settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.monitoring.enabled is True
        assert s.monitoring.websocket_enabled is True
        assert s.monitoring.jsonl_output is False
        assert s.monitoring.snapshot_screenshots is True
        assert s.monitoring.max_event_history == 500
        assert s.monitoring.guidance_timeout_sec == 300


class TestAPISettings:
    """API server settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.api.host == "0.0.0.0"
        assert s.api.port == 8100
        assert s.api.require_auth is False
        assert "http://localhost:3000" in s.api.cors_origins


class TestIntegrationSettings:
    """Core platform integration settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.integration.core_api_url == "http://localhost:8000"
        assert s.integration.push_to_core is False
        assert s.integration.dataset == "ssi"


class TestStealthSettings:
    """Anti-detection / stealth settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.stealth.randomize_fingerprint is True
        assert s.stealth.apply_stealth_scripts is True
        assert s.stealth.rotation_strategy == "round_robin"
        assert s.stealth.proxy_urls == []


class TestCaptchaSettings:
    """CAPTCHA handling settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.captcha.strategy == "skip"
        assert s.captcha.wait_seconds == 15
        assert s.captcha.screenshot_on_detect is True


class TestFeedbackSettings:
    """Feedback settings section."""

    def test_defaults(self):
        from ssi.settings.config import Settings

        s = Settings()
        assert s.feedback.enabled is True
        assert os.path.isabs(s.feedback.db_path)


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
