"""Unit tests for ssi.providers.gate."""

from __future__ import annotations

import pytest

from ssi.providers.gate import ProviderGate, SkippedResult


class TestProviderGateEnvPrefix:
    def test_env_prefix_uppercases_name(self) -> None:
        gate = ProviderGate("merklemap")
        assert gate.env_prefix == "SSI_PROVIDERS__MERKLEMAP__"

    def test_env_prefix_handles_mixed_case(self) -> None:
        gate = ProviderGate("myProvider")
        assert gate.env_prefix == "SSI_PROVIDERS__MYPROVIDER__"


class TestProviderGateEnabled:
    def test_enabled_requires_both_flag_and_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__ENABLED", "true")
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__API_KEY", "secret123")
        gate = ProviderGate("testprov")
        assert gate.enabled is True

    def test_enabled_with_flag_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__ENABLED", "1")
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__API_KEY", "secret123")
        gate = ProviderGate("testprov")
        assert gate.enabled is True

    def test_disabled_when_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__ENABLED", "true")
        monkeypatch.delenv("SSI_PROVIDERS__TESTPROV__API_KEY", raising=False)
        gate = ProviderGate("testprov")
        assert gate.enabled is False

    def test_disabled_when_flag_is_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__ENABLED", "false")
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__API_KEY", "secret123")
        gate = ProviderGate("testprov")
        assert gate.enabled is False

    def test_disabled_when_flag_is_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__ENABLED", "0")
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__API_KEY", "secret123")
        gate = ProviderGate("testprov")
        assert gate.enabled is False

    def test_disabled_when_no_env_vars_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SSI_PROVIDERS__TESTPROV__ENABLED", raising=False)
        monkeypatch.delenv("SSI_PROVIDERS__TESTPROV__API_KEY", raising=False)
        gate = ProviderGate("testprov")
        assert gate.enabled is False

    def test_disabled_when_api_key_is_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__ENABLED", "true")
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__API_KEY", "")
        gate = ProviderGate("testprov")
        assert gate.enabled is False

    def test_disabled_when_api_key_is_whitespace(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__ENABLED", "true")
        monkeypatch.setenv("SSI_PROVIDERS__TESTPROV__API_KEY", "   ")
        gate = ProviderGate("testprov")
        assert gate.enabled is False


class TestProviderGateSkip:
    def test_skip_returns_skipped_result(self) -> None:
        gate = ProviderGate("testprov")
        result = gate.skip(reason="quota_gated", detail="budget not allocated")
        assert isinstance(result, SkippedResult)
        assert result.provider == "testprov"
        assert result.reason == "quota_gated"
        assert result.detail == "budget not allocated"

    def test_skip_default_detail_is_empty_string(self) -> None:
        gate = ProviderGate("testprov")
        result = gate.skip(reason="disabled")
        assert result.detail == ""

    def test_skip_all_reason_variants(self) -> None:
        gate = ProviderGate("testprov")
        for reason in ("quota_gated", "auth_expired", "rate_limited", "disabled"):
            result = gate.skip(reason=reason)  # type: ignore[arg-type]
            assert result.reason == reason

    def test_skipped_result_is_frozen(self) -> None:
        gate = ProviderGate("testprov")
        result = gate.skip(reason="disabled")
        with pytest.raises(Exception):
            result.provider = "other"  # type: ignore[misc]
