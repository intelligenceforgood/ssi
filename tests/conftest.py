"""SSI test configuration — shared fixtures for unit and integration tests."""

from __future__ import annotations

from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SCAM_SITES_DIR = FIXTURES_DIR / "scam_sites"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_settings_cache() -> Generator[None, None, None]:
    """Clear the settings LRU cache between tests."""
    from ssi.settings.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


@pytest.fixture()
def scan_store(tmp_path: Path) -> ScanStore:
    """Create a disposable ``ScanStore`` backed by a temporary SQLite DB."""
    from ssi.store.scan_store import ScanStore

    return ScanStore(db_path=tmp_path / "test_scan.db")


# ---------------------------------------------------------------------------
# Mock LLM
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_llm_provider() -> MagicMock:
    """Return a ``MagicMock`` conforming to the ``LLMProvider`` interface.

    Default behaviour: returns a JSON blob with a no-op action so
    orchestrator and agent tests can run without a real LLM.
    """
    from ssi.llm.base import LLMProvider, LLMResult

    mock = MagicMock(spec=LLMProvider)
    mock.check_connectivity.return_value = True
    mock.chat.return_value = LLMResult(
        content='{"action": "none", "reasoning": "mock"}',
        input_tokens=100,
        output_tokens=50,
        model="mock",
    )
    mock.chat_with_images.return_value = LLMResult(
        content='{"action": "none", "reasoning": "mock vision"}',
        input_tokens=200,
        output_tokens=50,
        model="mock",
    )
    mock.close.return_value = None
    return mock


# ---------------------------------------------------------------------------
# Scam-site fixtures (HTML paths)
# ---------------------------------------------------------------------------


@pytest.fixture()
def register_page() -> Path:
    """Path to the fake exchange registration page fixture."""
    return SCAM_SITES_DIR / "register.html"


@pytest.fixture()
def deposit_page() -> Path:
    """Path to the fake exchange deposit page with wallet addresses."""
    return SCAM_SITES_DIR / "deposit.html"


@pytest.fixture()
def phishing_page() -> Path:
    """Path to the phishing page (credit card harvest) fixture."""
    return SCAM_SITES_DIR / "phishing.html"


# ---------------------------------------------------------------------------
# Phase 1 scam-type fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tech_support_page() -> Path:
    """Path to the tech-support scam page fixture."""
    return SCAM_SITES_DIR / "tech_support.html"


@pytest.fixture()
def fake_shop_page() -> Path:
    """Path to the fake e-commerce shop page fixture."""
    return SCAM_SITES_DIR / "fake_shop.html"


@pytest.fixture()
def romance_scam_page() -> Path:
    """Path to the romance / dating scam page fixture."""
    return SCAM_SITES_DIR / "romance_scam.html"


@pytest.fixture()
def crypto_mining_page() -> Path:
    """Path to the crypto mining scam page fixture."""
    return SCAM_SITES_DIR / "crypto_mining.html"


@pytest.fixture()
def employment_scam_page() -> Path:
    """Path to the employment scam page fixture."""
    return SCAM_SITES_DIR / "employment_scam.html"


@pytest.fixture()
def prize_lottery_page() -> Path:
    """Path to the prize / lottery scam page fixture."""
    return SCAM_SITES_DIR / "prize_lottery.html"


@pytest.fixture()
def gov_impersonation_page() -> Path:
    """Path to the government impersonation scam page fixture."""
    return SCAM_SITES_DIR / "gov_impersonation.html"


@pytest.fixture()
def bank_phishing_page() -> Path:
    """Path to the bank phishing page fixture."""
    return SCAM_SITES_DIR / "bank_phishing.html"


@pytest.fixture()
def charity_scam_page() -> Path:
    """Path to the charity scam page fixture."""
    return SCAM_SITES_DIR / "charity_scam.html"


@pytest.fixture()
def extortion_page() -> Path:
    """Path to the extortion / sextortion scam page fixture."""
    return SCAM_SITES_DIR / "extortion.html"


@pytest.fixture()
def investment_platform_page() -> Path:
    """Path to the investment platform scam page fixture."""
    return SCAM_SITES_DIR / "investment_platform.html"


@pytest.fixture()
def malware_download_page() -> Path:
    """Path to the malware download lure page fixture."""
    return SCAM_SITES_DIR / "malware_download.html"


@pytest.fixture()
def social_phishing_page() -> Path:
    """Path to the social media phishing page fixture."""
    return SCAM_SITES_DIR / "social_phishing.html"


@pytest.fixture()
def crypto_airdrop_page() -> Path:
    """Path to the crypto airdrop scam page fixture."""
    return SCAM_SITES_DIR / "crypto_airdrop.html"


@pytest.fixture()
def subscription_trap_page() -> Path:
    """Path to the subscription trap page fixture."""
    return SCAM_SITES_DIR / "subscription_trap.html"


@pytest.fixture()
def tech_company_phishing_page() -> Path:
    """Path to the tech company phishing page fixture."""
    return SCAM_SITES_DIR / "tech_company_phishing.html"


@pytest.fixture()
def sms_delivery_phish_page() -> Path:
    """Path to the SMS delivery phishing page fixture."""
    return SCAM_SITES_DIR / "sms_delivery_phish.html"


@pytest.fixture()
def survey_reward_page() -> Path:
    """Path to the survey reward scam page fixture."""
    return SCAM_SITES_DIR / "survey_reward.html"


@pytest.fixture()
def marketplace_escrow_page() -> Path:
    """Path to the marketplace escrow scam page fixture."""
    return SCAM_SITES_DIR / "marketplace_escrow.html"


@pytest.fixture()
def pig_butchering_page() -> Path:
    """Path to the pig butchering scam page fixture."""
    return SCAM_SITES_DIR / "pig_butchering.html"


# ---------------------------------------------------------------------------
# CAPTCHA fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def captcha_recaptcha_page() -> Path:
    """Path to the reCAPTCHA fixture page."""
    return SCAM_SITES_DIR / "captcha_recaptcha.html"


@pytest.fixture()
def captcha_hcaptcha_page() -> Path:
    """Path to the hCaptcha fixture page."""
    return SCAM_SITES_DIR / "captcha_hcaptcha.html"


@pytest.fixture()
def captcha_turnstile_page() -> Path:
    """Path to the Cloudflare Turnstile fixture page."""
    return SCAM_SITES_DIR / "captcha_turnstile.html"


# ---------------------------------------------------------------------------
# Pytest markers
# ---------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: marks tests that require external services or real I/O")
    config.addinivalue_line("markers", "slow: marks tests that take more than a few seconds")
    config.addinivalue_line("markers", "benchmark: marks performance benchmark tests")
