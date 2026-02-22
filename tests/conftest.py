"""SSI test configuration — shared fixtures for unit and integration tests."""

from __future__ import annotations

from pathlib import Path
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
def _reset_settings_cache():
    """Clear the settings LRU cache between tests."""
    from ssi.settings.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


@pytest.fixture()
def scan_store(tmp_path: Path):
    """Create a disposable ``ScanStore`` backed by a temporary SQLite DB."""
    from ssi.store.scan_store import ScanStore

    return ScanStore(db_path=tmp_path / "test_scan.db")


# ---------------------------------------------------------------------------
# Mock LLM
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_llm_provider():
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
# Pytest markers
# ---------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: marks tests that require external services or real I/O")
    config.addinivalue_line("markers", "slow: marks tests that take more than a few seconds")
