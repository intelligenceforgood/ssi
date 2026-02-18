"""SSI test configuration."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    """Clear the settings LRU cache between tests."""
    from ssi.settings.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
