"""Unit tests for Google Auth Manager."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ssi.osint.google.auth import GoogleAuthManager


@pytest.fixture
def mock_browser():
    """Mock ZenBrowserManager."""
    browser = MagicMock()
    # Mocking different cookie formats
    browser.get_cookies = AsyncMock(
        return_value=[
            {"name": "SAPISID", "value": "test_sapisid_value"},
            {"name": "authuser", "value": "0"},
            {"name": "OTHER", "value": "ignore"},
        ]
    )
    return browser


@pytest.mark.anyio
async def test_extract_auth_cookies(mock_browser):
    """Test extracting SAPISID and authuser cookies."""
    auth_manager = GoogleAuthManager(mock_browser)
    cookies = await auth_manager.extract_auth_cookies()

    assert "SAPISID" in cookies
    assert cookies["SAPISID"] == "test_sapisid_value"
    assert "authuser" in cookies
    assert cookies["authuser"] == "0"
    assert "OTHER" not in cookies


def test_generate_sapisidhash(mock_browser):
    """Test generation of the SAPISIDHASH header."""
    auth_manager = GoogleAuthManager(mock_browser)

    # Mock time to make the test deterministic
    import time

    original_time = time.time

    try:
        time.time = MagicMock(return_value=1234567890.0)
        sapisid = "test_sapisid"
        origin = "https://example.com"

        result = auth_manager.generate_sapisidhash(sapisid, origin)

        # format: SAPISIDHASH 1234567890_sha1(1234567890 test_sapisid https://example.com)
        # Expected hash:
        import hashlib

        expected_hash = hashlib.sha1(b"1234567890 test_sapisid https://example.com").hexdigest()

        assert result == f"SAPISIDHASH 1234567890_{expected_hash}"
    finally:
        time.time = original_time


@pytest.mark.anyio
async def test_get_auth_headers_success(mock_browser):
    """Test getting auth headers successfully."""
    auth_manager = GoogleAuthManager(mock_browser)

    headers = await auth_manager.get_auth_headers()

    assert headers is not None
    assert "Authorization" in headers
    assert "Cookie" in headers
    assert "SAPISIDHASH" in headers["Authorization"]
    assert "SAPISID=test_sapisid_value" in headers["Cookie"]
    assert "authuser=0" in headers["Cookie"]


@pytest.mark.anyio
async def test_get_auth_headers_missing_sapisid():
    """Test getting auth headers when SAPISID is missing."""
    mock_browser = MagicMock()
    mock_browser.get_cookies = AsyncMock(return_value=[{"name": "authuser", "value": "0"}])

    auth_manager = GoogleAuthManager(mock_browser)
    headers = await auth_manager.get_auth_headers()

    assert headers is None
