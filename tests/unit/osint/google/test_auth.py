"""Unit tests for Google Auth Manager."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ssi.osint.google.auth import GoogleAuthManager


@pytest.fixture
def mock_browser():
    """Mock ZenBrowserManager with realistic Google cookies."""
    browser = MagicMock()
    browser.get_cookies = AsyncMock(
        return_value=[
            {"name": "SID", "value": "test_sid", "domain": ".google.com"},
            {"name": "HSID", "value": "test_hsid", "domain": ".google.com"},
            {"name": "SSID", "value": "test_ssid", "domain": ".google.com"},
            {"name": "APISID", "value": "test_apisid", "domain": ".google.com"},
            {"name": "SAPISID", "value": "test_sapisid_value", "domain": ".google.com"},
            {"name": "NID", "value": "test_nid", "domain": ".google.com"},
            {"name": "unrelated", "value": "skip_me", "domain": ".example.com"},
        ]
    )
    return browser


@pytest.fixture
def auth_from_cookies():
    """GoogleAuthManager pre-initialized with explicit cookies."""
    return GoogleAuthManager(
        cookies={
            "SID": "test_sid",
            "HSID": "test_hsid",
            "SSID": "test_ssid",
            "APISID": "test_apisid",
            "SAPISID": "test_sapisid_value",
        }
    )


@pytest.mark.anyio
async def test_extract_auth_cookies(mock_browser):
    """Test extracting cookies from a browser session."""
    auth = GoogleAuthManager(mock_browser)
    cookies = await auth.extract_auth_cookies()

    # Should include all .google.com cookies
    assert "SAPISID" in cookies
    assert cookies["SAPISID"] == "test_sapisid_value"
    assert "SID" in cookies
    assert "HSID" in cookies
    # Non-google.com cookies should be excluded
    assert "unrelated" not in cookies


@pytest.mark.anyio
async def test_extract_cookies_skipped_when_pre_populated():
    """When cookies are provided at init, browser is not consulted."""
    browser = MagicMock()
    browser.get_cookies = AsyncMock(return_value=[])  # should not be called
    auth = GoogleAuthManager(browser, cookies={"SAPISID": "pre_set"})
    cookies = await auth.extract_auth_cookies()
    assert cookies["SAPISID"] == "pre_set"
    browser.get_cookies.assert_not_awaited()


def test_generate_sapisidhash():
    """Test deterministic SAPISIDHASH generation."""
    import hashlib

    sapisid = "test_sapisid"
    origin = "https://photos.google.com"
    ts = "1700000000"

    result = GoogleAuthManager.generate_sapisidhash(sapisid, origin, timestamp=ts)
    expected_hash = hashlib.sha1(f"{ts} {sapisid} {origin}".encode()).hexdigest()
    assert result == f"{ts}_{expected_hash}"


def test_build_authenticated_headers(auth_from_cookies):
    """Test building full authenticated headers."""
    headers = auth_from_cookies.build_authenticated_headers("https://photos.google.com")

    assert headers is not None
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("SAPISIDHASH ")
    assert "Cookie" in headers
    assert "SAPISID=test_sapisid_value" in headers["Cookie"]
    assert headers["Origin"] == "https://photos.google.com"


def test_build_authenticated_headers_missing_sapisid():
    """When SAPISID is missing, returns None."""
    auth = GoogleAuthManager(cookies={"SID": "abc"})
    headers = auth.build_authenticated_headers("https://photos.google.com")
    assert headers is None


def test_build_cookie_headers(auth_from_cookies):
    """Cookie-only headers for Maps-style endpoints."""
    headers = auth_from_cookies.build_cookie_headers()
    assert headers is not None
    assert "Cookie" in headers
    assert "Authorization" not in headers  # No SAPISIDHASH
    assert "SAPISID=test_sapisid_value" in headers["Cookie"]


def test_build_cookie_headers_empty():
    """When no cookies, returns None."""
    auth = GoogleAuthManager()
    assert auth.build_cookie_headers() is None


def test_has_required_cookies(auth_from_cookies):
    """Validation gate: required cookies present."""
    assert auth_from_cookies.has_required_cookies is True


def test_has_required_cookies_missing():
    """Validation gate: SAPISID missing → False."""
    auth = GoogleAuthManager(cookies={"SID": "abc", "HSID": "def"})
    assert auth.has_required_cookies is False


def test_cookies_property_returns_copy(auth_from_cookies):
    """cookies property returns a defensive copy."""
    c1 = auth_from_cookies.cookies
    c1["INJECTED"] = "bad"
    c2 = auth_from_cookies.cookies
    assert "INJECTED" not in c2
