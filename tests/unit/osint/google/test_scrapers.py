"""Tests for Google OSINT scrapers."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from ssi.osint.google.auth import GoogleAuthManager
from ssi.osint.google.drive import GoogleDriveScraper
from ssi.osint.google.maps import GoogleMapsScraper
from ssi.osint.google.people import GooglePeopleScraper


@pytest.fixture
def auth_manager() -> GoogleAuthManager:
    """GoogleAuthManager with pre-populated cookies."""
    return GoogleAuthManager(
        cookies={
            "SID": "test_sid",
            "HSID": "test_hsid",
            "SSID": "test_ssid",
            "APISID": "test_apisid",
            "SAPISID": "test_sapisid",
        }
    )


@pytest.mark.anyio
async def test_people_scraper_resolve_email(auth_manager: GoogleAuthManager) -> None:
    """Test resolving email via People internal API."""
    scraper = GooglePeopleScraper(auth_manager)

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "people": {
            "test@example.com": {
                "personId": "12345",
                "metadata": {"identityInfo": {"sourceIds": []}},
            }
        }
    }

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("ssi.osint.google.people.httpx.AsyncClient", return_value=mock_client):
        result = await scraper.resolve_email("test@example.com")

        assert result is not None
        assert result.account_id == "12345"
        assert result.email == "test@example.com"
        mock_client.get.assert_called_once()


@pytest.mark.anyio
async def test_people_scraper_not_found(auth_manager: GoogleAuthManager) -> None:
    """Test People scraper returns None for not-found accounts."""
    scraper = GooglePeopleScraper(auth_manager)

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"people": {}}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("ssi.osint.google.people.httpx.AsyncClient", return_value=mock_client):
        result = await scraper.resolve_email("nobody@example.com")
        assert result is None
        mock_client.get.assert_called_once()


@pytest.mark.anyio
async def test_maps_scraper(auth_manager: GoogleAuthManager) -> None:
    """Test Maps contribution stats scraping."""
    scraper = GoogleMapsScraper(auth_manager)

    # Simulate the JSONP-like Maps response
    maps_response_text = (
        ")]}'\n[[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],"
        "[[[],[]],null,null,null,null,null,null,null,[[[[null,null,null,null,null,null,"
        '"Reviews",42],[null,null,null,null,null,null,"Ratings",12],[null,null,null,'
        'null,null,null,"Photos",7]]]]]]]'
    )
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = maps_response_text

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("ssi.osint.google.maps.httpx.AsyncClient", return_value=mock_client):
        await scraper.get_contribution_stats("12345")
        mock_client.get.assert_called_once()


@pytest.mark.anyio
async def test_maps_scraper_rate_limited(auth_manager: GoogleAuthManager) -> None:
    """Maps scraper returns None on 302 rate-limit redirect."""
    scraper = GoogleMapsScraper(auth_manager)

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 302
    mock_response.headers = {"Location": "https://www.google.com/sorry/index"}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("ssi.osint.google.maps.httpx.AsyncClient", return_value=mock_client):
        result = await scraper.get_contribution_stats("12345")
        assert result is None
        mock_client.get.assert_called_once()


@pytest.mark.anyio
async def test_drive_scraper_placeholder() -> None:
    """Drive scraper placeholder returns None (not yet implemented)."""
    scraper = GoogleDriveScraper()
    result = await scraper.resolve_file("file123")
    assert result is None


@pytest.mark.anyio
async def test_people_scraper_no_auth() -> None:
    """People scraper returns None when no cookies are available."""
    auth = GoogleAuthManager()  # no cookies
    scraper = GooglePeopleScraper(auth)
    result = await scraper.resolve_email("test@example.com")
    assert result is None
