"""Tests for Google OSINT scrapers."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from ssi.osint.google.drive import GoogleDriveScraper
from ssi.osint.google.maps import GoogleMapsScraper
from ssi.osint.google.people import GooglePeopleScraper


@pytest.fixture
def mock_auth_manager() -> MagicMock:
    """Mock GoogleAuthManager."""
    manager = MagicMock()
    manager.get_auth_headers = AsyncMock(return_value={"Authorization": "mock", "Cookie": "mock"})
    return manager


@pytest.mark.asyncio
async def test_people_scraper(mock_auth_manager: MagicMock) -> None:
    """Test resolving email."""
    scraper = GooglePeopleScraper(mock_auth_manager)

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.json.return_value = {
        "searchResults": [{"person": {"metadata": {"sources": [{"type": "PROFILE", "id": "12345"}]}}}]
    }
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await scraper.resolve_email("test@example.com")

        assert result["gaia_id"] == "12345"
        mock_get.assert_called_once()


@pytest.mark.asyncio
async def test_maps_scraper(mock_auth_manager: MagicMock) -> None:
    """Test resolving location."""
    scraper = GoogleMapsScraper(mock_auth_manager)

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.json.return_value = {"candidates": []}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await scraper.get_location_data("12345")

        assert result["gaia_id"] == "12345"
        mock_get.assert_called_once()


@pytest.mark.asyncio
async def test_drive_scraper(mock_auth_manager: MagicMock) -> None:
    """Test resolving file."""
    scraper = GoogleDriveScraper(mock_auth_manager)

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.json.return_value = {"id": "file123", "name": "Secret"}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await scraper.resolve_file("file123")

        assert result["metadata"]["name"] == "Secret"
        mock_get.assert_called_once()
