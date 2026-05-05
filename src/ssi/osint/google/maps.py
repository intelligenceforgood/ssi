"""Google Maps OSINT scraper."""

import asyncio
import logging
from typing import Any

import httpx

from ssi.osint.google.auth import GoogleAuthManager

logger = logging.getLogger(__name__)


class GoogleMapsScraper:
    """Scraper for Google Maps location data."""

    def __init__(self, auth_manager: GoogleAuthManager) -> None:
        """Initialize with an auth manager."""
        self.auth_manager = auth_manager

    async def get_location_data(self, gaia_id: str) -> dict[str, Any]:
        """Extract location confidence scores."""
        headers = await self.auth_manager.get_auth_headers()
        if not headers:
            raise RuntimeError("Missing Google auth headers")

        url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json"

        async with httpx.AsyncClient() as client:
            for attempt in range(3):
                try:
                    response = await client.get(url, headers=headers)
                    response.raise_for_status()
                    return {"gaia_id": gaia_id, "locations": [], "raw": response.json()}
                except httpx.HTTPError:
                    if attempt == 2:
                        logger.exception("Failed to get location data for %s", gaia_id)
                        raise
                    await asyncio.sleep(2**attempt)
            return {"gaia_id": gaia_id, "locations": [], "raw": {}}
