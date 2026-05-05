"""Google People OSINT scraper."""

import asyncio
import logging
from typing import Any

import httpx

from ssi.osint.google.auth import GoogleAuthManager

logger = logging.getLogger(__name__)


class GooglePeopleScraper:
    """Scraper for Google People to resolve email to Gaia ID."""

    def __init__(self, auth_manager: GoogleAuthManager) -> None:
        """Initialize with an auth manager."""
        self.auth_manager = auth_manager

    async def resolve_email(self, email: str) -> dict[str, Any]:
        """Resolve an email to a Gaia ID and basic profile info."""
        headers = await self.auth_manager.get_auth_headers()
        if not headers:
            raise RuntimeError("Missing Google auth headers")

        url = "https://people.googleapis.com/v1/people:search"
        params = {"query": email, "readMask": "metadata,names,emailAddresses"}

        async with httpx.AsyncClient() as client:
            for attempt in range(3):
                try:
                    response = await client.get(url, headers=headers, params=params)
                    response.raise_for_status()
                    data = response.json()

                    gaia_id = ""
                    results = data.get("searchResults", [])
                    if results:
                        person = results[0].get("person", {})
                        metadata = person.get("metadata", {})
                        sources = metadata.get("sources", [])
                        for source in sources:
                            if source.get("type") == "PROFILE":
                                gaia_id = source.get("id", "")
                                break
                    return {"email": email, "gaia_id": gaia_id, "raw": data}
                except httpx.HTTPError:
                    if attempt == 2:
                        logger.exception("Failed to resolve email %s", email)
                        raise
                    await asyncio.sleep(2**attempt)
            return {"email": email, "gaia_id": "", "raw": {}}
