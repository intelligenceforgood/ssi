"""Google Drive OSINT scraper."""

import asyncio
import logging
from typing import Any

import httpx

from ssi.osint.google.auth import GoogleAuthManager

logger = logging.getLogger(__name__)


class GoogleDriveScraper:
    """Scraper for Google Drive metadata."""

    def __init__(self, auth_manager: GoogleAuthManager) -> None:
        """Initialize with an auth manager."""
        self.auth_manager = auth_manager

    async def resolve_file(self, file_id: str) -> dict[str, Any]:
        """Resolve Drive file metadata and comments."""
        headers = await self.auth_manager.get_auth_headers()
        if not headers:
            raise RuntimeError("Missing Google auth headers")

        url = f"https://www.googleapis.com/drive/v3/files/{file_id}"
        params = {"fields": "id,name,owners,comments"}

        async with httpx.AsyncClient() as client:
            for attempt in range(3):
                try:
                    response = await client.get(url, headers=headers, params=params)
                    response.raise_for_status()
                    return {"file_id": file_id, "metadata": response.json()}
                except httpx.HTTPError:
                    if attempt == 2:
                        logger.exception("Failed to resolve file %s", file_id)
                        raise
                    await asyncio.sleep(2**attempt)
            return {"file_id": file_id, "metadata": {}}
