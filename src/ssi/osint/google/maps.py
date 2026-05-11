"""Google Maps contribution statistics scraper.

Extracts review/rating/photo counts for a Google account using the
Maps contribution preview endpoint.  This endpoint uses cookie-based
(session) authentication — no SAPISIDHASH required.
"""

from __future__ import annotations

import logging

import httpx

from ssi.osint.google.auth import GoogleAuthManager
from ssi.osint.google.models import MapContributionStats
from ssi.osint.google.parsers import parse_maps_stats

logger = logging.getLogger(__name__)

# The protobuf-encoded query template for stats retrieval.
# The single ``{}`` placeholder is the account ID.
_STATS_PB_TEMPLATE = (
    "!1s{}!2m3!1sYE3rYc2rEsqOlwSHx534DA!7e81!15i14416"
    "!6m2!4b1!7b1!9m0"
    "!16m4!1i100!4b1!5b1!6BQ0FFU0JrVm5TVWxEenc9PQ"
    "!17m28"
    "!1m6!1m2!1i0!2i0!2m2!1i458!2i736"
    "!1m6!1m2!1i1868!2i0!2m2!1i1918!2i736"
    "!1m6!1m2!1i0!2i0!2m2!1i1918!2i20"
    "!1m6!1m2!1i0!2i716!2m2!1i1918!2i736"
    "!18m12!1m3!1d806313.5865720833!2d150.19484835!3d-34.53825215"
    "!2m3!1f0!2f0!3f0!3m2!1i1918!2i736!4f13.1"
)


class GoogleMapsScraper:
    """Scraper for Google Maps contribution statistics."""

    def __init__(self, auth_manager: GoogleAuthManager) -> None:
        self._auth = auth_manager

    async def get_contribution_stats(
        self,
        account_id: str,
        *,
        timeout: float = 15.0,
    ) -> MapContributionStats | None:
        """Fetch Maps contribution statistics for a Google account.

        Args:
            account_id: The Google account's internal numeric ID.
            timeout: HTTP request timeout in seconds.

        Returns:
            A ``MapContributionStats`` if the account has public
            contributions, ``None`` if not found or an error occurred.
        """
        headers = self._auth.build_cookie_headers()
        if not headers:
            logger.debug("Google Maps: cannot fetch stats — no cookies")
            return None

        pb_value = _STATS_PB_TEMPLATE.format(account_id)
        url = "https://www.google.com/locationhistory/preview/mas"
        params = {
            "authuser": "0",
            "hl": "en",
            "gl": "us",
            "pb": pb_value,
        }

        try:
            async with httpx.AsyncClient(
                http2=True,
                timeout=timeout,
                follow_redirects=False,
            ) as client:
                resp = await client.get(url, params=params, headers=headers)

                # A 302 redirect to /sorry/ means IP has been rate-limited.
                if resp.status_code == 302:
                    location = resp.headers.get("Location", "")
                    if "sorry" in location.lower():
                        logger.warning(
                            "Google Maps: IP rate-limited (302 → sorry) for %s",
                            account_id,
                        )
                    return None

                if resp.status_code != 200:
                    logger.warning(
                        "Google Maps stats returned %d for %s",
                        resp.status_code,
                        account_id,
                    )
                    return None

                return parse_maps_stats(account_id, resp.text)

        except httpx.HTTPError as exc:
            logger.warning("Google Maps stats request failed for %s: %s", account_id, exc)
            return None
