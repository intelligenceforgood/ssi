"""Google People internal API scraper.

Resolves email addresses to Google account profiles using the internal
People PA endpoint (``people-pa.clients6.google.com``).  This endpoint
uses SAPISIDHASH cookie-based authentication.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ssi.osint.google.auth import GoogleAuthManager
from ssi.osint.google.models import PersonProfile
from ssi.osint.google.parsers import parse_people_by_id, parse_people_lookup

logger = logging.getLogger(__name__)

# The internal People PA host and the API key required for requests.
_PEOPLE_PA_HOST = "people-pa.clients6.google.com"
_PEOPLE_PA_ORIGIN = "https://photos.google.com"
_PEOPLE_PA_API_KEY = "AIzaSyAa2odBewW-sPJu3jMORr0aNedh3YlkiQc"

# Request mask for full profile extraction.
_MAX_DETAIL_FIELD_PATHS = [
    "person.metadata.best_display_name",
    "person.photo",
    "person.cover_photo",
    "person.interaction_settings",
    "person.legacy_fields",
    "person.metadata",
    "person.in_app_reachability",
    "person.name",
    "person.read_only_profile_info",
    "person.sort_keys",
    "person.email",
]

_MAX_DETAIL_CONTAINERS = [
    "AFFINITY",
    "PROFILE",
    "DOMAIN_PROFILE",
    "ACCOUNT",
    "EXTERNAL_ACCOUNT",
    "CIRCLE",
    "DOMAIN_CONTACT",
    "DEVICE_CONTACT",
    "GOOGLE_GROUP",
    "CONTACT",
]

_MAX_DETAIL_EXTENSIONS = [
    "DYNAMITE_ADDITIONAL_DATA",
    "DYNAMITE_ORGANIZATION_INFO",
]


class GooglePeopleScraper:
    """Scraper for Google People internal API to resolve email → account profile."""

    def __init__(self, auth_manager: GoogleAuthManager) -> None:
        self._auth = auth_manager

    async def resolve_email(
        self,
        email: str,
        *,
        full_profile: bool = True,
        timeout: float = 15.0,
    ) -> PersonProfile | None:
        """Resolve an email address to a Google account profile.

        Args:
            email: The email address to look up.
            full_profile: If ``True``, request maximum detail fields.
                If ``False``, request only the account ID (faster).
            timeout: HTTP request timeout in seconds.

        Returns:
            A ``PersonProfile`` if the account was found, ``None`` otherwise.
        """
        headers = self._auth.build_authenticated_headers(
            _PEOPLE_PA_ORIGIN,
            extra_headers={"Host": _PEOPLE_PA_HOST},
        )
        if not headers:
            logger.warning("Google People: cannot resolve email — no auth headers")
            return None

        # Add API key
        params: dict[str, Any]
        if full_profile:
            params = {
                "id": email,
                "type": "EMAIL",
                "match_type": "EXACT",
                "extension_set.extension_names": _MAX_DETAIL_EXTENSIONS,
                "request_mask.include_field.paths": _MAX_DETAIL_FIELD_PATHS,
                "request_mask.include_container": _MAX_DETAIL_CONTAINERS,
                "core_id_params.enable_private_names": True,
                "key": _PEOPLE_PA_API_KEY,
            }
        else:
            params = {
                "id": email,
                "type": "EMAIL",
                "matchType": "EXACT",
                "requestMask.includeField.paths": "person.metadata",
                "key": _PEOPLE_PA_API_KEY,
            }

        url = f"https://{_PEOPLE_PA_HOST}/v2/people/lookup"

        try:
            async with httpx.AsyncClient(http2=True, timeout=timeout) as client:
                resp = await client.get(url, params=params, headers=headers)

                if resp.status_code != 200:
                    logger.warning(
                        "Google People lookup returned %d for %s",
                        resp.status_code,
                        email,
                    )
                    return None

                data = resp.json()
                return parse_people_lookup(email, data)

        except httpx.HTTPError as exc:
            logger.warning("Google People lookup failed for %s: %s", email, exc)
            return None

    async def get_profile_by_id(
        self,
        account_id: str,
        *,
        timeout: float = 15.0,
    ) -> PersonProfile | None:
        """Look up a Google account profile by its internal account ID.

        Args:
            account_id: The numeric account identifier.
            timeout: HTTP request timeout in seconds.

        Returns:
            A ``PersonProfile`` if found, ``None`` otherwise.
        """
        headers = self._auth.build_authenticated_headers(
            _PEOPLE_PA_ORIGIN,
            extra_headers={"Host": _PEOPLE_PA_HOST},
        )
        if not headers:
            return None

        params: dict[str, Any] = {
            "person_id": account_id,
            "extension_set.extension_names": _MAX_DETAIL_EXTENSIONS,
            "request_mask.include_field.paths": _MAX_DETAIL_FIELD_PATHS,
            "request_mask.include_container": _MAX_DETAIL_CONTAINERS,
            "core_id_params.enable_private_names": True,
            "key": _PEOPLE_PA_API_KEY,
        }

        url = f"https://{_PEOPLE_PA_HOST}/v2/people"

        try:
            async with httpx.AsyncClient(http2=True, timeout=timeout) as client:
                resp = await client.get(url, params=params, headers=headers)

                if resp.status_code != 200:
                    logger.warning(
                        "Google People by-ID returned %d for %s",
                        resp.status_code,
                        account_id,
                    )
                    return None

                data = resp.json()
                return parse_people_by_id(account_id, data)

        except httpx.HTTPError as exc:
            logger.warning("Google People by-ID lookup failed for %s: %s", account_id, exc)
            return None
