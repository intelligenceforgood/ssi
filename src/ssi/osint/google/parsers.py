"""Response parsers for Google internal API responses.

Transforms the raw JSON from Google's People and Maps internal endpoints
into the structured Pydantic models defined in ``ssi.osint.google.models``.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

from ssi.osint.google.models import MapContributionStats, PersonProfile

logger = logging.getLogger(__name__)


# ── People API Parsers ──────────────────────────────────────────────────────


def parse_people_lookup(email: str, data: dict[str, Any]) -> PersonProfile | None:
    """Parse a ``/v2/people/lookup`` response into a ``PersonProfile``.

    The response shape is::

        {
            "people": {
                "<email>": {
                    "personId": "...",
                    "metadata": { "identityInfo": { "sourceIds": [...] } },
                    "readOnlyProfileInfo": [...],
                    "photo": [...],
                    "coverPhoto": [...],
                    "inAppReachability": [...],
                    "extendedData": { ... }
                }
            }
        }

    Returns ``None`` if the person was not found.
    """
    if not data:
        return None

    people = data.get("people")
    if not people:
        return None

    # The lookup returns a dict keyed by the lookup identifier.
    # We take the first (and only) value.
    person_data = next(iter(people.values()), None)
    if not person_data:
        return None

    return _parse_person(email, person_data)


def parse_people_by_id(account_id: str, data: dict[str, Any]) -> PersonProfile | None:
    """Parse a ``/v2/people`` (by account ID) response into a ``PersonProfile``.

    The response shape is::

        {
            "personResponse": [
                { "status": "OK"|"NOT_FOUND", "person": { ... } }
            ]
        }

    Returns ``None`` if the person was not found.
    """
    if not data:
        return None

    responses = data.get("personResponse", [])
    if not responses:
        return None

    first = responses[0]
    if first.get("status") == "NOT_FOUND":
        return None

    person_data = first.get("person")
    if not person_data:
        return None

    return _parse_person("", person_data)


def _parse_person(email: str, person_data: dict[str, Any]) -> PersonProfile:
    """Shared parser for person data from either lookup or direct fetch."""
    profile = PersonProfile(email=email)

    # Account ID
    profile.account_id = person_data.get("personId", "")

    # Source IDs → last updated timestamp
    source_ids = person_data.get("metadata", {}).get("identityInfo", {}).get("sourceIds", [])
    for sid in source_ids:
        container = sid.get("container", "")
        if container == "PROFILE":
            ts_micros = sid.get("lastUpdatedMicros")
            if ts_micros:
                with contextlib.suppress(ValueError, OSError):
                    profile.last_updated = datetime.fromtimestamp(float(str(ts_micros)[:10]), tz=UTC)
            break

    # Profile photo
    photos = person_data.get("photo", [])
    if photos:
        first_photo = photos[0]
        profile.profile_photo_url = first_photo.get("url", "")
        # Default photo detection is best-effort; the reference approach
        # uses image hashing but we do a simpler URL heuristic for now.
        url = profile.profile_photo_url
        profile.is_default_photo = not url or "default-user" in url.lower()

    # Cover photo
    cover_photos = person_data.get("coverPhoto", [])
    if cover_photos:
        first_cover = cover_photos[0]
        raw_url = first_cover.get("imageUrl", "")
        # Strip the size suffix (everything after the last '=')
        if "=" in raw_url:
            profile.cover_photo_url = "=".join(raw_url.split("=")[:-1])
        else:
            profile.cover_photo_url = raw_url

    # User types from readOnlyProfileInfo
    for info in person_data.get("readOnlyProfileInfo", []):
        owner_types = info.get("ownerUserType", [])
        if owner_types:
            profile.user_types.extend(owner_types)

    # Activated services from inAppReachability
    seen_apps: set[str] = set()
    for app_data in person_data.get("inAppReachability", []):
        app_type = app_data.get("appType", "")
        if app_type and app_type not in seen_apps:
            seen_apps.add(app_type)
            profile.activated_services.append(app_type.title())

    # Extended data — Dynamite (Google Chat)
    extended = person_data.get("extendedData", {})

    dynamite = extended.get("dynamiteExtendedData", {})
    if dynamite:
        profile.entity_type = dynamite.get("entityType", "")
        org_info = dynamite.get("organizationInfo", {})
        customer_info = org_info.get("customerInfo", {})
        cid = customer_info.get("customerId", {})
        profile.customer_id = cid.get("customerId", "") if isinstance(cid, dict) else ""

    # Extended data — Google Plus
    gplus = extended.get("gplusExtendedData", {})
    if gplus:
        profile.is_enterprise_user = bool(gplus.get("isEnterpriseUser", False))

    # Display name — Google has patched name visibility in recent API updates,
    # so this field may often be empty.  We still attempt to parse it.
    names = person_data.get("name", [])
    if names:
        first_name = names[0]
        profile.display_name = first_name.get("displayName", "")

    return profile


# ── Maps Parsers ────────────────────────────────────────────────────────────


def parse_maps_stats(account_id: str, raw_text: str) -> MapContributionStats | None:
    """Parse a Maps contribution stats response.

    The response from ``/locationhistory/preview/mas`` is JSONP-like:
    it starts with ``)]}'\n`` which must be stripped before JSON parsing.

    The stats are at ``data[16][8][0]`` — an array of ``[..., label, count]``
    pairs where label is at index 6 and count at index 7.

    Returns ``None`` if parsing fails or the account has no contributions.
    """
    import json

    # Strip JSONP prefix
    text = raw_text
    if text.startswith(")]}'"):
        text = text[text.index("\n") + 1 :]

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.debug("Failed to parse Maps stats JSON for %s", account_id)
        return None

    try:
        sections = data[16][8]
        if not sections:
            return None
        sections = sections[0]
    except (IndexError, TypeError):
        return None

    # Build a label→count dict
    stats_dict: dict[str, int] = {}
    for section in sections:
        try:
            label = section[6]
            count = section[7]
            if isinstance(label, str) and isinstance(count, int):
                stats_dict[label] = count
        except (IndexError, TypeError):
            continue

    if not stats_dict:
        return None

    return MapContributionStats(
        account_id=account_id,
        reviews=stats_dict.get("Reviews", 0),
        ratings=stats_dict.get("Ratings", 0),
        photos=stats_dict.get("Photos", 0),
        profile_url=f"https://www.google.com/maps/contrib/{account_id}/reviews",
    )
