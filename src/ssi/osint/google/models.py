"""Google OSINT data models.

Pydantic models for structured Google identity intelligence
extracted during scam site investigations.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

# ── People / Identity Models ────────────────────────────────────────────────

# Canonical mapping of internal user type codes to human descriptions.
USER_TYPE_DEFINITIONS: dict[str, str] = {
    "USER_TYPE_UNKNOWN": "The user type is not known.",
    "GOOGLE_USER": "The user is a Google user.",
    "GPLUS_USER": "The user is a Currents user.",
    "GOOGLE_APPS_USER": "The user is a Google Workspace user.",
    "OWNER_USER_TYPE_UNKNOWN": "The user type is not known.",
    "GPLUS_DISABLED_BY_ADMIN": "Currents account disabled by an admin.",
    "GOOGLE_FAMILY_USER": "The user is a Google Family user.",
    "GOOGLE_FAMILY_CHILD_USER": "The user is a Google Family child user.",
    "GOOGLE_APPS_ADMIN_DISABLED": "Google Apps admin has been disabled.",
    "GOOGLE_ONE_USER": "The user is a Google One user.",
    "GOOGLE_FAMILY_CONVERTED_CHILD_USER": "Google Family user converted to child.",
}


class PersonProfile(BaseModel):
    """Structured profile data for a Google account."""

    account_id: str = ""
    """The internal numeric account ID (sometimes called Gaia ID)."""

    email: str = ""
    """The email address used to resolve this profile."""

    display_name: str = ""
    """Best display name, if available."""

    profile_photo_url: str = ""
    """URL to the profile photo. Empty if not found."""

    cover_photo_url: str = ""
    """URL to the cover photo. Empty if not found."""

    is_default_photo: bool = True
    """Whether the profile photo is the Google default avatar."""

    last_updated: datetime | None = None
    """When the profile was last edited (UTC)."""

    user_types: list[str] = Field(default_factory=list)
    """Account user types, e.g. ['GOOGLE_USER', 'GOOGLE_ONE_USER']."""

    activated_services: list[str] = Field(default_factory=list)
    """Google services the account has been seen using, e.g. ['Maps', 'Drive']."""

    entity_type: str = ""
    """Dynamite/Chat entity type."""

    customer_id: str = ""
    """Google Workspace customer ID, if enterprise."""

    is_enterprise_user: bool = False
    """Whether this is an enterprise/workspace user."""


class MapContributionStats(BaseModel):
    """Google Maps contribution statistics for an account."""

    account_id: str = ""
    """The account ID these stats belong to."""

    reviews: int = 0
    """Number of reviews."""

    ratings: int = 0
    """Number of ratings (without text)."""

    photos: int = 0
    """Number of photos contributed."""

    profile_url: str = ""
    """URL to the public Maps contribution profile."""


class DriveFileInfo(BaseModel):
    """Metadata extracted from a Google Drive file."""

    file_id: str = ""
    title: str = ""
    mime_type: str = ""
    owner_email: str = ""
    owner_account_id: str = ""
    created_date: datetime | None = None
    modified_date: datetime | None = None
    sharing_enabled: bool = False
    source_app: str = ""


class GoogleOSINTResult(BaseModel):
    """Aggregated result from all Google OSINT scrapers.

    Attached to ``InvestigationResult.google_osint`` and also flattened
    into ``threat_indicators`` / ``pii_exposures`` by the evidence mapper.
    """

    profiles: list[PersonProfile] = Field(default_factory=list)
    map_stats: list[MapContributionStats] = Field(default_factory=list)
    drive_files: list[DriveFileInfo] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    """Non-fatal error messages collected during scraping."""
