"""Mapping OSINT findings to evidence models."""

from __future__ import annotations

from ssi.models.investigation import PiiExposure, ThreatIndicator
from ssi.osint.google.models import GoogleOSINTResult


def route_google_osint_results(
    osint_result: GoogleOSINTResult,
) -> tuple[list[ThreatIndicator], list[PiiExposure]]:
    """Route Google OSINT results to standard evidence models.

    Transforms the structured ``GoogleOSINTResult`` into flat lists of
    ``ThreatIndicator`` and ``PiiExposure`` records for attachment to the
    ``InvestigationResult``.

    Mapping rules:

    - Each resolved account ID → ``ThreatIndicator(indicator_type="google_account_id")``
    - Each activated service → appended to the indicator context
    - Enterprise/workspace accounts → additional indicator
    - Maps profiles with contributions → ``ThreatIndicator(indicator_type="google_maps_profile")``
    - Non-primary emails discovered in profile → ``PiiExposure``

    Args:
        osint_result: The aggregated Google OSINT result.

    Returns:
        A tuple of (threat_indicators, pii_exposures).
    """
    indicators: list[ThreatIndicator] = []
    pii_exposures: list[PiiExposure] = []

    # ── Person Profiles ──────────────────────────────────────────────────
    for profile in osint_result.profiles:
        if profile.account_id:
            context_parts = [f"Resolved from email {profile.email}"]

            if profile.user_types:
                context_parts.append(f"User types: {', '.join(profile.user_types)}")

            if profile.activated_services:
                context_parts.append(f"Activated services: {', '.join(profile.activated_services)}")

            if profile.is_enterprise_user:
                context_parts.append("Enterprise/Workspace account")

            if profile.customer_id:
                context_parts.append(f"Customer ID: {profile.customer_id}")

            if profile.last_updated:
                context_parts.append(f"Last profile edit: {profile.last_updated.strftime('%Y-%m-%d %H:%M UTC')}")

            indicators.append(
                ThreatIndicator(
                    indicator_type="google_account_id",
                    value=profile.account_id,
                    context="; ".join(context_parts),
                    source="Google People API (internal)",
                )
            )

        # Non-default profile photo is an intelligence signal
        if profile.profile_photo_url and not profile.is_default_photo:
            indicators.append(
                ThreatIndicator(
                    indicator_type="profile_photo",
                    value=profile.profile_photo_url,
                    context=f"Custom Google profile photo for {profile.email}",
                    source="Google People API (internal)",
                )
            )

    # ── Maps Contributions ───────────────────────────────────────────────
    for stats in osint_result.map_stats:
        total = stats.reviews + stats.ratings + stats.photos
        if total > 0:
            indicators.append(
                ThreatIndicator(
                    indicator_type="google_maps_profile",
                    value=stats.profile_url,
                    context=(
                        f"Maps contributions: {stats.reviews} reviews, "
                        f"{stats.ratings} ratings, {stats.photos} photos"
                    ),
                    source="Google Maps (internal)",
                )
            )

    # ── Drive Files ──────────────────────────────────────────────────────
    for drive_file in osint_result.drive_files:
        if drive_file.owner_email:
            pii_exposures.append(
                PiiExposure(
                    field_type="email",
                    field_label=f"Drive file owner ({drive_file.title or drive_file.file_id})",
                    was_submitted=False,
                )
            )

        if drive_file.owner_account_id:
            indicators.append(
                ThreatIndicator(
                    indicator_type="google_account_id",
                    value=drive_file.owner_account_id,
                    context=f"Owner of Drive file {drive_file.file_id}",
                    source="Google Drive API (internal)",
                )
            )

    return indicators, pii_exposures
