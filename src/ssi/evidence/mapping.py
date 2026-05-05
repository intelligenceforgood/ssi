"""Mapping OSINT findings to evidence models."""

from __future__ import annotations

from typing import Any

from ssi.models.investigation import PiiExposure, ThreatIndicator


def route_google_osint_results(
    identifier: str,
    people_data: dict[str, Any] | None = None,
    maps_data: dict[str, Any] | None = None,
    drive_data: dict[str, Any] | None = None,
) -> tuple[list[ThreatIndicator], list[PiiExposure]]:
    """Route Google OSINT results to standard evidence models.

    Args:
        identifier: The email address or Drive file ID that was queried.
        people_data: Response dict from Google People API.
        maps_data: Response dict from Google Maps API.
        drive_data: Response dict from Google Drive API.
    """
    indicators: list[ThreatIndicator] = []
    pii_exposures: list[PiiExposure] = []

    if people_data:
        gaia_id = people_data.get("gaia_id")
        if gaia_id:
            indicators.append(
                ThreatIndicator(
                    indicator_type="gaia_id",
                    value=gaia_id,
                    context=f"Resolved from email {identifier}",
                    source="Google People API",
                )
            )

        raw = people_data.get("raw", {})
        results = raw.get("searchResults", [])
        if results:
            person = results[0].get("person", {})
            email_addresses = person.get("emailAddresses", [])
            for em in email_addresses:
                val = em.get("value")
                if val and val.lower() != identifier.lower():
                    # Secondary emails found in profile go to PII exposures
                    pii_exposures.append(
                        PiiExposure(
                            field_type="email",
                            field_label="Secondary Email (OSINT)",
                            was_submitted=False,
                        )
                    )

    if maps_data:
        # We could potentially map locations from maps_data to indicators,
        # but the manifest only mentioned Gaia IDs and secondary emails.
        pass

    if drive_data:
        metadata = drive_data.get("metadata", {})
        owners = metadata.get("owners", [])
        for owner in owners:
            owner_email = owner.get("emailAddress")
            if owner_email and owner_email.lower() != identifier.lower():
                pii_exposures.append(
                    PiiExposure(
                        field_type="email",
                        field_label="Drive Owner Email (OSINT)",
                        was_submitted=False,
                    )
                )

    return indicators, pii_exposures
