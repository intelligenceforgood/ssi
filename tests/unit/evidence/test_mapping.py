"""Tests for OSINT evidence mapping."""

from __future__ import annotations

from ssi.evidence.mapping import route_google_osint_results
from ssi.osint.google.models import DriveFileInfo, GoogleOSINTResult, MapContributionStats, PersonProfile


def test_route_google_osint_results_people():
    """Test mapping PersonProfile to indicators and PII exposures."""
    profile = PersonProfile(
        account_id="1234567890",
        email="primary@example.com",
        user_types=["GOOGLE_USER"],
        activated_services=["Maps", "Drive"],
        profile_photo_url="https://lh3.googleusercontent.com/custom",
        is_default_photo=False,
    )
    osint = GoogleOSINTResult(profiles=[profile])

    indicators, pii = route_google_osint_results(osint)

    # Should have account_id indicator + custom profile photo indicator
    assert len(indicators) == 2
    assert indicators[0].indicator_type == "google_account_id"
    assert indicators[0].value == "1234567890"
    assert "primary@example.com" in indicators[0].context
    assert "GOOGLE_USER" in indicators[0].context

    assert indicators[1].indicator_type == "profile_photo"

    # No PII exposures from a single profile with no secondary emails
    assert len(pii) == 0


def test_route_google_osint_results_maps():
    """Test mapping MapContributionStats to indicators."""
    stats = MapContributionStats(
        account_id="1234567890",
        reviews=42,
        ratings=12,
        photos=7,
        profile_url="https://www.google.com/maps/contrib/1234567890/reviews",
    )
    osint = GoogleOSINTResult(map_stats=[stats])

    indicators, pii = route_google_osint_results(osint)

    assert len(indicators) == 1
    assert indicators[0].indicator_type == "google_maps_profile"
    assert "42 reviews" in indicators[0].context


def test_route_google_osint_results_drive():
    """Test mapping DriveFileInfo owner to PII exposures."""
    drive_file = DriveFileInfo(
        file_id="file123",
        title="phishing-template.docx",
        owner_email="owner@example.com",
        owner_account_id="9876543210",
    )
    osint = GoogleOSINTResult(drive_files=[drive_file])

    indicators, pii = route_google_osint_results(osint)

    # Drive owner account ID → indicator
    assert len(indicators) == 1
    assert indicators[0].indicator_type == "google_account_id"
    assert indicators[0].value == "9876543210"

    # Drive owner email → PII exposure
    assert len(pii) == 1
    assert pii[0].field_type == "email"
    assert "phishing-template.docx" in pii[0].field_label


def test_route_google_osint_results_empty():
    """Empty result produces no indicators or PII."""
    osint = GoogleOSINTResult()
    indicators, pii = route_google_osint_results(osint)
    assert indicators == []
    assert pii == []
