"""Tests for OSINT evidence mapping."""

from __future__ import annotations

from ssi.evidence.mapping import route_google_osint_results


def test_route_google_osint_results_people():
    """Test mapping Google People API results (Gaia ID and secondary email)."""
    people_data = {
        "email": "primary@example.com",
        "gaia_id": "1234567890",
        "raw": {
            "searchResults": [
                {
                    "person": {
                        "emailAddresses": [
                            {"value": "primary@example.com"},
                            {"value": "secondary@example.com"},
                        ]
                    }
                }
            ]
        },
    }

    indicators, pii = route_google_osint_results("primary@example.com", people_data=people_data)

    assert len(indicators) == 1
    assert indicators[0].indicator_type == "gaia_id"
    assert indicators[0].value == "1234567890"

    assert len(pii) == 1
    assert pii[0].field_type == "email"
    assert pii[0].field_label == "Secondary Email (OSINT)"


def test_route_google_osint_results_drive():
    """Test mapping Google Drive API results (secondary email)."""
    drive_data = {
        "file_id": "file123",
        "metadata": {
            "owners": [
                {"emailAddress": "owner@example.com"},
            ]
        },
    }

    indicators, pii = route_google_osint_results("file123", drive_data=drive_data)

    assert len(indicators) == 0
    assert len(pii) == 1
    assert pii[0].field_type == "email"
    assert pii[0].field_label == "Drive Owner Email (OSINT)"
