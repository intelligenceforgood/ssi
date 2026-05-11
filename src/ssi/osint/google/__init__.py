"""Google OSINT package.

Provides scrapers for extracting identity intelligence from Google's
internal APIs during scam site investigations.
"""

from ssi.osint.google.auth import GoogleAuthManager
from ssi.osint.google.maps import GoogleMapsScraper
from ssi.osint.google.models import GoogleOSINTResult, MapContributionStats, PersonProfile
from ssi.osint.google.people import GooglePeopleScraper

__all__ = [
    "GoogleAuthManager",
    "GoogleMapsScraper",
    "GoogleOSINTResult",
    "GooglePeopleScraper",
    "MapContributionStats",
    "PersonProfile",
]
