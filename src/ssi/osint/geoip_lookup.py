"""GeoIP lookup module using ipinfo.io free API."""

from __future__ import annotations

import logging

import httpx

from ssi.models.investigation import GeoIPInfo

logger = logging.getLogger(__name__)


def lookup_geoip(ip: str) -> GeoIPInfo:
    """Look up geolocation and ASN data for an IP address.

    Uses ipinfo.io free tier (up to 50K/month). Falls back gracefully.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Populated ``GeoIPInfo``.
    """
    logger.info("GeoIP lookup for %s", ip)

    from ssi.settings import get_settings

    settings = get_settings()
    headers = {}
    if settings.osint.ipinfo_token:
        headers["Authorization"] = f"Bearer {settings.osint.ipinfo_token}"

    try:
        resp = httpx.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        return GeoIPInfo(
            ip=data.get("ip", ip),
            hostname=data.get("hostname", ""),
            city=data.get("city", ""),
            region=data.get("region", ""),
            country=data.get("country", ""),
            loc=data.get("loc", ""),
            org=data.get("org", ""),
            asn=data.get("asn", {}).get("asn", "") if isinstance(data.get("asn"), dict) else "",
            as_name=data.get("asn", {}).get("name", "") if isinstance(data.get("asn"), dict) else data.get("org", ""),
        )
    except Exception as e:
        logger.warning("GeoIP lookup failed for %s: %s", ip, e)
        return GeoIPInfo(ip=ip)
