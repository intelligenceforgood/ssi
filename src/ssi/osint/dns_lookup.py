"""DNS record lookup module."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from ssi.models.investigation import DNSRecords

logger = logging.getLogger(__name__)


def _extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def lookup_dns(url: str) -> DNSRecords:
    """Resolve common DNS record types for the domain in *url*.

    Args:
        url: Full URL or bare domain.

    Returns:
        Populated ``DNSRecords``.
    """
    import dns.resolver

    domain = _extract_domain(url)
    logger.info("DNS lookup for %s", domain)

    records = DNSRecords()

    record_map = {
        "A": "a",
        "AAAA": "aaaa",
        "MX": "mx",
        "TXT": "txt",
        "NS": "ns",
        "CNAME": "cname",
    }

    for rtype, attr in record_map.items():
        try:
            answers = dns.resolver.resolve(domain, rtype)
            setattr(records, attr, [str(r) for r in answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            logger.debug("DNS %s lookup failed for %s: %s", rtype, domain, e)

    return records
