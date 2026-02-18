"""WHOIS / RDAP lookup module."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from ssi.models.investigation import WHOISRecord

logger = logging.getLogger(__name__)


def _extract_domain(url: str) -> str:
    """Extract the registrable domain from a URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def lookup_whois(url: str) -> WHOISRecord:
    """Look up WHOIS data for the domain in *url*.

    Args:
        url: Full URL or bare domain.

    Returns:
        Populated ``WHOISRecord``.
    """
    import whois  # python-whois

    domain = _extract_domain(url)
    logger.info("WHOIS lookup for %s", domain)

    w = whois.whois(domain)

    def _first(val):
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""

    def _normalize_list(val) -> list[str]:
        """Ensure *val* is a list of strings, not a char-iterated string."""
        if not val:
            return []
        if isinstance(val, str):
            return [val]
        if isinstance(val, list):
            return [str(s) for s in val]
        return [str(val)]

    return WHOISRecord(
        domain=domain,
        registrar=_first(w.registrar),
        creation_date=_first(w.creation_date),
        expiration_date=_first(w.expiration_date),
        updated_date=_first(w.updated_date),
        registrant_name=_first(getattr(w, "name", "")),
        registrant_org=_first(getattr(w, "org", "")),
        registrant_country=_first(getattr(w, "country", "")),
        name_servers=[str(ns) for ns in (w.name_servers or [])],
        status=_normalize_list(w.status),
        raw=str(w.text) if hasattr(w, "text") else "",
    )
