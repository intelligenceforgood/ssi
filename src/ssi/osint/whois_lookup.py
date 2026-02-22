"""WHOIS / RDAP lookup module.

Attempts a raw WHOIS lookup first, then falls back to the RDAP
(HTTP-based) protocol if port 43 is blocked — common in containerized
environments like Cloud Run.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlparse

import httpx

from ssi.models.investigation import WHOISRecord

logger = logging.getLogger(__name__)

_RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/"

# Retry configuration
_MAX_RETRIES = 2
_BACKOFF_SECONDS = 1.0


def _extract_domain(url: str) -> str:
    """Extract the registrable domain from a URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def lookup_whois(url: str) -> WHOISRecord:
    """Look up WHOIS data for the domain in *url*.

    Strategy:
        1. Try ``python-whois`` (raw TCP port 43) with retry.
        2. On failure, fall back to RDAP (HTTP-based, works behind
           firewalls and on Cloud Run).

    Args:
        url: Full URL or bare domain.

    Returns:
        Populated ``WHOISRecord``.

    Raises:
        RuntimeError: If both WHOIS and RDAP lookups fail.
    """
    domain = _extract_domain(url)
    logger.info("WHOIS lookup for %s", domain)

    # --- Attempt 1: raw WHOIS (port 43) with retry ---
    last_error: Exception | None = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            return _whois_port43(domain)
        except Exception as e:
            last_error = e
            logger.warning(
                "WHOIS port-43 attempt %d/%d failed for %s: %s",
                attempt,
                _MAX_RETRIES,
                domain,
                e,
            )
            if attempt < _MAX_RETRIES:
                time.sleep(_BACKOFF_SECONDS * attempt)

    # --- Attempt 2: RDAP fallback (HTTP-based) ---
    logger.info("Falling back to RDAP for %s", domain)
    try:
        return _rdap_lookup(domain)
    except Exception as rdap_err:
        logger.warning("RDAP fallback also failed for %s: %s", domain, rdap_err)

    raise RuntimeError(
        f"All WHOIS/RDAP lookups failed for {domain}. "
        f"Last WHOIS error: {last_error}; RDAP also unavailable."
    )


def _whois_port43(domain: str) -> WHOISRecord:
    """Raw WHOIS lookup via python-whois (TCP port 43)."""
    import whois  # python-whois

    w = whois.whois(domain)

    def _first(val: object) -> str:
        """Return the first element of *val* as a string, or *val* itself."""
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""

    def _normalize_list(val: object) -> list[str]:
        """Coerce *val* into a flat list of strings."""
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


def _rdap_lookup(domain: str) -> WHOISRecord:
    """RDAP-based WHOIS fallback (HTTP, works through firewalls).

    Uses the RDAP bootstrap service at ``rdap.org`` which redirects to
    the authoritative RDAP server for the TLD.
    """
    url = f"{_RDAP_BOOTSTRAP_URL}{domain}"
    resp = httpx.get(url, timeout=15.0, follow_redirects=True)
    resp.raise_for_status()
    data = resp.json()

    def _first_event_date(action: str) -> str:
        """Return the date string for the first RDAP event matching *action*."""
        for ev in data.get("events", []):
            if ev.get("eventAction") == action:
                return str(ev.get("eventDate", ""))
        return ""

    # Extract registrar from entities with "registrar" role
    registrar = ""
    registrant_name = ""
    registrant_org = ""
    registrant_country = ""
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
        if "registrar" in roles:
            fn_entries = [v for v in vcard if v and v[0] == "fn"]
            if fn_entries:
                registrar = str(fn_entries[0][3])
        if "registrant" in roles:
            fn_entries = [v for v in vcard if v and v[0] == "fn"]
            org_entries = [v for v in vcard if v and v[0] == "org"]
            if fn_entries:
                registrant_name = str(fn_entries[0][3])
            if org_entries:
                registrant_org = str(org_entries[0][3])

    # Name servers
    name_servers = []
    for ns in data.get("nameservers", []):
        host = ns.get("ldhName", "")
        if host:
            name_servers.append(host)

    # Status
    status = data.get("status", [])

    return WHOISRecord(
        domain=domain,
        registrar=registrar,
        creation_date=_first_event_date("registration"),
        expiration_date=_first_event_date("expiration"),
        updated_date=_first_event_date("last changed"),
        registrant_name=registrant_name,
        registrant_org=registrant_org,
        registrant_country=registrant_country,
        name_servers=name_servers,
        status=status,
        raw=str(data),
    )
