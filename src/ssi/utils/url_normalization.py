"""URL canonicalization for deduplication matching.

This is a local copy of ``i4g.utils.url_normalization`` so that the SSI
package can normalise URLs without depending on the ``i4g`` distribution
at runtime.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)

_TRACKING_PARAMS: frozenset[str] = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid",
        "ref",
        "source",
        "mc_cid",
        "mc_eid",
    }
)

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

# Characters that are safe in URL path segments (RFC 3986 unreserved + sub-delims + '/' + '@')
_PATH_SAFE = "-._~!$&'()*+,;=:@/"


def normalize_url(url: str) -> str:
    """Canonicalize a URL for dedup matching.

    Steps:
        1. Lowercase the scheme and hostname
        2. Strip default ports (:80 for http, :443 for https)
        3. Remove trailing slash on path
        4. Sort query parameters alphabetically
        5. Remove common tracking parameters (utm_*, fbclid, gclid, ref, etc.)
        6. Remove fragment (#...)
        7. Decode percent-encoded characters that don't need encoding

    Args:
        url: Raw URL string to normalize.

    Returns:
        Canonicalized URL string, or the original string if parsing fails.
    """
    if not url or not url.strip():
        return url

    url = url.strip()

    # Prepend scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        logger.warning("Failed to parse URL: %s", url[:200])
        return url

    # 1. Lowercase scheme and hostname
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""

    # Handle IDN domains → punycode
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        # Already ASCII or invalid — keep as-is
        hostname = hostname.lower()

    hostname = hostname.lower()

    # 2. Strip default ports
    port = parsed.port
    if port and _DEFAULT_PORTS.get(scheme) == port:
        port = None

    netloc = hostname
    if port:
        netloc = f"{hostname}:{port}"

    # Add back userinfo if present (rare in scam URLs but preserve correctness)
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        netloc = f"{userinfo}@{netloc}"

    # 3. Decode and re-encode path for normalization, then remove trailing slash
    path = unquote(parsed.path)
    path = quote(path, safe=_PATH_SAFE)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    if not path:
        path = "/"

    # 4 & 5. Sort query params and remove tracking params
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    filtered_params: dict[str, list[str]] = {}
    for key in sorted(query_params.keys()):
        if key.lower() not in _TRACKING_PARAMS:
            filtered_params[key] = query_params[key]

    query = urlencode(filtered_params, doseq=True)

    # 6. Remove fragment
    fragment = ""

    return urlunparse((scheme, netloc, path, parsed.params, query, fragment))
