"""Google OSINT Authentication module.

Manages extraction of Google session cookies from the SSI browser
and generates the SAPISIDHASH authorization header required by
Google's internal (non-public) API endpoints.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from ssi.browser.zen_manager import ZenBrowserManager

logger = logging.getLogger(__name__)

# The full set of cookies required for authenticated Google internal API calls.
_REQUIRED_COOKIE_NAMES: frozenset[str] = frozenset({"SID", "HSID", "SSID", "APISID", "SAPISID"})

# Minimum required — SAPISID is needed for the hash; the others ride along
# in the Cookie header.  NID is optional but improves reliability.
_CRITICAL_COOKIE_NAMES: frozenset[str] = frozenset({"SAPISID"})

# Default User-Agent matching a standard desktop browser to reduce bot flags.
_DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:131.0) Gecko/20100101 Firefox/131.0"


class GoogleAuthManager:
    """Manages Google authentication and header generation for OSINT scrapers.

    Can be initialised in two ways:

    1. **From explicit cookies** — pass a ``cookies`` dict extracted earlier
       from the browser session (preferred for Phase 2.7 where the browser
       is already closed).
    2. **From a live browser** — pass a ``ZenBrowserManager`` and call
       ``extract_auth_cookies()`` to pull cookies from the Chromium session.
    """

    def __init__(
        self,
        browser: ZenBrowserManager | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        self._browser = browser
        self._cookies: dict[str, str] = dict(cookies) if cookies else {}
        self._validated: bool | None = None  # tri-state: None=unchecked

    # ── Cookie Extraction ────────────────────────────────────────────────

    async def extract_auth_cookies(self) -> dict[str, str]:
        """Extract Google auth cookies from the browser session.

        Populates ``self._cookies`` and returns the dict.  If cookies were
        already provided at init time, returns those without touching the
        browser.
        """
        if self._cookies:
            return self._cookies

        if not self._browser:
            logger.debug("GoogleAuthManager: no browser and no cookies provided")
            return {}

        try:
            cookies_raw = await self._browser.get_cookies()
        except Exception:
            logger.warning("Failed to extract cookies from browser session", exc_info=True)
            return {}

        auth_cookies: dict[str, str] = {}
        for cookie in cookies_raw:
            # Handle both dict and object cookie representations
            name = cookie.get("name") if isinstance(cookie, dict) else getattr(cookie, "name", "")
            value = cookie.get("value") if isinstance(cookie, dict) else getattr(cookie, "value", "")

            if not name or not value:
                continue

            # Collect all Google-domain session cookies
            domain = cookie.get("domain") if isinstance(cookie, dict) else getattr(cookie, "domain", "")
            if domain and ".google.com" in str(domain):
                auth_cookies[name] = value

        self._cookies = auth_cookies
        return auth_cookies

    # ── SAPISIDHASH Generation ───────────────────────────────────────────

    @staticmethod
    def generate_sapisidhash(
        sapisid: str,
        origin: str,
        timestamp: str | None = None,
    ) -> str:
        """Generate the SAPISIDHASH authorization header value.

        The algorithm:
            hash = SHA1(timestamp + " " + SAPISID + " " + origin)
            header = "{timestamp}_{hash}"

        Args:
            sapisid: The SAPISID cookie value.
            origin: The origin URL (e.g. ``https://photos.google.com``).
            timestamp: Optional override for reproducible testing.

        Returns:
            The SAPISIDHASH string (without the ``SAPISIDHASH `` prefix).
        """
        if timestamp is None:
            timestamp = str(int(time.time()))
        payload = f"{timestamp} {sapisid} {origin}"
        hash_hex = hashlib.sha1(payload.encode("utf-8")).hexdigest()
        return f"{timestamp}_{hash_hex}"

    # ── Header Construction ──────────────────────────────────────────────

    def build_authenticated_headers(
        self,
        origin: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, str] | None:
        """Build the full header set for an authenticated Google API request.

        Returns ``None`` if the SAPISID cookie is not available (caller
        should interpret this as "auth unavailable, skip").

        Args:
            origin: The origin URL for the SAPISIDHASH and referer.
            extra_headers: Additional headers to merge (e.g. Host override).
        """
        sapisid = self._cookies.get("SAPISID")
        if not sapisid:
            logger.debug("SAPISID cookie not available — cannot build auth headers")
            return None

        sapisidhash = self.generate_sapisidhash(sapisid, origin)

        # Build cookie header string from all available cookies
        cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookies.items())

        headers: dict[str, str] = {
            "User-Agent": _DEFAULT_USER_AGENT,
            "Authorization": f"SAPISIDHASH {sapisidhash}",
            "Cookie": cookie_str,
            "Origin": origin,
            "Referer": f"{origin}/",
            "Connection": "Keep-Alive",
        }

        if extra_headers:
            headers.update(extra_headers)

        return headers

    def build_cookie_headers(self) -> dict[str, str] | None:
        """Build headers with cookies only (no SAPISIDHASH).

        Used for endpoints like Maps that need session cookies but not
        the SAPISIDHASH authorization header.
        """
        if not self._cookies:
            return None

        cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
        return {
            "User-Agent": _DEFAULT_USER_AGENT,
            "Cookie": cookie_str,
            "Connection": "Keep-Alive",
        }

    # ── Validation Gate (Step 3) ─────────────────────────────────────────

    @property
    def has_required_cookies(self) -> bool:
        """Check whether the minimum required cookies are present."""
        return all(self._cookies.get(name) for name in _CRITICAL_COOKIE_NAMES)

    async def validate_cookies(self) -> bool:
        """Validate cookies against Google's CheckCookie endpoint.

        Returns ``True`` if cookies are valid, ``False`` otherwise.
        Caches the result so subsequent calls are free.
        """
        if self._validated is not None:
            return self._validated

        if not self.has_required_cookies:
            logger.info("Google OSINT: skipping — required cookies not available")
            self._validated = False
            return False

        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
                resp = await client.get(
                    "https://accounts.google.com/CheckCookie",
                    params={"continue": "https://www.google.com/robots.txt"},
                    cookies=self._cookies,
                    headers={"User-Agent": _DEFAULT_USER_AGENT},
                )
                # A valid session redirects (302) to the continue URL.
                # Invalid sessions redirect to support/CookieMismatch pages.
                is_valid = resp.status_code == 302 and not any(
                    resp.headers.get("Location", "").startswith(prefix)
                    for prefix in (
                        "https://support.google.com",
                        "https://accounts.google.com/CookieMismatch",
                    )
                )
        except Exception:
            logger.debug("Cookie validation request failed", exc_info=True)
            is_valid = False

        self._validated = is_valid
        if is_valid:
            logger.info("Google OSINT: session cookies validated successfully")
        else:
            logger.info("Google OSINT: session cookies are invalid or expired — skipping")

        return is_valid

    @property
    def cookies(self) -> dict[str, str]:
        """Read-only access to the current cookie dict."""
        return dict(self._cookies)
