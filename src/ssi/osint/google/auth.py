"""Google OSINT Authentication module."""

import hashlib
import time
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ssi.browser.zen_manager import ZenBrowserManager


class GoogleAuthManager:
    """Manages Google authentication and header generation for OSINT scrapers."""

    def __init__(
        self,
        browser: Optional["ZenBrowserManager"] = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        """Initialize with an active browser session or explicit cookies."""
        self.browser = browser
        self.cookies = cookies or {}

    async def extract_auth_cookies(self) -> dict[str, str]:
        """Extract SAPISID and authuser cookies from the browser session.

        Returns:
            A dictionary containing the required auth cookies if found.
        """
        if self.cookies:
            return self.cookies

        if not self.browser:
            return {}

        cookies_raw = await self.browser.get_cookies()
        auth_cookies = {}

        for cookie in cookies_raw:
            # Handle both dictionary and object representations of cookies
            name = cookie.get("name") if isinstance(cookie, dict) else getattr(cookie, "name", "")
            value = cookie.get("value") if isinstance(cookie, dict) else getattr(cookie, "value", "")

            if name in ("SAPISID", "authuser") and value:
                auth_cookies[name] = value

        return auth_cookies

    def generate_sapisidhash(self, sapisid: str, origin: str = "https://myaccount.google.com") -> str:
        """Generate the SAPISIDHASH header required for Google API requests.

        Args:
            sapisid: The SAPISID cookie value.
            origin: The origin domain to use for the hash (default: https://myaccount.google.com).

        Returns:
            The formatted SAPISIDHASH string.
        """
        timestamp = str(int(time.time()))
        payload = f"{timestamp} {sapisid} {origin}"
        hash_val = hashlib.sha1(payload.encode("utf-8")).hexdigest()
        return f"SAPISIDHASH {timestamp}_{hash_val}"

    async def get_auth_headers(self, origin: str = "https://myaccount.google.com") -> dict[str, str] | None:
        """Extract cookies and generate the required authentication headers.

        Returns:
            A dictionary with the Authorization and Cookie headers, or None if SAPISID is missing.
        """
        cookies = await self.extract_auth_cookies()
        sapisid = cookies.get("SAPISID")

        if not sapisid:
            return None

        sapisidhash = self.generate_sapisidhash(sapisid, origin=origin)

        # Build the cookie string from extracted cookies
        cookie_parts = []
        for name, value in cookies.items():
            cookie_parts.append(f"{name}={value}")

        return {"Authorization": sapisidhash, "Cookie": "; ".join(cookie_parts)}
