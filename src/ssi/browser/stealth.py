"""Browser anti-detection: proxy rotation and fingerprint randomization.

Provides a unified ``BrowserProfile`` that configures Playwright's
``launch()`` and ``new_context()`` calls with:

- Rotating proxy servers (round-robin or random from a pool)
- Randomized browser fingerprints (viewport, locale, timezone, user-agent, etc.)
- Stealth patches (disable ``navigator.webdriver``, patch ``chrome.runtime``)

Usage::

    from ssi.browser.stealth import build_browser_profile, apply_stealth_scripts

    profile = build_browser_profile()
    browser = pw.chromium.launch(**profile.launch_args)
    context = browser.new_context(**profile.context_args)
    page = context.new_page()
    apply_stealth_scripts(page)
"""

from __future__ import annotations

import itertools
import logging
import random
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Common user-agent strings (Chrome on desktop — recent versions)
# ---------------------------------------------------------------------------

_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# Common viewport sizes (width × height)
_VIEWPORTS: list[dict[str, int]] = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
    {"width": 1440, "height": 900},
    {"width": 1280, "height": 720},
    {"width": 1600, "height": 900},
    {"width": 2560, "height": 1440},
]

# Locale + timezone pairs (plausible combinations)
_LOCALE_TIMEZONE_PAIRS: list[tuple[str, str]] = [
    ("en-US", "America/New_York"),
    ("en-US", "America/Chicago"),
    ("en-US", "America/Denver"),
    ("en-US", "America/Los_Angeles"),
    ("en-GB", "Europe/London"),
    ("en-AU", "Australia/Sydney"),
    ("en-CA", "America/Toronto"),
    ("de-DE", "Europe/Berlin"),
    ("fr-FR", "Europe/Paris"),
    ("es-ES", "Europe/Madrid"),
    ("ja-JP", "Asia/Tokyo"),
    ("pt-BR", "America/Sao_Paulo"),
]

# Stealth JavaScript — injected via page.add_init_script()
_STEALTH_SCRIPTS: str = """
// Remove navigator.webdriver flag
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

// Mimic chrome.runtime (present in real Chrome)
if (!window.chrome) window.chrome = {};
if (!window.chrome.runtime) window.chrome.runtime = {};

// Patch navigator.plugins to look non-empty
Object.defineProperty(navigator, 'plugins', {
    get: () => [1, 2, 3, 4, 5],
});

// Patch navigator.languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en'],
});

// Prevent detection via permissions API
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) =>
    parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : originalQuery(parameters);
"""


# ---------------------------------------------------------------------------
# Proxy pool
# ---------------------------------------------------------------------------


class ProxyPool:
    """Thread-safe round-robin or random proxy selector.

    Args:
        proxies: List of proxy URLs (e.g. ``["socks5://host:port", "http://user:pass@host:port"]``).
        strategy: ``"round_robin"`` or ``"random"``.
    """

    def __init__(self, proxies: list[str], strategy: str = "round_robin") -> None:
        self._proxies = [p.strip() for p in proxies if p.strip()]
        self._strategy = strategy
        self._cycle = itertools.cycle(self._proxies) if self._proxies else None

    @property
    def available(self) -> bool:
        return bool(self._proxies)

    @property
    def size(self) -> int:
        return len(self._proxies)

    def __len__(self) -> int:
        return len(self._proxies)

    def next(self) -> str | None:
        """Return the next proxy URL, or ``None`` if pool is empty."""
        if not self._proxies:
            return None
        if self._strategy == "random":
            return random.choice(self._proxies)
        # round_robin
        return next(self._cycle)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Browser profile
# ---------------------------------------------------------------------------


@dataclass
class BrowserProfile:
    """All Playwright launch + context arguments for a single session.

    Generated by ``build_browser_profile()`` with randomized values.
    """

    # Arguments for pw.chromium.launch()
    launch_args: dict[str, Any] = field(default_factory=dict)

    # Arguments for browser.new_context()
    context_args: dict[str, Any] = field(default_factory=dict)

    # Metadata for logging / audit
    user_agent: str = ""
    viewport: dict[str, int] = field(default_factory=dict)
    locale: str = ""
    timezone_id: str = ""
    proxy_url: str = ""
    color_scheme: str = ""


def build_browser_profile(
    *,
    headless: bool = True,
    proxy_pool: ProxyPool | None = None,
    explicit_proxy: str = "",
    explicit_user_agent: str = "",
    randomize_fingerprint: bool = True,
    record_har_path: str = "",
    record_video_dir: str = "",
) -> BrowserProfile:
    """Build a ``BrowserProfile`` with optional proxy and fingerprint randomization.

    Args:
        headless: Run browser in headless mode.
        proxy_pool: A ``ProxyPool`` to select the next proxy from.
        explicit_proxy: A single proxy URL (overrides pool).
        explicit_user_agent: Force this user-agent (overrides random).
        randomize_fingerprint: Randomize viewport, locale, timezone, etc.
        record_har_path: Path to record HAR to.
        record_video_dir: Directory to record video to.

    Returns:
        A ``BrowserProfile`` ready for Playwright.
    """
    profile = BrowserProfile()

    # --- Launch args ---
    profile.launch_args["headless"] = headless

    # Proxy: pool > explicit > none (pool is the active rotation mechanism)
    proxy_url: str | None = None
    if proxy_pool and proxy_pool.available:
        proxy_url = proxy_pool.next()
    elif explicit_proxy:
        proxy_url = explicit_proxy.strip() or None

    if proxy_url:
        profile.launch_args["proxy"] = {"server": proxy_url}
        profile.proxy_url = proxy_url
        logger.debug("Using proxy: %s", proxy_url)

    # --- Context args ---
    ctx = profile.context_args

    # User-agent
    if explicit_user_agent:
        ctx["user_agent"] = explicit_user_agent
        profile.user_agent = explicit_user_agent
    elif randomize_fingerprint:
        ua = random.choice(_USER_AGENTS)
        ctx["user_agent"] = ua
        profile.user_agent = ua

    # Viewport
    if randomize_fingerprint:
        vp = random.choice(_VIEWPORTS)
        ctx["viewport"] = vp
        profile.viewport = vp

    # Locale + timezone
    if randomize_fingerprint:
        locale, tz = random.choice(_LOCALE_TIMEZONE_PAIRS)
        ctx["locale"] = locale
        ctx["timezone_id"] = tz
        profile.locale = locale
        profile.timezone_id = tz

    # Color scheme
    if randomize_fingerprint:
        scheme = random.choice(["light", "dark", "no-preference"])
        ctx["color_scheme"] = scheme
        profile.color_scheme = scheme

    # Device scale factor (DPR)
    if randomize_fingerprint:
        ctx["device_scale_factor"] = random.choice([1, 1.5, 2])

    # HAR / video recording
    if record_har_path:
        ctx["record_har_path"] = record_har_path
    if record_video_dir:
        ctx["record_video_dir"] = record_video_dir

    # Scam sites rarely have valid SSL certs — accept them anyway.
    ctx["ignore_https_errors"] = True

    return profile


def apply_stealth_scripts(page) -> None:
    """Inject stealth JavaScript into a Playwright page.

    Call this **before** navigating to the target URL so the scripts
    execute in every frame from the start.

    Args:
        page: Playwright ``Page`` object.
    """
    page.add_init_script(_STEALTH_SCRIPTS)
    logger.debug("Stealth scripts injected")
