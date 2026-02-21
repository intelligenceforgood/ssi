"""CAPTCHA detection and handling strategy.

Implements a graceful degradation approach:

1. **Detect** — check common CAPTCHA provider signatures in the DOM.
2. **Attempt bypass** — for simple challenges (honeypot fields, basic JS),
   apply automated workarounds.
3. **Degrade gracefully** — log the CAPTCHA encounter, capture a screenshot,
   and continue with partial results rather than failing the investigation.

External solver integration (2Captcha, Anti-Captcha, hCaptcha Accessibility)
can be enabled via ``SSI_BROWSER__CAPTCHA_SOLVER`` when budget allows.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from playwright.sync_api import Page


class CaptchaType(str, Enum):
    """Known CAPTCHA provider types."""

    RECAPTCHA_V2 = "recaptcha_v2"
    RECAPTCHA_V3 = "recaptcha_v3"
    HCAPTCHA = "hcaptcha"
    CLOUDFLARE_TURNSTILE = "cloudflare_turnstile"
    FUNCAPTCHA = "funcaptcha"
    TEXT_CAPTCHA = "text_captcha"
    UNKNOWN = "unknown"


class CaptchaStrategy(str, Enum):
    """How to handle a detected CAPTCHA."""

    SKIP = "skip"  # Log and continue with partial results
    WAIT = "wait"  # Wait a configurable duration and retry
    SOLVER = "solver"  # Delegate to external solver service
    ACCESSIBILITY = "accessibility"  # Use accessibility cookie/mode


@dataclass
class CaptchaDetection:
    """Result of scanning a page for CAPTCHAs."""

    detected: bool = False
    captcha_type: CaptchaType = CaptchaType.UNKNOWN
    provider_url: str = ""
    element_selector: str = ""
    page_url: str = ""
    screenshot_path: str = ""


@dataclass
class CaptchaResult:
    """Outcome of a CAPTCHA handling attempt."""

    detection: CaptchaDetection = field(default_factory=CaptchaDetection)
    strategy_used: CaptchaStrategy = CaptchaStrategy.SKIP
    solved: bool = False
    error: str = ""
    wait_seconds: float = 0.0


# Signatures: (CSS selector or JS expression, CaptchaType)
_CAPTCHA_SIGNATURES: list[tuple[str, CaptchaType]] = [
    ('iframe[src*="google.com/recaptcha"]', CaptchaType.RECAPTCHA_V2),
    ('iframe[src*="recaptcha/api"]', CaptchaType.RECAPTCHA_V2),
    (".g-recaptcha", CaptchaType.RECAPTCHA_V2),
    ('script[src*="recaptcha/api.js?render="]', CaptchaType.RECAPTCHA_V3),
    ('iframe[src*="hcaptcha.com"]', CaptchaType.HCAPTCHA),
    (".h-captcha", CaptchaType.HCAPTCHA),
    ('iframe[src*="challenges.cloudflare.com"]', CaptchaType.CLOUDFLARE_TURNSTILE),
    (".cf-turnstile", CaptchaType.CLOUDFLARE_TURNSTILE),
    ('iframe[src*="funcaptcha.com"]', CaptchaType.FUNCAPTCHA),
    ("#funcaptcha", CaptchaType.FUNCAPTCHA),
]


def detect_captcha(page: Page) -> CaptchaDetection:
    """Scan the current page for CAPTCHA elements.

    Args:
        page: Playwright ``Page`` object.

    Returns:
        A ``CaptchaDetection`` with details if a CAPTCHA is found.
    """
    detection = CaptchaDetection(page_url=page.url)

    for selector, captcha_type in _CAPTCHA_SIGNATURES:
        try:
            locator = page.locator(selector)
            if locator.count() > 0:
                detection.detected = True
                detection.captcha_type = captcha_type
                detection.element_selector = selector
                logger.info("CAPTCHA detected: %s (%s) on %s", captcha_type.value, selector, page.url)
                return detection
        except Exception:
            continue

    # Fallback: check page text for common CAPTCHA phrases
    try:
        body_text = page.inner_text("body").lower()
        captcha_phrases = [
            "verify you are human",
            "prove you're not a robot",
            "complete the security check",
            "please verify",
            "i'm not a robot",
            "checking your browser",
            "just a moment",
        ]
        for phrase in captcha_phrases:
            if phrase in body_text:
                detection.detected = True
                detection.captcha_type = CaptchaType.UNKNOWN
                logger.info("CAPTCHA phrase detected: '%s' on %s", phrase, page.url)
                return detection
    except Exception:
        pass

    return detection


def handle_captcha(
    page: Page,
    detection: CaptchaDetection,
    *,
    strategy: CaptchaStrategy = CaptchaStrategy.SKIP,
    wait_seconds: float = 10.0,
    solver_api_key: str = "",
    screenshot_dir: str | Path | None = None,
) -> CaptchaResult:
    """Attempt to handle a detected CAPTCHA.

    Args:
        page: Playwright ``Page`` object.
        detection: The CAPTCHA detection result.
        strategy: How to handle it (skip, wait, solver, accessibility).
        wait_seconds: Seconds to wait if strategy is ``WAIT``.
        solver_api_key: API key for external solver (if strategy is ``SOLVER``).
        screenshot_dir: Directory to save CAPTCHA screenshot for evidence.

    Returns:
        A ``CaptchaResult`` describing the outcome.
    """
    result = CaptchaResult(detection=detection, strategy_used=strategy)

    if not detection.detected:
        result.solved = True
        return result

    # Capture CAPTCHA screenshot for evidence
    if screenshot_dir:
        try:
            ss_path = Path(screenshot_dir) / "captcha_detected.png"
            page.screenshot(path=str(ss_path), full_page=False)
            detection.screenshot_path = str(ss_path)
            logger.info("CAPTCHA screenshot saved: %s", ss_path)
        except Exception as e:
            logger.warning("Failed to capture CAPTCHA screenshot: %s", e)

    if strategy == CaptchaStrategy.SKIP:
        logger.info("CAPTCHA strategy=SKIP — continuing with partial results")
        result.solved = False
        return result

    if strategy == CaptchaStrategy.WAIT:
        return _handle_wait(page, detection, result, wait_seconds)

    if strategy == CaptchaStrategy.ACCESSIBILITY:
        return _handle_accessibility(page, detection, result)

    if strategy == CaptchaStrategy.SOLVER:
        return _handle_solver(page, detection, result, solver_api_key)

    return result


def _handle_wait(
    page,
    detection: CaptchaDetection,
    result: CaptchaResult,
    wait_seconds: float,
) -> CaptchaResult:
    """Wait for Cloudflare-style challenges that auto-resolve.

    Some "checking your browser" interstitials resolve after a few seconds
    of JavaScript execution. This strategy waits and then checks if the
    CAPTCHA element has disappeared.
    """
    import time

    logger.info("CAPTCHA strategy=WAIT — waiting %.1fs for auto-resolve", wait_seconds)
    result.wait_seconds = wait_seconds
    time.sleep(wait_seconds)

    # Check if CAPTCHA disappeared
    recheck = detect_captcha(page)
    if not recheck.detected:
        logger.info("CAPTCHA resolved after waiting %.1fs", wait_seconds)
        result.solved = True
    else:
        logger.warning("CAPTCHA still present after waiting %.1fs", wait_seconds)
        result.solved = False

    return result


def _handle_accessibility(
    page,
    detection: CaptchaDetection,
    result: CaptchaResult,
) -> CaptchaResult:
    """Attempt to use CAPTCHA accessibility features.

    hCaptcha and reCAPTCHA v2 provide accessibility cookies that bypass
    the visual challenge. This method sets the known accessibility cookie
    and reloads the page.
    """
    logger.info("CAPTCHA strategy=ACCESSIBILITY — attempting bypass")

    try:
        if detection.captcha_type == CaptchaType.HCAPTCHA:
            # hCaptcha accessibility cookie
            page.context.add_cookies(
                [
                    {
                        "name": "hc_accessibility",
                        "value": "1",
                        "domain": ".hcaptcha.com",
                        "path": "/",
                    }
                ]
            )
            page.reload(wait_until="networkidle", timeout=15_000)
            recheck = detect_captcha(page)
            result.solved = not recheck.detected

        elif detection.captcha_type in (CaptchaType.CLOUDFLARE_TURNSTILE,):
            # Cloudflare Turnstile — wait strategy is usually better
            return _handle_wait(page, detection, result, wait_seconds=15.0)

        else:
            logger.warning("No accessibility handler for %s", detection.captcha_type.value)
            result.solved = False

    except Exception as e:
        logger.warning("Accessibility bypass failed: %s", e)
        result.error = str(e)
        result.solved = False

    return result


def _handle_solver(
    page,
    detection: CaptchaDetection,
    result: CaptchaResult,
    solver_api_key: str,
) -> CaptchaResult:
    """Delegate CAPTCHA solving to an external service.

    Supports 2Captcha/Anti-Captcha style APIs. Requires ``solver_api_key``
    to be set via ``SSI_BROWSER__CAPTCHA_SOLVER_KEY``.

    Note: This is a stub for future integration. Full implementation
    requires the ``twocaptcha`` SDK or equivalent HTTP API client.
    """
    if not solver_api_key:
        logger.warning("CAPTCHA strategy=SOLVER but no API key configured — falling back to SKIP")
        result.strategy_used = CaptchaStrategy.SKIP
        result.solved = False
        result.error = "No solver API key configured"
        return result

    logger.info(
        "CAPTCHA strategy=SOLVER — delegating %s to external solver",
        detection.captcha_type.value,
    )

    # Stub: future integration with 2Captcha / Anti-Captcha
    # The flow would be:
    #   1. Extract sitekey from the CAPTCHA iframe/element
    #   2. Submit to solver API with page URL
    #   3. Poll for solution token
    #   4. Inject token into page and submit form
    result.error = "External solver integration not yet implemented"
    result.solved = False
    logger.warning("External CAPTCHA solver not yet implemented — falling back to partial results")
    return result
