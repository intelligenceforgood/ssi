"""Playwright-based page capture for passive reconnaissance."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ssi.browser.downloads import DownloadInterceptor
from ssi.models.investigation import FormField, PageSnapshot

logger = logging.getLogger(__name__)


def capture_page(url: str, output_dir: Path) -> PageSnapshot:
    """Navigate to *url*, capture screenshot, DOM, forms, and network data.

    Uses Playwright in headless mode. Requires ``playwright install chromium``
    to have been run at least once.

    Args:
        url: The URL to visit.
        output_dir: Directory to write artifacts (screenshot, DOM, HAR).

    Returns:
        Populated ``PageSnapshot``.
    """
    from playwright.sync_api import sync_playwright

    from ssi.browser.stealth import ProxyPool, apply_stealth_scripts, build_browser_profile
    from ssi.settings import get_settings

    settings = get_settings()
    snapshot = PageSnapshot(url=url)

    with sync_playwright() as pw:
        # Build a stealth-aware browser profile
        proxy_pool = ProxyPool(settings.stealth.proxy_urls) if settings.stealth.proxy_urls else None
        har_path = output_dir / "network.har" if settings.browser.record_har else None
        video_dir = output_dir / "video" if settings.browser.record_video else None
        if video_dir:
            video_dir.mkdir(parents=True, exist_ok=True)

        profile = build_browser_profile(
            headless=settings.browser.headless,
            proxy_pool=proxy_pool,
            explicit_proxy=settings.browser.proxy or None,
            explicit_user_agent=settings.browser.user_agent or None,
            randomize_fingerprint=settings.stealth.randomize_fingerprint,
            record_har_path=str(har_path) if har_path else None,
            record_video_dir=str(video_dir) if video_dir else None,
        )

        browser = pw.chromium.launch(**profile.launch_args)
        context = browser.new_context(**profile.context_args)
        page = context.new_page()

        # Apply anti-detection stealth scripts
        if settings.stealth.apply_stealth_scripts:
            apply_stealth_scripts(page)

        # Attach download interceptor
        downloads_dir = output_dir / "downloads"
        interceptor = DownloadInterceptor(
            output_dir=downloads_dir,
            check_virustotal=bool(settings.osint.virustotal_api_key),
        )
        interceptor.attach(page)

        try:
            # Track redirects
            redirect_chain: list[str] = []

            def on_response(response):
                if 300 <= response.status < 400:
                    redirect_chain.append(response.url)

            page.on("response", on_response)

            # Navigate
            response = page.goto(url, wait_until="networkidle", timeout=settings.browser.timeout_ms)

            # Check for CAPTCHA
            from ssi.browser.captcha import CaptchaStrategy, detect_captcha, handle_captcha

            captcha_detection = detect_captcha(page)
            if captcha_detection.detected:
                logger.info("CAPTCHA detected: %s", captcha_detection.captcha_type.value)
                captcha_strategy = CaptchaStrategy(settings.captcha.strategy)
                handle_captcha(
                    page,
                    captcha_detection,
                    strategy=captcha_strategy,
                    wait_seconds=settings.captcha.wait_seconds,
                    screenshot_dir=output_dir if settings.captcha.screenshot_on_detect else None,
                )

            snapshot.final_url = page.url
            snapshot.status_code = response.status if response else 0
            snapshot.title = page.title()
            snapshot.redirect_chain = redirect_chain

            # Capture response headers
            if response:
                snapshot.headers = dict(response.headers)

            # Screenshot
            screenshot_path = output_dir / "screenshot.png"
            page.screenshot(path=str(screenshot_path), full_page=True)
            snapshot.screenshot_path = str(screenshot_path)

            # DOM snapshot
            dom_path = output_dir / "dom.html"
            dom_path.write_text(page.content())
            snapshot.dom_snapshot_path = str(dom_path)

            # Form field inventory
            snapshot.form_fields = _extract_form_fields(page)

            # External resources
            snapshot.external_resources = _extract_external_resources(page, url)

            # HAR path
            if har_path:
                snapshot.har_path = str(har_path)

            # Attach intercepted downloads metadata to snapshot
            snapshot.captured_downloads = [
                {
                    "url": d.url,
                    "filename": d.suggested_filename,
                    "saved_path": d.saved_path,
                    "sha256": d.sha256,
                    "md5": d.md5,
                    "size_bytes": d.size_bytes,
                    "is_malicious": d.is_malicious,
                }
                for d in interceptor.downloads
            ]

        except Exception as e:
            logger.error("Page capture failed for %s: %s", url, e)
            raise
        finally:
            context.close()
            browser.close()

    return snapshot


def _extract_form_fields(page) -> list[FormField]:
    """Extract all form input fields from the current page."""
    fields = page.evaluate(
        """() => {
        const fields = [];
        const inputs = document.querySelectorAll('input, select, textarea');
        inputs.forEach(el => {
            // Find associated label
            let label = '';
            if (el.id) {
                const labelEl = document.querySelector(`label[for="${el.id}"]`);
                if (labelEl) label = labelEl.textContent.trim();
            }
            if (!label && el.closest('label')) {
                label = el.closest('label').textContent.trim();
            }

            fields.push({
                tag: el.tagName.toLowerCase(),
                field_type: el.type || el.tagName.toLowerCase(),
                name: el.name || '',
                label: label,
                placeholder: el.placeholder || '',
                required: el.required || false,
            });
        });
        return fields;
    }"""
    )

    return [FormField(**f) for f in fields]


def _extract_external_resources(page, base_url: str) -> list[str]:
    """Extract URLs of external resources loaded by the page."""
    from urllib.parse import urlparse

    base_domain = urlparse(base_url).hostname or ""

    resources = page.evaluate(
        """() => {
        const urls = new Set();
        // Scripts
        document.querySelectorAll('script[src]').forEach(el => urls.add(el.src));
        // Stylesheets
        document.querySelectorAll('link[rel="stylesheet"]').forEach(el => urls.add(el.href));
        // Images
        document.querySelectorAll('img[src]').forEach(el => urls.add(el.src));
        // Iframes
        document.querySelectorAll('iframe[src]').forEach(el => urls.add(el.src));
        return [...urls];
    }"""
    )

    return [r for r in resources if r and urlparse(r).hostname != base_domain]
