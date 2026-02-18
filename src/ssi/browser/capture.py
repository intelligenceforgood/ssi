"""Playwright-based page capture for passive reconnaissance."""

from __future__ import annotations

import json
import logging
from pathlib import Path

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

    from ssi.settings import get_settings

    settings = get_settings()
    snapshot = PageSnapshot(url=url)

    with sync_playwright() as pw:
        browser_args: dict = {
            "headless": settings.browser.headless,
        }

        # Record HAR if enabled
        har_path = output_dir / "network.har" if settings.browser.record_har else None

        browser = pw.chromium.launch(**browser_args)
        context_args: dict = {}
        if har_path:
            context_args["record_har_path"] = str(har_path)
        if settings.browser.user_agent:
            context_args["user_agent"] = settings.browser.user_agent

        context = browser.new_context(**context_args)
        page = context.new_page()

        try:
            # Track redirects
            redirect_chain: list[str] = []

            def on_response(response):
                if 300 <= response.status < 400:
                    redirect_chain.append(response.url)

            page.on("response", on_response)

            # Navigate
            response = page.goto(url, wait_until="networkidle", timeout=settings.browser.timeout_ms)

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
