"""Zen Browser Manager — wraps zendriver for undetected Chrome automation.

Handles browser lifecycle, proxy configuration, page navigation,
element interaction, and screenshot capture. Ported from AWH's
``browser_manager.py`` with SSI settings integration.

NOTE ON ZENDRIVER API COMPATIBILITY:
zendriver's API is based on CDP and may change across versions.
This module uses zendriver's documented patterns:
  - zd.start(config) → Browser
  - browser.get(url) → Tab
  - tab.find(text/selector) → Element
  - tab.evaluate(js) → result

If method signatures change, update this file — the rest of the agent
is isolated from zendriver internals through this abstraction.
"""

from __future__ import annotations

import asyncio
import base64
import json as _json
import logging
import re
from io import BytesIO
from pathlib import Path

import zendriver as zd
from PIL import Image

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _cdp_screenshot(tab) -> bytes:
    """Take a screenshot using CDP directly."""
    result = await tab.send(zd.cdp.page.capture_screenshot(format_="png"))
    return base64.b64decode(result)


def _resize_png(png_bytes: bytes, width: int, height: int) -> bytes:
    """Downscale PNG bytes to fit within target resolution, preserving aspect ratio.

    Uses thumbnail() which never upscales and always preserves aspect ratio.
    If the image is already at or below the target, returns original bytes unchanged.
    """
    img = Image.open(BytesIO(png_bytes))
    if img.width <= width and img.height <= height:
        return png_bytes
    img.thumbnail((width, height), Image.LANCZOS)
    buf = BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class ZenBrowserManager:
    """Manages a single zendriver browser session with proxy and anti-detection.

    Proxy auth uses IP whitelisting on the Decodo dashboard — no credentials
    needed in the proxy URL. Just whitelist your outbound IP and connect to
    gate.decodo.com:PORT directly.

    All configuration is read from ``ssi.settings.get_settings()`` at
    construction time.
    """

    def __init__(self) -> None:
        from ssi.settings import get_settings

        s = get_settings()

        self._headless: bool = s.zen_browser.headless
        self._chrome_binary: str = s.zen_browser.chrome_binary
        self._page_zoom: float = s.zen_browser.page_zoom
        self._action_timeout: int = s.zen_browser.action_timeout
        self._resize_w: int = s.zen_browser.screenshot_resize_width
        self._resize_h: int = s.zen_browser.screenshot_resize_height
        self._proxy_host: str = s.proxy.host
        self._proxy_port: str = s.proxy.port
        self._proxy_enabled: bool = s.proxy.enabled

        self._browser: zd.Browser | None = None
        self._page = None  # zendriver.Tab
        self.last_click_strategy: str = ""
        self.last_type_strategy: str = ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Launch the browser with proxy and anti-detection settings."""
        config = zd.Config()

        if self._proxy_enabled and self._proxy_host and self._proxy_port:
            proxy_url = f"http://{self._proxy_host}:{self._proxy_port}"
            config.add_argument(f"--proxy-server={proxy_url}")
            logger.info("Proxy configured: %s:%s", self._proxy_host, self._proxy_port)

        config.headless = self._headless
        config.sandbox = False

        config.add_argument("--disable-gpu")
        config.add_argument("--window-size=1920,1080")
        config.add_argument("--disable-blink-features=AutomationControlled")

        if self._chrome_binary:
            config.browser_executable_path = self._chrome_binary

        self._browser = await zd.start(config=config)
        logger.info("Browser started (headless=%s)", self._headless)

    async def stop(self) -> None:
        """Shut down the browser cleanly."""
        if self._browser:
            try:
                await self._browser.stop()
            except Exception as e:
                logger.warning("Browser stop error (non-fatal): %s", e)
            finally:
                self._browser = None
                self._page = None
            logger.info("Browser stopped")

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    async def navigate(self, url: str) -> bool:
        """Navigate to a URL. Returns True if the page loaded successfully."""
        if not self._browser:
            raise RuntimeError("Browser not started. Call start() first.")
        try:
            self._page = await self._browser.get(url)
            await asyncio.sleep(5)
            await self._apply_zoom()
            logger.info("Navigated to: %s", url)
            return True
        except asyncio.TimeoutError:
            logger.error("Navigation timeout: %s", url)
            return False
        except Exception as e:
            logger.error("Navigation error for %s: %s", url, e)
            return False

    # ------------------------------------------------------------------
    # Screenshots
    # ------------------------------------------------------------------

    async def screenshot_base64(self) -> str:
        """Capture a downscaled screenshot as base64 PNG for LLM consumption."""
        if not self._page:
            raise RuntimeError("No active page")
        try:
            png_bytes = await _cdp_screenshot(self._page)
            resized = _resize_png(png_bytes, self._resize_w, self._resize_h)
            return base64.b64encode(resized).decode("utf-8")
        except Exception as e:
            logger.error("Screenshot failed: %s", e)
            raise

    async def screenshot_base64_full_res(self) -> str:
        """Capture a full-resolution screenshot for milestone/error archiving."""
        if not self._page:
            raise RuntimeError("No active page")
        try:
            png_bytes = await _cdp_screenshot(self._page)
            return base64.b64encode(png_bytes).decode("utf-8")
        except Exception as e:
            logger.error("Full-res screenshot failed: %s", e)
            raise

    async def screenshot_to_file(self, path: Path) -> Path:
        """Save a screenshot to a local file path."""
        b64_data = await self.screenshot_base64()
        png_bytes = base64.b64decode(b64_data)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(png_bytes)
        logger.info("Screenshot saved: %s", path)
        return path

    # ------------------------------------------------------------------
    # Scrolling / zoom
    # ------------------------------------------------------------------

    async def scroll_to_top(self) -> None:
        """Scroll the page to the very top."""
        if self._page:
            await self._page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(0.3)

    async def scroll_down(self, pixels: int = 500) -> None:
        """Scroll the page down by *pixels*."""
        if self._page:
            pixels = int(pixels)
            await self._page.evaluate(f"window.scrollBy(0, {pixels})")
            await asyncio.sleep(0.5)

    async def get_scroll_position(self) -> int:
        """Get the current vertical scroll position."""
        if not self._page:
            return 0
        try:
            pos = await self._page.evaluate("window.pageYOffset || 0")
            return int(pos)
        except Exception as e:
            logger.warning("Failed to get scroll position: %s", e)
            return 0

    async def _apply_zoom(self) -> None:
        """Apply CSS zoom so more content fits in each screenshot."""
        if not self._page or self._page_zoom >= 1.0:
            return
        try:
            zoom = _json.dumps(str(self._page_zoom))
            await self._page.evaluate(f"document.documentElement.style.zoom = {zoom}")
        except Exception as e:
            logger.debug("Failed to apply zoom: %s", e)

    # ------------------------------------------------------------------
    # Page information
    # ------------------------------------------------------------------

    async def get_page_text(self) -> str:
        """Extract visible text content from the current page."""
        if not self._page:
            return ""
        try:
            result = await self._page.evaluate("document.body ? document.body.innerText : ''")
            return result or ""
        except Exception as e:
            logger.warning("Failed to extract page text: %s", e)
            return ""

    async def get_page_url(self) -> str:
        """Get the current page URL."""
        if not self._page:
            return ""
        try:
            return await self._page.evaluate("window.location.href") or ""
        except Exception as e:
            logger.warning("Failed to get page URL: %s", e)
            return ""

    async def get_page_title(self) -> str:
        """Get the current page title."""
        if not self._page:
            return ""
        try:
            return await self._page.evaluate("document.title") or ""
        except Exception as e:
            logger.warning("Failed to get page title: %s", e)
            return ""

    async def get_page_html(self) -> str:
        """Get the outer HTML of the page (truncated for LLM context)."""
        if not self._page:
            return ""
        try:
            html = await self._page.evaluate("document.documentElement.outerHTML")
            if html and len(html) > 15000:
                return html[:15000] + "\n... [truncated]"
            return html or ""
        except Exception as e:
            logger.warning("Failed to get page HTML: %s", e)
            return ""

    async def get_field_value(self, selector: str) -> str:
        """Read the current value of an input field via JS."""
        if not self._page:
            return ""
        try:
            safe_sel = _json.dumps(selector)
            value = await self._page.evaluate(f"""
                (() => {{
                    const el = document.querySelector({safe_sel});
                    return el ? (el.value || '') : '';
                }})()
            """)
            return value or ""
        except Exception as e:
            logger.debug("get_field_value failed for '%s': %s", selector, e)
            return ""

    async def get_visible_errors(self) -> list[str]:
        """Extract visible error/validation messages from the DOM."""
        if not self._page:
            return []
        try:
            errors = await self._page.evaluate("""
                (() => {
                    const errors = new Set();
                    const isVisible = (el) => {
                        if (!el || !el.offsetParent && el.tagName !== 'BODY') return false;
                        const style = window.getComputedStyle(el);
                        return style.display !== 'none'
                            && style.visibility !== 'hidden'
                            && style.opacity !== '0';
                    };
                    const classPatterns = [
                        '[class*="error"]', '[class*="Error"]',
                        '[class*="alert"]', '[class*="Alert"]',
                        '[class*="danger"]', '[class*="Danger"]',
                        '[class*="warning"]', '[class*="Warning"]',
                        '[class*="invalid"]', '[class*="Invalid"]',
                        '[class*="toast"]', '[class*="Toast"]',
                        '[class*="notification"]', '[class*="Notification"]',
                    ];
                    for (const pattern of classPatterns) {
                        try {
                            for (const el of document.querySelectorAll(pattern)) {
                                if (isVisible(el)) {
                                    const text = (el.textContent || '').trim();
                                    if (text && text.length > 2 && text.length < 500) {
                                        errors.add(text);
                                    }
                                }
                            }
                        } catch(e) {}
                    }
                    for (const el of document.querySelectorAll('[role="alert"]')) {
                        if (isVisible(el)) {
                            const text = (el.textContent || '').trim();
                            if (text && text.length > 2 && text.length < 500) {
                                errors.add(text);
                            }
                        }
                    }
                    for (const el of document.querySelectorAll('input:invalid, select:invalid, textarea:invalid')) {
                        if (isVisible(el) && el.validationMessage) {
                            const label = el.name || el.id || el.type || 'field';
                            errors.add(label + ': ' + el.validationMessage);
                        }
                    }
                    return [...errors];
                })()
            """)
            return errors or []
        except Exception as e:
            logger.warning("Failed to extract visible errors: %s", e)
            return []

    async def get_form_field_values(self) -> str:
        """Read all visible form field values and format as a status string."""
        if not self._page:
            return ""
        try:
            fields = await self._page.evaluate("""
                (() => {
                    const results = [];
                    const fields = document.querySelectorAll('input, select, textarea');
                    for (const el of fields) {
                        if (el.type === 'hidden') continue;
                        const style = window.getComputedStyle(el);
                        const pos = style.position;
                        if (!el.offsetParent && pos !== 'fixed' && pos !== 'sticky' && el.tagName !== 'BODY') continue;
                        if (style.display === 'none' || style.visibility === 'hidden') continue;
                        const name = el.name || el.id || el.getAttribute('aria-label') || el.type || 'unknown';
                        const type = el.type || el.tagName.toLowerCase();
                        const value = el.value || '';
                        const placeholder = el.placeholder || '';
                        let status;
                        if (el.type === 'checkbox') {
                            status = el.checked ? 'CHECKED' : 'UNCHECKED';
                        } else if (el.type === 'password') {
                            status = value ? 'HAS VALUE (' + value.length + ' chars)' : 'EMPTY';
                        } else if (el.tagName === 'SELECT') {
                            const opt = el.options[el.selectedIndex];
                            const txt = opt ? opt.text : '';
                            const isDefault = !el.value || el.value === '' ||
                                txt.toLowerCase() === 'select' ||
                                txt.toLowerCase().startsWith('select ') ||
                                txt === '---' || txt === '--';
                            status = isDefault ? '"' + txt + '" [DEFAULT - needs selection]' : '"' + txt + '"';
                        } else {
                            status = value ? '"' + value.substring(0, 60) + '"' : 'EMPTY';
                        }
                        results.push({name: name, type: type, status: status, placeholder: placeholder});
                    }
                    return results;
                })()
            """)
            if not fields:
                return ""
            lines = ["FORM FIELD STATUS (actual current values from DOM, NOT placeholder text):"]
            for f in fields:
                ph = f.get("placeholder", "")
                ph_safe = ph.replace('"', '\\"') if ph else ""
                ph_suffix = f' [placeholder: "{ph_safe}"]' if ph else ""
                lines.append(f"  {f['name']} ({f['type']}){ph_suffix}: {f['status']}")
            return "\n".join(lines)
        except Exception as e:
            logger.debug("get_form_field_values failed: %s", e)
            return ""

    # ------------------------------------------------------------------
    # Keyboard
    # ------------------------------------------------------------------

    async def press_key(self, key: str) -> bool:
        """Press a keyboard key (Escape, Enter, Tab, etc.).

        Uses CDP Input.dispatchKeyEvent with JS KeyboardEvent fallback.
        """
        if not self._page:
            return False
        # CDP path
        try:
            await self._page.send(zd.cdp.input_.dispatch_key_event(type_="keyDown", key=key))
            await asyncio.sleep(0.05)
            await self._page.send(zd.cdp.input_.dispatch_key_event(type_="keyUp", key=key))
            await asyncio.sleep(0.5)
            logger.info("Pressed key via CDP: %s", key)
            return True
        except Exception as e:
            logger.debug("CDP key press failed for '%s': %s — trying JS fallback", key, e)
        # JS fallback
        try:
            safe_key = _json.dumps(key)
            await self._page.evaluate(f"""
                (() => {{
                    const key = {safe_key};
                    const target = document.activeElement || document.body;
                    target.dispatchEvent(new KeyboardEvent('keydown', {{key: key, bubbles: true, cancelable: true}}));
                    target.dispatchEvent(new KeyboardEvent('keyup', {{key: key, bubbles: true, cancelable: true}}));
                }})()
            """)
            await asyncio.sleep(0.5)
            logger.info("Pressed key via JS: %s", key)
            return True
        except Exception as e2:
            logger.warning("All key press strategies failed for '%s': %s", key, e2)
            return False

    # ------------------------------------------------------------------
    # Click (4-tier)
    # ------------------------------------------------------------------

    async def click(self, selector: str) -> bool:
        """Click an element by CSS selector or text content search.

        Strategy order:
          1. CSS querySelector
          2. JS text content search (extracted from :contains() / plain text)
          3. zendriver's find()
          4. Fuzzy keyword matching
        """
        if not self._page:
            self.last_click_strategy = "failed"
            return False

        # Strategy 1: CSS selector via JavaScript
        try:
            safe_sel = _json.dumps(selector)
            clicked = await self._page.evaluate(f"""
                (() => {{
                    const el = document.querySelector({safe_sel});
                    if (el) {{ el.click(); return true; }}
                    return false;
                }})()
            """)
            if clicked:
                await asyncio.sleep(1)
                logger.info("Clicked (JS selector): %s", selector)
                self.last_click_strategy = "css"
                return True
        except Exception as e:
            logger.debug("Click CSS strategy failed for '%s': %s", selector, e)

        # Strategy 2: JS text content search
        search_text = self._extract_click_text(selector)
        if search_text:
            try:
                safe_text = _json.dumps(search_text)
                clicked = await self._page.evaluate(f"""
                    (() => {{
                        const target = {safe_text}.toLowerCase().trim();
                        const candidates = document.querySelectorAll(
                            'button, a, input[type="submit"], input[type="button"], '
                            + '[role="button"], [onclick], .btn, [class*="button"], [class*="Button"]'
                        );
                        for (const el of candidates) {{
                            const text = (el.textContent || el.value || '').trim().toLowerCase();
                            if (text === target || text.includes(target)) {{
                                el.scrollIntoView({{block: 'center'}});
                                el.click();
                                return true;
                            }}
                        }}
                        return false;
                    }})()
                """)
                if clicked:
                    await asyncio.sleep(1)
                    logger.info("Clicked (JS text search '%s'): %s", search_text, selector)
                    self.last_click_strategy = "js_text"
                    return True
            except Exception as e:
                logger.debug("Click JS text search failed for '%s': %s", selector, e)

        # Strategy 3: zendriver's find()
        try:
            find_text = search_text or selector
            element = await self._page.find(find_text, timeout=self._action_timeout)
            if element:
                await element.click()
                await asyncio.sleep(1)
                logger.info("Clicked (zendriver find): %s", find_text)
                self.last_click_strategy = "zendriver"
                return True
        except Exception as e:
            logger.debug("Click zendriver find failed for '%s': %s", selector, e)

        # Strategy 4: Fuzzy match
        fuzzy_clicked = await self._fuzzy_find_and_click(selector)
        if fuzzy_clicked:
            self.last_click_strategy = "fuzzy"
            return True

        logger.warning("All click strategies failed for '%s'", selector)
        self.last_click_strategy = "failed"
        return False

    @staticmethod
    def _extract_click_text(selector: str) -> str:
        """Extract searchable text from a selector string."""
        if not selector:
            return ""
        m = re.search(r":(?:contains|has-text)\(['\"](.+?)['\"]\)", selector)
        if m:
            return m.group(1)
        m = re.search(r"\[value=['\"](.+?)['\"]\]", selector)
        if m:
            return m.group(1)
        if not any(c in selector for c in "[]()#>+~=:@"):
            if "." in selector:
                parts = selector.split(".")
                candidate = parts[-1].strip()
                if candidate and candidate[0].isupper() and "-" not in candidate:
                    return candidate
            if not selector.startswith((".", "#")) and (" " in selector or selector[0].isupper()):
                return selector
        return ""

    # ------------------------------------------------------------------
    # Type (4-tier with readback verification)
    # ------------------------------------------------------------------

    async def type_text(self, selector: str, text: str) -> tuple[bool, str]:
        """Type text into an input field.

        Strategy order:
          1. CSS selector → zendriver Element → clear → send_keys
          2. zendriver find (text/label match)
          3. JS native setter (React/Vue compatible)
          4. Fuzzy partial match

        Returns (success, actual_value) after readback verification.
        """
        if not self._page:
            self.last_type_strategy = "failed"
            return (False, "")

        best_actual = ""

        # Strategy 1: CSS query_selector → real Element
        try:
            element = await self._page.query_selector(selector)
            if element:
                if await self._element_clear_and_type(element, text):
                    await self._fire_input_events(selector)
                    actual = await self.get_field_value(selector)
                    if actual == text:
                        logger.info("Typed + verified (CSS element): %s", selector)
                        self.last_type_strategy = "css_verified"
                        return (True, actual)
                    best_actual = actual
                    logger.warning(
                        "Type CSS value mismatch for '%s': expected=%r actual=%r",
                        selector, text, actual,
                    )
        except Exception as e:
            logger.debug("Type CSS strategy failed for '%s': %s", selector, e)

        # Strategy 2: zendriver find
        try:
            element = await self._page.find(selector, timeout=self._action_timeout)
            if element:
                if await self._element_clear_and_type(element, text):
                    actual = await self.get_field_value(selector)
                    if actual == text:
                        logger.info("Typed + verified (text match): %s", selector)
                        self.last_type_strategy = "textmatch_verified"
                        return (True, actual)
                    if not best_actual:
                        best_actual = actual
        except Exception as e:
            logger.debug("Type text-match strategy failed for '%s': %s", selector, e)

        # Strategy 3: JS native setter
        try:
            safe_sel = _json.dumps(selector)
            safe_val = _json.dumps(text)
            done = await self._page.evaluate(f"""
                (() => {{
                    const el = document.querySelector({safe_sel});
                    if (!el) return false;
                    el.focus();
                    const nativeSetter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value'
                    )?.set || Object.getOwnPropertyDescriptor(
                        window.HTMLTextAreaElement.prototype, 'value'
                    )?.set;
                    if (nativeSetter) nativeSetter.call(el, {safe_val});
                    else el.value = {safe_val};
                    el.dispatchEvent(new Event('input', {{bubbles: true}}));
                    el.dispatchEvent(new Event('change', {{bubbles: true}}));
                    return true;
                }})()
            """)
            if done:
                actual = await self.get_field_value(selector)
                if actual == text:
                    logger.info("Typed + verified (JS value setter): %s", selector)
                    self.last_type_strategy = "js_setter_verified"
                    return (True, actual)
                if not best_actual:
                    best_actual = actual
        except Exception as e:
            logger.debug("Type JS-setter strategy failed for '%s': %s", selector, e)

        # Strategy 4: Fuzzy match
        fuzzy_result = await self._fuzzy_find_and_type(selector, text)
        if fuzzy_result[0]:
            if fuzzy_result[1] == text:
                self.last_type_strategy = "fuzzy_verified"
                return fuzzy_result
            else:
                self.last_type_strategy = "fuzzy_mismatch"
                if not best_actual:
                    best_actual = fuzzy_result[1]

        if best_actual:
            logger.warning(
                "All type strategies exhausted for '%s' — best effort value: %r (expected %r)",
                selector, best_actual, text,
            )
            self.last_type_strategy = "css_mismatch"
            return (True, best_actual)

        logger.warning("All type strategies failed for '%s'", selector)
        self.last_type_strategy = "failed"
        return (False, "")

    async def _element_clear_and_type(self, element, text: str) -> bool:
        """Click element, clear content, type new text via CDP key events."""
        try:
            await element.click()
            await asyncio.sleep(0.2)
            try:
                await element.clear_input()
            except Exception as e:
                logger.debug("clear_input failed (non-critical): %s", e)
            await element.send_keys(text)
            return True
        except Exception as e:
            logger.debug("_element_clear_and_type failed: %s", e)
            return False

    async def _fire_input_events(self, selector: str) -> None:
        """Dispatch input+change events so reactive frameworks pick up the value."""
        try:
            safe_sel = _json.dumps(selector)
            await self._page.evaluate(f"""
                (() => {{
                    const el = document.querySelector({safe_sel});
                    if (el) {{
                        el.dispatchEvent(new Event('input', {{bubbles: true}}));
                        el.dispatchEvent(new Event('change', {{bubbles: true}}));
                    }}
                }})()
            """)
        except Exception as e:
            logger.debug("_fire_input_events failed for '%s': %s", selector, e)

    @staticmethod
    def _extract_input_keywords(selector: str) -> list[str]:
        """Extract meaningful search keywords from a CSS selector for fuzzy matching."""
        STOP_WORDS = {
            "the", "your", "enter", "input", "please", "here", "field",
            "form", "this", "that", "with", "for", "and", "you", "wish",
        }
        keywords: list[str] = []
        for m in re.finditer(r"placeholder=['\"](.+?)['\"]", selector):
            words = re.findall(r"[a-zA-Z]{3,}", m.group(1))
            keywords.extend(w.lower() for w in words if w.lower() not in STOP_WORDS)
        for m in re.finditer(r"name=['\"](.+?)['\"]", selector):
            parts = re.findall(r"[a-zA-Z]{2,}", m.group(1))
            keywords.extend(w.lower() for w in parts if w.lower() not in STOP_WORDS)
        for m in re.finditer(r"(?:#|id=['\"])([a-zA-Z][\w-]*)", selector):
            parts = re.findall(r"[a-zA-Z]{3,}", m.group(1))
            keywords.extend(w.lower() for w in parts if w.lower() not in STOP_WORDS)
        for m in re.finditer(r"type=['\"](.+?)['\"]", selector):
            t = m.group(1).lower()
            if t in ("tel", "email", "password", "number", "url", "date"):
                keywords.append(t)
        for m in re.finditer(r"\.([a-zA-Z][\w-]*)", selector):
            parts = re.findall(r"[a-zA-Z]{3,}", m.group(1))
            keywords.extend(w.lower() for w in parts if w.lower() not in STOP_WORDS)
        if not keywords and not any(c in selector for c in "[]#.>+~="):
            words = re.findall(r"[a-zA-Z]{3,}", selector)
            keywords.extend(w.lower() for w in words if w.lower() not in STOP_WORDS)
        return list(dict.fromkeys(keywords))

    async def _fuzzy_find_and_type(self, selector: str, text: str) -> tuple[bool, str]:
        """Find input by fuzzy placeholder/name/label match, type via native setter."""
        if not self._page:
            return (False, "")
        keywords = self._extract_input_keywords(selector)
        if not keywords:
            return (False, "")
        try:
            safe_keywords = _json.dumps(keywords)
            safe_val = _json.dumps(text)
            result = await self._page.evaluate(f"""
                (() => {{
                    const keywords = {safe_keywords};
                    const value = {safe_val};
                    const inputs = document.querySelectorAll('input, textarea, select');
                    let bestMatch = null;
                    let bestScore = 0;
                    for (const el of inputs) {{
                        if (!el.offsetParent && el.tagName !== 'BODY') continue;
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden') continue;
                        const attrs = [
                            el.placeholder || '', el.name || '',
                            el.id || '', el.getAttribute('aria-label') || '',
                        ].join(' ').toLowerCase();
                        let labelText = '';
                        if (el.id) {{
                            const lbl = document.querySelector('label[for="' + el.id + '"]');
                            if (lbl) labelText = (lbl.textContent || '').toLowerCase();
                        }}
                        const parent = el.closest(
                            '.form-group, .form-item, .input-group, .el-form-item, '
                            + '.field, .form-field, div'
                        );
                        if (parent) {{
                            const lbl = parent.querySelector('label, .label, [class*="label"]');
                            if (lbl && lbl !== el) labelText += ' ' + (lbl.textContent || '').toLowerCase();
                        }}
                        const fullText = attrs + ' ' + labelText;
                        let score = 0;
                        for (const kw of keywords) {{
                            if (fullText.includes(kw.toLowerCase())) score++;
                        }}
                        if (score > bestScore) {{ bestScore = score; bestMatch = el; }}
                    }}
                    if (!bestMatch || bestScore === 0) return {{found: false}};
                    bestMatch.scrollIntoView({{block: 'center'}});
                    bestMatch.focus();
                    const nativeSetter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value'
                    )?.set || Object.getOwnPropertyDescriptor(
                        window.HTMLTextAreaElement.prototype, 'value'
                    )?.set;
                    if (nativeSetter) nativeSetter.call(bestMatch, value);
                    else bestMatch.value = value;
                    bestMatch.dispatchEvent(new Event('input', {{bubbles: true}}));
                    bestMatch.dispatchEvent(new Event('change', {{bubbles: true}}));
                    return {{
                        found: true,
                        actualValue: bestMatch.value || '',
                        matchedBy: bestMatch.placeholder || bestMatch.name || bestMatch.id || 'unknown',
                        score: bestScore,
                    }};
                }})()
            """)
            if result and result.get("found"):
                actual = result.get("actualValue", "")
                matched_by = result.get("matchedBy", "?")
                logger.info("Typed + fuzzy matched (by '%s', score=%d): %s", matched_by, result.get("score", 0), selector)
                return (True, actual)
        except Exception as e:
            logger.debug("Fuzzy type failed for '%s': %s", selector, e)
        return (False, "")

    async def _fuzzy_find_and_click(self, selector: str) -> bool:
        """Find and click an element by fuzzy keyword matching (last-resort)."""
        if not self._page:
            return False
        keywords = self._extract_input_keywords(selector)
        if not keywords:
            return False
        try:
            safe_keywords = _json.dumps(keywords)
            clicked = await self._page.evaluate(f"""
                (() => {{
                    const keywords = {safe_keywords};
                    const candidates = document.querySelectorAll(
                        'input, textarea, select, button, a, [role="button"], '
                        + '[onclick], .btn, [class*="button"], [class*="Button"]'
                    );
                    let bestMatch = null;
                    let bestScore = 0;
                    for (const el of candidates) {{
                        if (!el.offsetParent && el.tagName !== 'BODY') continue;
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden') continue;
                        const searchable = [
                            el.placeholder || '', el.name || '', el.id || '',
                            el.getAttribute('aria-label') || '',
                            (el.textContent || '').substring(0, 50), el.value || '',
                        ].join(' ').toLowerCase();
                        let score = 0;
                        for (const kw of keywords) {{
                            if (searchable.includes(kw.toLowerCase())) score++;
                        }}
                        if (score > bestScore) {{ bestScore = score; bestMatch = el; }}
                    }}
                    if (bestMatch && bestScore > 0) {{
                        bestMatch.scrollIntoView({{block: 'center'}});
                        bestMatch.focus();
                        bestMatch.click();
                        return true;
                    }}
                    return false;
                }})()
            """)
            if clicked:
                await asyncio.sleep(1)
                logger.info("Clicked (fuzzy match): %s", selector)
                return True
        except Exception as e:
            logger.debug("Fuzzy click failed for '%s': %s", selector, e)
        return False

    # ------------------------------------------------------------------
    # Select dropdown
    # ------------------------------------------------------------------

    async def select_option(self, selector: str, value: str) -> bool:
        """Select a dropdown option (3-strategy: value match, text match, partial)."""
        if not self._page:
            return False
        try:
            safe_sel = _json.dumps(selector)
            safe_val = _json.dumps(value)
            result = await self._page.evaluate(f"""
                (() => {{
                    const sel = document.querySelector({safe_sel});
                    if (!sel) return false;
                    const value = {safe_val};
                    const hasOpt = Array.from(sel.options).some(o => o.value === value);
                    if (hasOpt) {{
                        sel.value = value;
                        sel.dispatchEvent(new Event('input', {{bubbles: true}}));
                        sel.dispatchEvent(new Event('change', {{bubbles: true}}));
                        return true;
                    }}
                    const target = value.trim().toLowerCase();
                    for (const opt of sel.options) {{
                        if (opt.text.trim().toLowerCase() === target) {{
                            sel.value = opt.value;
                            sel.dispatchEvent(new Event('input', {{bubbles: true}}));
                            sel.dispatchEvent(new Event('change', {{bubbles: true}}));
                            return true;
                        }}
                    }}
                    for (const opt of sel.options) {{
                        const optText = opt.text.trim().toLowerCase();
                        if (optText.includes(target) || target.includes(optText)) {{
                            sel.value = opt.value;
                            sel.dispatchEvent(new Event('input', {{bubbles: true}}));
                            sel.dispatchEvent(new Event('change', {{bubbles: true}}));
                            return true;
                        }}
                    }}
                    return false;
                }})()
            """)
            if result:
                logger.info("Selected '%s' in %s", value, selector)
                return True
        except Exception as e:
            logger.warning("Select failed for '%s': %s", selector, e)
        return False

    # ------------------------------------------------------------------
    # Wait
    # ------------------------------------------------------------------

    async def wait(self, seconds: float = 2.0) -> None:
        """Wait for a specified duration."""
        await asyncio.sleep(seconds)

    # ------------------------------------------------------------------
    # Overlay dismissal
    # ------------------------------------------------------------------

    async def dismiss_overlays(self) -> int:
        """Remove overlay elements (cookie banners, chat widgets, translate bars).

        Uses element.remove() — removed elements are gone permanently.
        Returns count of elements removed.
        """
        if not self._page:
            return 0
        try:
            count = await self._page.evaluate("""
                (() => {
                    let removed = 0;
                    const selectors = [
                        '#google_translate_element', '.goog-te-banner-frame',
                        '.goog-te-gadget', '#goog-gt-tt', '.skiptranslate',
                        '.goog-te-combo',
                        '[class*="cookie-banner"]', '[class*="cookie-consent"]',
                        '[class*="cookieconsent"]', '[id*="cookiebanner"]',
                        '#onetrust-banner-sdk', '.cc-window',
                        '[class*="consent-banner"]', '[id*="consent"]',
                        '[aria-label*="cookie" i]',
                        '#intercom-container', '#intercom-frame',
                        '.intercom-lightweight-app',
                        '#crisp-chatbox', '[id^="crisp-"]',
                        '.drift-widget-container',
                        '[id^="tidio-"]',
                        '#livechat-full', '#livechat-compact-container',
                        '[class*="chat-widget"]', '[id*="chat-widget"]',
                        '[class*="live-chat"]', '[id*="live-chat"]',
                        '.tawk-widget', '#tawkchat-container',
                        'iframe[src*="tawk.to"]', 'iframe[src*="intercom"]',
                        'iframe[src*="crisp.chat"]', 'iframe[src*="drift.com"]',
                        'iframe[src*="livechat"]',
                    ];
                    for (const sel of selectors) {
                        try {
                            for (const el of document.querySelectorAll(sel)) {
                                el.remove();
                                removed++;
                            }
                        } catch(e) {}
                    }
                    return removed;
                })()
            """)
            if count:
                logger.info("Overlay dismissal removed %d elements", count)
            return int(count or 0)
        except Exception as e:
            logger.debug("Overlay dismissal failed (non-critical): %s", e)
            return 0

    # ------------------------------------------------------------------
    # DOM scans (state-specific)
    # ------------------------------------------------------------------

    async def run_dom_scan(self, scan_type: str) -> dict:
        """Execute composite DOM scan for the given type.

        Args:
            scan_type: ``"find_register"`` | ``"navigate_deposit"`` | ``"check_email"``

        Returns a raw dict of JS scan results. Returns ``{}`` on any error.
        """
        if not self._page:
            return {}
        try:
            if scan_type == "find_register":
                return await self._scan_find_register()
            elif scan_type == "navigate_deposit":
                return await self._scan_navigate_deposit()
            elif scan_type == "check_email":
                return await self._scan_check_email()
            else:
                logger.warning("Unknown scan_type: %s", scan_type)
                return {}
        except Exception as e:
            logger.warning("DOM scan '%s' failed: %s", scan_type, e)
            return {}

    async def _scan_find_register(self) -> dict:
        """JS scan for FIND_REGISTER: form detection, link text, URL patterns, modal detection."""
        register_keywords = _json.dumps([
            "register", "sign up", "signup", "create account", "join now",
            "get started", "open account", "registrar", "registrarse",
            "crear cuenta", "cadastro", "cadastrar", "criar conta",
            "\u6ce8\u518c", "\u7acb\u5373\u6ce8\u518c",
            "\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u044f",
            "\u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u0442\u044c\u0441\u044f",
            "\u0111\u0103ng k\u00fd", "\u0e2a\u0e21\u0e31\u0e04\u0e23\u0e2a\u0e21\u0e32\u0e0a\u0e34\u0e01",
        ])
        result = await self._page.evaluate(f"""
            (() => {{
                const KEYWORDS = {register_keywords};
                const currentUrl = window.location.href.toLowerCase();
                const isVisible = (el) => {{
                    if (!el) return false;
                    const s = window.getComputedStyle(el);
                    return s.display !== 'none' && s.visibility !== 'hidden'
                        && s.opacity !== '0' && (el.offsetParent !== null || el.tagName === 'BODY');
                }};
                let hasRegistrationForm = false; let formSelector = ''; let fieldSummary = '';
                const forms = document.querySelectorAll('form');
                for (const form of forms) {{
                    if (!isVisible(form)) continue;
                    const hasPw = form.querySelector('input[type="password"]');
                    const hasEmail = form.querySelector('input[type="email"], input[type="text"], input[type="tel"]');
                    if (hasPw && hasEmail) {{
                        hasRegistrationForm = true;
                        formSelector = form.id ? '#' + form.id : 'form';
                        const fields = [];
                        if (form.querySelector('input[type="password"]')) fields.push('password');
                        if (form.querySelector('input[type="email"]')) fields.push('email');
                        if (form.querySelector('input[type="text"]')) fields.push('text');
                        if (form.querySelector('input[type="tel"]')) fields.push('phone');
                        fieldSummary = fields.join(', ');
                        break;
                    }}
                }}
                if (!hasRegistrationForm) {{
                    const pwInputs = document.querySelectorAll('input[type="password"]');
                    for (const pw of pwInputs) {{
                        if (!isVisible(pw)) continue;
                        const container = pw.closest('div, section, main, [class*="form"]');
                        if (container) {{
                            const hasEmail = container.querySelector('input[type="email"], input[type="text"]');
                            if (hasEmail && isVisible(hasEmail)) {{
                                hasRegistrationForm = true;
                                formSelector = 'input[type="password"]';
                                fieldSummary = 'password, email/text (formless)';
                                break;
                            }}
                        }}
                    }}
                }}
                const registerLinks = [];
                const clickables = document.querySelectorAll(
                    'a, button, [role="button"], input[type="submit"], .btn, [class*="button"]'
                );
                for (const el of clickables) {{
                    if (!isVisible(el)) continue;
                    const text = (el.textContent || el.value || '').trim();
                    const textLower = text.toLowerCase();
                    if (textLower.length > 60 || textLower.length < 2) continue;
                    for (const kw of KEYWORDS) {{
                        if (textLower.includes(kw.toLowerCase())) {{
                            let sel = '';
                            if (el.id) sel = '#' + CSS.escape(el.id);
                            else if (el.tagName === 'A' && el.getAttribute('href'))
                                sel = 'a[href="' + el.getAttribute('href') + '"]';
                            registerLinks.push({{ text: text.substring(0, 60), selector: sel, keyword: kw }});
                            break;
                        }}
                    }}
                    if (registerLinks.length >= 5) break;
                }}
                const urlIsRegisterPage = /\\/(register|signup|sign-up|join|create|account\\/new)/i.test(currentUrl);
                let modalHasForm = false; let modalSelector = '';
                const modals = document.querySelectorAll('[role="dialog"], .modal, [class*="modal"], [class*="popup"]');
                for (const modal of modals) {{
                    if (!isVisible(modal)) continue;
                    if (modal.querySelector('input[type="password"]')) {{
                        modalHasForm = true;
                        modalSelector = modal.id ? '#' + modal.id : '[role="dialog"]';
                        break;
                    }}
                }}
                return {{
                    has_registration_form: hasRegistrationForm, form_selector: formSelector,
                    field_summary: fieldSummary, register_links: registerLinks,
                    url_is_register_page: urlIsRegisterPage, modal_has_form: modalHasForm,
                    modal_selector: modalSelector, current_url: currentUrl,
                }};
            }})()
        """)
        return result or {}

    async def _scan_navigate_deposit(self) -> dict:
        """JS scan for NAVIGATE_DEPOSIT: link text, URL patterns, class matching."""
        deposit_keywords = _json.dumps([
            "deposit", "recharge", "fund", "top up", "topup", "add funds",
            "invest", "buy", "add money",
            "\u5145\u503c", "\u5b58\u6b3e", "\u5165\u91d1",
            "depositar", "recargar", "fondos",
            "\u043f\u043e\u043f\u043e\u043b\u043d\u0438\u0442\u044c", "\u0434\u0435\u043f\u043e\u0437\u0438\u0442",
            "n\u1ea1p ti\u1ec1n", "\u0e1d\u0e32\u0e01\u0e40\u0e07\u0e34\u0e19",
        ])
        result = await self._page.evaluate(f"""
            (() => {{
                const KEYWORDS = {deposit_keywords};
                const currentUrl = window.location.href.toLowerCase();
                const isVisible = (el) => {{
                    if (!el) return false;
                    const s = window.getComputedStyle(el);
                    return s.display !== 'none' && s.visibility !== 'hidden'
                        && s.opacity !== '0' && (el.offsetParent !== null || el.tagName === 'BODY');
                }};
                const depositLinks = [];
                const clickables = document.querySelectorAll(
                    'a, button, [role="button"], [role="tab"], [role="menuitem"], '
                    + 'nav a, .nav a, [class*="menu"] a, [class*="sidebar"] a, .btn, [class*="button"]'
                );
                for (const el of clickables) {{
                    if (!isVisible(el)) continue;
                    const text = (el.textContent || el.value || '').trim();
                    const textLower = text.toLowerCase();
                    if (textLower.length > 60 || textLower.length < 2) continue;
                    for (const kw of KEYWORDS) {{
                        if (textLower.includes(kw.toLowerCase())) {{
                            let sel = '';
                            if (el.id) sel = '#' + CSS.escape(el.id);
                            else if (el.tagName === 'A' && el.getAttribute('href'))
                                sel = 'a[href="' + el.getAttribute('href') + '"]';
                            depositLinks.push({{
                                text: text.substring(0, 60), selector: sel,
                                keyword: kw, href: el.tagName === 'A' ? el.href : '',
                            }});
                            break;
                        }}
                    }}
                    if (depositLinks.length >= 5) break;
                }}
                const urlIsDepositPage = /\\/(deposit|recharge|fund|invest|top-?up|wallet\\/add)/i.test(currentUrl);
                let depositClassMatch = false; let depositClassSelector = '';
                const classEl = document.querySelector(
                    '[class*="deposit"], [class*="recharge"], [class*="topup"], [id*="deposit"]'
                );
                if (classEl && isVisible(classEl)) {{
                    depositClassMatch = true;
                    depositClassSelector = classEl.id ? '#' + CSS.escape(classEl.id)
                        : classEl.tagName.toLowerCase() + '[class*="deposit"]';
                }}
                return {{
                    deposit_links: depositLinks,
                    url_is_deposit_page: urlIsDepositPage,
                    deposit_class_match: depositClassMatch,
                    deposit_class_selector: depositClassSelector,
                    current_url: currentUrl,
                }};
            }})()
        """)
        return result or {}

    async def _scan_check_email(self) -> dict:
        """JS scan for CHECK_EMAIL_VERIFICATION: text patterns + URL + dashboard detection."""
        email_patterns = _json.dumps([
            "verify your email", "check your email", "verification link",
            "confirm your email", "email confirmation", "check your inbox",
            "we sent you", "we've sent", "activation link", "activate your account",
            "\u9a8c\u8bc1\u90ae\u4ef6", "\u90ae\u7bb1\u9a8c\u8bc1",
            "verifica tu email", "verificar correo",
        ])
        dashboard_patterns = _json.dumps([
            "dashboard", "welcome back", "my account", "account overview",
            "portfolio", "balance", "my wallet", "trading",
        ])
        result = await self._page.evaluate(f"""
            (() => {{
                const EMAIL_PATTERNS = {email_patterns};
                const DASHBOARD_PATTERNS = {dashboard_patterns};
                const pageText = (document.body ? document.body.innerText : '').toLowerCase();
                const currentUrl = window.location.href.toLowerCase();
                let emailVerifyTextFound = false; let emailVerifySnippet = '';
                for (const p of EMAIL_PATTERNS) {{
                    const idx = pageText.indexOf(p.toLowerCase());
                    if (idx !== -1) {{
                        emailVerifyTextFound = true;
                        emailVerifySnippet = pageText.substring(
                            Math.max(0, idx - 10), Math.min(pageText.length, idx + 80)
                        ).trim();
                        break;
                    }}
                }}
                let dashboardTextFound = false; let dashboardSnippet = '';
                for (const p of DASHBOARD_PATTERNS) {{
                    const idx = pageText.indexOf(p.toLowerCase());
                    if (idx !== -1) {{
                        dashboardTextFound = true;
                        dashboardSnippet = pageText.substring(
                            Math.max(0, idx - 10), Math.min(pageText.length, idx + 60)
                        ).trim();
                        break;
                    }}
                }}
                const urlIsVerifyPage = /\\/(verify|confirm|activate|email-verification)/i.test(currentUrl);
                return {{
                    email_verify_text_found: emailVerifyTextFound,
                    email_verify_snippet: emailVerifySnippet,
                    dashboard_text_found: dashboardTextFound,
                    dashboard_snippet: dashboardSnippet,
                    url_is_verify_page: urlIsVerifyPage,
                    current_url: currentUrl,
                }};
            }})()
        """)
        return result or {}

    # ------------------------------------------------------------------
    # Crypto wallet extraction helpers
    # ------------------------------------------------------------------

    async def discover_crypto_selectors(self) -> list[dict]:
        """Scan the DOM for cryptocurrency coin/network selector elements."""
        if not self._page:
            return []
        try:
            discovered = await self._page.evaluate("""
                (() => {
                    const results = [];
                    const seen = new Set();
                    const SYMBOLS = [
                        'BTC', 'ETH', 'USDT', 'USDC', 'BNB', 'XRP', 'ADA', 'SOL',
                        'DOGE', 'TRX', 'DOT', 'MATIC', 'LTC', 'AVAX', 'UNI', 'LINK',
                        'EOS', 'FIL', 'XLM', 'ATOM', 'APT', 'ARB', 'OP',
                    ];
                    const isVisible = (el) => {
                        if (!el || (!el.offsetParent && el.tagName !== 'BODY')) return false;
                        const s = window.getComputedStyle(el);
                        return s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0';
                    };
                    const clickables = document.querySelectorAll(
                        'button, a, [role="tab"], [role="button"], [class*="tab"], '
                        + '[class*="coin"], [class*="crypto"], [class*="token"], '
                        + '[data-coin], [data-token], li, span'
                    );
                    for (let i = 0; i < clickables.length; i++) {
                        const el = clickables[i];
                        if (!isVisible(el)) continue;
                        const text = (el.textContent || '').trim();
                        if (text.length > 30) continue;
                        for (const sym of SYMBOLS) {
                            if (text.toUpperCase().includes(sym)) {
                                const key = sym + ':' + text;
                                if (seen.has(key)) break;
                                seen.add(key);
                                let selector = '';
                                if (el.id) selector = '#' + CSS.escape(el.id);
                                else if (el.dataset && el.dataset.coin) selector = '[data-coin="' + CSS.escape(el.dataset.coin) + '"]';
                                else if (el.dataset && el.dataset.token) selector = '[data-token="' + CSS.escape(el.dataset.token) + '"]';
                                results.push({
                                    type: el.tagName.toLowerCase(), selector: selector,
                                    label: text, symbol: sym, index: i,
                                });
                                break;
                            }
                        }
                    }
                    for (const sel of document.querySelectorAll('select')) {
                        if (!isVisible(sel)) continue;
                        for (const opt of sel.options) {
                            const text = opt.textContent.trim();
                            for (const sym of SYMBOLS) {
                                if (text.toUpperCase().includes(sym)) {
                                    results.push({
                                        type: 'option',
                                        selector: sel.id ? '#' + sel.id : (sel.name ? 'select[name="' + sel.name + '"]' : ''),
                                        label: text, symbol: sym, value: opt.value,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    return results;
                })()
            """)
            logger.info("Crypto selector discovery: found %d candidates", len(discovered or []))
            return discovered or []
        except Exception as e:
            logger.warning("Crypto selector discovery failed: %s", e)
            return []

    async def click_crypto_option(self, option: dict) -> bool:
        """Click a discovered crypto option (tab, button, or select dropdown)."""
        if not self._page:
            return False
        try:
            if option.get("type") == "option" and option.get("selector") and option.get("value"):
                return await self.select_option(option["selector"], option["value"])
            if option.get("selector"):
                clicked = await self.click(option["selector"])
                if clicked:
                    return True
            if option.get("label"):
                return await self.click(option["label"])
            if "index" in option:
                idx = int(option["index"])
                clicked = await self._page.evaluate(f"""
                    (() => {{
                        const clickables = document.querySelectorAll(
                            'button, a, [role="tab"], [role="button"], [class*="tab"], '
                            + '[class*="coin"], [class*="crypto"], [class*="token"], '
                            + '[data-coin], [data-token], li, span'
                        );
                        if (clickables[{idx}]) {{
                            clickables[{idx}].scrollIntoView({{block: 'center'}});
                            clickables[{idx}].click();
                            return true;
                        }}
                        return false;
                    }})()
                """)
                if clicked:
                    await asyncio.sleep(1)
                    return True
            return False
        except Exception as e:
            logger.warning("Failed to click crypto option %s: %s", option.get("label", "?"), e)
            return False

    async def extract_wallet_address(self) -> str:
        """Extract a cryptocurrency wallet address from the current page."""
        if not self._page:
            return ""
        try:
            address = await self._page.evaluate("""
                (() => {
                    const patterns = [
                        /\\b(0x[a-fA-F0-9]{40})\\b/,
                        /\\b(T[A-HJ-NP-Za-km-z1-9]{33})\\b/,
                        /\\b(bc1[a-z0-9]{39,59})\\b/,
                        /\\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\\b/,
                        /\\b(r[0-9a-zA-Z]{24,34})\\b/,
                        /\\b(addr1[a-z0-9]{58})\\b/,
                        /\\b([A-HJ-NP-Za-km-z1-9]{32,44})\\b/,
                    ];
                    for (const input of document.querySelectorAll('input[readonly], input[disabled]')) {
                        const val = (input.value || '').trim();
                        if (val.length >= 26 && val.length <= 100) {
                            for (const p of patterns) { if (p.test(val)) return val; }
                        }
                    }
                    for (const el of document.querySelectorAll('[data-clipboard-text]')) {
                        const val = (el.dataset.clipboardText || '').trim();
                        if (val.length >= 26 && val.length <= 100) {
                            for (const p of patterns) { if (p.test(val)) return val; }
                        }
                    }
                    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
                    while (walker.nextNode()) {
                        const text = walker.currentNode.textContent.trim();
                        if (text.length >= 26 && text.length <= 100) {
                            for (const p of patterns) {
                                const m = text.match(p);
                                if (m) return m[1] || m[0];
                            }
                        }
                    }
                    return '';
                })()
            """)
            if address:
                logger.info("JS wallet extraction found: %s...", address[:20])
            return address or ""
        except Exception as e:
            logger.warning("JS wallet extraction failed: %s", e)
            return ""
