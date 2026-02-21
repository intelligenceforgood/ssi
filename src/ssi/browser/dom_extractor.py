"""DOM extraction for the AI agent.

Extracts a simplified, token-efficient representation of the current page
that includes numbered interactive elements the agent can reference
in its action decisions.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from ssi.models.agent import InteractiveElement, PageObservation

if TYPE_CHECKING:
    from playwright.sync_api import Page

logger = logging.getLogger(__name__)

# JavaScript to extract interactive elements from the page.  Returns a flat
# list of objects that map 1-to-1 to ``InteractiveElement``.
_EXTRACT_ELEMENTS_JS = """
() => {
    const elements = [];
    let index = 0;

    // Helper: get label text for an element
    function getLabel(el) {
        // Explicit <label for="id">
        if (el.id) {
            const lbl = document.querySelector(`label[for="${el.id}"]`);
            if (lbl) return lbl.textContent.trim();
        }
        // Wrapping <label>
        const parent = el.closest('label');
        if (parent) {
            // Remove the element's own text to get only the label portion
            const clone = parent.cloneNode(true);
            const inputs = clone.querySelectorAll('input, select, textarea, button');
            inputs.forEach(i => i.remove());
            return clone.textContent.trim();
        }
        // aria-label
        if (el.getAttribute('aria-label')) return el.getAttribute('aria-label');
        // title attribute
        if (el.title) return el.title;
        return '';
    }

    // Helper: build a unique CSS selector for Playwright
    function buildSelector(el) {
        if (el.id) return '#' + CSS.escape(el.id);
        if (el.name && el.tagName !== 'BUTTON') {
            return `${el.tagName.toLowerCase()}[name="${CSS.escape(el.name)}"]`;
        }
        // Fallback: nth-of-type within parent
        const parent = el.parentElement;
        if (parent) {
            const siblings = Array.from(parent.children).filter(
                c => c.tagName === el.tagName
            );
            const idx = siblings.indexOf(el) + 1;
            // Try to give a more specific selector
            const parentId = parent.id ? '#' + CSS.escape(parent.id) + ' > ' : '';
            return `${parentId}${el.tagName.toLowerCase()}:nth-of-type(${idx})`;
        }
        return el.tagName.toLowerCase();
    }

    // Helper: check if element is visible
    function isVisible(el) {
        const rect = el.getBoundingClientRect();
        const style = window.getComputedStyle(el);
        return (
            rect.width > 0 &&
            rect.height > 0 &&
            style.display !== 'none' &&
            style.visibility !== 'hidden' &&
            style.opacity !== '0'
        );
    }

    // Collect inputs
    document.querySelectorAll('input, textarea, select').forEach(el => {
        if (!isVisible(el)) return;
        const t = (el.type || el.tagName.toLowerCase()).toLowerCase();
        if (t === 'hidden') return;
        elements.push({
            index: index++,
            tag: el.tagName.toLowerCase(),
            element_type: t,
            name: el.name || '',
            label: getLabel(el),
            placeholder: el.placeholder || '',
            text: '',
            value: el.value || '',
            href: '',
            required: el.required || false,
            selector: buildSelector(el),
        });
    });

    // Collect buttons and submit inputs
    document.querySelectorAll('button, input[type="submit"], input[type="button"]').forEach(el => {
        if (!isVisible(el)) return;
        // Skip if already collected as input
        if (el.tagName === 'INPUT' && elements.some(e => e.selector === buildSelector(el))) return;
        elements.push({
            index: index++,
            tag: el.tagName.toLowerCase(),
            element_type: el.type || 'button',
            name: el.name || '',
            label: '',
            placeholder: '',
            text: (el.textContent || el.value || '').trim().substring(0, 80),
            value: el.value || '',
            href: '',
            required: false,
            selector: buildSelector(el),
        });
    });

    // Collect prominent links (nav, CTA-style)
    document.querySelectorAll('a[href]').forEach(el => {
        if (!isVisible(el)) return;
        const text = (el.textContent || '').trim();
        if (!text || text.length > 100) return;
        // Skip anchor-only links
        const href = el.getAttribute('href') || '';
        if (href === '#' || href.startsWith('javascript:')) return;
        elements.push({
            index: index++,
            tag: 'a',
            element_type: 'link',
            name: '',
            label: '',
            placeholder: '',
            text: text.substring(0, 80),
            value: '',
            href: href.substring(0, 200),
            required: false,
            selector: buildSelector(el),
        });
    });

    return elements;
}
"""

# JavaScript to extract visible text content (truncated for token budget).
_EXTRACT_VISIBLE_TEXT_JS = """
(maxLength) => {
    const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode: (node) => {
                const parent = node.parentElement;
                if (!parent) return NodeFilter.FILTER_REJECT;
                const tag = parent.tagName;
                if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'SVG'].includes(tag)) {
                    return NodeFilter.FILTER_REJECT;
                }
                const style = window.getComputedStyle(parent);
                if (style.display === 'none' || style.visibility === 'hidden') {
                    return NodeFilter.FILTER_REJECT;
                }
                const text = node.textContent.trim();
                if (text.length === 0) return NodeFilter.FILTER_REJECT;
                return NodeFilter.FILTER_ACCEPT;
            }
        }
    );

    const parts = [];
    let total = 0;
    while (walker.nextNode() && total < maxLength) {
        const t = walker.currentNode.textContent.trim();
        if (t) {
            parts.push(t);
            total += t.length;
        }
    }
    return parts.join(' ').substring(0, maxLength);
}
"""


def extract_page_observation(page: Page, output_dir: str | Path | None = None, step_number: int = 0) -> PageObservation:
    """Extract a structured observation of the current page state.

    Args:
        page: A Playwright ``Page`` object.
        output_dir: Optional directory to save step screenshots.
        step_number: Step counter for naming screenshot files.

    Returns:
        A ``PageObservation`` with elements and visible text.
    """
    observation = PageObservation(
        url=page.url,
        title=page.title() or "",
    )

    # Extract interactive elements
    try:
        raw_elements = page.evaluate(_EXTRACT_ELEMENTS_JS)
        observation.interactive_elements = [InteractiveElement(**el) for el in raw_elements]
    except Exception as e:
        logger.warning("Failed to extract interactive elements: %s", e)

    # Extract visible text (limit to ~2000 chars for token efficiency)
    try:
        observation.visible_text = page.evaluate(_EXTRACT_VISIBLE_TEXT_JS, 2000)
    except Exception as e:
        logger.warning("Failed to extract visible text: %s", e)

    # Step screenshot
    if output_dir:
        try:
            from pathlib import Path

            screenshot_path = Path(output_dir) / f"step_{step_number:03d}.png"
            page.screenshot(path=str(screenshot_path), full_page=False)
            observation.screenshot_path = str(screenshot_path)
        except Exception as e:
            logger.warning("Failed to capture step screenshot: %s", e)

    # Build DOM summary string for the LLM
    observation.dom_summary = _format_dom_summary(observation)

    return observation


def _format_dom_summary(observation: PageObservation) -> str:
    """Format the observation into a concise text block for the LLM prompt.

    Each interactive element is numbered so the LLM can reference it
    by index in its action response.
    """
    lines = [
        f"Page: {observation.title}",
        f"URL: {observation.url}",
        "",
        "--- Visible Text (excerpt) ---",
        _truncate(observation.visible_text, 1500),
        "",
        "--- Interactive Elements ---",
    ]

    for el in observation.interactive_elements:
        parts = [f"[{el.index}]", f"<{el.tag}>"]
        if el.element_type and el.element_type != el.tag:
            parts.append(f"type={el.element_type}")
        if el.name:
            parts.append(f'name="{el.name}"')
        if el.label:
            parts.append(f'label="{el.label}"')
        if el.placeholder:
            parts.append(f'placeholder="{el.placeholder}"')
        if el.text:
            parts.append(f'text="{el.text}"')
        if el.href:
            parts.append(f'href="{el.href}"')
        if el.value:
            parts.append(f'value="{el.value}"')
        if el.required:
            parts.append("REQUIRED")
        lines.append(" ".join(parts))

    return "\n".join(lines)


def _truncate(text: str, max_len: int) -> str:
    """Truncate text with ellipsis if needed, collapsing whitespace."""
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"
