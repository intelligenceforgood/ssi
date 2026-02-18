"""Unit tests for DOM extraction logic."""

from __future__ import annotations

from ssi.browser.dom_extractor import _format_dom_summary, _truncate
from ssi.models.agent import InteractiveElement, PageObservation


class TestFormatDomSummary:
    """Test the DOM summary formatting for LLM prompts."""

    def test_basic_format(self):
        obs = PageObservation(
            url="https://example.com",
            title="Example Page",
            visible_text="Welcome to the site",
            interactive_elements=[
                InteractiveElement(
                    index=0,
                    tag="input",
                    element_type="text",
                    name="email",
                    label="Email",
                    placeholder="you@example.com",
                    required=True,
                    selector='input[name="email"]',
                ),
                InteractiveElement(
                    index=1,
                    tag="button",
                    element_type="submit",
                    text="Submit",
                    selector="button:nth-of-type(1)",
                ),
            ],
        )
        summary = _format_dom_summary(obs)
        assert "Example Page" in summary
        assert "[0]" in summary
        assert "[1]" in summary
        assert "Email" in summary
        assert "Submit" in summary
        assert "REQUIRED" in summary

    def test_empty_elements(self):
        obs = PageObservation(url="https://example.com", title="Empty Page")
        summary = _format_dom_summary(obs)
        assert "Empty Page" in summary
        assert "Interactive Elements" in summary

    def test_link_element(self):
        obs = PageObservation(
            url="https://example.com",
            title="Links",
            interactive_elements=[
                InteractiveElement(index=0, tag="a", element_type="link", text="Next Page", href="/step2"),
            ],
        )
        summary = _format_dom_summary(obs)
        assert "href=" in summary
        assert "Next Page" in summary


class TestTruncate:
    """Test text truncation helper."""

    def test_short_text_unchanged(self):
        assert _truncate("hello", 100) == "hello"

    def test_long_text_truncated(self):
        result = _truncate("a" * 200, 50)
        assert len(result) == 51  # 50 chars + ellipsis
        assert result.endswith("…")

    def test_whitespace_collapsed(self):
        result = _truncate("hello   world\n\nfoo", 100)
        assert result == "hello world foo"
