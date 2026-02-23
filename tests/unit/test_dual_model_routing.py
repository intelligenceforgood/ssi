"""Unit tests for Ollama vision support and dual-model routing.

Covers C3 (Ollama ``chat_with_images``), C4 (cheap/vision model routing
via ``create_llm_provider``), and ``PageAnalyzer`` model selection.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from ssi.llm.base import LLMProvider, LLMResult


# ---------------------------------------------------------------------------
# C3: Ollama vision support
# ---------------------------------------------------------------------------


class TestOllamaVisionDetection:
    """Test ``OllamaProvider.supports_vision`` for known model prefixes."""

    def test_llama_not_vision(self) -> None:
        """Text-only model llama3.1 is not vision-capable."""
        from ssi.llm.ollama_provider import OllamaProvider

        provider = OllamaProvider(model="llama3.1")
        assert provider.supports_vision is False

    def test_gemma3_is_vision(self) -> None:
        """Gemma 3 is a vision-capable model."""
        from ssi.llm.ollama_provider import OllamaProvider

        provider = OllamaProvider(model="gemma3:12b")
        assert provider.supports_vision is True

    def test_llava_is_vision(self) -> None:
        """LLaVA is a vision-capable model."""
        from ssi.llm.ollama_provider import OllamaProvider

        provider = OllamaProvider(model="llava:13b")
        assert provider.supports_vision is True

    def test_qwen2_vl_is_vision(self) -> None:
        """Qwen2-VL is a vision-capable model."""
        from ssi.llm.ollama_provider import OllamaProvider

        provider = OllamaProvider(model="qwen2-vl:7b")
        assert provider.supports_vision is True

    def test_qwen3_vl_is_vision(self) -> None:
        """Qwen3-VL is a vision-capable model."""
        from ssi.llm.ollama_provider import OllamaProvider

        provider = OllamaProvider(model="qwen3-vl:8b")
        assert provider.supports_vision is True

    def test_moondream_is_vision(self) -> None:
        """Moondream is a vision-capable model."""
        from ssi.llm.ollama_provider import OllamaProvider

        provider = OllamaProvider(model="moondream")
        assert provider.supports_vision is True

    def test_minicpm_v_is_vision(self) -> None:
        """MiniCPM-V is a vision-capable model."""
        from ssi.llm.ollama_provider import OllamaProvider

        provider = OllamaProvider(model="minicpm-v")
        assert provider.supports_vision is True


class TestOllamaMessageConversion:
    """Test message format conversion for Ollama multimodal API."""

    def test_text_only_message_passthrough(self) -> None:
        """Plain text messages are passed through unchanged."""
        from ssi.llm.ollama_provider import OllamaProvider

        messages = [
            {"role": "system", "content": "You are a bot."},
            {"role": "user", "content": "Hello"},
        ]
        result = OllamaProvider._convert_messages_for_ollama(messages)
        assert len(result) == 2
        assert result[0]["content"] == "You are a bot."
        assert "images" not in result[0]

    def test_image_parts_extracted(self) -> None:
        """Image parts are moved to the ``images`` field."""
        from ssi.llm.ollama_provider import OllamaProvider

        messages = [
            {"role": "system", "content": "Describe the image."},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What do you see?"},
                    {"type": "image", "media_type": "image/png", "data": "base64data123"},
                ],
            },
        ]
        result = OllamaProvider._convert_messages_for_ollama(messages)
        assert len(result) == 2
        assert result[1]["content"] == "What do you see?"
        assert result[1]["images"] == ["base64data123"]

    def test_multiple_images(self) -> None:
        """Multiple images in one message are all collected."""
        from ssi.llm.ollama_provider import OllamaProvider

        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Compare these images."},
                    {"type": "image", "data": "img1"},
                    {"type": "image", "data": "img2"},
                ],
            }
        ]
        result = OllamaProvider._convert_messages_for_ollama(messages)
        assert result[0]["images"] == ["img1", "img2"]


class TestOllamaImageStripping:
    """Test fallback image stripping for non-vision models."""

    def test_strips_images_keeps_text(self) -> None:
        """Image parts are removed and text is preserved."""
        from ssi.llm.ollama_provider import OllamaProvider

        messages = [
            {"role": "system", "content": "System prompt."},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Analyse this page."},
                    {"type": "image", "media_type": "image/png", "data": "screenshotdata"},
                ],
            },
        ]
        result = OllamaProvider._strip_images(messages)
        assert len(result) == 2
        assert result[0]["content"] == "System prompt."
        assert result[1]["content"] == "Analyse this page."


class TestOllamaChatWithImages:
    """Test ``chat_with_images()`` routing based on vision capability."""

    @patch("ssi.llm.ollama_provider.OllamaProvider.chat")
    def test_non_vision_model_falls_back_to_text(self, mock_chat: MagicMock) -> None:
        """Non-vision model strips images and delegates to ``chat()``."""
        from ssi.llm.ollama_provider import OllamaProvider

        mock_chat.return_value = LLMResult(content='{"action": "done"}', model="llama3.1")
        provider = OllamaProvider(model="llama3.1")  # Not vision

        messages = [
            {"role": "system", "content": "System"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What?"},
                    {"type": "image", "data": "abc"},
                ],
            },
        ]
        result = provider.chat_with_images(messages, json_mode=True)

        mock_chat.assert_called_once()
        call_args = mock_chat.call_args
        # Should have been stripped to text-only messages
        text_msgs = call_args[0][0]
        assert isinstance(text_msgs[1]["content"], str)
        assert result.content == '{"action": "done"}'

    @patch("httpx.Client.post")
    def test_vision_model_sends_images(self, mock_post: MagicMock) -> None:
        """Vision-capable model sends images via Ollama API."""
        from ssi.llm.ollama_provider import OllamaProvider

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "message": {"content": '{"action": "click", "reasoning": "found button"}'},
            "prompt_eval_count": 200,
            "eval_count": 50,
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = OllamaProvider(model="gemma3:12b")  # Vision-capable

        messages = [
            {"role": "system", "content": "System"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What?"},
                    {"type": "image", "data": "base64screenshot"},
                ],
            },
        ]
        result = provider.chat_with_images(messages, json_mode=True)

        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["model"] == "gemma3:12b"
        assert payload["format"] == "json"
        # Messages should have images field
        user_msg = [m for m in payload["messages"] if m["role"] == "user"][0]
        assert "images" in user_msg
        assert user_msg["images"] == ["base64screenshot"]
        assert result.input_tokens == 200


# ---------------------------------------------------------------------------
# C4: Dual-model routing
# ---------------------------------------------------------------------------


class TestDualModelFactory:
    """Test ``create_llm_provider`` with role-based model selection."""

    @patch("ssi.settings.get_settings")
    def test_primary_role_uses_default_model(self, mock_settings: MagicMock) -> None:
        """Default (primary) role uses ``llm.model``."""
        settings = MagicMock()
        settings.llm.provider = "ollama"
        settings.llm.model = "llama3.1"
        settings.llm.cheap_model = "llama3.2:1b"
        settings.llm.vision_model = "gemma3"
        settings.llm.ollama_base_url = "http://localhost:11434"
        settings.llm.temperature = 0.1
        settings.llm.max_tokens = 4096
        mock_settings.return_value = settings

        from ssi.llm.factory import create_llm_provider

        provider = create_llm_provider(role="primary")
        # Unwrap RetryingLLMProvider
        inner = provider._delegate
        assert inner.model == "llama3.1"

    @patch("ssi.settings.get_settings")
    def test_cheap_role_uses_cheap_model(self, mock_settings: MagicMock) -> None:
        """Cheap role uses ``llm.cheap_model`` when set."""
        settings = MagicMock()
        settings.llm.provider = "ollama"
        settings.llm.model = "llama3.1"
        settings.llm.cheap_model = "llama3.2:1b"
        settings.llm.vision_model = ""
        settings.llm.ollama_base_url = "http://localhost:11434"
        settings.llm.temperature = 0.1
        settings.llm.max_tokens = 4096
        mock_settings.return_value = settings

        from ssi.llm.factory import create_llm_provider

        provider = create_llm_provider(role="cheap")
        inner = provider._delegate
        assert inner.model == "llama3.2:1b"

    @patch("ssi.settings.get_settings")
    def test_cheap_role_falls_back_to_primary(self, mock_settings: MagicMock) -> None:
        """Cheap role falls back to primary model when ``cheap_model`` is empty."""
        settings = MagicMock()
        settings.llm.provider = "ollama"
        settings.llm.model = "llama3.1"
        settings.llm.cheap_model = ""
        settings.llm.vision_model = ""
        settings.llm.ollama_base_url = "http://localhost:11434"
        settings.llm.temperature = 0.1
        settings.llm.max_tokens = 4096
        mock_settings.return_value = settings

        from ssi.llm.factory import create_llm_provider

        provider = create_llm_provider(role="cheap")
        inner = provider._delegate
        assert inner.model == "llama3.1"

    @patch("ssi.settings.get_settings")
    def test_vision_role_uses_vision_model(self, mock_settings: MagicMock) -> None:
        """Vision role uses ``llm.vision_model`` when set."""
        settings = MagicMock()
        settings.llm.provider = "ollama"
        settings.llm.model = "llama3.1"
        settings.llm.cheap_model = ""
        settings.llm.vision_model = "gemma3:12b"
        settings.llm.ollama_base_url = "http://localhost:11434"
        settings.llm.temperature = 0.1
        settings.llm.max_tokens = 4096
        mock_settings.return_value = settings

        from ssi.llm.factory import create_llm_provider

        provider = create_llm_provider(role="vision")
        inner = provider._delegate
        assert inner.model == "gemma3:12b"


class TestPageAnalyzerModelSelection:
    """Test that ``PageAnalyzer._select_llm()`` routes to the correct provider."""

    def test_cheap_state_uses_cheap_llm(self) -> None:
        """FILL_REGISTER (a cheap_model_state) selects the cheap LLM."""
        from ssi.browser.page_analyzer import PageAnalyzer

        primary = MagicMock(spec=LLMProvider)
        cheap = MagicMock(spec=LLMProvider)

        analyzer = PageAnalyzer(llm=primary, cheap_llm=cheap)
        analyzer._cheap_model_states = {"FILL_REGISTER", "SUBMIT_REGISTER", "CHECK_EMAIL_VERIFICATION"}

        assert analyzer._select_llm("FILL_REGISTER") is cheap
        assert analyzer._select_llm("SUBMIT_REGISTER") is cheap
        assert analyzer._select_llm("CHECK_EMAIL_VERIFICATION") is cheap

    def test_non_cheap_state_uses_primary_llm(self) -> None:
        """States not in cheap_model_states use the primary LLM."""
        from ssi.browser.page_analyzer import PageAnalyzer

        primary = MagicMock(spec=LLMProvider)
        cheap = MagicMock(spec=LLMProvider)

        analyzer = PageAnalyzer(llm=primary, cheap_llm=cheap)
        analyzer._cheap_model_states = {"FILL_REGISTER"}

        assert analyzer._select_llm("FIND_REGISTER") is primary
        assert analyzer._select_llm("NAVIGATE_DEPOSIT") is primary
        assert analyzer._select_llm("EXTRACT_WALLETS") is primary

    def test_no_cheap_llm_always_primary(self) -> None:
        """When no cheap LLM is provided, primary is used for everything."""
        from ssi.browser.page_analyzer import PageAnalyzer

        primary = MagicMock(spec=LLMProvider)

        analyzer = PageAnalyzer(llm=primary, cheap_llm=None)
        analyzer._cheap_model_states = {"FILL_REGISTER"}

        assert analyzer._select_llm("FILL_REGISTER") is primary
        assert analyzer._select_llm("NAVIGATE_DEPOSIT") is primary
