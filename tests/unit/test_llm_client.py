"""Unit tests for the LLM client (action parsing, prompt building)."""

from __future__ import annotations

import json

import pytest

from ssi.browser.llm_client import AgentLLMClient
from ssi.identity.vault import IdentityVault
from ssi.models.agent import ActionType, InteractiveElement, PageObservation


@pytest.fixture()
def llm_client():
    """Create client with a mock LLM provider (no real backend needed)."""
    from unittest.mock import MagicMock

    from ssi.llm.base import LLMProvider

    mock_llm = MagicMock(spec=LLMProvider)
    mock_llm.check_connectivity.return_value = True
    return AgentLLMClient(llm=mock_llm)


@pytest.fixture()
def identity():
    return IdentityVault().generate()


@pytest.fixture()
def sample_observation():
    return PageObservation(
        url="https://example.com/login",
        title="Login Page",
        visible_text="Please enter your credentials to continue.",
        interactive_elements=[
            InteractiveElement(index=0, tag="input", element_type="text", name="username", label="Username"),
            InteractiveElement(index=1, tag="input", element_type="password", name="password", label="Password"),
            InteractiveElement(index=2, tag="button", element_type="submit", text="Sign In"),
        ],
        dom_summary="Page: Login Page\nURL: https://example.com/login\n\n[0] <input> type=text name=username\n[1] <input> type=password name=password\n[2] <button> text=Sign In",
    )


class TestActionParsing:
    """Test LLM response parsing into AgentAction."""

    def test_parse_valid_click(self, llm_client):
        content = json.dumps(
            {"reasoning": "Click the submit button", "action_type": "click", "element_index": 2, "value": ""}
        )
        action = llm_client._parse_action(content)
        assert action.action_type == ActionType.CLICK
        assert action.element_index == 2
        assert action.reasoning == "Click the submit button"

    def test_parse_valid_type(self, llm_client):
        content = json.dumps(
            {
                "reasoning": "Fill in email field",
                "action_type": "type",
                "element_index": 0,
                "value": "test@example.com",
            }
        )
        action = llm_client._parse_action(content)
        assert action.action_type == ActionType.TYPE
        assert action.value == "test@example.com"

    def test_parse_done(self, llm_client):
        content = json.dumps(
            {"reasoning": "Reached confirmation page", "action_type": "done", "element_index": None, "value": ""}
        )
        action = llm_client._parse_action(content)
        assert action.action_type == ActionType.DONE

    def test_parse_with_markdown_fences(self, llm_client):
        content = '```json\n{"reasoning": "test", "action_type": "click", "element_index": 1, "value": ""}\n```'
        action = llm_client._parse_action(content)
        assert action.action_type == ActionType.CLICK
        assert action.element_index == 1

    def test_parse_invalid_json(self, llm_client):
        action = llm_client._parse_action("This is not JSON at all")
        assert action.action_type == ActionType.FAIL

    def test_parse_unknown_action_type(self, llm_client):
        content = json.dumps({"reasoning": "test", "action_type": "explode", "element_index": None, "value": ""})
        action = llm_client._parse_action(content)
        assert action.action_type == ActionType.FAIL


class TestPromptBuilding:
    """Test that prompts are constructed correctly."""

    def test_messages_structure(self, llm_client, sample_observation, identity):
        messages = llm_client._build_messages(sample_observation, identity, history=None)
        assert len(messages) == 2  # system + user
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"

    def test_system_prompt_contains_identity(self, llm_client, sample_observation, identity):
        messages = llm_client._build_messages(sample_observation, identity, history=None)
        system = messages[0]["content"]
        assert identity.first_name in system
        assert identity.email in system
        assert "@i4g-probe.net" in system

    def test_user_prompt_contains_dom(self, llm_client, sample_observation, identity):
        messages = llm_client._build_messages(sample_observation, identity, history=None)
        user = messages[1]["content"]
        assert "Login Page" in user
        assert "input" in user.lower()

    def test_history_appended(self, llm_client, sample_observation, identity):
        history = [
            {"role": "user", "content": "Previous observation"},
            {"role": "assistant", "content": '{"action_type": "click", "element_index": 0}'},
        ]
        messages = llm_client._build_messages(sample_observation, identity, history=history)
        assert len(messages) == 4  # system + 2 history + current user
        assert messages[1]["content"] == "Previous observation"


class TestConnectivity:
    """Test connectivity checks (will fail without Ollama running)."""

    def test_check_connectivity_returns_bool(self, llm_client):
        # Should return False when Ollama isn't running in test env
        result = llm_client.check_connectivity()
        assert isinstance(result, bool)
