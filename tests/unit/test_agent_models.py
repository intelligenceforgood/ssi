"""Unit tests for the AI browser agent models."""

from __future__ import annotations

from ssi.models.agent import (
    ActionType,
    AgentAction,
    AgentMetrics,
    AgentSession,
    AgentStep,
    InteractiveElement,
    PageObservation,
)


class TestActionType:
    """ActionType enum covers all expected browser actions."""

    def test_all_action_types_exist(self):
        expected = {"click", "type", "select", "scroll", "wait", "navigate", "submit", "screenshot", "done", "fail"}
        assert {a.value for a in ActionType} == expected

    def test_terminal_actions(self):
        assert ActionType.DONE.value == "done"
        assert ActionType.FAIL.value == "fail"


class TestInteractiveElement:
    """InteractiveElement captures DOM element metadata for the LLM."""

    def test_defaults(self):
        el = InteractiveElement(index=0, tag="input")
        assert el.index == 0
        assert el.tag == "input"
        assert el.label == ""
        assert el.selector == ""

    def test_full_element(self):
        el = InteractiveElement(
            index=3,
            tag="input",
            element_type="email",
            name="user_email",
            label="Email Address",
            placeholder="you@example.com",
            required=True,
            selector='input[name="user_email"]',
        )
        assert el.element_type == "email"
        assert el.required is True


class TestPageObservation:
    """PageObservation bundles the page state for the LLM."""

    def test_defaults(self):
        obs = PageObservation(url="https://example.com", title="Example")
        assert obs.url == "https://example.com"
        assert obs.interactive_elements == []
        assert obs.visible_text == ""

    def test_with_elements(self):
        obs = PageObservation(
            url="https://example.com",
            title="Test",
            interactive_elements=[
                InteractiveElement(index=0, tag="input", label="Name"),
                InteractiveElement(index=1, tag="button", text="Submit"),
            ],
        )
        assert len(obs.interactive_elements) == 2
        assert obs.interactive_elements[1].text == "Submit"


class TestAgentAction:
    """AgentAction represents a single LLM decision."""

    def test_click_action(self):
        action = AgentAction(action_type=ActionType.CLICK, element_index=3, reasoning="Click the login button")
        assert action.action_type == ActionType.CLICK
        assert action.element_index == 3

    def test_type_action(self):
        action = AgentAction(action_type=ActionType.TYPE, element_index=1, value="test@example.com")
        assert action.value == "test@example.com"

    def test_done_action(self):
        action = AgentAction(action_type=ActionType.DONE, reasoning="Reached confirmation page")
        assert action.element_index is None


class TestAgentStep:
    """AgentStep records a full observe→decide→act cycle."""

    def test_step_creation(self):
        obs = PageObservation(url="https://example.com", title="Test")
        action = AgentAction(action_type=ActionType.CLICK, element_index=0)
        step = AgentStep(step_number=0, observation=obs, action=action, input_tokens=500, output_tokens=100)
        assert step.step_number == 0
        assert step.input_tokens == 500
        assert step.output_tokens == 100
        assert step.error == ""


class TestAgentMetrics:
    """AgentMetrics aggregates session-level measurements."""

    def test_defaults(self):
        m = AgentMetrics()
        assert m.total_steps == 0
        assert m.total_input_tokens == 0
        assert m.completed_successfully is False
        assert m.termination_reason == ""

    def test_populated_metrics(self):
        m = AgentMetrics(
            total_steps=5,
            total_input_tokens=3000,
            total_output_tokens=800,
            total_duration_ms=15000,
            budget_remaining=46200,
            completed_successfully=True,
            termination_reason="done: Reached confirmation page",
        )
        assert m.total_steps == 5
        assert m.budget_remaining == 46200


class TestAgentSession:
    """AgentSession is the top-level session record."""

    def test_defaults(self):
        s = AgentSession()
        assert s.steps == []
        assert s.pages_visited == []
        assert s.pii_fields_submitted == []

    def test_to_dict(self):
        s = AgentSession(url="https://example.com")
        d = s.to_dict()
        assert d["url"] == "https://example.com"
        assert isinstance(d["steps"], list)
        assert "metrics" in d
