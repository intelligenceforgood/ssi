"""Prompt refinement analysis — Task 1.6 of SSI roadmap Phase 1.

Validates that the classification prompt templates:
  - Contain all five taxonomy axes.
  - Reference every label used in the codebase.
  - Produce a parseable JSON schema definition in the system prompt.
  - Have consistent label naming between the prompt and the weight maps.

Also verifies that the risk-score calculation is deterministic and
bounded [0, 100].
"""

from __future__ import annotations

from typing import Any

import pytest

from ssi.classification.classifier import (
    FraudTaxonomyResult,
    ScoredLabel,
    _ACTION_WEIGHTS,
    _INTENT_WEIGHTS,
    _TECHNIQUE_WEIGHTS,
    _calculate_risk_score,
)
from ssi.classification.labels import CODE_TO_LABEL
from ssi.classification.prompts import (
    CLASSIFICATION_SYSTEM_PROMPT,
    CLASSIFICATION_USER_TEMPLATE,
)


# ---------------------------------------------------------------------------
# Prompt content validation
# ---------------------------------------------------------------------------


class TestPromptCompleteness:
    """Verify prompt templates cover all taxonomy labels."""

    def test_system_prompt_mentions_all_intent_labels(self) -> None:
        """System prompt lists every INTENT.* label."""
        for label in _INTENT_WEIGHTS:
            assert label in CLASSIFICATION_SYSTEM_PROMPT, (
                f"System prompt missing intent label: {label}"
            )

    def test_system_prompt_mentions_all_action_labels(self) -> None:
        """System prompt lists every ACTION.* label."""
        for label in _ACTION_WEIGHTS:
            assert label in CLASSIFICATION_SYSTEM_PROMPT, (
                f"System prompt missing action label: {label}"
            )

    def test_system_prompt_mentions_all_technique_labels(self) -> None:
        """System prompt lists every SE.* technique label."""
        for label in _TECHNIQUE_WEIGHTS:
            assert label in CLASSIFICATION_SYSTEM_PROMPT, (
                f"System prompt missing technique label: {label}"
            )

    def test_system_prompt_has_five_axes(self) -> None:
        """System prompt names all five taxonomy axes."""
        for axis in ("Intent", "Delivery Channel", "Social Engineering Technique",
                      "Requested Action", "Claimed Persona"):
            assert axis.lower() in CLASSIFICATION_SYSTEM_PROMPT.lower(), (
                f"System prompt missing axis: {axis}"
            )

    def test_system_prompt_has_json_schema_hint(self) -> None:
        """System prompt includes JSON output schema with all five keys."""
        for key in ("intent", "channel", "techniques", "actions", "persona"):
            assert f'"{key}"' in CLASSIFICATION_SYSTEM_PROMPT, (
                f"System prompt missing JSON key: {key}"
            )

    def test_user_template_has_all_placeholders(self) -> None:
        """User template contains all expected placeholders."""
        expected_placeholders = [
            "url", "page_title", "redirect_chain", "technologies",
            "form_fields_text", "registrar", "domain_creation_date",
            "hosting_info", "ssl_issuer", "ssl_valid", "geoip_info",
            "threat_indicators_text", "brand_impersonation",
            "downloads_text", "agent_steps_text",
        ]
        for placeholder in expected_placeholders:
            assert f"{{{placeholder}}}" in CLASSIFICATION_USER_TEMPLATE, (
                f"User template missing placeholder: {{{placeholder}}}"
            )


# ---------------------------------------------------------------------------
# Label consistency
# ---------------------------------------------------------------------------


class TestLabelConsistency:
    """Verify label names are consistent between prompts, weights, and display map."""

    def test_all_intent_labels_in_code_to_label(self) -> None:
        """Every INTENT.* weight key has a display label in CODE_TO_LABEL."""
        for code in _INTENT_WEIGHTS:
            assert code in CODE_TO_LABEL, f"CODE_TO_LABEL missing: {code}"

    def test_all_action_labels_in_code_to_label(self) -> None:
        """Every ACTION.* weight key has a display label in CODE_TO_LABEL."""
        for code in _ACTION_WEIGHTS:
            assert code in CODE_TO_LABEL, f"CODE_TO_LABEL missing: {code}"

    def test_all_technique_labels_in_code_to_label(self) -> None:
        """Every SE.* weight key has a display label in CODE_TO_LABEL."""
        for code in _TECHNIQUE_WEIGHTS:
            assert code in CODE_TO_LABEL, f"CODE_TO_LABEL missing: {code}"


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------


class TestRiskScoreCalculation:
    """Validate risk-score determinism and bounds."""

    def _taxonomy(self, **kwargs: Any) -> FraudTaxonomyResult:
        """Build a minimal FraudTaxonomyResult."""
        return FraudTaxonomyResult(**kwargs)

    def test_empty_taxonomy_gives_zero(self) -> None:
        """A taxonomy with no labels produces a risk score of 0."""
        score = _calculate_risk_score(self._taxonomy())
        assert score == 0.0

    def test_max_confidence_high_weight_bounded_at_100(self) -> None:
        """Risk score never exceeds 100, even with many high-weight labels."""
        taxonomy = self._taxonomy(
            intent=[ScoredLabel("INTENT.EXTORTION", 1.0)],
            actions=[
                ScoredLabel("ACTION.SEND_MONEY", 1.0),
                ScoredLabel("ACTION.CRYPTO", 1.0),
                ScoredLabel("ACTION.CREDENTIALS", 1.0),
            ],
            techniques=[
                ScoredLabel("SE.FEAR", 1.0),
                ScoredLabel("SE.URGENCY", 1.0),
                ScoredLabel("SE.AUTHORITY", 1.0),
            ],
        )
        score = _calculate_risk_score(taxonomy)
        assert 0.0 <= score <= 100.0

    def test_low_confidence_gives_low_score(self) -> None:
        """Labels with very low confidence produce a correspondingly low score."""
        taxonomy = self._taxonomy(
            intent=[ScoredLabel("INTENT.SHOPPING", 0.1)],
        )
        score = _calculate_risk_score(taxonomy)
        assert score < 5.0

    def test_score_is_deterministic(self) -> None:
        """Same inputs always produce the same risk score."""
        taxonomy = self._taxonomy(
            intent=[ScoredLabel("INTENT.INVESTMENT", 0.9)],
            actions=[ScoredLabel("ACTION.CRYPTO", 0.8)],
            techniques=[ScoredLabel("SE.URGENCY", 0.7)],
        )
        score1 = _calculate_risk_score(taxonomy)
        score2 = _calculate_risk_score(taxonomy)
        assert score1 == score2

    def test_unknown_labels_use_default_weight(self) -> None:
        """Labels not in the weight map still produce a score (default weight)."""
        taxonomy = self._taxonomy(
            intent=[ScoredLabel("INTENT.UNKNOWN_NEW_TYPE", 0.8)],
        )
        score = _calculate_risk_score(taxonomy)
        assert score > 0.0


# ---------------------------------------------------------------------------
# Taxonomy-to-ScamClassification collapse
# ---------------------------------------------------------------------------


class TestTaxonomyToScamClassification:
    """Verify FraudTaxonomyResult.to_scam_classification() correctness."""

    def test_top_labels_propagate(self) -> None:
        """ScamClassification takes the top label from each axis."""
        taxonomy = FraudTaxonomyResult(
            intent=[ScoredLabel("INTENT.INVESTMENT", 0.9)],
            channel=[ScoredLabel("CHANNEL.WEB", 0.95)],
            techniques=[ScoredLabel("SE.URGENCY", 0.8)],
            actions=[ScoredLabel("ACTION.CRYPTO", 0.85)],
            persona=[ScoredLabel("PERSONA.MARKETPLACE", 0.7)],
            explanation="Test classification.",
        )
        sc = taxonomy.to_scam_classification()
        assert sc.scam_type == "INTENT.INVESTMENT"
        assert sc.confidence == 0.9
        assert sc.intent == "INTENT.INVESTMENT"
        assert sc.channel == "CHANNEL.WEB"
        assert sc.technique == "SE.URGENCY"
        assert sc.action == "ACTION.CRYPTO"
        assert sc.persona == "PERSONA.MARKETPLACE"
        assert sc.summary == "Test classification."

    def test_empty_taxonomy_collapses_safely(self) -> None:
        """ScamClassification from empty taxonomy has blank fields."""
        taxonomy = FraudTaxonomyResult()
        sc = taxonomy.to_scam_classification()
        assert sc.scam_type == ""
        assert sc.confidence == 0.0
