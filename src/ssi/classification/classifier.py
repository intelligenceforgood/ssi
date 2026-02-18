"""LLM-based fraud taxonomy classifier for SSI investigations.

Takes an ``InvestigationResult`` and produces a ``FraudTaxonomyResult``
aligned with the i4g five-axis fraud taxonomy.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from ssi.classification.prompts import CLASSIFICATION_SYSTEM_PROMPT, CLASSIFICATION_USER_TEMPLATE
from ssi.models.investigation import InvestigationResult, ScamClassification

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public data model — mirrors i4g's FraudClassificationResult shape
# ---------------------------------------------------------------------------


class ScoredLabel:
    """A single classification label with a confidence score."""

    __slots__ = ("label", "confidence", "explanation")

    def __init__(self, label: str, confidence: float, explanation: str = "") -> None:
        self.label = label
        self.confidence = max(0.0, min(1.0, confidence))
        self.explanation = explanation

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "confidence": self.confidence, "explanation": self.explanation}


class FraudTaxonomyResult:
    """Five-axis fraud classification result compatible with i4g taxonomy."""

    __slots__ = (
        "intent",
        "channel",
        "techniques",
        "actions",
        "persona",
        "explanation",
        "risk_score",
        "taxonomy_version",
    )

    def __init__(
        self,
        *,
        intent: list[ScoredLabel] | None = None,
        channel: list[ScoredLabel] | None = None,
        techniques: list[ScoredLabel] | None = None,
        actions: list[ScoredLabel] | None = None,
        persona: list[ScoredLabel] | None = None,
        explanation: str = "",
        risk_score: float = 0.0,
        taxonomy_version: str = "1.0",
    ) -> None:
        self.intent = intent or []
        self.channel = channel or []
        self.techniques = techniques or []
        self.actions = actions or []
        self.persona = persona or []
        self.explanation = explanation
        self.risk_score = max(0.0, min(100.0, risk_score))
        self.taxonomy_version = taxonomy_version

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": [l.to_dict() for l in self.intent],
            "channel": [l.to_dict() for l in self.channel],
            "techniques": [l.to_dict() for l in self.techniques],
            "actions": [l.to_dict() for l in self.actions],
            "persona": [l.to_dict() for l in self.persona],
            "explanation": self.explanation,
            "risk_score": self.risk_score,
            "taxonomy_version": self.taxonomy_version,
        }

    def to_scam_classification(self) -> ScamClassification:
        """Collapse into the SSI-native ``ScamClassification`` model."""
        top_intent = self.intent[0] if self.intent else None
        top_channel = self.channel[0] if self.channel else None
        top_technique = self.techniques[0] if self.techniques else None
        top_action = self.actions[0] if self.actions else None
        top_persona = self.persona[0] if self.persona else None

        return ScamClassification(
            scam_type=top_intent.label if top_intent else "",
            confidence=top_intent.confidence if top_intent else 0.0,
            intent=top_intent.label if top_intent else "",
            channel=top_channel.label if top_channel else "",
            technique=top_technique.label if top_technique else "",
            action=top_action.label if top_action else "",
            persona=top_persona.label if top_persona else "",
            summary=self.explanation,
        )


# ---------------------------------------------------------------------------
# Risk score weights (mirrors core's definitions.yaml)
# ---------------------------------------------------------------------------

_INTENT_WEIGHTS: dict[str, float] = {
    "INTENT.IMPOSTER": 8,
    "INTENT.INVESTMENT": 9,
    "INTENT.ROMANCE": 7,
    "INTENT.EMPLOYMENT": 6,
    "INTENT.SHOPPING": 5,
    "INTENT.TECH_SUPPORT": 7,
    "INTENT.PRIZE": 5,
    "INTENT.EXTORTION": 10,
    "INTENT.CHARITY": 6,
}

_ACTION_WEIGHTS: dict[str, float] = {
    "ACTION.SEND_MONEY": 10,
    "ACTION.GIFT_CARDS": 8,
    "ACTION.CRYPTO": 9,
    "ACTION.CREDENTIALS": 8,
    "ACTION.INSTALL": 7,
    "ACTION.CLICK_LINK": 3,
    "ACTION.PROVIDE_PII": 6,
}

_TECHNIQUE_WEIGHTS: dict[str, float] = {
    "SE.URGENCY": 7,
    "SE.AUTHORITY": 7,
    "SE.SCARCITY": 5,
    "SE.FEAR": 8,
    "SE.RECIPROCITY": 4,
    "SE.TRUST_BUILDING": 4,
    "SE.CONFUSION": 5,
}


def _calculate_risk_score(taxonomy: FraudTaxonomyResult) -> float:
    """Compute base risk score from taxonomy labels and confidence * weights.

    Formula: ``sum(confidence * weight) * 2.5``, capped at 100.
    This is the LLM-based component; ``_apply_infrastructure_boost`` adds
    evidence from the OSINT modules.
    """
    total = 0.0
    for lbl in taxonomy.intent:
        total += lbl.confidence * _INTENT_WEIGHTS.get(lbl.label, 5)
    for lbl in taxonomy.actions:
        total += lbl.confidence * _ACTION_WEIGHTS.get(lbl.label, 5)
    for lbl in taxonomy.techniques:
        total += lbl.confidence * _TECHNIQUE_WEIGHTS.get(lbl.label, 5)
    return min(100.0, total * 2.5)


def _apply_infrastructure_boost(
    base_score: float,
    result: "InvestigationResult",
) -> float:
    """Add risk points for suspicious infrastructure signals the LLM may overlook.

    Each signal adds a small additive bonus. The total is capped at 100.
    """
    boost = 0.0

    # --- Domain age ---
    if result.whois and result.whois.creation_date:
        try:
            from datetime import datetime, timezone

            created = result.whois.creation_date
            if isinstance(created, str):
                # Strip timezone suffix for fromisoformat compat
                created = created.replace("+00:00", "").replace("Z", "").strip()
                dt = datetime.fromisoformat(created)
            else:
                dt = created  # type: ignore[assignment]
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - dt).days
            if age_days < 30:
                boost += 15  # Created in the last month
            elif age_days < 90:
                boost += 10  # Created in the last 3 months
            elif age_days < 365:
                boost += 5   # Created in the last year
        except Exception:
            pass

    # --- SSL certificate ---
    if result.ssl:
        if not result.ssl.is_valid and not result.ssl.issuer:
            boost += 8  # No SSL cert at all (for an https URL)
        elif result.ssl.is_self_signed:
            boost += 10  # Self-signed cert

    # --- Suspicious TLD ---
    from urllib.parse import urlparse

    host = urlparse(result.url).hostname or ""
    _SUSPICIOUS_TLDS = {
        ".cc", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top",
        ".xyz", ".icu", ".club", ".wang", ".work", ".live", ".click",
        ".surf", ".rest", ".monster",
    }
    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            boost += 5
            break

    # --- Brand name in subdomain (impersonation signal) ---
    _COMMON_BRANDS = {
        "paypal", "apple", "amazon", "microsoft", "google", "netflix",
        "chase", "wells-fargo", "wellsfargo", "bank-of-america",
        "t-mobile", "tmobile", "verizon", "att", "usps", "fedex",
        "dhl", "ups", "irs", "costco", "walmart", "target", "etsy",
        "facebook", "instagram", "whatsapp", "linkedin",
    }
    host_lower = host.lower()
    for brand in _COMMON_BRANDS:
        if brand in host_lower:
            # Only count if the brand is NOT the registrable domain itself
            parts = host_lower.rsplit(".", 2)
            registrable = parts[-2] if len(parts) >= 2 else host_lower
            if brand != registrable:
                boost += 10
                break

    # --- Privacy-protected or missing registrant ---
    if result.whois and not result.whois.registrant_name and not result.whois.registrant_org:
        boost += 3

    # --- No DNS records (domain parked / dead) ---
    if result.dns and not result.dns.a and not result.dns.aaaa:
        boost += 5

    return min(100.0, base_score + boost)


# ---------------------------------------------------------------------------
# Evidence text assembly
# ---------------------------------------------------------------------------


def _build_evidence_text(result: InvestigationResult) -> str:
    """Render investigation evidence into the classification prompt template."""
    # Form fields
    form_lines: list[str] = []
    if result.page_snapshot and result.page_snapshot.form_fields:
        for ff in result.page_snapshot.form_fields:
            label_str = ff.label or ff.placeholder or ff.name
            pii_note = f" [PII: {ff.pii_category}]" if ff.pii_category else ""
            form_lines.append(f"- {ff.tag}[{ff.field_type}] name={ff.name!r} label={label_str!r}{pii_note}")
    form_fields_text = "\n".join(form_lines) if form_lines else "None found."

    # Threat indicators
    ti_lines = [f"- [{ti.indicator_type}] {ti.value} ({ti.context})" for ti in result.threat_indicators]
    threat_indicators_text = "\n".join(ti_lines) if ti_lines else "None found."

    # Downloads
    dl_lines = [
        f"- {d.filename} (SHA-256: {d.sha256[:16]}…) malicious={d.is_malicious} VT={d.vt_detections}/{d.vt_total_engines}"
        for d in result.downloads
    ]
    downloads_text = "\n".join(dl_lines) if dl_lines else "None."

    # Agent steps
    agent_lines: list[str] = []
    for step in result.agent_steps:
        s_num = step.get("step", "?")
        s_action = step.get("action", "?")
        s_reason = step.get("reasoning", "")
        agent_lines.append(f"Step {s_num}: {s_action} — {s_reason}")
    agent_steps_text = "\n".join(agent_lines) if agent_lines else "No active interaction performed."

    # Infrastructure
    registrar = result.whois.registrar if result.whois else "Unknown"
    domain_creation_date = result.whois.creation_date if result.whois else "Unknown"
    hosting_info = f"{result.geoip.org} ({result.geoip.country})" if result.geoip else "Unknown"
    ssl_issuer = result.ssl.issuer if result.ssl else "Unknown"
    ssl_valid = str(result.ssl.is_valid) if result.ssl else "Unknown"
    geoip_info = f"{result.geoip.city}, {result.geoip.region}, {result.geoip.country}" if result.geoip else "Unknown"

    # Page info
    page_title = result.page_snapshot.title if result.page_snapshot else "N/A"
    redirect_chain = " → ".join(result.page_snapshot.redirect_chain) if result.page_snapshot else "N/A"
    technologies = ", ".join(result.page_snapshot.technologies) if result.page_snapshot else "None detected"

    return CLASSIFICATION_USER_TEMPLATE.format(
        url=result.url,
        page_title=page_title,
        redirect_chain=redirect_chain,
        technologies=technologies,
        form_fields_text=form_fields_text,
        registrar=registrar,
        domain_creation_date=domain_creation_date,
        hosting_info=hosting_info,
        ssl_issuer=ssl_issuer,
        ssl_valid=ssl_valid,
        geoip_info=geoip_info,
        threat_indicators_text=threat_indicators_text,
        brand_impersonation=result.brand_impersonation or "None detected.",
        downloads_text=downloads_text,
        agent_steps_text=agent_steps_text,
    )


# ---------------------------------------------------------------------------
# LLM classification call
# ---------------------------------------------------------------------------


def _parse_llm_response(raw: str) -> FraudTaxonomyResult:
    """Parse LLM JSON output into a ``FraudTaxonomyResult``."""
    # Strip markdown code fences if present
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
    if text.endswith("```"):
        text = text[: text.rfind("```")]
    text = text.strip()

    data = json.loads(text)

    def _to_scored_labels(items: list[dict[str, Any]]) -> list[ScoredLabel]:
        return [
            ScoredLabel(
                label=item.get("label", ""),
                confidence=float(item.get("confidence", 0.0)),
                explanation=item.get("explanation", ""),
            )
            for item in items
        ]

    taxonomy = FraudTaxonomyResult(
        intent=_to_scored_labels(data.get("intent", [])),
        channel=_to_scored_labels(data.get("channel", [])),
        techniques=_to_scored_labels(data.get("techniques", [])),
        actions=_to_scored_labels(data.get("actions", [])),
        persona=_to_scored_labels(data.get("persona", [])),
        explanation=data.get("explanation", ""),
        taxonomy_version="1.0",
    )
    taxonomy.risk_score = _calculate_risk_score(taxonomy)
    return taxonomy


def classify_investigation(
    result: InvestigationResult,
    *,
    ollama_base_url: str | None = None,
    model: str | None = None,
) -> FraudTaxonomyResult:
    """Classify an SSI investigation using the fraud taxonomy via LLM.

    Args:
        result: Completed investigation result.
        ollama_base_url: Override Ollama endpoint.
        model: Override LLM model name.

    Returns:
        A ``FraudTaxonomyResult`` with scored labels across all five axes.
    """
    from ssi.settings import get_settings

    settings = get_settings()
    base_url = (ollama_base_url or settings.llm.ollama_base_url).rstrip("/")
    model_name = model or settings.llm.model

    evidence_text = _build_evidence_text(result)

    messages = [
        {"role": "system", "content": CLASSIFICATION_SYSTEM_PROMPT},
        {"role": "user", "content": evidence_text},
    ]

    payload = {
        "model": model_name,
        "messages": messages,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": settings.llm.temperature,
            "num_predict": settings.llm.max_tokens,
        },
    }

    try:
        resp = httpx.post(
            f"{base_url}/api/chat",
            json=payload,
            timeout=120.0,
        )
        resp.raise_for_status()
        body = resp.json()
        raw_content = body.get("message", {}).get("content", "")

        taxonomy = _parse_llm_response(raw_content)
        # Apply infrastructure-based boost on top of the LLM-derived base score
        taxonomy.risk_score = _apply_infrastructure_boost(taxonomy.risk_score, result)
        logger.info(
            "Classification complete: risk_score=%.1f intent=%s",
            taxonomy.risk_score,
            [l.label for l in taxonomy.intent],
        )
        return taxonomy

    except httpx.HTTPError as e:
        logger.error("LLM classification request failed: %s", e)
        # Return empty taxonomy with WEB channel set
        return FraudTaxonomyResult(
            channel=[ScoredLabel("CHANNEL.WEB", 1.0, "SSI investigates web-based scam sites.")],
            explanation=f"Classification failed: {e}",
        )
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.error("Failed to parse classification response: %s", e)
        return FraudTaxonomyResult(
            channel=[ScoredLabel("CHANNEL.WEB", 1.0, "SSI investigates web-based scam sites.")],
            explanation=f"Classification parse error: {e}",
        )
