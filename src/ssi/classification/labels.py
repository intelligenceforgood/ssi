"""Human-friendly display labels for taxonomy codes.

This map mirrors core's ``CODE_TO_LABEL`` so that SSI can render
readable labels in reports and CLI output without importing core.

When new taxonomy items are added via ``i4g taxonomy refresh``, update
this map to keep SSI reports in sync.
"""

from __future__ import annotations

CODE_TO_LABEL: dict[str, str] = {
    "INTENT.IMPOSTER": "Imposter",
    "INTENT.INVESTMENT": "Investment",
    "INTENT.ROMANCE": "Romance",
    "INTENT.EMPLOYMENT": "Employment",
    "INTENT.SHOPPING": "Shopping",
    "INTENT.TECH_SUPPORT": "Tech Support",
    "INTENT.PRIZE": "Prize",
    "INTENT.EXTORTION": "Extortion",
    "INTENT.CHARITY": "Charity",
    "CHANNEL.EMAIL": "Email",
    "CHANNEL.SMS": "SMS",
    "CHANNEL.CHAT": "Chat",
    "CHANNEL.SOCIAL": "Social Media",
    "CHANNEL.PHONE": "Phone",
    "CHANNEL.WEB": "Web",
    "SE.URGENCY": "Urgency",
    "SE.AUTHORITY": "Authority",
    "SE.SCARCITY": "Scarcity",
    "SE.FEAR": "Fear",
    "SE.RECIPROCITY": "Reciprocity",
    "SE.TRUST_BUILDING": "Trust Building",
    "SE.CONFUSION": "Confusion",
    "ACTION.SEND_MONEY": "Send Money",
    "ACTION.GIFT_CARDS": "Gift Cards",
    "ACTION.CRYPTO": "Crypto",
    "ACTION.CREDENTIALS": "Credentials",
    "ACTION.INSTALL": "Install",
    "ACTION.CLICK_LINK": "Click Link",
    "ACTION.PROVIDE_PII": "Provide PII",
    "PERSONA.GOVERNMENT": "Government",
    "PERSONA.BANK": "Bank",
    "PERSONA.TECH_COMPANY": "Tech Company",
    "PERSONA.EMPLOYER": "Employer",
    "PERSONA.ROMANTIC": "Romantic Partner",
    "PERSONA.MARKETPLACE": "Marketplace User",
    "PERSONA.CHARITY": "Charity",
}


def get_display_label(code: str) -> str:
    """Return a human-readable label for a taxonomy code.

    Falls back to a title-cased version of the code suffix when the code
    is not found in the lookup map.
    """
    if code in CODE_TO_LABEL:
        return CODE_TO_LABEL[code]
    suffix = code.split(".", 1)[-1] if "." in code else code
    return suffix.replace("_", " ").title()
