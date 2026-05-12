"""Prompt templates for Sec-Gemini investigation sessions.

Each function builds a focused prompt that guides the Sec-Gemini agent
to analyse only what SSI's existing OSINT cannot cover — email security
posture, vulnerability correlation, and infrastructure fingerprinting.

The prompts explicitly instruct the agent to *not* repeat DNS, WHOIS,
or SSL lookups already provided as context.
"""

from __future__ import annotations

from typing import Any


def build_investigation_prompt(url: str, existing_osint: dict[str, Any]) -> str:
    """Build the primary investigation prompt for Sec-Gemini.

    Args:
        url: The target URL under investigation.
        existing_osint: Serialized dict of SSI's existing OSINT results
            (WHOIS, DNS, SSL, GeoIP, threat indicators).

    Returns:
        A prompt string to send via ``session.prompt()``.
    """
    # Extract domain-related info for targeted analysis
    domain = _extract_domain(url)
    email_domains = _extract_email_domains(existing_osint)
    whois_registrant = existing_osint.get("whois", {}).get("registrant_org", "")

    prompt_parts = [
        f"## Scam Site Security Analysis: {url}",
        "",
        "You are assisting a scam site investigation system. I have already collected",
        "WHOIS, DNS, SSL, and GeoIP data for this target. That data is attached as",
        "`ssi_osint_context.json`. **Do NOT repeat** those lookups.",
        "",
        "Perform the following targeted analyses:",
        "",
        "### 1. Email Security Posture",
        f"Analyze the email security configuration for domain `{domain}`.",
    ]

    if email_domains:
        domains_list = ", ".join(f"`{d}`" for d in sorted(email_domains))
        prompt_parts.append(f"Also check these additional domains found in the investigation: {domains_list}.")

    prompt_parts.extend(
        [
            "For each domain, use `check_email_security` to determine:",
            "- SPF record and validity",
            "- DKIM configuration",
            "- DMARC record and policy (none/quarantine/reject)",
            "- MX records",
            "",
            "### 2. Infrastructure Fingerprinting",
            f"Use `http_headers` on `{url}` to identify:",
            "- Web server software and version",
            "- Application framework",
            "- CMS (if any)",
            "- CDN or hosting provider",
            "",
            "For any identified software versions, use `lookup_vulnerability` to check",
            "for known CVEs. Note which CVEs are actively exploited.",
            "",
            "### 3. Threat Synthesis",
            "Based on ALL available data (the attached OSINT context + your new findings),",
            "write a brief threat synthesis paragraph covering:",
            "- Overall sophistication level of the scam operation",
            "- Whether the infrastructure appears purpose-built or compromised",
            "- Any indicators of professional fraud operation vs. amateur scam",
        ]
    )

    if whois_registrant:
        prompt_parts.append(f"- The WHOIS registrant is: {whois_registrant}")

    prompt_parts.extend(
        [
            "",
            "### Output Format",
            "Return your findings as a JSON object with this exact structure:",
            "```json",
            "{",
            '  "email_security": [',
            "    {",
            '      "domain": "example.com",',
            '      "spf_record": "v=spf1 ...",',
            '      "spf_valid": true,',
            '      "dkim_configured": true,',
            '      "dmarc_record": "v=DMARC1; p=reject",',
            '      "dmarc_policy": "reject",',
            '      "mx_records": ["mx1.example.com"],',
            '      "assessment": "Well-configured email security"',
            "    }",
            "  ],",
            '  "infrastructure": {',
            '    "web_server": "nginx/1.24",',
            '    "framework": null,',
            '    "cms": "WordPress 6.4",',
            '    "hosting_provider": "Cloudflare",',
            '    "cdn": "Cloudflare",',
            '    "technologies": ["PHP 8.1", "MySQL"],',
            '    "vulnerabilities": [',
            "      {",
            '        "cve_id": "CVE-2024-1234",',
            '        "software": "WordPress 6.4",',
            '        "severity": "high",',
            '        "cvss_score": 8.1,',
            '        "is_exploited": false,',
            '        "patch_available": true,',
            '        "description": "..."',
            "      }",
            "    ]",
            "  },",
            '  "threat_synthesis": "...",',
            '  "risk_adjustment": 0',
            "}",
            "```",
            "",
            "The `risk_adjustment` should be a number from -10 to +10 indicating how",
            "much your findings should increase (+) or decrease (-) the overall risk score.",
        ]
    )

    return "\n".join(prompt_parts)


def _extract_domain(url: str) -> str:
    """Extract the domain from a URL."""
    from urllib.parse import urlparse

    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def _extract_email_domains(existing_osint: dict[str, Any]) -> set[str]:
    """Extract unique email domains from existing OSINT data.

    Looks through WHOIS registrant info and threat indicators for
    email addresses and returns their domains.
    """
    import re

    domains: set[str] = set()
    # Search all string values in the OSINT data for email patterns
    text = _flatten_to_text(existing_osint)
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", text)
    domains.update(emails)
    return domains


def _flatten_to_text(obj: Any, depth: int = 0) -> str:
    """Recursively flatten a dict/list to a single searchable string."""
    if depth > 10:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_to_text(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten_to_text(v, depth + 1) for v in obj)
    return str(obj) if obj is not None else ""
