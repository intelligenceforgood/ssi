"""STIX 2.1 threat indicator export for SSI investigations.

Converts SSI ``ThreatIndicator`` and ``InvestigationResult`` data into a
STIX 2.1 bundle that can be shared via TAXII or imported into threat intel
platforms.

References:
    - https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
    - https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid5, NAMESPACE_URL

from ssi.models.investigation import InvestigationResult, ThreatIndicator
from ssi.wallet.models import WalletEntry

logger = logging.getLogger(__name__)

# STIX 2.1 namespace for deterministic UUIDs
_STIX_NAMESPACE = NAMESPACE_URL

# Mapping from SSI indicator types to STIX indicator patterns
_INDICATOR_TYPE_MAP: dict[str, str] = {
    "ip": "ipv4-addr",
    "ipv4": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "domain": "domain-name",
    "email": "email-addr",
    "url": "url",
    "crypto_wallet": "artifact",
    "phone": "artifact",
    "sha256": "file",
    "md5": "file",
}


def _make_stix_id(stix_type: str, value: str) -> str:
    """Generate a deterministic STIX ID from type and value."""
    seed = f"{stix_type}--{value}"
    return f"{stix_type}--{uuid5(_STIX_NAMESPACE, seed)}"


def _indicator_to_pattern(indicator: ThreatIndicator) -> str:
    """Convert an SSI ThreatIndicator to a STIX 2.1 pattern string."""
    itype = indicator.indicator_type.lower()
    value = indicator.value

    if itype in ("ip", "ipv4"):
        return f"[ipv4-addr:value = '{value}']"
    elif itype == "ipv6":
        return f"[ipv6-addr:value = '{value}']"
    elif itype == "domain":
        return f"[domain-name:value = '{value}']"
    elif itype == "email":
        return f"[email-addr:value = '{value}']"
    elif itype == "url":
        return f"[url:value = '{value}']"
    elif itype == "crypto_wallet":
        # Use cryptocurrency-wallet SCO pattern for proper TIP ingestion
        return f"[cryptocurrency-wallet:address = '{value}']"
    elif itype == "sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    elif itype == "md5":
        return f"[file:hashes.MD5 = '{value}']"
    else:
        return f"[artifact:payload_bin = '{value}']"


def _create_indicator_sdo(indicator: ThreatIndicator, investigation_url: str) -> dict[str, Any]:
    """Create a STIX Indicator SDO from an SSI ThreatIndicator."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pattern = _indicator_to_pattern(indicator)
    stix_id = _make_stix_id("indicator", f"{indicator.indicator_type}:{indicator.value}")

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "name": f"{indicator.indicator_type}: {indicator.value}",
        "description": indicator.context or f"IOC from SSI investigation of {investigation_url}",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "labels": ["scam-infrastructure"],
        "external_references": [
            {
                "source_name": "SSI Investigation",
                "description": f"Source: {indicator.source}",
                "url": investigation_url,
            }
        ],
    }


def _create_infrastructure_sdo(result: InvestigationResult) -> dict[str, Any] | None:
    """Create a STIX Infrastructure SDO summarising the scam site."""
    if not result.url:
        return None

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    stix_id = _make_stix_id("infrastructure", result.url)

    description_parts = [f"Scam site at {result.url}."]
    if result.whois and result.whois.registrar:
        description_parts.append(f"Registrar: {result.whois.registrar}.")
    if result.geoip and result.geoip.org:
        description_parts.append(f"Hosted by: {result.geoip.org} ({result.geoip.country}).")
    if result.ssl and result.ssl.issuer:
        description_parts.append(f"SSL issuer: {result.ssl.issuer}.")
    if result.wallets:
        description_parts.append(f"Extracted {len(result.wallets)} cryptocurrency wallet address(es).")

    return {
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "name": result.url,
        "description": " ".join(description_parts),
        "infrastructure_types": ["phishing"],
    }


def _create_wallet_indicator_sdo(wallet: WalletEntry, investigation_url: str) -> dict[str, Any]:
    """Create a STIX Indicator SDO for a harvested cryptocurrency wallet.

    Uses the ``cryptocurrency-wallet`` SCO pattern for proper ingestion
    by threat intelligence platforms with blockchain-analysis support.

    Args:
        wallet: The extracted wallet entry.
        investigation_url: The scam site URL for external references.

    Returns:
        A STIX Indicator SDO dictionary.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pattern = f"[cryptocurrency-wallet:address = '{wallet.wallet_address}']"
    stix_id = _make_stix_id("indicator", f"crypto_wallet:{wallet.wallet_address}")

    description = (
        f"{wallet.token_symbol} wallet on {wallet.network_short} network "
        f"extracted from {investigation_url}. "
        f"Source: {wallet.source}, confidence: {wallet.confidence:.0%}."
    )

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "name": f"Crypto wallet: {wallet.token_symbol}/{wallet.network_short} — {wallet.wallet_address[:16]}…",
        "description": description,
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "labels": ["scam-infrastructure", "cryptocurrency", wallet.network_short],
        "external_references": [
            {
                "source_name": "SSI Investigation",
                "description": f"Extracted via {wallet.source} from scam site",
                "url": investigation_url,
            }
        ],
    }


def investigation_to_stix_bundle(result: InvestigationResult) -> dict[str, Any]:
    """Convert an SSI investigation into a STIX 2.1 bundle.

    Args:
        result: A completed SSI investigation result.

    Returns:
        A STIX 2.1 bundle dictionary ready for JSON serialisation.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects: list[dict[str, Any]] = []

    # Identity for SSI as the source
    identity_id = _make_stix_id("identity", "ssi-scam-site-investigator")
    objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "SSI (Scam Site Investigator)",
            "description": "Automated scam site investigation tool by Intelligence For Good.",
            "identity_class": "organization",
        }
    )

    # Infrastructure SDO for the scam site
    infra = _create_infrastructure_sdo(result)
    if infra:
        objects.append(infra)

    # Indicator SDOs
    seen_values: set[str] = set()
    for ti in result.threat_indicators:
        key = f"{ti.indicator_type}:{ti.value}"
        if key in seen_values:
            continue
        seen_values.add(key)
        sdo = _create_indicator_sdo(ti, result.url)
        objects.append(sdo)

        # Relationship: indicator → infrastructure
        if infra:
            rel_id = _make_stix_id("relationship", f"{sdo['id']}--indicates--{infra['id']}")
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": sdo["id"],
                    "target_ref": infra["id"],
                }
            )

    # Malware SDOs for downloaded artifacts
    for dl in result.downloads:
        if dl.is_malicious and dl.sha256:
            malware_id = _make_stix_id("malware", dl.sha256)
            objects.append(
                {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": malware_id,
                    "created": now,
                    "modified": now,
                    "name": dl.filename or "Unknown malware",
                    "description": f"Malicious file downloaded from {dl.url}. "
                    f"VT detections: {dl.vt_detections}/{dl.vt_total_engines}.",
                    "malware_types": ["trojan"],
                    "is_family": False,
                    "hashes": {"SHA-256": dl.sha256, "MD5": dl.md5} if dl.md5 else {"SHA-256": dl.sha256},
                }
            )

    # Wallet Indicator SDOs — created directly from result.wallets for
    # richer metadata (token, network, confidence) than threat_indicators alone.
    seen_wallet_addrs: set[str] = set()
    for wallet in result.wallets:
        if wallet.wallet_address in seen_wallet_addrs:
            continue
        seen_wallet_addrs.add(wallet.wallet_address)

        # Skip if already emitted via threat_indicators
        ti_key = f"crypto_wallet:{wallet.wallet_address}"
        if ti_key in seen_values:
            continue
        seen_values.add(ti_key)

        sdo = _create_wallet_indicator_sdo(wallet, result.url)
        objects.append(sdo)

        if infra:
            rel_id = _make_stix_id("relationship", f"{sdo['id']}--indicates--{infra['id']}")
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": sdo["id"],
                    "target_ref": infra["id"],
                }
            )

    bundle_id = f"bundle--{uuid5(_STIX_NAMESPACE, str(result.investigation_id))}"
    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }

    logger.info("STIX bundle: %d objects for investigation %s", len(objects), result.investigation_id)
    return bundle
