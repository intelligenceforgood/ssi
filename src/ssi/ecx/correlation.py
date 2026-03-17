"""eCrimeX Campaign Correlation — Phase 3C.

Links SSI investigations through shared indicators (wallets, IPs/ASNs,
brand impersonation patterns) and creates campaign records in the core
``threat_campaigns`` table so analysts can see coordinated threat activity.

Correlation strategies:

- **Wallet-based**: Investigations sharing the same cryptocurrency
  wallet address belong to the same operation.
- **IP/ASN-based**: Investigations hosted on the same IP or ASN
  suggest shared infrastructure.
- **Brand pattern**: Investigations impersonating the same brand
  in a time window indicate coordinated phishing waves.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import sqlalchemy as sa

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Minimum cluster size to form a campaign
_MIN_CLUSTER_SIZE = 2

# Default time window for brand pattern correlation (days)
_BRAND_WINDOW_DAYS = 30


class CampaignCorrelator:
    """Correlate SSI investigations and create campaign records.

    Operates against the shared database — the same instance used by
    core — querying ``site_scans``, ``harvested_wallets``, and
    ``ecx_enrichments`` tables to discover clusters of related
    investigations.

    Args:
        session_factory: A ``sessionmaker`` bound to the shared DB engine.
    """

    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate_all(self) -> dict[str, Any]:
        """Run all correlation strategies and return a summary.

        Returns:
            Dict with per-strategy results::

                {
                    "wallet": {"campaigns_created": 1, "cases_linked": 4},
                    "infrastructure": {"campaigns_created": 0, "cases_linked": 0},
                    "brand": {"campaigns_created": 2, "cases_linked": 6},
                    "errors": [],
                }
        """
        summary: dict[str, Any] = {"errors": []}

        for name, method in [
            ("wallet", self.correlate_by_wallet),
            ("infrastructure", self.correlate_by_infrastructure),
            ("brand", self.correlate_by_brand),
        ]:
            try:
                result = method()
                summary[name] = result
            except Exception as exc:
                msg = f"{name}: {type(exc).__name__}: {exc}"
                logger.error("Correlation strategy %s failed: %s", name, msg)
                summary[name] = {"campaigns_created": 0, "cases_linked": 0}
                summary["errors"].append(msg)

        return summary

    def correlate_by_wallet(self) -> dict[str, int]:
        """Link investigations sharing the same cryptocurrency wallet.

        Queries ``harvested_wallets`` for addresses that appear in
        multiple scans, then groups the associated cases into campaigns.

        Returns:
            Dict with ``campaigns_created`` and ``cases_linked`` counts.
        """

        campaigns_created = 0
        cases_linked = 0

        with self._session_factory() as session:
            # Find wallet addresses seen in 2+ scans that have case_ids
            wallet_clusters = self._find_wallet_clusters(session)

            for address, case_ids in wallet_clusters.items():
                if len(case_ids) < _MIN_CLUSTER_SIZE:
                    continue

                # Check if these cases already share a campaign
                existing_campaign = self._find_existing_campaign_for_cases(session, case_ids)
                if existing_campaign:
                    # Add any unlinked cases to the existing campaign
                    newly_linked = self._link_cases_to_campaign(session, existing_campaign, case_ids)
                    cases_linked += newly_linked
                    continue

                # Create a new campaign
                campaign_id = self._create_campaign(
                    session,
                    name=f"Shared Wallet: {address[:16]}…",
                    description=(
                        f"Investigations linked by shared cryptocurrency wallet "
                        f"{address}. {len(case_ids)} cases identified."
                    ),
                    taxonomy_labels=["wallet_cluster"],
                )
                linked = self._link_cases_to_campaign(session, campaign_id, case_ids)
                campaigns_created += 1
                cases_linked += linked
                logger.info(
                    "Created wallet campaign %s for address %s (%d cases)",
                    campaign_id,
                    address[:20],
                    linked,
                )

            session.commit()

        return {"campaigns_created": campaigns_created, "cases_linked": cases_linked}

    def correlate_by_infrastructure(self) -> dict[str, int]:
        """Link investigations sharing the same hosting IP or ASN.

        Examines ``ecx_enrichments`` and ``site_scans`` metadata for
        IP addresses and ASNs, then clusters cases on shared
        infrastructure.

        Returns:
            Dict with ``campaigns_created`` and ``cases_linked`` counts.
        """

        campaigns_created = 0
        cases_linked = 0

        with self._session_factory() as session:
            ip_clusters = self._find_ip_clusters(session)

            for ip_addr, case_ids in ip_clusters.items():
                if len(case_ids) < _MIN_CLUSTER_SIZE:
                    continue

                existing = self._find_existing_campaign_for_cases(session, case_ids)
                if existing:
                    newly_linked = self._link_cases_to_campaign(session, existing, case_ids)
                    cases_linked += newly_linked
                    continue

                campaign_id = self._create_campaign(
                    session,
                    name=f"Shared Infrastructure: {ip_addr}",
                    description=(
                        f"Investigations hosted on the same IP {ip_addr}. " f"{len(case_ids)} cases identified."
                    ),
                    taxonomy_labels=["infrastructure_cluster"],
                )
                linked = self._link_cases_to_campaign(session, campaign_id, case_ids)
                campaigns_created += 1
                cases_linked += linked
                logger.info(
                    "Created infrastructure campaign %s for IP %s (%d cases)",
                    campaign_id,
                    ip_addr,
                    linked,
                )

            session.commit()

        return {"campaigns_created": campaigns_created, "cases_linked": cases_linked}

    def correlate_by_brand(self, *, window_days: int = _BRAND_WINDOW_DAYS) -> dict[str, int]:
        """Link investigations impersonating the same brand in a time window.

        Examines eCX enrichment data for brand labels and groups cases
        that target the same brand within ``window_days``.

        Args:
            window_days: Time window for grouping brand impersonation.

        Returns:
            Dict with ``campaigns_created`` and ``cases_linked`` counts.
        """

        campaigns_created = 0
        cases_linked = 0
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        with self._session_factory() as session:
            brand_clusters = self._find_brand_clusters(session, cutoff=cutoff)

            for brand, case_ids in brand_clusters.items():
                if len(case_ids) < _MIN_CLUSTER_SIZE:
                    continue

                existing = self._find_existing_campaign_for_cases(session, case_ids)
                if existing:
                    newly_linked = self._link_cases_to_campaign(session, existing, case_ids)
                    cases_linked += newly_linked
                    continue

                campaign_id = self._create_campaign(
                    session,
                    name=f"Brand Impersonation: {brand}",
                    description=(
                        f"Coordinated phishing wave impersonating {brand}. "
                        f"{len(case_ids)} cases detected within {window_days} days."
                    ),
                    taxonomy_labels=["brand_impersonation", brand.lower()],
                )
                linked = self._link_cases_to_campaign(session, campaign_id, case_ids)
                campaigns_created += 1
                cases_linked += linked
                logger.info(
                    "Created brand campaign %s for %s (%d cases)",
                    campaign_id,
                    brand,
                    linked,
                )

            session.commit()

        return {"campaigns_created": campaigns_created, "cases_linked": cases_linked}

    # ------------------------------------------------------------------
    # Cluster discovery helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_wallet_clusters(session: Session) -> dict[str, set[str]]:
        """Find wallet addresses appearing in 2+ scans with linked cases.

        Returns:
            Mapping of wallet_address → set of case_ids.
        """
        from ssi.store.sql import harvested_wallets, site_scans

        # Join wallets → scans to get case_ids, group by address
        stmt = (
            sa.select(
                harvested_wallets.c.wallet_address,
                site_scans.c.case_id,
            )
            .select_from(
                harvested_wallets.join(
                    site_scans,
                    harvested_wallets.c.scan_id == site_scans.c.scan_id,
                )
            )
            .where(site_scans.c.case_id.isnot(None))
        )
        rows = session.execute(stmt).fetchall()

        clusters: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            clusters[row.wallet_address].add(row.case_id)

        # Keep only addresses with 2+ cases
        return {addr: cases for addr, cases in clusters.items() if len(cases) >= _MIN_CLUSTER_SIZE}

    @staticmethod
    def _find_ip_clusters(session: Session) -> dict[str, set[str]]:
        """Find IP addresses shared across 2+ investigations.

        Looks for IP data in eCX enrichments (phish and malicious-ip
        modules store IP information) and scan metadata.

        Returns:
            Mapping of IP address → set of case_ids.
        """
        from ssi.store.sql import ecx_enrichments

        clusters: dict[str, set[str]] = defaultdict(set)

        # Strategy 1: eCX enrichment data contains IPs
        stmt = sa.select(
            ecx_enrichments.c.scan_id,
            ecx_enrichments.c.ecx_data,
            ecx_enrichments.c.query_module,
        ).where(ecx_enrichments.c.query_module.in_(["phish", "malicious-ip"]))
        enrichment_rows = session.execute(stmt).fetchall()

        # Map scan_id → case_id
        scan_ids = {row.scan_id for row in enrichment_rows}
        case_map = _build_scan_case_map(session, scan_ids) if scan_ids else {}

        for row in enrichment_rows:
            case_id = case_map.get(row.scan_id)
            if not case_id:
                continue

            ecx_data = _parse_json(row.ecx_data)
            if not isinstance(ecx_data, dict):
                continue

            # Extract IP from phish records (ip field) or malicious-ip records
            ips: list[str] = []
            if row.query_module == "malicious-ip":
                ip_val = ecx_data.get("ip")
                if ip_val:
                    ips.append(ip_val)
            elif row.query_module == "phish":
                # phish records may have an ip list
                ip_val = ecx_data.get("ip")
                if isinstance(ip_val, list):
                    ips.extend(ip_val)
                elif isinstance(ip_val, str) and ip_val:
                    ips.append(ip_val)

            for ip in ips:
                clusters[ip].add(case_id)

        return {ip: cases for ip, cases in clusters.items() if len(cases) >= _MIN_CLUSTER_SIZE}

    @staticmethod
    def _find_brand_clusters(
        session: Session,
        *,
        cutoff: datetime,
    ) -> dict[str, set[str]]:
        """Find brand labels shared across 2+ recent investigations.

        Uses eCX enrichment data (phish module stores brand) and scan
        metadata to identify coordinated brand impersonation.

        Args:
            cutoff: Only consider enrichments queried after this time.

        Returns:
            Mapping of brand name → set of case_ids.
        """
        from ssi.store.sql import ecx_enrichments

        clusters: dict[str, set[str]] = defaultdict(set)

        stmt = sa.select(
            ecx_enrichments.c.scan_id,
            ecx_enrichments.c.ecx_data,
        ).where(
            ecx_enrichments.c.query_module == "phish",
            ecx_enrichments.c.queried_at >= cutoff,
        )
        rows = session.execute(stmt).fetchall()

        scan_ids = {row.scan_id for row in rows}
        case_map = _build_scan_case_map(session, scan_ids) if scan_ids else {}

        for row in rows:
            case_id = case_map.get(row.scan_id)
            if not case_id:
                continue

            ecx_data = _parse_json(row.ecx_data)
            if not isinstance(ecx_data, dict):
                continue

            brand = ecx_data.get("brand")
            if brand and isinstance(brand, str):
                # Normalize brand for consistent grouping
                clusters[brand.strip().title()].add(case_id)

        return {brand: cases for brand, cases in clusters.items() if len(cases) >= _MIN_CLUSTER_SIZE}

    # ------------------------------------------------------------------
    # Campaign CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _create_campaign(
        session: Session,
        *,
        name: str,
        description: str,
        taxonomy_labels: list[str],
        origin: str = "ssi_correlation",
    ) -> str:
        """Insert a new campaign row into core's ``threat_campaigns`` table.

        Args:
            session: Active DB session.
            name: Campaign display name (truncated to 60 chars).
            description: Human-readable description.
            taxonomy_labels: Classification labels for the campaign.
            origin: Origin source identifier.

        Returns:
            The generated ``campaign_id``.
        """
        import json

        from ssi.store.sql import threat_campaigns

        campaign_id = str(uuid4())
        now = datetime.now(UTC)

        # Truncate name to 60 chars per S1-27; preserve original in metadata
        display_name = name[:60] if len(name) > 60 else name
        metadata = {"original_label": name, "taxonomy_labels": taxonomy_labels}

        session.execute(
            sa.insert(threat_campaigns).values(
                campaign_id=campaign_id,
                name=display_name,
                description=description,
                origin=origin,
                status="emerging",
                metadata=json.dumps(metadata),
                created_by="ssi_correlator",
                created_at=now,
                updated_at=now,
            )
        )
        return campaign_id

    @staticmethod
    def _find_existing_campaign_for_cases(
        session: Session,
        case_ids: set[str],
    ) -> str | None:
        """Check if any of the given cases already belong to a threat campaign.

        Looks up ``threat_campaign_cases`` for existing links.

        Args:
            session: Active DB session.
            case_ids: Cases to look up.

        Returns:
            The ``campaign_id`` if found, else ``None``.
        """
        from ssi.store.sql import threat_campaign_cases

        stmt = (
            sa.select(threat_campaign_cases.c.campaign_id)
            .where(threat_campaign_cases.c.case_id.in_(list(case_ids)))
            .limit(1)
        )
        row = session.execute(stmt).first()
        return row.campaign_id if row else None

    @staticmethod
    def _link_cases_to_campaign(
        session: Session,
        campaign_id: str,
        case_ids: set[str],
    ) -> int:
        """Insert rows into ``threat_campaign_cases`` for unlinked cases.

        Args:
            session: Active DB session.
            campaign_id: Target campaign.
            case_ids: Cases to link.

        Returns:
            Number of cases actually linked.
        """
        from ssi.store.sql import threat_campaign_cases

        now = datetime.now(UTC)
        linked = 0

        # Find which case_ids are already linked to this campaign
        existing_stmt = sa.select(threat_campaign_cases.c.case_id).where(
            threat_campaign_cases.c.campaign_id == campaign_id,
            threat_campaign_cases.c.case_id.in_(list(case_ids)),
        )
        already_linked = {r.case_id for r in session.execute(existing_stmt).fetchall()}

        for cid in case_ids:
            if cid in already_linked:
                continue
            session.execute(
                sa.insert(threat_campaign_cases).values(
                    campaign_id=campaign_id,
                    case_id=cid,
                    linked_at=now,
                    linked_by="ssi_correlator",
                    link_reason="auto_correlation",
                )
            )
            linked += 1

        return linked


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _parse_json(value: Any) -> Any:
    """Parse a JSON value that may be a string (SQLite) or a dict (PostgreSQL).

    Args:
        value: Raw value from the database row.

    Returns:
        Parsed Python object.
    """
    import json

    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    return value


def _build_scan_case_map(session: Session, scan_ids: set[str]) -> dict[str, str]:
    """Build a mapping of scan_id → case_id for the given scans.

    Args:
        session: Active DB session.
        scan_ids: Set of scan IDs to look up.

    Returns:
        Dict mapping scan_id to case_id (only scans with a case).
    """
    from ssi.store.sql import site_scans

    stmt = sa.select(site_scans.c.scan_id, site_scans.c.case_id).where(
        site_scans.c.scan_id.in_(list(scan_ids)),
        site_scans.c.case_id.isnot(None),
    )
    rows = session.execute(stmt).fetchall()
    return {row.scan_id: row.case_id for row in rows}


def get_correlator() -> CampaignCorrelator | None:
    """Return a configured :class:`CampaignCorrelator` or ``None``.

    Returns:
        A ready-to-use correlator, or ``None`` when eCX is disabled
        or the database is not available.
    """
    from ssi.store.sql import build_session_factory

    try:
        session_factory = build_session_factory()
        return CampaignCorrelator(session_factory)
    except Exception:
        logger.warning("Cannot create CampaignCorrelator — database unavailable")
        return None
