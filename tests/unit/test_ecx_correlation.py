"""Unit tests for the eCrimeX Phase 3C campaign correlation service.

Covers:
- Wallet-based campaign creation: cases sharing wallets → campaign
- IP/ASN-based infrastructure clustering: cases sharing IPs → campaign
- Brand impersonation pattern detection: same brand → campaign
- Deduplication: cases already in a campaign are not re-clustered
- Campaign CRUD helpers: create, find existing, link cases
- correlate_all: runs all strategies and returns summary
- Error isolation: one strategy failure does not block others
- get_correlator factory
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_db() -> tuple[sa.Engine, Any]:
    """Create an in-memory SQLite DB with both SSI and CORE_METADATA tables.

    Returns:
        Tuple of (engine, session_factory).
    """
    from ssi.store import sql as sql_schema

    engine = sa.create_engine("sqlite:///:memory:")

    # Create SSI tables (site_scans, harvested_wallets, ecx_enrichments, etc.)
    sql_schema.METADATA.create_all(engine)

    # Create core tables (campaigns, cases, etc.)
    sql_schema.CORE_METADATA.create_all(engine)

    factory = sessionmaker(bind=engine)
    return engine, factory


def _insert_scan(session: Any, scan_id: str, case_id: str | None = None) -> None:
    """Insert a site_scans row."""
    from ssi.store.sql import site_scans

    session.execute(
        sa.insert(site_scans).values(
            scan_id=scan_id,
            case_id=case_id,
            url="https://example.com",
            scan_type="passive",
            status="completed",
        )
    )


def _insert_case(session: Any, case_id: str, campaign_id: str | None = None) -> None:
    """Insert a case row in CORE_METADATA tables."""
    from ssi.store.sql import cases

    session.execute(
        sa.insert(cases).values(
            case_id=case_id,
            campaign_id=campaign_id,
            dataset="ssi",
            source_type="ssi_investigation",
            raw_text_sha256=f"sha_{case_id}",
            status="open",
        )
    )


def _insert_wallet(
    session: Any,
    wallet_id: str,
    scan_id: str,
    address: str,
    token_symbol: str = "BTC",
    network_short: str = "btc",
) -> None:
    """Insert a harvested_wallets row."""
    from ssi.store.sql import harvested_wallets

    session.execute(
        sa.insert(harvested_wallets).values(
            wallet_id=wallet_id,
            scan_id=scan_id,
            token_symbol=token_symbol,
            network_short=network_short,
            wallet_address=address,
            source="js",
        )
    )


def _insert_enrichment(
    session: Any,
    scan_id: str,
    query_module: str,
    ecx_data: dict[str, Any],
    queried_at: datetime | None = None,
) -> None:
    """Insert an ecx_enrichments row."""
    from ssi.store.sql import ecx_enrichments

    session.execute(
        sa.insert(ecx_enrichments).values(
            enrichment_id=str(uuid4()),
            scan_id=scan_id,
            query_module=query_module,
            query_value=ecx_data.get("url", ecx_data.get("ip", "unknown")),
            ecx_data=json.dumps(ecx_data) if not isinstance(ecx_data, str) else ecx_data,
            queried_at=queried_at or datetime.now(UTC),
        )
    )


# ---------------------------------------------------------------------------
# Wallet-based correlation
# ---------------------------------------------------------------------------


class TestWalletCorrelation:
    """Test wallet-based campaign creation."""

    def test_shared_wallet_creates_campaign(self) -> None:
        """Two cases sharing a wallet should form a campaign."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            # Create 2 scans with linked cases
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_scan(session, "scan-2", case_id="case-2")
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")

            # Both scans share the same wallet address
            _insert_wallet(session, "w1", "scan-1", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            _insert_wallet(session, "w2", "scan-2", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            session.commit()

        result = correlator.correlate_by_wallet()
        assert result["campaigns_created"] == 1
        assert result["cases_linked"] == 2

        # Verify cases are linked to the campaign
        with factory() as session:
            from ssi.store.sql import cases

            rows = session.execute(
                sa.select(cases.c.case_id, cases.c.campaign_id).where(cases.c.case_id.in_(["case-1", "case-2"]))
            ).fetchall()
            campaign_ids = {r.campaign_id for r in rows}
            assert len(campaign_ids) == 1
            assert None not in campaign_ids

    def test_single_wallet_no_campaign(self) -> None:
        """A wallet in only one scan should not create a campaign."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_case(session, "case-1")
            _insert_wallet(session, "w1", "scan-1", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            session.commit()

        result = correlator.correlate_by_wallet()
        assert result["campaigns_created"] == 0
        assert result["cases_linked"] == 0

    def test_existing_campaign_links_new_cases(self) -> None:
        """Cases already in a campaign should not create a duplicate."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        existing_campaign_id = str(uuid4())

        with factory() as session:
            # Pre-create a campaign and link case-1
            from ssi.store.sql import campaigns

            session.execute(
                sa.insert(campaigns).values(
                    campaign_id=existing_campaign_id,
                    name="Existing Campaign",
                    status="active",
                )
            )
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_scan(session, "scan-2", case_id="case-2")
            _insert_case(session, "case-1", campaign_id=existing_campaign_id)
            _insert_case(session, "case-2")

            # Shared wallet
            _insert_wallet(session, "w1", "scan-1", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
            _insert_wallet(session, "w2", "scan-2", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
            session.commit()

        result = correlator.correlate_by_wallet()
        assert result["campaigns_created"] == 0
        assert result["cases_linked"] >= 1  # case-2 linked to existing campaign

    def test_no_case_id_skipped(self) -> None:
        """Scans without case_ids should not participate in clustering."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_scan(session, "scan-1", case_id=None)  # No case
            _insert_scan(session, "scan-2", case_id=None)  # No case
            _insert_wallet(session, "w1", "scan-1", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            _insert_wallet(session, "w2", "scan-2", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            session.commit()

        result = correlator.correlate_by_wallet()
        assert result["campaigns_created"] == 0

    def test_multiple_wallet_clusters(self) -> None:
        """Multiple distinct wallet clusters create separate campaigns."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            for i in range(1, 5):
                _insert_scan(session, f"scan-{i}", case_id=f"case-{i}")
                _insert_case(session, f"case-{i}")

            # Cluster 1: cases 1,2 share wallet A
            _insert_wallet(session, "w1", "scan-1", "walletAAAA")
            _insert_wallet(session, "w2", "scan-2", "walletAAAA")
            # Cluster 2: cases 3,4 share wallet B
            _insert_wallet(session, "w3", "scan-3", "walletBBBB")
            _insert_wallet(session, "w4", "scan-4", "walletBBBB")
            session.commit()

        result = correlator.correlate_by_wallet()
        assert result["campaigns_created"] == 2
        assert result["cases_linked"] == 4


# ---------------------------------------------------------------------------
# IP/ASN-based infrastructure clustering
# ---------------------------------------------------------------------------


class TestInfrastructureCorrelation:
    """Test IP-based campaign creation from eCX enrichment data."""

    def test_shared_ip_creates_campaign(self) -> None:
        """Two investigations linked to the same IP → campaign."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_scan(session, "scan-2", case_id="case-2")
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")

            # phish enrichments with an IP field
            _insert_enrichment(session, "scan-1", "phish", {"ip": ["192.0.2.1"], "url": "https://a.com"})
            _insert_enrichment(session, "scan-2", "phish", {"ip": ["192.0.2.1"], "url": "https://b.com"})
            session.commit()

        result = correlator.correlate_by_infrastructure()
        assert result["campaigns_created"] == 1
        assert result["cases_linked"] == 2

    def test_malicious_ip_module_creates_campaign(self) -> None:
        """Two malicious-ip enrichments with the same IP → campaign."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_scan(session, "scan-2", case_id="case-2")
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")

            _insert_enrichment(session, "scan-1", "malicious-ip", {"ip": "10.0.0.5"})
            _insert_enrichment(session, "scan-2", "malicious-ip", {"ip": "10.0.0.5"})
            session.commit()

        result = correlator.correlate_by_infrastructure()
        assert result["campaigns_created"] == 1
        assert result["cases_linked"] == 2

    def test_unique_ips_no_campaign(self) -> None:
        """Investigations with different IPs should not cluster."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_scan(session, "scan-2", case_id="case-2")
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")

            _insert_enrichment(session, "scan-1", "phish", {"ip": ["192.0.2.1"], "url": "https://a.com"})
            _insert_enrichment(session, "scan-2", "phish", {"ip": ["198.51.100.1"], "url": "https://b.com"})
            session.commit()

        result = correlator.correlate_by_infrastructure()
        assert result["campaigns_created"] == 0


# ---------------------------------------------------------------------------
# Brand impersonation correlation
# ---------------------------------------------------------------------------


class TestBrandCorrelation:
    """Test brand-based campaign creation."""

    def test_shared_brand_creates_campaign(self) -> None:
        """Two phish enrichments with the same brand → campaign."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_scan(session, "scan-2", case_id="case-2")
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")

            now = datetime.now(UTC)
            _insert_enrichment(
                session,
                "scan-1",
                "phish",
                {"brand": "ExampleBank", "url": "https://phish1.com"},
                queried_at=now,
            )
            _insert_enrichment(
                session,
                "scan-2",
                "phish",
                {"brand": "ExampleBank", "url": "https://phish2.com"},
                queried_at=now,
            )
            session.commit()

        result = correlator.correlate_by_brand(window_days=30)
        assert result["campaigns_created"] == 1
        assert result["cases_linked"] == 2

    def test_brand_normalization(self) -> None:
        """Brands with different casing should still cluster together."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_scan(session, "scan-2", case_id="case-2")
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")

            now = datetime.now(UTC)
            _insert_enrichment(
                session,
                "scan-1",
                "phish",
                {"brand": "example bank", "url": "https://phish1.com"},
                queried_at=now,
            )
            _insert_enrichment(
                session,
                "scan-2",
                "phish",
                {"brand": "EXAMPLE BANK", "url": "https://phish2.com"},
                queried_at=now,
            )
            session.commit()

        result = correlator.correlate_by_brand(window_days=30)
        assert result["campaigns_created"] == 1

    def test_old_enrichments_outside_window(self) -> None:
        """Enrichments outside the time window should not cluster."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_scan(session, "scan-2", case_id="case-2")
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")

            old = datetime.now(UTC) - timedelta(days=60)
            _insert_enrichment(
                session,
                "scan-1",
                "phish",
                {"brand": "OldBank", "url": "https://old1.com"},
                queried_at=old,
            )
            _insert_enrichment(
                session,
                "scan-2",
                "phish",
                {"brand": "OldBank", "url": "https://old2.com"},
                queried_at=old,
            )
            session.commit()

        result = correlator.correlate_by_brand(window_days=30)
        assert result["campaigns_created"] == 0

    def test_different_brands_no_campaign(self) -> None:
        """Different brands should not form a campaign."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_scan(session, "scan-1", case_id="case-1")
            _insert_scan(session, "scan-2", case_id="case-2")
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")

            now = datetime.now(UTC)
            _insert_enrichment(
                session,
                "scan-1",
                "phish",
                {"brand": "BankA", "url": "https://a.com"},
                queried_at=now,
            )
            _insert_enrichment(
                session,
                "scan-2",
                "phish",
                {"brand": "BankB", "url": "https://b.com"},
                queried_at=now,
            )
            session.commit()

        result = correlator.correlate_by_brand(window_days=30)
        assert result["campaigns_created"] == 0


# ---------------------------------------------------------------------------
# correlate_all: combined strategy runner
# ---------------------------------------------------------------------------


class TestCorrelateAll:
    """Test the combined correlate_all method."""

    def test_correlate_all_runs_all_strategies(self) -> None:
        """All three strategies should run and return results."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            # Set up data for wallet and brand correlation
            for i in range(1, 5):
                _insert_scan(session, f"scan-{i}", case_id=f"case-{i}")
                _insert_case(session, f"case-{i}")

            # Wallet cluster: cases 1,2
            _insert_wallet(session, "w1", "scan-1", "shared_wallet_addr")
            _insert_wallet(session, "w2", "scan-2", "shared_wallet_addr")

            # Brand cluster: cases 3,4
            now = datetime.now(UTC)
            _insert_enrichment(
                session,
                "scan-3",
                "phish",
                {"brand": "TestBrand", "url": "https://t1.com"},
                queried_at=now,
            )
            _insert_enrichment(
                session,
                "scan-4",
                "phish",
                {"brand": "TestBrand", "url": "https://t2.com"},
                queried_at=now,
            )
            session.commit()

        result = correlator.correlate_all()
        assert "wallet" in result
        assert "infrastructure" in result
        assert "brand" in result
        assert result["wallet"]["campaigns_created"] == 1
        assert result["brand"]["campaigns_created"] == 1
        total_campaigns = sum(result[k]["campaigns_created"] for k in ["wallet", "infrastructure", "brand"])
        assert total_campaigns == 2

    def test_correlate_all_isolates_errors(self) -> None:
        """A failure in one strategy should not block others."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with patch.object(correlator, "correlate_by_wallet", side_effect=RuntimeError("boom")):
            result = correlator.correlate_all()

        assert len(result["errors"]) == 1
        assert "wallet" in result["errors"][0]
        assert result["wallet"]["campaigns_created"] == 0
        # Other strategies still ran
        assert "infrastructure" in result
        assert "brand" in result

    def test_correlate_all_empty_db(self) -> None:
        """With no data, all strategies return zero."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        result = correlator.correlate_all()
        for key in ["wallet", "infrastructure", "brand"]:
            assert result[key]["campaigns_created"] == 0
            assert result[key]["cases_linked"] == 0
        assert result["errors"] == []


# ---------------------------------------------------------------------------
# Campaign CRUD helpers
# ---------------------------------------------------------------------------


class TestCampaignCRUD:
    """Test the internal campaign creation and linking helpers."""

    def test_create_campaign(self) -> None:
        """Create a campaign and verify it exists."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            campaign_id = correlator._create_campaign(
                session,
                name="Test Campaign",
                description="A test campaign",
                taxonomy_labels=["test"],
            )
            session.commit()

        with factory() as session:
            from ssi.store.sql import threat_campaigns

            row = session.execute(
                sa.select(threat_campaigns).where(threat_campaigns.c.campaign_id == campaign_id)
            ).first()
            assert row is not None
            assert row.name == "Test Campaign"

    def test_link_cases_to_campaign(self) -> None:
        """Link multiple cases to a campaign."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        campaign_id = str(uuid4())

        with factory() as session:
            from ssi.store.sql import campaigns

            session.execute(
                sa.insert(campaigns).values(
                    campaign_id=campaign_id,
                    name="Link Test",
                    status="active",
                )
            )
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")
            session.commit()

        with factory() as session:
            linked = correlator._link_cases_to_campaign(session, campaign_id, {"case-1", "case-2"})
            session.commit()

        assert linked == 2

        with factory() as session:
            from ssi.store.sql import cases

            rows = session.execute(
                sa.select(cases.c.campaign_id).where(cases.c.case_id.in_(["case-1", "case-2"]))
            ).fetchall()
            assert all(r.campaign_id == campaign_id for r in rows)

    def test_link_cases_idempotent(self) -> None:
        """Linking already-linked cases should not re-count."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        campaign_id = str(uuid4())

        with factory() as session:
            from ssi.store.sql import campaigns

            session.execute(
                sa.insert(campaigns).values(
                    campaign_id=campaign_id,
                    name="Idempotent Test",
                    status="active",
                )
            )
            _insert_case(session, "case-1", campaign_id=campaign_id)
            session.commit()

        with factory() as session:
            linked = correlator._link_cases_to_campaign(session, campaign_id, {"case-1"})
            session.commit()

        assert linked == 0

    def test_find_existing_campaign_for_cases(self) -> None:
        """Find an existing campaign that one of the cases belongs to."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        campaign_id = str(uuid4())

        with factory() as session:
            from ssi.store.sql import campaigns

            session.execute(
                sa.insert(campaigns).values(
                    campaign_id=campaign_id,
                    name="Pre-existing",
                    status="active",
                )
            )
            _insert_case(session, "case-1", campaign_id=campaign_id)
            _insert_case(session, "case-2")
            session.commit()

        with factory() as session:
            found = correlator._find_existing_campaign_for_cases(session, {"case-1", "case-2"})
            assert found == campaign_id

    def test_find_existing_campaign_returns_none(self) -> None:
        """Return None when no case has a campaign."""
        from ssi.ecx.correlation import CampaignCorrelator

        _, factory = _build_db()
        correlator = CampaignCorrelator(factory)

        with factory() as session:
            _insert_case(session, "case-1")
            _insert_case(session, "case-2")
            session.commit()

        with factory() as session:
            found = correlator._find_existing_campaign_for_cases(session, {"case-1", "case-2"})
            assert found is None


# ---------------------------------------------------------------------------
# get_correlator factory
# ---------------------------------------------------------------------------


class TestGetCorrelatorFactory:
    """Test the module-level get_correlator factory."""

    def test_returns_correlator_when_db_available(self) -> None:
        """Should return a CampaignCorrelator when the DB is available."""
        from ssi.ecx.correlation import CampaignCorrelator, get_correlator

        with patch("ssi.store.sql.build_session_factory") as mock_factory:
            mock_factory.return_value = MagicMock()
            correlator = get_correlator()
            assert isinstance(correlator, CampaignCorrelator)

    def test_returns_none_when_db_unavailable(self) -> None:
        """Should return None when the database is not available."""
        from ssi.ecx.correlation import get_correlator

        with patch("ssi.store.sql.build_session_factory", side_effect=RuntimeError("no db")):
            correlator = get_correlator()
            assert correlator is None
