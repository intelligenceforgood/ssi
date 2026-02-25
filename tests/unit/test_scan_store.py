"""Unit tests for ScanStore CRUD operations.

Tests exercise all four tables (site_scans, harvested_wallets,
agent_sessions, pii_exposures) using an in-memory SQLite database.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from ssi.store.scan_store import ScanStore
from ssi.store.sql import METADATA


@pytest.fixture()
def store(tmp_path):
    """Return a ScanStore backed by a temporary SQLite database."""
    db_path = tmp_path / "test_scan.db"
    return ScanStore(db_path=db_path)


# ------------------------------------------------------------------
# site_scans
# ------------------------------------------------------------------


class TestSiteScansCRUD:
    """Tests for site_scans table operations."""

    def test_create_scan(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com", scan_type="full", domain="scam.example.com")
        assert scan_id
        assert len(scan_id) == 36  # UUID4 format

    def test_get_scan(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com", domain="scam.example.com")
        row = store.get_scan(scan_id)
        assert row is not None
        assert row["url"] == "https://scam.example.com"
        assert row["domain"] == "scam.example.com"
        assert row["status"] == "running"
        assert row["scan_type"] == "passive"

    def test_get_scan_not_found(self, store: ScanStore):
        assert store.get_scan("nonexistent") is None

    def test_update_scan(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        store.update_scan(scan_id, status="completed", risk_score=7.5)
        row = store.get_scan(scan_id)
        assert row["status"] == "completed"

    def test_complete_scan(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        store.complete_scan(
            scan_id,
            status="completed",
            risk_score=8.2,
            wallet_count=3,
            duration_seconds=42.5,
            evidence_path="/tmp/evidence",
        )
        row = store.get_scan(scan_id)
        assert row["status"] == "completed"
        assert row["wallet_count"] == 3
        assert row["evidence_path"] == "/tmp/evidence"
        assert row["completed_at"] is not None

    def test_list_scans(self, store: ScanStore):
        store.create_scan(url="https://a.com", domain="a.com")
        store.create_scan(url="https://b.com", domain="b.com")
        store.create_scan(url="https://a.com/page2", domain="a.com")

        all_scans = store.list_scans()
        assert len(all_scans) == 3

        a_scans = store.list_scans(domain="a.com")
        assert len(a_scans) == 2

    def test_list_scans_filter_status(self, store: ScanStore):
        sid1 = store.create_scan(url="https://a.com")
        sid2 = store.create_scan(url="https://b.com")
        store.update_scan(sid1, status="completed")

        running = store.list_scans(status="running")
        assert len(running) == 1
        assert running[0]["scan_id"] == sid2


# ------------------------------------------------------------------
# harvested_wallets
# ------------------------------------------------------------------


class TestHarvestedWalletsCRUD:
    """Tests for harvested_wallets table operations."""

    def test_add_wallet(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        wallet_id = store.add_wallet(
            scan_id=scan_id,
            token_symbol="USDT",
            network_short="trx",
            wallet_address="TXyz123abc",
            source="js",
            confidence=0.95,
        )
        assert wallet_id
        wallets = store.get_wallets(scan_id)
        assert len(wallets) == 1
        assert wallets[0]["token_symbol"] == "USDT"
        assert wallets[0]["wallet_address"] == "TXyz123abc"

    def test_add_wallet_upsert_on_conflict(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        store.add_wallet(
            scan_id=scan_id,
            token_symbol="USDT",
            network_short="trx",
            wallet_address="TXyz123abc",
            confidence=0.5,
            source="js",
        )
        # Same address — should upsert and update confidence
        store.add_wallet(
            scan_id=scan_id,
            token_symbol="USDT",
            network_short="trx",
            wallet_address="TXyz123abc",
            confidence=0.95,
            source="llm",
        )
        wallets = store.get_wallets(scan_id)
        assert len(wallets) == 1
        # confidence should be the updated value
        assert float(wallets[0]["confidence"]) == pytest.approx(0.95, abs=0.01)

    def test_add_wallets_bulk(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        wallet_data = [
            {"token_symbol": "USDT", "network_short": "trx", "wallet_address": "TAddr1"},
            {"token_symbol": "BTC", "network_short": "btc", "wallet_address": "bc1qAddr2"},
            {"token_symbol": "ETH", "network_short": "eth", "wallet_address": "0xAddr3"},
        ]
        count = store.add_wallets_bulk(scan_id, wallet_data)
        assert count == 3
        wallets = store.get_wallets(scan_id)
        assert len(wallets) == 3

    def test_add_wallets_bulk_empty(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        assert store.add_wallets_bulk(scan_id, []) == 0

    def test_search_wallets_by_address(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        store.add_wallet(
            scan_id=scan_id,
            token_symbol="USDT",
            network_short="trx",
            wallet_address="TSearchAddr",
        )
        results = store.search_wallets(address="TSearchAddr")
        assert len(results) == 1
        assert results[0]["wallet_address"] == "TSearchAddr"

    def test_search_wallets_by_token(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        store.add_wallet(scan_id=scan_id, token_symbol="BTC", network_short="btc", wallet_address="bc1qA")
        store.add_wallet(scan_id=scan_id, token_symbol="ETH", network_short="eth", wallet_address="0xB")

        btc_results = store.search_wallets(token_symbol="BTC")
        assert len(btc_results) == 1
        assert btc_results[0]["token_symbol"] == "BTC"

    # --- deduplication tests ---

    def test_search_wallets_dedup_collapses_same_address(self, store: ScanStore):
        """Same wallet harvested across two scans should yield one row when deduplicate=True."""
        scan1 = store.create_scan(url="https://scam-a.example.com")
        scan2 = store.create_scan(url="https://scam-a.example.com")
        for sid in (scan1, scan2):
            store.add_wallet(
                scan_id=sid,
                token_symbol="ETH",
                network_short="eth",
                wallet_address="0xDEAD",
                confidence=0.8 if sid == scan1 else 0.95,
                site_url="https://scam-a.example.com",
            )
        results = store.search_wallets(deduplicate=True)
        assert len(results) == 1
        row = results[0]
        assert row["wallet_address"] == "0xDEAD"
        assert row["seen_count"] == 2

    def test_search_wallets_dedup_aggregates(self, store: ScanStore):
        """Dedup should return max confidence, first/last seen timestamps."""
        from datetime import timedelta

        scan1 = store.create_scan(url="https://scam.example.com")
        scan2 = store.create_scan(url="https://scam.example.com")

        early = datetime(2025, 1, 1, tzinfo=timezone.utc)
        late = datetime(2025, 6, 1, tzinfo=timezone.utc)

        store.add_wallet(
            scan_id=scan1, token_symbol="BTC", network_short="btc",
            wallet_address="bc1qXYZ", confidence=0.5, harvested_at=early,
        )
        store.add_wallet(
            scan_id=scan2, token_symbol="BTC", network_short="btc",
            wallet_address="bc1qXYZ", confidence=0.9, harvested_at=late,
        )

        results = store.search_wallets(deduplicate=True)
        assert len(results) == 1
        row = results[0]
        assert float(row["confidence"]) == pytest.approx(0.9)  # max
        # SQLite may strip tzinfo on aggregated datetimes; compare naively
        assert row["first_seen_at"].replace(tzinfo=None) == early.replace(tzinfo=None)
        assert row["last_seen_at"].replace(tzinfo=None) == late.replace(tzinfo=None)

    def test_search_wallets_dedup_false_returns_all_rows(self, store: ScanStore):
        """With deduplicate=False, duplicate wallet rows should remain."""
        scan1 = store.create_scan(url="https://scam-a.example.com")
        scan2 = store.create_scan(url="https://scam-a.example.com")
        for sid in (scan1, scan2):
            store.add_wallet(
                scan_id=sid, token_symbol="ETH", network_short="eth",
                wallet_address="0xDEAD",
            )
        results = store.search_wallets(deduplicate=False)
        assert len(results) == 2

    def test_search_wallets_dedup_distinct_addresses_count(self, store: ScanStore):
        """Different addresses should remain separate rows even when dedup is on."""
        scan = store.create_scan(url="https://scam.example.com")
        store.add_wallet(scan_id=scan, token_symbol="ETH", network_short="eth", wallet_address="0xAAA")
        store.add_wallet(scan_id=scan, token_symbol="ETH", network_short="eth", wallet_address="0xBBB")
        results = store.search_wallets(deduplicate=True)
        assert len(results) == 2
        addresses = {r["wallet_address"] for r in results}
        assert addresses == {"0xAAA", "0xBBB"}

    def test_search_wallets_dedup_filter_by_address(self, store: ScanStore):
        """Dedup + address filter should still return the correct aggregated row."""
        scan1 = store.create_scan(url="https://scam.example.com")
        scan2 = store.create_scan(url="https://scam.example.com")
        for sid in (scan1, scan2):
            store.add_wallet(scan_id=sid, token_symbol="ETH", network_short="eth", wallet_address="0xF00")
            store.add_wallet(scan_id=sid, token_symbol="BTC", network_short="btc", wallet_address="bc1other")
        results = store.search_wallets(address="0xF00", deduplicate=True)
        assert len(results) == 1
        assert results[0]["wallet_address"] == "0xF00"
        assert results[0]["seen_count"] == 2

    def test_search_wallets_dedup_default_is_true(self, store: ScanStore):
        """search_wallets should deduplicate by default."""
        scan1 = store.create_scan(url="https://a.example.com")
        scan2 = store.create_scan(url="https://a.example.com")
        for sid in (scan1, scan2):
            store.add_wallet(scan_id=sid, token_symbol="ETH", network_short="eth", wallet_address="0xDE")
        # No explicit deduplicate= argument → should default to True
        results = store.search_wallets()
        assert len(results) == 1


# ------------------------------------------------------------------
# agent_sessions
# ------------------------------------------------------------------


class TestAgentSessionsCRUD:
    """Tests for agent_sessions table operations."""

    def test_log_agent_action(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        session_id = store.log_agent_action(
            scan_id=scan_id,
            state="LOAD_SITE",
            sequence=0,
            action_type="navigate",
            page_url="https://scam.example.com",
        )
        assert session_id

        actions = store.get_agent_actions(scan_id)
        assert len(actions) == 1
        assert actions[0]["state"] == "LOAD_SITE"
        assert actions[0]["action_type"] == "navigate"

    def test_agent_actions_ordered_by_sequence(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        store.log_agent_action(scan_id=scan_id, state="FILL_REGISTER", sequence=2, action_type="type")
        store.log_agent_action(scan_id=scan_id, state="LOAD_SITE", sequence=0, action_type="navigate")
        store.log_agent_action(scan_id=scan_id, state="FIND_REGISTER", sequence=1, action_type="click")

        actions = store.get_agent_actions(scan_id)
        assert len(actions) == 3
        assert [a["sequence"] for a in actions] == [0, 1, 2]

    def test_log_agent_action_with_llm_metrics(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        store.log_agent_action(
            scan_id=scan_id,
            state="FILL_REGISTER",
            sequence=3,
            action_type="type",
            llm_model="gemini-2.0-flash",
            llm_input_tokens=500,
            llm_output_tokens=150,
            cost_usd=0.00032,
            duration_ms=1200,
        )
        actions = store.get_agent_actions(scan_id)
        assert actions[0]["llm_model"] == "gemini-2.0-flash"
        assert actions[0]["llm_input_tokens"] == 500
        assert actions[0]["llm_output_tokens"] == 150


# ------------------------------------------------------------------
# pii_exposures
# ------------------------------------------------------------------


class TestPIIExposuresCRUD:
    """Tests for pii_exposures table operations."""

    def test_add_pii_exposure(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        exposure_id = store.add_pii_exposure(
            scan_id=scan_id,
            field_type="email",
            field_label="Email Address",
            page_url="https://scam.example.com/register",
            is_required=True,
            was_submitted=True,
        )
        assert exposure_id

        exposures = store.get_pii_exposures(scan_id)
        assert len(exposures) == 1
        assert exposures[0]["field_type"] == "email"
        assert exposures[0]["field_label"] == "Email Address"

    def test_add_pii_exposures_bulk(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        pii_data = [
            {"field_type": "email", "field_label": "Email", "is_required": True},
            {"field_type": "password", "field_label": "Password", "is_required": True},
            {"field_type": "phone", "field_label": "Phone Number", "is_required": False},
        ]
        count = store.add_pii_exposures_bulk(scan_id, pii_data)
        assert count == 3
        exposures = store.get_pii_exposures(scan_id)
        assert len(exposures) == 3

    def test_add_pii_exposures_bulk_empty(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        assert store.add_pii_exposures_bulk(scan_id, []) == 0


# ------------------------------------------------------------------
# _classify_form_field
# ------------------------------------------------------------------


class TestClassifyFormField:
    """Tests for the PII field classification helper."""

    def test_email_by_type(self):
        from ssi.store.scan_store import _classify_form_field

        assert _classify_form_field({"type": "email", "name": "user_email"}) == "email"

    def test_password_by_type(self):
        from ssi.store.scan_store import _classify_form_field

        assert _classify_form_field({"type": "password", "name": "pwd"}) == "password"

    def test_phone_by_name(self):
        from ssi.store.scan_store import _classify_form_field

        assert _classify_form_field({"type": "text", "name": "phone_number"}) == "phone"

    def test_name_by_label(self):
        from ssi.store.scan_store import _classify_form_field

        assert _classify_form_field({"type": "text", "name": "field1", "label": "Full Name"}) == "name"

    def test_financial_by_name(self):
        from ssi.store.scan_store import _classify_form_field

        assert _classify_form_field({"type": "text", "name": "credit_card_number"}) == "financial"

    def test_unknown_field(self):
        from ssi.store.scan_store import _classify_form_field

        assert _classify_form_field({"type": "text", "name": "preferences"}) == "other"


# ------------------------------------------------------------------
# Cross-table: persist_investigation
# ------------------------------------------------------------------


class TestPersistInvestigation:
    """Test the high-level persist_investigation integration method."""

    def test_persist_investigation_minimal(self, store: ScanStore):
        """persist_investigation should work with a minimal InvestigationResult."""
        from ssi.models.investigation import InvestigationResult, InvestigationStatus

        scan_id = store.create_scan(url="https://scam.example.com")
        result = InvestigationResult(url="https://scam.example.com", passive_only=True)
        result.status = InvestigationStatus.COMPLETED
        result.duration_seconds = 12.5

        store.persist_investigation(scan_id, result)

        row = store.get_scan(scan_id)
        assert row["status"] == "completed"

    def test_persist_investigation_wrong_type(self, store: ScanStore):
        scan_id = store.create_scan(url="https://scam.example.com")
        with pytest.raises(TypeError, match="Expected InvestigationResult"):
            store.persist_investigation(scan_id, {"url": "https://scam.example.com"})

    def test_persist_investigation_with_agent_steps(self, store: ScanStore):
        """persist_investigation should bulk-insert agent steps into agent_sessions."""
        from ssi.models.investigation import InvestigationResult, InvestigationStatus

        scan_id = store.create_scan(url="https://scam.example.com")
        result = InvestigationResult(url="https://scam.example.com", passive_only=False)
        result.status = InvestigationStatus.COMPLETED
        result.duration_seconds = 45.0
        result.agent_steps = [
            {
                "step": 1,
                "action": "click",
                "element": 5,
                "value": "Sign In",
                "reasoning": "Clicking login button to proceed",
                "tokens": 1200,
                "duration_ms": 350,
                "error": None,
            },
            {
                "step": 2,
                "action": "type",
                "element": 8,
                "value": "test@example.com",
                "reasoning": "Entering email into form",
                "tokens": 800,
                "duration_ms": 120,
                "error": None,
            },
            {
                "step": 3,
                "action": "click",
                "element": 12,
                "value": "",
                "reasoning": "Submitting form",
                "tokens": 600,
                "duration_ms": 500,
                "error": "timeout",
            },
        ]

        store.persist_investigation(scan_id, result)

        actions = store.get_agent_actions(scan_id)
        assert len(actions) == 3
        assert actions[0]["action_type"] == "click"
        assert actions[0]["sequence"] == 1
        assert actions[0]["state"] == "completed"
        assert actions[1]["action_type"] == "type"
        assert actions[1]["sequence"] == 2
        assert actions[2]["state"] == "error"
        assert actions[2]["error"] == "timeout"
