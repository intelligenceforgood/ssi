"""Tests for case enrichment: timeline events + evidence documents.

Verifies that ``ScanStore.create_case_record()`` populates the
``review_actions`` (timeline) and ``source_documents`` (artifacts)
tables alongside the standard ``cases`` / ``scam_records`` /
``review_queue`` inserts.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import sqlalchemy as sa

from ssi.models.investigation import (
    ChainOfCustody,
    EvidenceArtifact,
    FraudTaxonomyResult,
    InvestigationResult,
    TaxonomyScoredLabel,
    ThreatIndicator,
)
from ssi.store.scan_store import ScanStore
from ssi.store.sql import CORE_METADATA

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture()
def store(tmp_path):
    """Return a ScanStore with both SSI and Core tables created."""
    db_path = tmp_path / "test_enrichment.db"
    s = ScanStore(db_path=db_path)

    # create_case_record uses CORE_METADATA tables — ensure they exist
    with s._session_factory() as session:
        CORE_METADATA.create_all(session.get_bind())

    return s


def _make_result(
    *,
    url: str = "https://scam.example.com",
    wallets: int = 0,
    evidence_count: int = 0,
    chain_artifacts: list[EvidenceArtifact] | None = None,
    output_path: str = "",
    risk_score: float = 85.0,
) -> InvestigationResult:
    """Build a minimal ``InvestigationResult`` for testing."""
    now = datetime.now(UTC)
    r = InvestigationResult(
        url=url,
        started_at=now,
        completed_at=now,
        success=True,
        output_path=output_path,
        taxonomy_result=FraudTaxonomyResult(
            intent=[TaxonomyScoredLabel(label="INTENT.INVESTMENT_SCAM", confidence=0.9, explanation="")],
            risk_score=risk_score,
        ),
    )

    # Add wallets as threat indicators
    for i in range(wallets):
        r.threat_indicators.append(
            ThreatIndicator(
                indicator_type="crypto_wallet",
                value=f"0xDEAD{i:04d}",
                context="eth",
                source="js",
            )
        )

    # Chain of custody
    if chain_artifacts is not None:
        r.chain_of_custody = ChainOfCustody(
            investigation_id=str(r.investigation_id),
            target_url=url,
            artifacts=chain_artifacts,
            total_artifacts=len(chain_artifacts),
        )

    return r


# ------------------------------------------------------------------
# Timeline events
# ------------------------------------------------------------------


class TestTimelineEvents:
    """Verify ``_insert_timeline_events()`` creates review_actions rows."""

    def test_creates_basic_timeline(self, store: ScanStore):
        """A successful investigation should produce at least 4 events."""
        result = _make_result(wallets=2)
        scan_id = store.create_scan(url=result.url)
        case_id = store.create_case_record(scan_id=scan_id, result=result)
        assert case_id is not None

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(
                sa.select(sql_schema.review_actions).order_by(sql_schema.review_actions.c.created_at)
            ).fetchall()

        actions = [r._mapping["action"] for r in rows]
        # Should contain these events at minimum
        assert "investigation_submitted" in actions
        assert "classification_completed" in actions
        assert "wallets_harvested" in actions
        assert "case_created" in actions

    def test_no_wallets_skips_event(self, store: ScanStore):
        """When no wallets are found, wallets_harvested should not appear."""
        result = _make_result(wallets=0)
        scan_id = store.create_scan(url=result.url)
        store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(sa.select(sql_schema.review_actions)).fetchall()

        actions = [r._mapping["action"] for r in rows]
        assert "wallets_harvested" not in actions

    def test_actor_is_ssi_agent(self, store: ScanStore):
        """All timeline events should have actor='ssi-agent'."""
        result = _make_result()
        scan_id = store.create_scan(url=result.url)
        store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(sa.select(sql_schema.review_actions)).fetchall()

        for row in rows:
            assert row._mapping["actor"] == "ssi-agent"

    def test_payload_has_description(self, store: ScanStore):
        """Each event's payload should contain a description string."""
        result = _make_result()
        scan_id = store.create_scan(url=result.url)
        store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(sa.select(sql_schema.review_actions)).fetchall()

        for row in rows:
            payload = row._mapping["payload"]
            assert isinstance(payload, dict)
            assert "description" in payload
            assert isinstance(payload["description"], str)
            assert len(payload["description"]) > 0

    def test_report_generated_when_success(self, store: ScanStore):
        """Success + GCS output path should produce report_generated event."""
        result = _make_result(output_path="gs://bucket/prefix/abc")
        scan_id = store.create_scan(url=result.url)
        store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(sa.select(sql_schema.review_actions)).fetchall()

        actions = [r._mapping["action"] for r in rows]
        assert "report_generated" in actions

    def test_evidence_collected_with_chain(self, store: ScanStore):
        """Chain of custody with artifacts triggers evidence_collected."""
        artifacts = [
            EvidenceArtifact(file="screenshot.png", sha256="abc123", size_bytes=1024),
            EvidenceArtifact(file="report.pdf", sha256="def456", size_bytes=2048),
        ]
        result = _make_result(chain_artifacts=artifacts, output_path="gs://b/p")
        scan_id = store.create_scan(url=result.url)
        store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(sa.select(sql_schema.review_actions)).fetchall()

        actions = [r._mapping["action"] for r in rows]
        assert "evidence_collected" in actions
        # Find the event and check the description
        ev_row = [r for r in rows if r._mapping["action"] == "evidence_collected"][0]
        assert "2 evidence artifact" in ev_row._mapping["payload"]["description"]


# ------------------------------------------------------------------
# Evidence documents
# ------------------------------------------------------------------


class TestEvidenceDocuments:
    """Verify ``_insert_evidence_documents()`` creates source_documents rows."""

    def test_creates_docs_from_chain_artifacts(self, store: ScanStore):
        """Chain-of-custody artifacts become source_documents rows."""
        artifacts = [
            EvidenceArtifact(file="investigation.json", sha256="a1", size_bytes=500),
            EvidenceArtifact(file="report.pdf", sha256="b2", size_bytes=1024),
            EvidenceArtifact(file="screenshot.png", sha256="c3", size_bytes=2048),
        ]
        result = _make_result(
            chain_artifacts=artifacts,
            output_path="gs://evidence-bucket/ssi/inv-123",
        )
        scan_id = store.create_scan(url=result.url)
        case_id = store.create_case_record(scan_id=scan_id, result=result)
        assert case_id is not None

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(
                sa.select(sql_schema.source_documents).where(sql_schema.source_documents.c.case_id == case_id)
            ).fetchall()

        assert len(rows) == 3

        titles = {r._mapping["title"] for r in rows}
        assert titles == {"investigation.json", "report.pdf", "screenshot.png"}

    def test_gcs_source_url(self, store: ScanStore):
        """Each document should have a gs:// source_url built from output_path."""
        artifacts = [
            EvidenceArtifact(file="report.md", sha256="x", size_bytes=100),
        ]
        result = _make_result(
            chain_artifacts=artifacts,
            output_path="gs://my-bucket/ssi/inv-abc",
        )
        scan_id = store.create_scan(url=result.url)
        case_id = store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(
                sa.select(sql_schema.source_documents).where(sql_schema.source_documents.c.case_id == case_id)
            ).fetchall()

        assert len(rows) == 1
        row = rows[0]._mapping
        assert row["source_url"] == "gs://my-bucket/ssi/inv-abc/report.md"
        assert row["mime_type"] == "text/markdown"

    def test_mime_type_mapping(self, store: ScanStore):
        """Various file extensions map to correct MIME types."""
        artifacts = [
            EvidenceArtifact(file="data.json", sha256="1", size_bytes=10),
            EvidenceArtifact(file="report.pdf", sha256="2", size_bytes=20),
            EvidenceArtifact(file="evidence.zip", sha256="3", size_bytes=30),
            EvidenceArtifact(file="screenshot.png", sha256="4", size_bytes=40),
            EvidenceArtifact(file="page.html", sha256="5", size_bytes=50),
        ]
        result = _make_result(chain_artifacts=artifacts, output_path="gs://b/p")
        scan_id = store.create_scan(url=result.url)
        case_id = store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(
                sa.select(sql_schema.source_documents).where(sql_schema.source_documents.c.case_id == case_id)
            ).fetchall()

        mime_by_title = {r._mapping["title"]: r._mapping["mime_type"] for r in rows}
        assert mime_by_title["data.json"] == "application/json"
        assert mime_by_title["report.pdf"] == "application/pdf"
        assert mime_by_title["evidence.zip"] == "application/zip"
        assert mime_by_title["screenshot.png"] == "image/png"
        assert mime_by_title["page.html"] == "text/html"

    def test_fallback_known_files_on_gcs_without_chain(self, store: ScanStore):
        """When chain_of_custody is missing but output_path is GCS, insert known files."""
        result = _make_result(
            chain_artifacts=None,
            output_path="gs://bucket/prefix/inv-fallback",
        )
        scan_id = store.create_scan(url=result.url)
        case_id = store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(
                sa.select(sql_schema.source_documents).where(sql_schema.source_documents.c.case_id == case_id)
            ).fetchall()

        titles = {r._mapping["title"] for r in rows}
        # Should include the well-known evidence files
        assert "investigation.json" in titles
        assert "report.pdf" in titles
        assert "evidence.zip" in titles

    def test_no_docs_without_output_path(self, store: ScanStore):
        """No source_documents when output_path is empty and no chain."""
        result = _make_result(chain_artifacts=None, output_path="")
        scan_id = store.create_scan(url=result.url)
        case_id = store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(
                sa.select(sql_schema.source_documents).where(sql_schema.source_documents.c.case_id == case_id)
            ).fetchall()

        assert len(rows) == 0

    def test_sha256_stored_from_artifacts(self, store: ScanStore):
        """file_sha256 from chain artifacts should be persisted."""
        artifacts = [
            EvidenceArtifact(file="report.pdf", sha256="deadbeef1234", size_bytes=9999),
        ]
        result = _make_result(chain_artifacts=artifacts, output_path="gs://b/p")
        scan_id = store.create_scan(url=result.url)
        case_id = store.create_case_record(scan_id=scan_id, result=result)

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            rows = session.execute(
                sa.select(sql_schema.source_documents).where(sql_schema.source_documents.c.case_id == case_id)
            ).fetchall()

        assert len(rows) == 1
        assert rows[0]._mapping["file_sha256"] == "deadbeef1234"


# ------------------------------------------------------------------
# Dedup guard
# ------------------------------------------------------------------


class TestDedupGuard:
    """Verify timeline + docs are only inserted for new cases, not dedup."""

    def test_duplicate_case_skips_enrichment(self, store: ScanStore):
        """A second call with the same scan_id should return the existing case without duplicating rows."""
        result = _make_result(
            chain_artifacts=[
                EvidenceArtifact(file="report.pdf", sha256="x", size_bytes=1),
            ],
            output_path="gs://b/p",
        )
        scan_id = store.create_scan(url=result.url)
        case1 = store.create_case_record(scan_id=scan_id, result=result)

        # Second call with the same scan_id → dedup (same metadata hash,
        # because ssi_investigation_id is identical)
        case2 = store.create_case_record(scan_id=scan_id, result=result)

        # Should return the same case_id
        assert case1 == case2

        with store._session_factory() as session:
            from ssi.store import sql as sql_schema

            actions = session.execute(sa.select(sql_schema.review_actions)).fetchall()
            docs = session.execute(sa.select(sql_schema.source_documents)).fetchall()

        # Only one set of events + documents from the first insert
        # (dedup path skips the insert block with timeline/evidence)
        action_types = [r._mapping["action"] for r in actions]
        assert action_types.count("case_created") == 1
        assert len(docs) == 1
