"""Scan persistence store for SSI investigations.

``ScanStore`` follows the same constructor / session pattern used by the
stores in ``i4g.store.*``: accept an optional *db_path* for convenience
or a pre-built *session_factory* for shared / Cloud SQL engines.

All four tables (``site_scans``, ``harvested_wallets``, ``agent_sessions``,
``pii_exposures``) are managed through a single store instance so callers
can persist an entire investigation result in one call.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from ssi.store import sql as sql_schema
from ssi.store.sql import METADATA, build_session_factory, dialect_insert

logger = logging.getLogger(__name__)


class ScanStore:
    """Persist SSI scan results, wallets, agent actions, and PII exposures.

    Args:
        db_path: Convenience path for a local SQLite file.  Mutually
            exclusive with *session_factory*.
        session_factory: Pre-configured ``sessionmaker`` (e.g. Cloud SQL
            or a shared test fixture).
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        session_factory: sessionmaker | None = None,
    ) -> None:
        if session_factory is not None:
            self._session_factory = session_factory
        elif db_path is not None:
            self._session_factory = build_session_factory(db_path=db_path)
        else:
            self._session_factory = build_session_factory()

        # Auto-create tables.  On PostgreSQL the schema is normally managed
        # by Alembic in the core repo (migration 20260221_01_add_ssi_scan_tables).
        # However, we fall back to METADATA.create_all() if the tables don't
        # exist yet — this prevents silent data loss when the migration
        # hasn't been applied to the target database.
        try:
            with self._session_factory() as session:
                bind = session.get_bind()
                dialect_name = bind.dialect.name
                if dialect_name != "postgresql":
                    METADATA.create_all(session.connection())
                else:
                    from sqlalchemy import inspect as sa_inspect

                    existing = sa_inspect(bind).get_table_names()
                    required = {"site_scans", "harvested_wallets", "agent_sessions", "pii_exposures"}
                    missing = required - set(existing)
                    if missing:
                        logger.warning(
                            "SSI tables missing in PostgreSQL (%s) — running auto-create. "
                            "Apply Alembic migration 20260221_01 for proper FK constraints.",
                            ", ".join(sorted(missing)),
                        )
                        METADATA.create_all(bind, checkfirst=True)
                    else:
                        logger.info("SSI scan tables verified in PostgreSQL")
        except Exception:
            logger.warning("Table verification/creation failed during ScanStore init", exc_info=True)

    # ------------------------------------------------------------------
    # site_scans CRUD
    # ------------------------------------------------------------------

    def create_scan(
        self,
        *,
        url: str,
        scan_type: str = "passive",
        domain: str | None = None,
        case_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        scan_id: str | None = None,
    ) -> str:
        """Insert a new ``site_scans`` row and return the ``scan_id``.

        Args:
            url: Target URL being investigated.
            scan_type: Scan mode — ``"passive"``, ``"active"``, or ``"full"``.
            domain: Domain slug extracted from the URL.
            case_id: Optional core case ID to link this scan to.
            metadata: Arbitrary JSON metadata stored with the scan.
            scan_id: Optional pre-generated ID.  When *None* a fresh UUID is
                created.  Pass the orchestrator's ``investigation_id`` here so
                the DB record and the result object share the same identifier.
        """
        scan_id = scan_id or str(uuid4())
        now = datetime.now(UTC)

        # Compute canonical URL for dedup lookups
        from ssi.utils.url_normalization import normalize_url

        normalized = normalize_url(url)

        with self._session_factory() as session:
            session.execute(
                sa.insert(sql_schema.site_scans).values(
                    scan_id=scan_id,
                    case_id=case_id,
                    url=url,
                    domain=domain,
                    scan_type=scan_type,
                    status="running",
                    normalized_url=normalized,
                    metadata=metadata or {},
                    started_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.commit()
        logger.debug("Created scan %s for %s", scan_id, url)
        return scan_id

    def update_scan(self, scan_id: str, **fields: Any) -> None:
        """Update arbitrary columns on a ``site_scans`` row."""
        fields["updated_at"] = datetime.now(UTC)
        with self._session_factory() as session:
            session.execute(
                sa.update(sql_schema.site_scans).where(sql_schema.site_scans.c.scan_id == scan_id).values(**fields)
            )
            session.commit()

    def complete_scan(
        self,
        scan_id: str,
        *,
        status: str = "completed",
        passive_result: dict[str, Any] | None = None,
        active_result: dict[str, Any] | None = None,
        classification_result: dict[str, Any] | None = None,
        risk_score: float | None = None,
        taxonomy_version: str | None = None,
        wallet_count: int = 0,
        total_cost_usd: float | None = None,
        llm_input_tokens: int = 0,
        llm_output_tokens: int = 0,
        duration_seconds: float | None = None,
        error_message: str | None = None,
        evidence_path: str | None = None,
        evidence_zip_sha256: str | None = None,
    ) -> None:
        """Finalise a scan with aggregated results."""
        now = datetime.now(UTC)
        values: dict[str, Any] = {
            "status": status,
            "wallet_count": wallet_count,
            "llm_input_tokens": llm_input_tokens,
            "llm_output_tokens": llm_output_tokens,
            "completed_at": now,
            "updated_at": now,
        }
        if passive_result is not None:
            values["passive_result"] = passive_result
        if active_result is not None:
            values["active_result"] = active_result
        if classification_result is not None:
            values["classification_result"] = classification_result
        if risk_score is not None:
            values["risk_score"] = risk_score
        if taxonomy_version is not None:
            values["taxonomy_version"] = taxonomy_version
        if total_cost_usd is not None:
            values["total_cost_usd"] = total_cost_usd
        if duration_seconds is not None:
            values["duration_seconds"] = duration_seconds
        if error_message is not None:
            values["error_message"] = error_message
        if evidence_path is not None:
            values["evidence_path"] = evidence_path
        if evidence_zip_sha256 is not None:
            values["evidence_zip_sha256"] = evidence_zip_sha256

        with self._session_factory() as session:
            session.execute(
                sa.update(sql_schema.site_scans).where(sql_schema.site_scans.c.scan_id == scan_id).values(**values)
            )
            session.commit()
        logger.info("Completed scan %s with status=%s", scan_id, status)

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Return a single scan row as a dict, or ``None``."""
        with self._session_factory() as session:
            row = session.execute(
                sa.select(sql_schema.site_scans).where(sql_schema.site_scans.c.scan_id == scan_id)
            ).first()
        return dict(row._mapping) if row else None

    def list_scans(
        self,
        *,
        domain: str | None = None,
        status: str | None = None,
        ecx_submission_status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return a paginated list of scans, optionally filtered.

        Args:
            domain: Filter by exact domain name.
            status: Filter by scan status.
            ecx_submission_status: Filter to scans that have at least one
                ``ecx_submissions`` row in this status (e.g. ``"queued"``).
            limit: Maximum rows to return.
            offset: Pagination offset.

        Returns:
            List of scan dicts ordered by ``created_at`` descending.
        """
        tbl = sql_schema.site_scans
        stmt = sa.select(tbl).order_by(tbl.c.created_at.desc())
        if domain is not None:
            stmt = stmt.where(tbl.c.domain == domain)
        if status is not None:
            stmt = stmt.where(tbl.c.status == status)
        if ecx_submission_status is not None:
            sub = sa.select(sql_schema.ecx_submissions.c.scan_id).where(
                sql_schema.ecx_submissions.c.scan_id == tbl.c.scan_id,
                sql_schema.ecx_submissions.c.status == ecx_submission_status,
            )
            stmt = stmt.where(sa.exists(sub))
        stmt = stmt.limit(limit).offset(offset)
        with self._session_factory() as session:
            rows = session.execute(stmt).all()
        return [dict(r._mapping) for r in rows]

    # ------------------------------------------------------------------
    # harvested_wallets CRUD
    # ------------------------------------------------------------------

    def add_wallet(
        self,
        *,
        scan_id: str,
        token_symbol: str,
        network_short: str,
        wallet_address: str,
        token_label: str = "",
        network_label: str = "",
        source: str = "js",
        confidence: float = 0.0,
        site_url: str = "",
        case_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        harvested_at: datetime | None = None,
    ) -> str:
        """Insert a single wallet row.  Returns the ``wallet_id``."""
        wallet_id = str(uuid4())
        with self._session_factory() as session:
            stmt = dialect_insert(session, sql_schema.harvested_wallets).values(
                wallet_id=wallet_id,
                scan_id=scan_id,
                case_id=case_id,
                token_label=token_label,
                token_symbol=token_symbol,
                network_label=network_label,
                network_short=network_short,
                wallet_address=wallet_address,
                source=source,
                confidence=confidence,
                site_url=site_url,
                metadata=metadata or {},
                harvested_at=harvested_at or datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
            # On conflict (duplicate address for same scan), update confidence
            stmt = stmt.on_conflict_do_update(
                index_elements=["scan_id", "token_symbol", "network_short", "wallet_address"],
                set_={
                    "confidence": confidence,
                    "source": source,
                    "metadata": metadata or {},
                },
            )
            session.execute(stmt)
            session.commit()
        return wallet_id

    def add_wallets_bulk(self, scan_id: str, wallets: list[dict[str, Any]]) -> int:
        """Bulk-insert wallets from a list of dicts.  Returns count inserted."""
        if not wallets:
            return 0
        now = datetime.now(UTC)
        rows = []
        for w in wallets:
            rows.append(
                {
                    "wallet_id": str(uuid4()),
                    "scan_id": scan_id,
                    "case_id": w.get("case_id"),
                    "token_label": w.get("token_label", ""),
                    "token_symbol": w["token_symbol"],
                    "network_label": w.get("network_label", ""),
                    "network_short": w["network_short"],
                    "wallet_address": w["wallet_address"],
                    "source": w.get("source", "js"),
                    "confidence": w.get("confidence", 0.0),
                    "site_url": w.get("site_url", ""),
                    "metadata": w.get("metadata", {}),
                    "harvested_at": w.get("harvested_at", now),
                    "created_at": now,
                }
            )
        with self._session_factory() as session:
            session.execute(sa.insert(sql_schema.harvested_wallets), rows)
            session.commit()
        logger.debug("Bulk-inserted %d wallets for scan %s", len(rows), scan_id)
        return len(rows)

    def get_wallets(self, scan_id: str) -> list[dict[str, Any]]:
        """Return all wallet rows for a scan."""
        with self._session_factory() as session:
            rows = session.execute(
                sa.select(sql_schema.harvested_wallets)
                .where(sql_schema.harvested_wallets.c.scan_id == scan_id)
                .order_by(sql_schema.harvested_wallets.c.created_at)
            ).all()
        return [dict(r._mapping) for r in rows]

    def search_wallets(
        self,
        *,
        address: str | None = None,
        token_symbol: str | None = None,
        limit: int = 100,
        deduplicate: bool = True,
    ) -> list[dict[str, Any]]:
        """Search wallets across all scans by address or token.

        Args:
            address: Filter by exact wallet address.
            token_symbol: Filter by token symbol (e.g. ``ETH``, ``BTC``).
            limit: Maximum number of results.
            deduplicate: When ``True`` (default), groups by
                ``(wallet_address, token_symbol, network_short)`` and returns
                one row per unique address with ``first_seen_at``,
                ``last_seen_at``, and ``seen_count`` aggregates.

        Returns:
            List of wallet dicts, deduplicated by default.
        """
        hw = sql_schema.harvested_wallets

        if deduplicate:
            stmt = sa.select(
                hw.c.wallet_address,
                hw.c.token_symbol,
                hw.c.token_label,
                hw.c.network_short,
                hw.c.network_label,
                sa.func.max(hw.c.confidence).label("confidence"),
                sa.func.max(hw.c.source).label("source"),
                sa.func.max(hw.c.site_url).label("site_url"),
                sa.func.min(hw.c.harvested_at).label("first_seen_at"),
                sa.func.max(hw.c.harvested_at).label("last_seen_at"),
                sa.func.count().label("seen_count"),
            ).group_by(
                hw.c.wallet_address,
                hw.c.token_symbol,
                hw.c.token_label,
                hw.c.network_short,
                hw.c.network_label,
            )
            if address is not None:
                stmt = stmt.where(hw.c.wallet_address == address)
            if token_symbol is not None:
                stmt = stmt.where(hw.c.token_symbol == token_symbol.upper())
            stmt = stmt.order_by(sa.desc("last_seen_at")).limit(limit)
        else:
            stmt = sa.select(hw)
            if address is not None:
                stmt = stmt.where(hw.c.wallet_address == address)
            if token_symbol is not None:
                stmt = stmt.where(hw.c.token_symbol == token_symbol.upper())
            stmt = stmt.order_by(hw.c.created_at.desc()).limit(limit)

        with self._session_factory() as session:
            rows = session.execute(stmt).all()
        return [dict(r._mapping) for r in rows]

    # ------------------------------------------------------------------
    # agent_sessions CRUD
    # ------------------------------------------------------------------

    def log_agent_action(
        self,
        *,
        scan_id: str,
        state: str,
        sequence: int,
        action_type: str | None = None,
        action_detail: dict[str, Any] | None = None,
        screenshot_path: str | None = None,
        page_url: str | None = None,
        dom_confidence: float | None = None,
        llm_model: str | None = None,
        llm_input_tokens: int | None = None,
        llm_output_tokens: int | None = None,
        cost_usd: float | None = None,
        duration_ms: int | float | None = None,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Record a single agent action in the audit trail."""
        session_id = str(uuid4())
        with self._session_factory() as session:
            session.execute(
                sa.insert(sql_schema.agent_sessions).values(
                    session_id=session_id,
                    scan_id=scan_id,
                    state=state,
                    action_type=action_type,
                    action_detail=action_detail,
                    screenshot_path=screenshot_path,
                    page_url=page_url,
                    dom_confidence=dom_confidence,
                    llm_model=llm_model,
                    llm_input_tokens=llm_input_tokens,
                    llm_output_tokens=llm_output_tokens,
                    cost_usd=cost_usd,
                    duration_ms=int(duration_ms) if duration_ms is not None else None,
                    error=error,
                    sequence=sequence,
                    metadata=metadata or {},
                    created_at=datetime.now(UTC),
                )
            )
            session.commit()
        return session_id

    def get_agent_actions(self, scan_id: str) -> list[dict[str, Any]]:
        """Return the full agent action trail for a scan, ordered by sequence."""
        with self._session_factory() as session:
            rows = session.execute(
                sa.select(sql_schema.agent_sessions)
                .where(sql_schema.agent_sessions.c.scan_id == scan_id)
                .order_by(sql_schema.agent_sessions.c.sequence)
            ).all()
        return [dict(r._mapping) for r in rows]

    # ------------------------------------------------------------------
    # pii_exposures CRUD
    # ------------------------------------------------------------------

    def add_pii_exposure(
        self,
        *,
        scan_id: str,
        field_type: str,
        field_label: str | None = None,
        form_action: str | None = None,
        page_url: str | None = None,
        is_required: bool | None = None,
        was_submitted: bool = False,
        case_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        detected_at: datetime | None = None,
    ) -> str:
        """Record a PII field found on the scam site."""
        exposure_id = str(uuid4())
        with self._session_factory() as session:
            session.execute(
                sa.insert(sql_schema.pii_exposures).values(
                    exposure_id=exposure_id,
                    scan_id=scan_id,
                    case_id=case_id,
                    field_type=field_type,
                    field_label=field_label,
                    form_action=form_action,
                    page_url=page_url,
                    is_required=is_required,
                    was_submitted=was_submitted,
                    metadata=metadata or {},
                    detected_at=detected_at or datetime.now(UTC),
                    created_at=datetime.now(UTC),
                )
            )
            session.commit()
        return exposure_id

    def add_pii_exposures_bulk(self, scan_id: str, exposures: list[dict[str, Any]]) -> int:
        """Bulk-insert PII exposure records.  Returns count inserted."""
        if not exposures:
            return 0
        now = datetime.now(UTC)
        rows = []
        for e in exposures:
            rows.append(
                {
                    "exposure_id": str(uuid4()),
                    "scan_id": scan_id,
                    "case_id": e.get("case_id"),
                    "field_type": e["field_type"],
                    "field_label": e.get("field_label"),
                    "form_action": e.get("form_action"),
                    "page_url": e.get("page_url"),
                    "is_required": e.get("is_required"),
                    "was_submitted": e.get("was_submitted", False),
                    "metadata": e.get("metadata", {}),
                    "detected_at": e.get("detected_at", now),
                    "created_at": now,
                }
            )
        with self._session_factory() as session:
            session.execute(sa.insert(sql_schema.pii_exposures), rows)
            session.commit()
        logger.debug("Bulk-inserted %d PII exposures for scan %s", len(rows), scan_id)
        return len(rows)

    def get_pii_exposures(self, scan_id: str) -> list[dict[str, Any]]:
        """Return all PII exposure records for a scan."""
        with self._session_factory() as session:
            rows = session.execute(
                sa.select(sql_schema.pii_exposures)
                .where(sql_schema.pii_exposures.c.scan_id == scan_id)
                .order_by(sql_schema.pii_exposures.c.created_at)
            ).all()
        return [dict(r._mapping) for r in rows]

    # ------------------------------------------------------------------
    # Convenience: persist a full InvestigationResult
    # ------------------------------------------------------------------

    def persist_investigation(
        self,
        scan_id: str,
        result: Any,
        *,
        site_result: Any | None = None,
    ) -> None:
        """Persist a complete ``InvestigationResult`` (and optional ``SiteResult``).

        This is the main integration point called by the orchestrator after
        all investigation phases complete.  It updates the scan row and
        bulk-inserts wallets, agent actions, and PII exposures.

        Args:
            scan_id: The ``scan_id`` returned by :meth:`create_scan`.
            result: An ``InvestigationResult`` instance.
            site_result: An optional ``SiteResult`` from the agent controller.
        """
        from ssi.models.investigation import InvestigationResult

        if not isinstance(result, InvestigationResult):
            raise TypeError(f"Expected InvestigationResult, got {type(result).__name__}")

        # Build passive result summary
        passive_result: dict[str, Any] = {}
        if result.whois:
            passive_result["whois"] = (
                result.whois.model_dump(mode="json") if hasattr(result.whois, "model_dump") else {}
            )
        if result.dns:
            passive_result["dns"] = result.dns.model_dump(mode="json") if hasattr(result.dns, "model_dump") else {}
        if result.ssl:
            passive_result["ssl"] = result.ssl.model_dump(mode="json") if hasattr(result.ssl, "model_dump") else {}
        if result.geoip:
            passive_result["geoip"] = (
                result.geoip.model_dump(mode="json") if hasattr(result.geoip, "model_dump") else {}
            )

        # Build active result summary from site_result
        active_result: dict[str, Any] | None = None
        if site_result is not None:
            active_result = site_result.to_dict() if hasattr(site_result, "to_dict") else {}

        # Classification
        classification_result: dict[str, Any] | None = None
        risk_score: float | None = None
        taxonomy_version: str | None = None
        if result.taxonomy_result:
            classification_result = result.taxonomy_result.model_dump(mode="json")
            risk_score = result.taxonomy_result.risk_score
            taxonomy_version = getattr(result.taxonomy_result, "taxonomy_version", None)

        # Token usage from result
        llm_input_tokens = getattr(result, "total_input_tokens", 0) or 0
        llm_output_tokens = getattr(result, "total_output_tokens", 0) or 0
        total_cost_usd: float | None = None
        if result.cost_summary:
            total_cost_usd = (
                result.cost_summary.get("total_cost_usd") if isinstance(result.cost_summary, dict) else None
            )

        # Wallet count — prefer site_result wallets, fall back to InvestigationResult.wallets
        wallet_entries = []
        if site_result and hasattr(site_result, "wallets"):
            wallet_entries = site_result.wallets or []
        if not wallet_entries and hasattr(result, "wallets"):
            wallet_entries = result.wallets or []

        # Complete the scan row
        status = "completed" if not result.status or result.status.value == "completed" else str(result.status.value)
        self.complete_scan(
            scan_id,
            status=status,
            passive_result=passive_result or None,
            active_result=active_result,
            classification_result=classification_result,
            risk_score=risk_score,
            taxonomy_version=taxonomy_version,
            wallet_count=len(wallet_entries),
            total_cost_usd=total_cost_usd,
            llm_input_tokens=llm_input_tokens,
            llm_output_tokens=llm_output_tokens,
            duration_seconds=result.duration_seconds,
            error_message=None,
            evidence_path=result.output_path,
            evidence_zip_sha256=(
                getattr(result.chain_of_custody, "package_sha256", None) if result.chain_of_custody else None
            ),
        )

        # Bulk-insert wallets
        if wallet_entries:
            wallet_dicts = []
            for w in wallet_entries:
                if hasattr(w, "model_dump"):
                    # Use mode="python" (default) to keep datetime as native objects
                    # for SQLAlchemy compatibility with SQLite DateTime columns.
                    wd = w.model_dump()
                elif hasattr(w, "to_dict"):
                    wd = w.to_dict()
                else:
                    wd = {}
                harvested_at = wd.get("harvested_at")
                # Ensure harvested_at is a datetime, not an ISO string
                if isinstance(harvested_at, str):
                    from datetime import datetime as _dt

                    try:
                        harvested_at = _dt.fromisoformat(harvested_at.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        harvested_at = None
                wallet_dicts.append(
                    {
                        "token_label": wd.get("token_label", ""),
                        "token_symbol": wd.get("token_symbol", ""),
                        "network_label": wd.get("network_label", ""),
                        "network_short": wd.get("network_short", ""),
                        "wallet_address": wd.get("wallet_address", ""),
                        "source": wd.get("source", "js"),
                        "confidence": wd.get("confidence", 0.0),
                        "site_url": wd.get("site_url", ""),
                        "harvested_at": harvested_at,
                    }
                )
            self.add_wallets_bulk(scan_id, wallet_dicts)

        # Extract PII exposures from page snapshot form fields
        pii_dicts: list[dict[str, Any]] = []
        if result.page_snapshot and result.page_snapshot.form_fields:
            for ff in result.page_snapshot.form_fields:
                field_dict = ff.model_dump(mode="json") if hasattr(ff, "model_dump") else {}
                field_type = _classify_form_field(field_dict)
                pii_dicts.append(
                    {
                        "field_type": field_type,
                        "field_label": field_dict.get("label") or field_dict.get("name", ""),
                        "page_url": result.url,
                        "is_required": field_dict.get("required"),
                        "was_submitted": not result.passive_only,
                    }
                )
            if pii_dicts:
                self.add_pii_exposures_bulk(scan_id, pii_dicts)

        # Bulk-insert agent session steps
        agent_step_count = 0
        agent_steps = getattr(result, "agent_steps", None) or []
        if agent_steps:
            now_ts = datetime.now(UTC)
            step_rows = []
            for step in agent_steps:
                step_rows.append(
                    {
                        "session_id": str(uuid4()),
                        "scan_id": scan_id,
                        "state": "completed" if not step.get("error") else "error",
                        "action_type": step.get("action", ""),
                        "action_detail": {
                            "element_index": step.get("element"),
                            "value": step.get("value", ""),
                            "reasoning": step.get("reasoning", ""),
                        },
                        "llm_input_tokens": step.get("tokens"),
                        "llm_output_tokens": None,
                        "duration_ms": int(step.get("duration_ms", 0)),
                        "error": step.get("error"),
                        "sequence": step.get("step", 0),
                        "metadata": {},
                        "created_at": now_ts,
                    }
                )
            if step_rows:
                with self._session_factory() as session:
                    session.execute(sa.insert(sql_schema.agent_sessions), step_rows)
                    session.commit()
                agent_step_count = len(step_rows)

        logger.info(
            "Persisted investigation for scan %s: %d wallets, %d PII fields, %d agent steps",
            scan_id,
            len(wallet_entries),
            len(pii_dicts),
            agent_step_count,
        )

    # ------------------------------------------------------------------
    # ecx_enrichments cache
    # ------------------------------------------------------------------

    def cache_ecx_enrichments(
        self,
        scan_id: str,
        enrichment_result: Any,
        *,
        cache_ttl_hours: int = 24,
    ) -> int:
        """Persist eCX enrichment records for cache and audit.

        One row per (query_module, query_value) pair from the enrichment result.
        Rows include the full eCX record data as JSON so cached results can be
        returned without another eCX API call.

        Args:
            scan_id: The investigation scan ID.
            enrichment_result: An ``ECXEnrichmentResult`` instance.
            cache_ttl_hours: Hours until cache entries expire.

        Returns:
            Number of rows inserted.
        """
        from ssi.models.ecx import ECXEnrichmentResult

        if not isinstance(enrichment_result, ECXEnrichmentResult):
            return 0
        if not enrichment_result.has_hits and not enrichment_result.query_count:
            return 0

        now = datetime.now(UTC)
        expires_at = now + timedelta(hours=cache_ttl_hours)
        rows: list[dict[str, Any]] = []

        for hit in enrichment_result.phish_hits:
            rows.append(
                {
                    "enrichment_id": str(uuid4()),
                    "scan_id": scan_id,
                    "query_module": "phish",
                    "query_value": hit.url,
                    "ecx_record_id": hit.id,
                    "ecx_data": hit.model_dump(mode="json"),
                    "confidence": hit.confidence,
                    "queried_at": now,
                    "cache_expires_at": expires_at,
                }
            )

        for hit in enrichment_result.domain_hits:
            rows.append(
                {
                    "enrichment_id": str(uuid4()),
                    "scan_id": scan_id,
                    "query_module": "malicious-domain",
                    "query_value": hit.domain,
                    "ecx_record_id": hit.id,
                    "ecx_data": hit.model_dump(mode="json"),
                    "confidence": hit.confidence,
                    "queried_at": now,
                    "cache_expires_at": expires_at,
                }
            )

        for hit in enrichment_result.ip_hits:
            rows.append(
                {
                    "enrichment_id": str(uuid4()),
                    "scan_id": scan_id,
                    "query_module": "malicious-ip",
                    "query_value": hit.ip,
                    "ecx_record_id": hit.id,
                    "ecx_data": hit.model_dump(mode="json"),
                    "confidence": hit.confidence,
                    "queried_at": now,
                    "cache_expires_at": expires_at,
                }
            )

        for hit in enrichment_result.crypto_hits:
            rows.append(
                {
                    "enrichment_id": str(uuid4()),
                    "scan_id": scan_id,
                    "query_module": "cryptocurrency-addresses",
                    "query_value": hit.address,
                    "ecx_record_id": hit.id,
                    "ecx_data": hit.model_dump(mode="json"),
                    "confidence": hit.confidence,
                    "queried_at": now,
                    "cache_expires_at": expires_at,
                }
            )

        if not rows:
            return 0

        with self._session_factory() as session:
            session.execute(sa.insert(sql_schema.ecx_enrichments), rows)
            session.commit()
        logger.debug("Cached %d eCX enrichment rows for scan %s", len(rows), scan_id)
        return len(rows)

    def get_ecx_enrichments(self, scan_id: str) -> list[dict[str, Any]]:
        """Return all cached eCX enrichment rows for a scan.

        Args:
            scan_id: The investigation scan ID.

        Returns:
            List of enrichment row dicts.
        """
        with self._session_factory() as session:
            rows = session.execute(
                sa.select(sql_schema.ecx_enrichments)
                .where(sql_schema.ecx_enrichments.c.scan_id == scan_id)
                .order_by(sql_schema.ecx_enrichments.c.queried_at)
            ).all()
        result = []
        for r in rows:
            d = dict(r._mapping)
            for key, val in d.items():
                if hasattr(val, "isoformat"):
                    d[key] = val.isoformat()
            result.append(d)
        return result

    def get_cached_ecx_enrichment(
        self,
        query_module: str,
        query_value: str,
    ) -> list[dict[str, Any]]:
        """Return unexpired cached eCX enrichment rows for a specific query.

        Args:
            query_module: eCX module name (e.g. ``"phish"``).
            query_value: Query value (URL, domain, IP, or address).

        Returns:
            List of cached enrichment rows that have not expired.
        """
        now = datetime.now(UTC)
        tbl = sql_schema.ecx_enrichments
        with self._session_factory() as session:
            rows = session.execute(
                sa.select(tbl)
                .where(tbl.c.query_module == query_module)
                .where(tbl.c.query_value == query_value)
                .where(
                    sa.or_(
                        tbl.c.cache_expires_at.is_(None),
                        tbl.c.cache_expires_at > now,
                    )
                )
                .order_by(tbl.c.queried_at.desc())
            ).all()
        result = []
        for r in rows:
            d = dict(r._mapping)
            for key, val in d.items():
                if hasattr(val, "isoformat"):
                    d[key] = val.isoformat()
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # ecx_submissions CRUD (Phase 2)
    # ------------------------------------------------------------------

    def create_ecx_submission(
        self,
        *,
        submission_id: str,
        scan_id: str | None = None,
        case_id: str | None = None,
        ecx_module: str,
        submitted_value: str,
        confidence: int = 0,
        release_label: str = "",
        status: str = "pending",
        submitted_by: str = "",
    ) -> str:
        """Insert a new eCX submission tracking row.

        Args:
            submission_id: Pre-generated UUID for the row.
            scan_id: SSI scan this submission belongs to.
            case_id: Core case ID (if linked).
            ecx_module: eCX module (e.g. ``"phish"``).
            submitted_value: URL / domain / IP / address being submitted.
            confidence: Confidence 0–100.
            release_label: eCX release label (phish module).
            status: Initial status — ``"pending"`` or ``"queued"``.
            submitted_by: ``"auto"`` or analyst identifier.

        Returns:
            The ``submission_id``.
        """
        now = datetime.now(UTC)
        with self._session_factory() as session:
            session.execute(
                sa.insert(sql_schema.ecx_submissions).values(
                    submission_id=submission_id,
                    scan_id=scan_id,
                    case_id=case_id,
                    ecx_module=ecx_module,
                    submitted_value=submitted_value,
                    confidence=confidence,
                    release_label=release_label,
                    status=status,
                    submitted_by=submitted_by,
                    submitted_at=None,
                    error_message=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.commit()
        logger.debug("Created ECX submission %s (%s %s)", submission_id, ecx_module, status)
        return submission_id

    def update_ecx_submission(self, submission_id: str, **fields: Any) -> None:
        """Update arbitrary columns on an ``ecx_submissions`` row.

        Args:
            submission_id: The row to update.
            **fields: Column values to set (e.g. ``status="submitted"``,
                ``ecx_record_id=42``).
        """
        fields["updated_at"] = datetime.now(UTC)
        tbl = sql_schema.ecx_submissions
        with self._session_factory() as session:
            session.execute(sa.update(tbl).where(tbl.c.submission_id == submission_id).values(**fields))
            session.commit()

    def get_ecx_submission(self, submission_id: str) -> dict[str, Any] | None:
        """Return a single submission row as a dict, or ``None`` if not found.

        Args:
            submission_id: UUID of the submission row.

        Returns:
            Dict of column values, or ``None``.
        """
        tbl = sql_schema.ecx_submissions
        with self._session_factory() as session:
            row = session.execute(sa.select(tbl).where(tbl.c.submission_id == submission_id)).first()
        return self._row_to_dict(row) if row else None

    def list_ecx_submissions(
        self,
        *,
        scan_id: str | None = None,
        case_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return a paginated list of submission rows.

        Args:
            scan_id: Filter by investigation scan ID.
            case_id: Filter by core case ID.
            status: Filter by submission status.
            limit: Maximum rows to return.
            offset: Pagination offset.

        Returns:
            List of submission dicts ordered by ``created_at`` descending.
        """
        tbl = sql_schema.ecx_submissions
        stmt = sa.select(tbl).order_by(tbl.c.created_at.desc())
        if scan_id is not None:
            stmt = stmt.where(tbl.c.scan_id == scan_id)
        if case_id is not None:
            stmt = stmt.where(tbl.c.case_id == case_id)
        if status is not None:
            stmt = stmt.where(tbl.c.status == status)
        stmt = stmt.limit(limit).offset(offset)
        with self._session_factory() as session:
            rows = session.execute(stmt).all()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # eCX polling state (Phase 3)
    # ------------------------------------------------------------------

    def get_polling_state(self, module: str) -> dict[str, Any] | None:
        """Return the polling cursor for an eCX module, or ``None``.

        Args:
            module: eCX module name (e.g. ``"phish"``).

        Returns:
            Polling state dict or ``None`` if never polled.
        """
        tbl = sql_schema.ecx_polling_state
        stmt = sa.select(tbl).where(tbl.c.module == module)
        with self._session_factory() as session:
            row = session.execute(stmt).first()
        return self._row_to_dict(row) if row else None

    def upsert_polling_state(
        self,
        module: str,
        *,
        last_polled_id: int,
        records_found: int = 0,
        errors: int = 0,
    ) -> None:
        """Insert or update the polling cursor for an eCX module.

        Args:
            module: eCX module name.
            last_polled_id: Highest eCX record ID seen in this poll cycle.
            records_found: Number of new records found.
            errors: Number of errors encountered.
        """
        from datetime import datetime

        now = datetime.now(UTC)
        tbl = sql_schema.ecx_polling_state
        with self._session_factory() as session:
            existing = session.execute(sa.select(tbl).where(tbl.c.module == module)).first()
            if existing:
                session.execute(
                    sa.update(tbl)
                    .where(tbl.c.module == module)
                    .values(
                        last_polled_id=last_polled_id,
                        last_polled_at=now,
                        records_found=records_found,
                        errors=errors,
                        updated_at=now,
                    )
                )
            else:
                session.execute(
                    sa.insert(tbl).values(
                        module=module,
                        last_polled_id=last_polled_id,
                        last_polled_at=now,
                        records_found=records_found,
                        errors=errors,
                        updated_at=now,
                    )
                )
            session.commit()

    def list_polling_states(self) -> list[dict[str, Any]]:
        """Return all polling state rows, ordered by module name.

        Returns:
            List of polling state dicts.
        """
        tbl = sql_schema.ecx_polling_state
        stmt = sa.select(tbl).order_by(tbl.c.module)
        with self._session_factory() as session:
            rows = session.execute(stmt).all()
        return [self._row_to_dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(row: Any) -> dict[str, Any]:
        """Convert a SQLAlchemy row to a JSON-serialisable dict."""
        d = dict(row._mapping)
        for key, val in d.items():
            if hasattr(val, "isoformat"):
                d[key] = val.isoformat()
        return d

    # ------------------------------------------------------------------
    # Statistics / trend queries
    # ------------------------------------------------------------------

    def stats_submissions_by_brand(self, days: int = 30) -> list[dict[str, Any]]:
        """Return submission counts grouped by brand and date.

        Joins ``ecx_submissions`` with ``ecx_enrichments`` to correlate
        brand names, then aggregates by day.  Returns a list of dicts:
        ``[{brand, date, count}]`` sorted by date ascending.
        """
        subs = sql_schema.ecx_submissions
        enr = sql_schema.ecx_enrichments
        cutoff = datetime.now(UTC) - timedelta(days=days)

        # Brand is stored in ecx_enrichments.ecx_data JSON.
        # We join on scan_id and extract brand from the JSON field.
        stmt = (
            sa.select(
                enr.c.ecx_data["brand"].label("brand"),
                sa.func.date(subs.c.created_at).label("date"),
                sa.func.count().label("count"),
            )
            .select_from(subs.join(enr, subs.c.scan_id == enr.c.scan_id, isouter=True))
            .where(subs.c.ecx_module == "phish")
            .where(subs.c.created_at >= cutoff)
            .group_by("brand", "date")
            .order_by(sa.text("date"))
        )

        with self._session_factory() as session:
            rows = session.execute(stmt).all()

        results: list[dict[str, Any]] = []
        for r in rows:
            brand_val = r.brand if r.brand else "unknown"
            # Strip JSON quotes from SQLite JSON extraction
            if isinstance(brand_val, str):
                brand_val = brand_val.strip('"')
            results.append({"brand": brand_val, "date": str(r.date), "count": r.count})
        return results

    def stats_wallet_heatmap(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return top wallets by occurrence count, grouped by currency.

        Returns ``[{token_symbol, network_short, wallet_address, count}]``
        ordered by count descending.
        """
        tbl = sql_schema.harvested_wallets
        stmt = (
            sa.select(
                tbl.c.token_symbol,
                tbl.c.network_short,
                tbl.c.wallet_address,
                sa.func.count().label("count"),
            )
            .group_by(tbl.c.token_symbol, tbl.c.network_short, tbl.c.wallet_address)
            .order_by(sa.desc("count"))
            .limit(limit)
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).all()
        return [
            {
                "token_symbol": r.token_symbol,
                "network_short": r.network_short,
                "wallet_address": r.wallet_address,
                "count": r.count,
            }
            for r in rows
        ]

    def stats_wallet_currency_breakdown(self) -> list[dict[str, Any]]:
        """Return wallet counts grouped by token_symbol (currency).

        Returns ``[{token_symbol, count}]`` ordered by count descending.
        """
        tbl = sql_schema.harvested_wallets
        stmt = (
            sa.select(
                tbl.c.token_symbol,
                sa.func.count().label("count"),
            )
            .group_by(tbl.c.token_symbol)
            .order_by(sa.desc("count"))
        )
        with self._session_factory() as session:
            rows = session.execute(stmt).all()
        return [{"token_symbol": r.token_symbol, "count": r.count} for r in rows]

    def stats_geo_infrastructure(self, days: int = 90) -> list[dict[str, Any]]:
        """Return geographic distribution from enrichment data.

        Extracts ``country_code`` (or ``ip_country``) from the
        ``ecx_data`` JSON in ``ecx_enrichments`` and aggregates by
        country.  Returns ``[{country, count}]`` ordered by count
        descending.
        """
        tbl = sql_schema.ecx_enrichments
        cutoff = datetime.now(UTC) - timedelta(days=days)

        stmt = (
            sa.select(tbl.c.ecx_data, tbl.c.queried_at)
            .where(tbl.c.queried_at >= cutoff)
            .where(tbl.c.ecx_record_id.isnot(None))
        )

        with self._session_factory() as session:
            rows = session.execute(stmt).all()

        country_counts: dict[str, int] = {}
        for r in rows:
            data = r.ecx_data or {}
            if isinstance(data, str):
                import json

                try:
                    data = json.loads(data)
                except (json.JSONDecodeError, TypeError):
                    continue
            country = data.get("country_code") or data.get("ip_country") or data.get("country") or "unknown"
            if isinstance(country, str):
                country = country.strip('"').upper()
            country_counts[country] = country_counts.get(country, 0) + 1

        return sorted(
            [{"country": k, "count": v} for k, v in country_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )

    # ------------------------------------------------------------------
    # Case creation (direct DB write to core's tables)
    # ------------------------------------------------------------------

    def create_case_record(
        self,
        *,
        scan_id: str,
        result: Any,
        dataset: str = "ssi",
    ) -> str | None:
        """Create a case record directly in core's DB tables.

        Inserts into ``cases``, ``scam_records``, and ``review_queue``
        so the analyst console can display the case.  Also links the
        scan row's ``case_id`` foreign key.

        Writes directly to the shared database so both SSI and
        the analyst console see the same data without HTTP round-trips.

        Args:
            scan_id: The investigation's scan_id (links ``site_scans``).
            result: An ``InvestigationResult`` instance.
            dataset: Dataset label (e.g. ``"ssi"``).

        Returns:
            The ``case_id`` if the case was created, or ``None`` on failure.
        """
        import hashlib
        import json
        from urllib.parse import urlparse

        now = datetime.now(UTC)
        case_id = str(uuid4())

        # Build title
        title = ""
        try:
            domain = urlparse(result.url).netloc or result.url
            if domain.startswith("www."):
                domain = domain[4:]
            intent_label = ""
            if result.taxonomy_result and result.taxonomy_result.intent:
                top_intent = result.taxonomy_result.intent[0]
                if top_intent.label:
                    intent_label = top_intent.label.replace("INTENT.", "").replace("_", " ").title()
            elif result.classification and result.classification.intent:
                intent_label = result.classification.intent.replace("_", " ").title()
            prefix = intent_label if intent_label else "Investigation"
            title = f"{prefix} — {domain}"
        except Exception:
            title = f"Investigation — {result.url[:60] if result.url else 'unknown'}"

        # Content hash for dedup (matches core's POST /cases logic)
        metadata_dict = {
            "title": title,
            "ssi_investigation_id": scan_id,
            "scan_type": (
                result.scan_type
                if isinstance(result.scan_type, str)
                else (result.scan_type.value if result.scan_type else "full")
            ),
            "passive_only": result.passive_only,
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "duration_seconds": result.duration_seconds,
        }
        raw_content = json.dumps(metadata_dict, sort_keys=True) + (result.url or "")
        raw_text_sha256 = hashlib.sha256(raw_content.encode()).hexdigest()

        classification_result = None
        risk_score: float = 0.0
        if result.taxonomy_result:
            classification_result = result.taxonomy_result.model_dump(mode="json")
            risk_score = result.taxonomy_result.risk_score or 0.0

        priority = "high" if risk_score >= 70 else "medium"

        try:
            with self._session_factory() as session:
                # Check for existing case with same dataset + hash (dedup)
                existing = session.execute(
                    sa.select(sql_schema.cases.c.case_id)
                    .where(sql_schema.cases.c.dataset == dataset)
                    .where(sql_schema.cases.c.raw_text_sha256 == raw_text_sha256)
                ).scalar()

                if existing:
                    case_id = existing
                    # Update existing case with latest results
                    update_vals: dict[str, Any] = {"updated_at": now}
                    if classification_result:
                        update_vals["classification_result"] = classification_result
                        update_vals["classification_status"] = "completed"
                    if risk_score:
                        update_vals["risk_score"] = risk_score
                    update_vals["metadata"] = metadata_dict
                    session.execute(
                        sa.update(sql_schema.cases).where(sql_schema.cases.c.case_id == existing).values(**update_vals)
                    )
                else:
                    # Insert new case
                    session.execute(
                        sa.insert(sql_schema.cases).values(
                            case_id=case_id,
                            dataset=dataset,
                            source_type="ssi_investigation",
                            classification=None,
                            classification_status="completed" if classification_result else "pending",
                            classification_result=classification_result,
                            confidence=0,
                            risk_score=risk_score,
                            raw_text_sha256=raw_text_sha256,
                            status="open",
                            metadata=metadata_dict,
                            created_at=now,
                            updated_at=now,
                        )
                    )

                    # Insert scam_records row (needed for dashboard join)
                    insert_sr = dialect_insert(session, sql_schema.scam_records)
                    session.execute(
                        insert_sr.values(
                            case_id=case_id,
                            text=result.url or "",
                            entities=None,
                            classification=None,
                            confidence=0,
                            classification_result=classification_result,
                            tags=None,
                            created_at=now,
                            metadata=metadata_dict,
                        ).on_conflict_do_nothing(index_elements=["case_id"])
                    )

                    # Insert review_queue row (makes case visible on dashboard)
                    review_id = str(uuid4())
                    insert_rq = dialect_insert(session, sql_schema.review_queue)
                    session.execute(
                        insert_rq.values(
                            review_id=review_id,
                            case_id=case_id,
                            queued_at=now,
                            priority=priority,
                            status="new",
                            last_updated=now,
                            classification_result=classification_result,
                        ).on_conflict_do_nothing(index_elements=["review_id"])
                    )

                    # Insert timeline events so the case detail page has
                    # a populated timeline card.
                    self._insert_timeline_events(
                        session,
                        review_id=review_id,
                        result=result,
                        scan_id=scan_id,
                        now=now,
                    )

                    # Insert source_documents rows pointing at GCS
                    # evidence files so the Artifacts card is populated.
                    self._insert_evidence_documents(
                        session,
                        case_id=case_id,
                        result=result,
                        now=now,
                    )

                # Link the scan row to the case
                session.execute(
                    sa.update(sql_schema.site_scans)
                    .where(sql_schema.site_scans.c.scan_id == scan_id)
                    .values(case_id=case_id, updated_at=now)
                )

                # Write to case_investigations join table (many-to-many link)
                link_insert = dialect_insert(session, sql_schema.case_investigations)
                session.execute(
                    link_insert.values(
                        case_id=case_id,
                        scan_id=scan_id,
                        trigger_type="case_created",
                    ).on_conflict_do_nothing()
                )

                session.commit()

            logger.info("Created case record %s for scan %s (dataset=%s)", case_id, scan_id, dataset)
            return case_id

        except Exception:
            logger.exception("Failed to create case record for scan %s", scan_id)
            return None

    # ------------------------------------------------------------------
    # Timeline & evidence insertion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _insert_timeline_events(
        session: Any,
        *,
        review_id: str,
        result: Any,
        scan_id: str,
        now: datetime,
    ) -> int:
        """Insert ``review_actions`` rows for SSI investigation milestones.

        Writes investigation milestone events directly to the
        database as ``review_actions`` rows.

        Args:
            session: Active SQLAlchemy session.
            review_id: The ``review_queue.review_id`` for this case.
            result: An ``InvestigationResult`` instance.
            scan_id: Investigation scan ID.
            now: Current UTC timestamp.

        Returns:
            Number of events inserted.
        """
        events: list[dict[str, Any]] = []

        # 1. Investigation submitted
        if result.started_at:
            events.append(
                {
                    "action": "investigation_submitted",
                    "description": f"SSI investigation initiated for {result.url}",
                    "ts": result.started_at,
                }
            )

        # 2. Classification completed
        if result.taxonomy_result:
            intent_label = "unknown"
            if result.taxonomy_result.intent:
                top = result.taxonomy_result.intent[0]
                raw = getattr(top, "label", str(top))
                intent_label = raw.replace("INTENT.", "").replace("_", " ").title()
            events.append(
                {
                    "action": "classification_completed",
                    "description": (
                        f"Classified as {intent_label} " f"(risk score: {result.taxonomy_result.risk_score:.0f})"
                    ),
                    "ts": result.completed_at or now,
                }
            )

        # 3. Wallets harvested
        wallet_count = 0
        networks: set[str] = set()
        if hasattr(result, "wallets") and result.wallets:
            wallet_count = len(result.wallets)
            for w in result.wallets:
                net = getattr(w, "network_short", None) or getattr(w, "token_symbol", None)
                if net:
                    networks.add(str(net))
        elif result.threat_indicators:
            for ti in result.threat_indicators:
                if ti.indicator_type == "crypto_wallet":
                    wallet_count += 1
                    if ti.context:
                        networks.add(ti.context)
        if wallet_count > 0:
            net_str = ", ".join(sorted(networks)) if networks else "unknown"
            suffix = "es" if wallet_count != 1 else ""
            events.append(
                {
                    "action": "wallets_harvested",
                    "description": f"Found {wallet_count} wallet address{suffix} ({net_str})",
                    "ts": result.completed_at or now,
                }
            )

        # 4. Evidence collected
        evidence_count = 0
        if result.chain_of_custody:
            evidence_count = result.chain_of_custody.total_artifacts
        elif result.output_path:
            output = Path(result.output_path)
            if output.is_dir():
                evidence_count = sum(1 for f in output.rglob("*") if f.is_file())
        if evidence_count > 0:
            suffix = "s" if evidence_count != 1 else ""
            events.append(
                {
                    "action": "evidence_collected",
                    "description": f"Collected {evidence_count} evidence artifact{suffix}",
                    "ts": result.completed_at or now,
                }
            )

        # 5. Report generated
        has_report = False
        if result.output_path:
            report_path = Path(result.output_path)
            if report_path.is_dir() and (report_path / "report.md").is_file():
                has_report = True
            elif str(result.output_path).startswith("gs://"):
                # On GCS the file check is not possible but the report
                # was always generated if the investigation succeeded.
                has_report = result.success
        if has_report:
            events.append(
                {
                    "action": "report_generated",
                    "description": "Investigation report generated",
                    "ts": result.completed_at or now,
                }
            )

        # 6. Case created
        events.append(
            {
                "action": "case_created",
                "description": f"Case created from SSI investigation {scan_id}",
                "ts": now,
            }
        )

        rows = []
        for ev in events:
            rows.append(
                {
                    "action_id": str(uuid4()),
                    "review_id": review_id,
                    "actor": "ssi-agent",
                    "action": ev["action"],
                    "payload": {
                        "description": ev["description"],
                        "timestamp": ev["ts"].isoformat() if hasattr(ev["ts"], "isoformat") else str(ev["ts"]),
                    },
                    "created_at": ev["ts"],
                }
            )

        if rows:
            session.execute(sa.insert(sql_schema.review_actions), rows)
            logger.info("Inserted %d timeline events for review %s", len(rows), review_id)

        return len(rows)

    @staticmethod
    def _insert_evidence_documents(
        session: Any,
        *,
        case_id: str,
        result: Any,
        now: datetime,
    ) -> int:
        """Insert ``source_documents`` rows for SSI evidence artifacts.

        Creates a document row for each artifact listed in
        ``result.chain_of_custody.artifacts``.  When evidence is stored
        on GCS (Cloud Run Job path), the ``source_url`` is the
        ``gs://`` URI built from ``result.output_path``.

        Args:
            session: Active SQLAlchemy session.
            case_id: The parent case.
            result: An ``InvestigationResult`` instance.
            now: Current UTC timestamp.

        Returns:
            Number of documents inserted.
        """
        evidence_mime: dict[str, str] = {
            ".json": "application/json",
            ".md": "text/markdown",
            ".pdf": "application/pdf",
            ".zip": "application/zip",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".html": "text/html",
            ".har": "application/json",
            ".stix": "application/json",
        }

        rows: list[dict[str, Any]] = []
        output_path = result.output_path or ""
        is_gcs = output_path.startswith("gs://")

        # Prefer chain_of_custody artifacts (has per-file SHA-256)
        if result.chain_of_custody and result.chain_of_custody.artifacts:
            for art in result.chain_of_custody.artifacts:
                filename = getattr(art, "file", "") or ""
                if not filename:
                    continue
                ext = Path(filename).suffix.lower()
                mime = evidence_mime.get(ext, "application/octet-stream")
                if is_gcs:
                    source_url: str | None = f"{output_path}/{filename}"
                elif output_path:
                    source_url = str(Path(output_path) / filename)
                else:
                    source_url = None
                rows.append(
                    {
                        "document_id": str(uuid4()),
                        "case_id": case_id,
                        "title": filename,
                        "source_url": source_url,
                        "mime_type": mime,
                        "file_sha256": getattr(art, "sha256", None),
                        "captured_at": now,
                        "created_at": now,
                        "updated_at": now,
                        "metadata": {"source": "ssi", "size_bytes": getattr(art, "size_bytes", None)},
                    }
                )
        elif is_gcs:
            # Fallback: insert rows for the well-known evidence files
            # when chain_of_custody isn't available.
            known_files = [
                ("investigation.json", "application/json"),
                ("report.md", "text/markdown"),
                ("report.pdf", "application/pdf"),
                ("leo_evidence_report.md", "text/markdown"),
                ("stix_bundle.json", "application/json"),
                ("evidence.zip", "application/zip"),
            ]
            for fn, mime in known_files:
                rows.append(
                    {
                        "document_id": str(uuid4()),
                        "case_id": case_id,
                        "title": fn,
                        "source_url": f"{output_path}/{fn}",
                        "mime_type": mime,
                        "captured_at": now,
                        "created_at": now,
                        "updated_at": now,
                        "metadata": {"source": "ssi"},
                    }
                )
        elif not is_gcs and output_path:
            # Local filesystem: list actual files in the output directory
            out_dir = Path(output_path)
            if out_dir.is_dir():
                for f in sorted(out_dir.rglob("*")):
                    if not f.is_file():
                        continue
                    ext = f.suffix.lower()
                    mime = evidence_mime.get(ext, "application/octet-stream")
                    rows.append(
                        {
                            "document_id": str(uuid4()),
                            "case_id": case_id,
                            "title": f.name,
                            "source_url": str(f),
                            "mime_type": mime,
                            "captured_at": now,
                            "created_at": now,
                            "updated_at": now,
                            "metadata": {"source": "ssi"},
                        }
                    )

        if rows:
            session.execute(sa.insert(sql_schema.source_documents), rows)
            logger.info("Inserted %d evidence documents for case %s", len(rows), case_id)

        return len(rows)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Map HTML input types / names to PII field categories
_FIELD_TYPE_MAP: dict[str, str] = {
    "email": "email",
    "password": "password",
    "tel": "phone",
    "phone": "phone",
    "name": "name",
    "first_name": "name",
    "last_name": "name",
    "full_name": "name",
    "address": "address",
    "street": "address",
    "city": "address",
    "zip": "address",
    "postal": "address",
    "ssn": "ssn",
    "social": "ssn",
    "tax": "id_number",
    "id_number": "id_number",
    "passport": "id_number",
    "credit_card": "financial",
    "card_number": "financial",
    "cvv": "financial",
    "expiry": "financial",
    "bank": "financial",
    "iban": "financial",
    "routing": "financial",
    "account_number": "financial",
}


def _classify_form_field(field: dict[str, Any]) -> str:
    """Classify an HTML form field into a PII category."""
    input_type = (field.get("type") or "").lower()
    name = (field.get("name") or "").lower()
    label = (field.get("label") or "").lower()

    # Direct type match
    if input_type in ("email", "password", "tel"):
        return _FIELD_TYPE_MAP.get(input_type, "other")

    # Name / label keyword match
    for keyword, category in _FIELD_TYPE_MAP.items():
        if keyword in name or keyword in label:
            return category

    return "other"
