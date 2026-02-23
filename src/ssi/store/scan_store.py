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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from ssi.store import sql as sql_schema
from ssi.store.sql import (
    METADATA,
    build_session_factory,
    dialect_insert,
)

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

        # Ensure schema exists (auto-create for SQLite / local dev)
        with self._session_factory() as session:
            METADATA.create_all(session.connection())

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
    ) -> str:
        """Insert a new ``site_scans`` row and return the ``scan_id``."""
        scan_id = str(uuid4())
        now = datetime.now(timezone.utc)
        with self._session_factory() as session:
            session.execute(
                sa.insert(sql_schema.site_scans).values(
                    scan_id=scan_id,
                    case_id=case_id,
                    url=url,
                    domain=domain,
                    scan_type=scan_type,
                    status="running",
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
        fields["updated_at"] = datetime.now(timezone.utc)
        with self._session_factory() as session:
            session.execute(
                sa.update(sql_schema.site_scans)
                .where(sql_schema.site_scans.c.scan_id == scan_id)
                .values(**fields)
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
        now = datetime.now(timezone.utc)
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
                sa.update(sql_schema.site_scans)
                .where(sql_schema.site_scans.c.scan_id == scan_id)
                .values(**values)
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
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return a paginated list of scans, optionally filtered."""
        stmt = sa.select(sql_schema.site_scans).order_by(sql_schema.site_scans.c.created_at.desc())
        if domain is not None:
            stmt = stmt.where(sql_schema.site_scans.c.domain == domain)
        if status is not None:
            stmt = stmt.where(sql_schema.site_scans.c.status == status)
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
                harvested_at=harvested_at or datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
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
        now = datetime.now(timezone.utc)
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
            stmt = (
                sa.select(
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
                )
                .group_by(
                    hw.c.wallet_address,
                    hw.c.token_symbol,
                    hw.c.token_label,
                    hw.c.network_short,
                    hw.c.network_label,
                )
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
        duration_ms: int | None = None,
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
                    duration_ms=duration_ms,
                    error=error,
                    sequence=sequence,
                    metadata=metadata or {},
                    created_at=datetime.now(timezone.utc),
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
                    detected_at=detected_at or datetime.now(timezone.utc),
                    created_at=datetime.now(timezone.utc),
                )
            )
            session.commit()
        return exposure_id

    def add_pii_exposures_bulk(self, scan_id: str, exposures: list[dict[str, Any]]) -> int:
        """Bulk-insert PII exposure records.  Returns count inserted."""
        if not exposures:
            return 0
        now = datetime.now(timezone.utc)
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
            passive_result["whois"] = result.whois.model_dump(mode="json") if hasattr(result.whois, "model_dump") else {}
        if result.dns:
            passive_result["dns"] = result.dns.model_dump(mode="json") if hasattr(result.dns, "model_dump") else {}
        if result.ssl:
            passive_result["ssl"] = result.ssl.model_dump(mode="json") if hasattr(result.ssl, "model_dump") else {}
        if result.geoip:
            passive_result["geoip"] = result.geoip.model_dump(mode="json") if hasattr(result.geoip, "model_dump") else {}

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
            total_cost_usd = result.cost_summary.get("total_cost_usd") if isinstance(result.cost_summary, dict) else None

        # Wallet count — prefer site_result wallets, fall back to InvestigationResult.wallets
        wallet_entries = []
        if site_result and hasattr(site_result, "wallets"):
            wallet_entries = site_result.wallets or []
        if not wallet_entries and hasattr(result, "wallets"):
            wallet_entries = result.wallets or []

        # Complete the scan row
        if not result.status:
            status = "completed"
        elif result.status.value == "completed":
            status = "completed"
        else:
            status = str(result.status.value)
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
            evidence_zip_sha256=getattr(result.chain_of_custody, "package_sha256", None)
            if result.chain_of_custody
            else None,
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

        logger.info(
            "Persisted investigation for scan %s: %d wallets, %d PII fields",
            scan_id,
            len(wallet_entries),
            len(pii_dicts),
        )


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
