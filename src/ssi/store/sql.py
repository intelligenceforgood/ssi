"""SQLAlchemy table definitions for SSI scan persistence.

These table definitions mirror the corresponding tables added to
``core/src/i4g/store/sql.py`` so that SSI can operate against its own
local SQLite database or a shared Cloud SQL instance without importing
from the ``i4g`` package.

All tables share the same ``METADATA`` instance used by ``create_all``
and Alembic (in core) for schema management.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session, sessionmaker

JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TIMESTAMP = sa.DateTime(timezone=True)
UUID_TYPE = sa.String(length=64)

METADATA = sa.MetaData()

# ---------------------------------------------------------------------------
# site_scans — one row per investigation / scan run
# ---------------------------------------------------------------------------

site_scans = sa.Table(
    "site_scans",
    METADATA,
    sa.Column("scan_id", UUID_TYPE, primary_key=True),
    sa.Column("case_id", sa.Text(), nullable=True),
    sa.Column("url", sa.Text(), nullable=False),
    sa.Column("domain", sa.Text(), nullable=True),
    sa.Column("scan_type", sa.Text(), nullable=False, server_default="passive"),
    sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
    sa.Column("passive_result", JSON_TYPE, nullable=True),
    sa.Column("active_result", JSON_TYPE, nullable=True),
    sa.Column("classification_result", JSON_TYPE, nullable=True),
    sa.Column("risk_score", sa.Numeric(5, 1), nullable=True),
    sa.Column("taxonomy_version", sa.Text(), nullable=True),
    sa.Column("wallet_count", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("total_cost_usd", sa.Numeric(10, 6), nullable=True),
    sa.Column("llm_input_tokens", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("llm_output_tokens", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("duration_seconds", sa.Numeric(10, 2), nullable=True),
    sa.Column("error_message", sa.Text(), nullable=True),
    sa.Column("evidence_path", sa.Text(), nullable=True),
    sa.Column("evidence_zip_sha256", sa.Text(), nullable=True),
    sa.Column("metadata", JSON_TYPE, nullable=True),
    sa.Column("started_at", TIMESTAMP, nullable=True),
    sa.Column("completed_at", TIMESTAMP, nullable=True),
    sa.Column("created_at", TIMESTAMP, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    sa.Column("updated_at", TIMESTAMP, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
)
sa.Index("idx_site_scans_case_id", site_scans.c.case_id)
sa.Index("idx_site_scans_domain", site_scans.c.domain)
sa.Index("idx_site_scans_status", site_scans.c.status)
sa.Index("idx_site_scans_created_at", site_scans.c.created_at)
sa.Index("idx_site_scans_risk_score", site_scans.c.risk_score)

# ---------------------------------------------------------------------------
# harvested_wallets — extracted cryptocurrency addresses
# ---------------------------------------------------------------------------

harvested_wallets = sa.Table(
    "harvested_wallets",
    METADATA,
    sa.Column("wallet_id", UUID_TYPE, primary_key=True),
    sa.Column("scan_id", UUID_TYPE, nullable=False),
    sa.Column("case_id", sa.Text(), nullable=True),
    sa.Column("token_label", sa.Text(), nullable=True),
    sa.Column("token_symbol", sa.Text(), nullable=False),
    sa.Column("network_label", sa.Text(), nullable=True),
    sa.Column("network_short", sa.Text(), nullable=False),
    sa.Column("wallet_address", sa.Text(), nullable=False),
    sa.Column("source", sa.Text(), nullable=False, server_default="js"),
    sa.Column("confidence", sa.Numeric(3, 2), nullable=False, server_default="0"),
    sa.Column("site_url", sa.Text(), nullable=True),
    sa.Column("metadata", JSON_TYPE, nullable=True),
    sa.Column("harvested_at", TIMESTAMP, nullable=True),
    sa.Column("created_at", TIMESTAMP, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    sa.UniqueConstraint("scan_id", "token_symbol", "network_short", "wallet_address", name="uq_wallets_scan_token_addr"),
)
sa.Index("idx_wallets_scan_id", harvested_wallets.c.scan_id)
sa.Index("idx_wallets_case_id", harvested_wallets.c.case_id)
sa.Index("idx_wallets_address", harvested_wallets.c.wallet_address)
sa.Index("idx_wallets_token_symbol", harvested_wallets.c.token_symbol)

# ---------------------------------------------------------------------------
# agent_sessions — per-action audit trail for the browser agent
# ---------------------------------------------------------------------------

agent_sessions = sa.Table(
    "agent_sessions",
    METADATA,
    sa.Column("session_id", UUID_TYPE, primary_key=True),
    sa.Column("scan_id", UUID_TYPE, nullable=False),
    sa.Column("state", sa.Text(), nullable=False),
    sa.Column("action_type", sa.Text(), nullable=True),
    sa.Column("action_detail", JSON_TYPE, nullable=True),
    sa.Column("screenshot_path", sa.Text(), nullable=True),
    sa.Column("page_url", sa.Text(), nullable=True),
    sa.Column("dom_confidence", sa.Numeric(5, 2), nullable=True),
    sa.Column("llm_model", sa.Text(), nullable=True),
    sa.Column("llm_input_tokens", sa.Integer(), nullable=True),
    sa.Column("llm_output_tokens", sa.Integer(), nullable=True),
    sa.Column("cost_usd", sa.Numeric(10, 6), nullable=True),
    sa.Column("duration_ms", sa.Integer(), nullable=True),
    sa.Column("error", sa.Text(), nullable=True),
    sa.Column("sequence", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("metadata", JSON_TYPE, nullable=True),
    sa.Column("created_at", TIMESTAMP, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
)
sa.Index("idx_agent_sessions_scan_id", agent_sessions.c.scan_id, agent_sessions.c.sequence)
sa.Index("idx_agent_sessions_state", agent_sessions.c.state)

# ---------------------------------------------------------------------------
# pii_exposures — PII fields the scam site collects
# ---------------------------------------------------------------------------

pii_exposures = sa.Table(
    "pii_exposures",
    METADATA,
    sa.Column("exposure_id", UUID_TYPE, primary_key=True),
    sa.Column("scan_id", UUID_TYPE, nullable=False),
    sa.Column("case_id", sa.Text(), nullable=True),
    sa.Column("field_type", sa.Text(), nullable=False),
    sa.Column("field_label", sa.Text(), nullable=True),
    sa.Column("form_action", sa.Text(), nullable=True),
    sa.Column("page_url", sa.Text(), nullable=True),
    sa.Column("is_required", sa.Boolean(), nullable=True),
    sa.Column("was_submitted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    sa.Column("metadata", JSON_TYPE, nullable=True),
    sa.Column("detected_at", TIMESTAMP, nullable=True),
    sa.Column("created_at", TIMESTAMP, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
)
sa.Index("idx_pii_exposures_scan_id", pii_exposures.c.scan_id)
sa.Index("idx_pii_exposures_case_id", pii_exposures.c.case_id)
sa.Index("idx_pii_exposures_field_type", pii_exposures.c.field_type)


# ---------------------------------------------------------------------------
# Engine / session helpers
# ---------------------------------------------------------------------------


def build_engine(*, db_path: str | Path | None = None, echo: bool = False) -> sa.Engine:
    """Create a SQLAlchemy engine for SSI's scan database.

    Behaviour depends on ``get_settings().storage.backend``:

    - **sqlite** (default) — local file at *db_path* or
      ``settings.storage.sqlite_path``.
    - **cloudsql** — Google Cloud SQL via
      ``google-cloud-sql-connector`` with optional IAM authentication.
      Connection parameters come from ``StorageSettings.cloudsql_*``
      fields (typically set via ``SSI_STORAGE__CLOUDSQL_*`` env vars).

    Args:
        db_path: Override path for the SQLite file.  Ignored when the
            backend is ``cloudsql``.
        echo: When True, log all SQL statements.
    """
    from ssi.settings import get_settings

    settings = get_settings()
    backend = settings.storage.backend

    if backend == "cloudsql":
        return _build_cloudsql_engine(settings, echo=echo)

    # Default: SQLite
    if db_path is None:
        db_path = settings.storage.sqlite_path

    resolved = Path(db_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{resolved.as_posix()}"
    return sa.create_engine(
        url,
        echo=echo,
        pool_pre_ping=True,
        connect_args={"check_same_thread": False, "timeout": 30},
    )


def _build_cloudsql_engine(settings: Any, *, echo: bool = False) -> sa.Engine:
    """Build a PostgreSQL engine via ``cloud-sql-python-connector``.

    Uses the same approach as the core platform: the Cloud SQL Python
    Connector manages IAM token generation and connects directly to the
    Cloud SQL instance's public IP.  This does **not** require the
    Cloud Run built-in proxy volume mount.

    The service account must have ``roles/cloudsql.client`` and
    ``roles/cloudsql.instanceUser``, and must be registered as a Cloud SQL
    IAM database user (``google_sql_user`` with type
    ``CLOUD_IAM_SERVICE_ACCOUNT``).

    Args:
        settings: The resolved SSI settings object.
        echo: When True, log all SQL statements.

    Raises:
        ValueError: When required connection fields are missing.
    """
    import logging

    from google.cloud.sql.connector import Connector, IPTypes

    log = logging.getLogger(__name__)

    storage = settings.storage
    instance = storage.cloudsql_instance
    db_user = storage.cloudsql_user
    db_name = storage.cloudsql_database
    enable_iam_auth = storage.cloudsql_enable_iam_auth

    if not all([instance, db_user, db_name]):
        raise ValueError(
            "Missing Cloud SQL configuration: set SSI_STORAGE__CLOUDSQL_INSTANCE, "
            "SSI_STORAGE__CLOUDSQL_DATABASE, and SSI_STORAGE__CLOUDSQL_USER."
        )

    # Auto-detect IAM auth: if the username looks like a service-account IAM
    # user (contains ".iam"), force enable_iam_auth regardless of the setting.
    # This prevents silent failures where the setting defaults to False.
    if ".iam" in db_user and not enable_iam_auth:
        log.warning(
            "CloudSQL user %r looks like an IAM user but enable_iam_auth=%s — "
            "forcing enable_iam_auth=True",
            db_user,
            enable_iam_auth,
        )
        enable_iam_auth = True

    log.info(
        "Connecting to Cloud SQL: instance=%s, user=%s, db=%s, iam_auth=%s",
        instance,
        db_user,
        db_name,
        enable_iam_auth,
    )

    connector = Connector()

    def getconn():
        """Create a new pg8000 connection via the Cloud SQL Connector."""
        return connector.connect(
            instance,
            "pg8000",
            user=db_user,
            db=db_name,
            ip_type=IPTypes.PUBLIC,
            enable_iam_auth=enable_iam_auth,
        )

    return sa.create_engine(
        "postgresql+pg8000://",
        creator=getconn,
        echo=echo,
        pool_pre_ping=True,
    )


def build_session_factory(*, db_path: str | Path | None = None) -> sessionmaker:
    """Return a ``sessionmaker`` bound to the SSI scan engine."""
    engine = build_engine(db_path=db_path)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def dialect_insert(session: Session, table: sa.Table) -> sa.Insert:
    """Return a dialect-aware INSERT that supports ``on_conflict_do_update``.

    Picks the correct dialect (SQLite or PostgreSQL) based on the session's
    bound engine.
    """
    bind = session.get_bind()
    dialect_name = bind.dialect.name
    if dialect_name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    return insert(table)
