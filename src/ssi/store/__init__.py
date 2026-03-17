"""SSI Store — SQL schema, engine helpers, and ScanStore.

SSI shares a single database with core (locally ``core/data/i4g_store.db``,
in cloud the shared Cloud SQL instance).  This package mirrors the four
SSI table definitions (``site_scans``, ``harvested_wallets``,
``agent_sessions``, ``pii_exposures``) so SSI can read/write them
without importing the ``i4g`` package.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ssi.store.scan_store import ScanStore


def build_scan_store(db_path: str | Path | None = None) -> ScanStore:
    """Factory: return a ``ScanStore`` honouring SSI settings.

    When *db_path* is ``None``, the store resolves its database from
    ``get_settings().storage.sqlite_path``. If the ``storage.backend``
    is ``"core_api"``, persistence is disabled and this still
    returns a working store backed by the local SQLite path for
    caching.

    Args:
        db_path: Optional override for the SQLite file path.

    Returns:
        A configured :class:`ScanStore` instance.
    """
    from ssi.store.scan_store import ScanStore

    return ScanStore(db_path=db_path)
