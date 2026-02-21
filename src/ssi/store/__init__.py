"""SSI Store — SQL schema, engine helpers, and ScanStore.

This package provides SSI's local persistence layer, mirroring the four
tables defined in core's schema (``site_scans``, ``harvested_wallets``,
``agent_sessions``, ``pii_exposures``) so SSI can read/write them
independently of the core API.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ssi.store.scan_store import ScanStore


def build_scan_store(db_path: str | Path | None = None) -> "ScanStore":
    """Factory: return a ``ScanStore`` honouring SSI settings.

    When *db_path* is ``None``, the store resolves its database from
    ``get_settings().storage.sqlite_path``. If the ``storage.backend``
    is ``"core_api"`` (results pushed exclusively via ``CoreBridge``),
    persistence is disabled and this still returns a working store
    backed by the local SQLite path for caching.

    Args:
        db_path: Optional override for the SQLite file path.

    Returns:
        A configured :class:`ScanStore` instance.
    """
    from ssi.store.scan_store import ScanStore

    return ScanStore(db_path=db_path)
