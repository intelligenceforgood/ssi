"""Task-status reporter for SSI investigations — direct database variant.

When an SSI investigation is triggered by the core API
(``POST /investigations/ssi``), the caller provides a ``scan_id``
identifying the pre-created scan row in ``site_scans``.

The reporter updates ``site_scans.status`` (and related columns)
directly via ``ScanStore.update_scan()``.

Core's ``GET /tasks/{task_id}`` has a DB fallback: when the
in-memory task entry contains a ``scan_id``, status is read from
``site_scans``.  So direct DB writes here are picked up by the
UI's polling loop transparently.

Falls back to a no-op when ``scan_id`` is absent (standalone mode).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Columns in ``site_scans`` that can be set via **extra kwargs.
_EXTRA_COLUMN_KEYS = frozenset({"risk_score", "case_id", "duration_seconds"})


class TaskStatusReporter:
    """Reports SSI investigation progress by updating the ``site_scans`` DB row.

    Args:
        scan_id: Pre-created scan ID. When empty/None the reporter
            is disabled and all ``update()`` calls are no-ops.
    """

    def __init__(self, scan_id: str | None = None) -> None:
        self.scan_id = scan_id or ""
        self._store: Any | None = None  # lazy ScanStore

    @property
    def is_enabled(self) -> bool:
        """Return ``True`` when a scan_id is available for DB updates."""
        return bool(self.scan_id)

    def update(self, *, status: str, message: str, **extra: Any) -> None:
        """Update the scan status in the database.

        Maps the call to ``ScanStore.update_scan()`` on the
        ``site_scans`` row identified by ``self.scan_id``.

        Args:
            status: Short status string (``running``, ``completed``,
                ``failed``).
            message: Human-readable progress description.  Stored as
                ``error_message`` when *status* is ``"failed"``.
            **extra: Additional fields.  ``risk_score``, ``case_id``,
                and ``duration_seconds`` are persisted to the
                corresponding ``site_scans`` columns; others are
                logged and ignored.
        """
        if not self.is_enabled:
            logger.debug("TaskStatusReporter skipped (no scan_id)")
            return

        fields: dict[str, Any] = {"status": status}

        if status == "failed":
            fields["error_message"] = message
        if status == "completed":
            fields["completed_at"] = datetime.now(timezone.utc)

        # Map recognised extra kwargs to site_scans columns.
        for col in _EXTRA_COLUMN_KEYS:
            if col in extra and extra[col] is not None:
                fields[col] = extra[col]

        try:
            store = self._get_store()
            store.update_scan(self.scan_id, **fields)
            logger.debug("Task status updated via DB: %s → %s", self.scan_id, status)
        except Exception as exc:
            logger.warning("Task status DB update failed for %s: %s", self.scan_id, exc)

    def _get_store(self) -> Any:
        """Lazily build and cache a ``ScanStore`` instance."""
        if self._store is None:
            from ssi.store import build_scan_store

            self._store = build_scan_store()
        return self._store
