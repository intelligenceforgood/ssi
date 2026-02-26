"""Task-status reporter for SSI jobs that posts updates to core's API.

When an SSI Cloud Run Job is triggered by the core API
(``POST /investigations/ssi``), the job receives two environment
variables:

* ``I4G_TASK_ID`` — the task identifier to update.
* ``I4G_TASK_STATUS_URL`` — base URL for the task status API
  (e.g. ``https://api.intelligenceforgood.org/tasks``).

The reporter posts JSON payloads to
``{I4G_TASK_STATUS_URL}/{task_id}/update`` using the configured
API key for authentication.

Falls back to a no-op if neither env var is set (standalone mode).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class TaskStatusReporter:
    """Reports SSI job progress back to the i4g core task-status API.

    Designed to mirror core's ``TaskStatusReporter`` but adapted for
    cross-service HTTP communication with API-key auth.

    Args:
        task_id: Task identifier (from ``I4G_TASK_ID`` env var).
        endpoint: Base URL for the task status API.
        api_key: API key for authenticating with the core API.
        iap_audience: IAP OAuth client ID for acquiring an OIDC token.
    """

    def __init__(
        self,
        task_id: str | None = None,
        endpoint: str | None = None,
        api_key: str | None = None,
        iap_audience: str | None = None,
    ) -> None:
        self.task_id = task_id or os.environ.get("I4G_TASK_ID", "")
        self.endpoint = endpoint or os.environ.get("I4G_TASK_STATUS_URL", "")
        self._api_key = api_key or os.environ.get("SSI_INTEGRATION__CORE_API_KEY", "")
        self._iap_audience = iap_audience or os.environ.get("SSI_INTEGRATION__IAP_AUDIENCE", "")

    @property
    def is_enabled(self) -> bool:
        """Return ``True`` when both task ID and endpoint are available."""
        return bool(self.task_id and self.endpoint)

    def update(self, *, status: str, message: str, **extra: Any) -> None:
        """Post a task-status update to the core API.

        Args:
            status: Short status string (e.g. ``running``, ``completed``).
            message: Human-readable progress description.
            **extra: Additional JSON-serializable fields.
        """
        if not self.is_enabled:
            logger.debug("TaskStatusReporter skipped (task_id=%s, endpoint=%s)", self.task_id, self.endpoint)
            return

        body: dict[str, Any] = {"status": status, "message": message}
        body.update(extra)

        url = f"{self.endpoint.rstrip('/')}/{self.task_id}/update"
        headers = self._build_headers()

        try:
            resp = httpx.post(url, json=body, headers=headers, timeout=10.0)
            resp.raise_for_status()
            logger.debug("Task status updated: %s → %s", self.task_id, status)
        except httpx.HTTPError as exc:
            logger.warning("Task status POST failed (%s): %s", url, exc)

    def _build_headers(self) -> dict[str, str]:
        """Build auth headers for the core API.

        Uses the same dual-auth pattern as ``CoreBridge``:
        OIDC Bearer token for IAP + API key fallback.

        Returns:
            Header dict with authentication credentials.
        """
        headers: dict[str, str] = {}

        if self._api_key:
            headers["X-API-KEY"] = self._api_key

        if self._iap_audience:
            try:
                from google.auth.transport.requests import Request
                from google.oauth2 import id_token

                token = id_token.fetch_id_token(Request(), self._iap_audience)
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            except Exception as exc:
                logger.debug("Could not fetch OIDC token for task updates: %s", exc)

        return headers
