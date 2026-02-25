"""Task status store with pluggable Redis / in-memory backends.

Production deployments use Redis so that task state survives process
restarts and is visible across replicas.  Local development falls back
to an in-memory dict for zero-dependency convenience.

Usage::

    from ssi.store.task_store import build_task_store

    store = build_task_store()
    store.set("task-123", {"status": "running"})
    info = store.get("task-123")
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class TaskStore:
    """Abstract-ish task store interface implemented by both backends."""

    def get(self, task_id: str) -> dict[str, Any] | None:
        """Return the task dict or ``None`` if unknown."""
        raise NotImplementedError

    def set(self, task_id: str, data: dict[str, Any], *, ttl_seconds: int = 0) -> None:
        """Create or replace the task entry.

        Args:
            task_id: Unique task identifier.
            data: Arbitrary JSON-serialisable dict.
            ttl_seconds: Optional time-to-live in seconds (0 = no expiry).
        """
        raise NotImplementedError

    def update(self, task_id: str, **fields: Any) -> None:
        """Merge *fields* into an existing task entry.

        Creates the entry if it does not exist.

        Args:
            task_id: Unique task identifier.
            fields: Key-value pairs to merge.
        """
        existing = self.get(task_id) or {}
        existing.update(fields)
        self.set(task_id, existing)

    def delete(self, task_id: str) -> None:
        """Remove a task entry."""
        raise NotImplementedError

    def exists(self, task_id: str) -> bool:
        """Return True if the task exists."""
        return self.get(task_id) is not None


class InMemoryTaskStore(TaskStore):
    """In-memory task store for local development."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}

    def get(self, task_id: str) -> dict[str, Any] | None:
        """Return the task dict or ``None``."""
        return self._data.get(task_id)

    def set(self, task_id: str, data: dict[str, Any], *, ttl_seconds: int = 0) -> None:
        """Store the task data (TTL ignored in-memory)."""
        self._data[task_id] = data

    def delete(self, task_id: str) -> None:
        """Remove a task entry."""
        self._data.pop(task_id, None)


class RedisTaskStore(TaskStore):
    """Redis-backed task store for production deployments.

    Keys are stored under a configurable prefix (default ``ssi:task:``)
    with an optional TTL so completed tasks expire automatically.

    Args:
        redis_url: Redis connection string (e.g. ``redis://localhost:6379/0``).
        prefix: Key prefix for all task entries.
        default_ttl: Default TTL in seconds (0 = no expiry).
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        prefix: str = "ssi:task:",
        default_ttl: int = 86400,
    ) -> None:
        try:
            import redis as redis_lib
        except ImportError as exc:
            raise ImportError(
                "Redis support requires the 'redis' package. "
                "Install it with: pip install redis"
            ) from exc

        self._client = redis_lib.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = prefix
        self._default_ttl = default_ttl

    def _key(self, task_id: str) -> str:
        """Return the full Redis key for *task_id*."""
        return f"{self._prefix}{task_id}"

    def get(self, task_id: str) -> dict[str, Any] | None:
        """Return the task dict from Redis or ``None``."""
        raw = self._client.get(self._key(task_id))
        if raw is None:
            return None
        return json.loads(raw)

    def set(self, task_id: str, data: dict[str, Any], *, ttl_seconds: int = 0) -> None:
        """Store task data in Redis with optional TTL."""
        effective_ttl = ttl_seconds or self._default_ttl
        key = self._key(task_id)
        payload = json.dumps(data, default=str)
        if effective_ttl > 0:
            self._client.setex(key, effective_ttl, payload)
        else:
            self._client.set(key, payload)

    def delete(self, task_id: str) -> None:
        """Remove task from Redis."""
        self._client.delete(self._key(task_id))


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_singleton: TaskStore | None = None


def build_task_store(*, force_new: bool = False) -> TaskStore:
    """Return a task store matching the current SSI settings.

    The instance is cached as a module singleton so all callers share the
    same store (important for the in-memory backend).

    Args:
        force_new: Bypass the singleton cache and create a fresh instance.

    Returns:
        :class:`TaskStore` instance.
    """
    global _singleton  # noqa: PLW0603
    if _singleton is not None and not force_new:
        return _singleton

    from ssi.settings import get_settings

    settings = get_settings()
    task_cfg = getattr(settings, "task_store", None)

    backend = getattr(task_cfg, "backend", "memory") if task_cfg else "memory"

    if backend == "redis":
        redis_url = getattr(task_cfg, "redis_url", "redis://localhost:6379/0")
        prefix = getattr(task_cfg, "key_prefix", "ssi:task:")
        ttl = getattr(task_cfg, "default_ttl_seconds", 86400)
        logger.info("Using Redis task store at %s (prefix=%s, ttl=%d)", redis_url, prefix, ttl)
        _singleton = RedisTaskStore(redis_url=redis_url, prefix=prefix, default_ttl=ttl)
    else:
        logger.info("Using in-memory task store")
        _singleton = InMemoryTaskStore()

    return _singleton
