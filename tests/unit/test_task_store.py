"""Unit tests for the pluggable task store module."""

from __future__ import annotations

import pytest

from ssi.store.task_store import InMemoryTaskStore, build_task_store


class TestInMemoryTaskStore:
    """Tests for the in-memory (default) backend."""

    def test_set_and_get(self) -> None:
        """Stored data is retrievable by task ID."""
        store = InMemoryTaskStore()
        store.set("t1", {"status": "pending"})
        assert store.get("t1") == {"status": "pending"}

    def test_get_missing_returns_none(self) -> None:
        """Getting a non-existent key returns None."""
        store = InMemoryTaskStore()
        assert store.get("nonexistent") is None

    def test_update_merges_fields(self) -> None:
        """Update merges new fields into an existing entry."""
        store = InMemoryTaskStore()
        store.set("t1", {"status": "running"})
        store.update("t1", result={"success": True})
        task = store.get("t1")
        assert task is not None
        assert task["status"] == "running"
        assert task["result"] == {"success": True}

    def test_update_creates_if_missing(self) -> None:
        """Update creates the entry when the key does not exist."""
        store = InMemoryTaskStore()
        store.update("new", status="pending")
        assert store.get("new") == {"status": "pending"}

    def test_delete(self) -> None:
        """Delete removes an existing entry."""
        store = InMemoryTaskStore()
        store.set("t1", {"status": "done"})
        store.delete("t1")
        assert store.get("t1") is None

    def test_delete_missing_is_noop(self) -> None:
        """Deleting a non-existent key does not raise."""
        store = InMemoryTaskStore()
        store.delete("nope")  # Should not raise

    def test_exists(self) -> None:
        """Exists reflects whether the key has been set."""
        store = InMemoryTaskStore()
        assert store.exists("x") is False
        store.set("x", {"status": "ok"})
        assert store.exists("x") is True

    def test_overwrite(self) -> None:
        """A second set replaces the previous value entirely."""
        store = InMemoryTaskStore()
        store.set("t1", {"status": "pending"})
        store.set("t1", {"status": "completed", "result": {}})
        assert store.get("t1") == {"status": "completed", "result": {}}


class TestBuildTaskStore:
    """Tests for the task store factory."""

    def test_returns_in_memory_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Default settings should yield an InMemoryTaskStore."""
        import ssi.store.task_store as mod

        # Reset singleton
        monkeypatch.setattr(mod, "_singleton", None)
        store = build_task_store(force_new=True)
        assert isinstance(store, InMemoryTaskStore)

    def test_singleton_caching(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Repeated calls return the same instance."""
        import ssi.store.task_store as mod

        monkeypatch.setattr(mod, "_singleton", None)
        s1 = build_task_store(force_new=True)
        s2 = build_task_store()
        assert s1 is s2

    def test_force_new_bypasses_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """force_new=True creates a distinct instance each time."""
        import ssi.store.task_store as mod

        monkeypatch.setattr(mod, "_singleton", None)
        s1 = build_task_store(force_new=True)
        s2 = build_task_store(force_new=True)
        assert s1 is not s2
