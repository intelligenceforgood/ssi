"""Playbook matcher — URL-to-playbook matching engine.

The matcher holds a registry of ``Playbook`` instances and returns the
first playbook whose ``url_pattern`` regex matches a given site URL.
Disabled playbooks (``enabled=False``) are skipped.
"""

from __future__ import annotations

import logging
import re

from ssi.playbook.models import Playbook

logger = logging.getLogger(__name__)


class PlaybookMatcher:
    """Matches site URLs to registered playbooks.

    Playbooks are checked in registration order. The first match wins.
    Disabled playbooks are ignored.
    """

    def __init__(self) -> None:
        self._playbooks: list[Playbook] = []
        self._compiled: dict[str, re.Pattern[str]] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, playbook: Playbook) -> None:
        """Register a playbook for matching.

        Args:
            playbook: The playbook to add to the registry.
        """
        self._playbooks.append(playbook)
        try:
            self._compiled[playbook.playbook_id] = re.compile(playbook.url_pattern, re.IGNORECASE)
        except re.error as exc:
            logger.warning(
                "Failed to compile url_pattern for playbook %s: %s",
                playbook.playbook_id,
                exc,
            )

    def register_many(self, playbooks: list[Playbook]) -> int:
        """Register multiple playbooks at once.

        Args:
            playbooks: List of playbooks to register.

        Returns:
            The number of playbooks successfully registered.
        """
        count = 0
        for pb in playbooks:
            self.register(pb)
            count += 1
        return count

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match(self, site_url: str) -> Playbook | None:
        """Find the first enabled playbook whose url_pattern matches the URL.

        Args:
            site_url: The site URL to match against.

        Returns:
            The matching ``Playbook``, or ``None`` if no match.
        """
        for pb in self._playbooks:
            if not pb.enabled:
                continue
            compiled = self._compiled.get(pb.playbook_id)
            if compiled is None:
                continue
            try:
                if compiled.search(site_url):
                    logger.info(
                        "Playbook match: %s → %s",
                        site_url,
                        pb.playbook_id,
                    )
                    return pb
            except Exception:
                logger.warning("Error matching playbook %s against %s", pb.playbook_id, site_url)
                continue
        return None

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def count(self) -> int:
        """Return the number of registered playbooks."""
        return len(self._playbooks)

    @property
    def playbooks(self) -> list[Playbook]:
        """Return a copy of all registered playbooks."""
        return list(self._playbooks)

    def get(self, playbook_id: str) -> Playbook | None:
        """Retrieve a playbook by ID.

        Args:
            playbook_id: The unique playbook identifier.

        Returns:
            The matching playbook or ``None``.
        """
        for pb in self._playbooks:
            if pb.playbook_id == playbook_id:
                return pb
        return None

    def remove(self, playbook_id: str) -> bool:
        """Remove a playbook by ID.

        Args:
            playbook_id: The unique playbook identifier.

        Returns:
            ``True`` if found and removed, ``False`` otherwise.
        """
        for i, pb in enumerate(self._playbooks):
            if pb.playbook_id == playbook_id:
                self._playbooks.pop(i)
                self._compiled.pop(playbook_id, None)
                return True
        return False

    def clear(self) -> None:
        """Remove all registered playbooks."""
        self._playbooks.clear()
        self._compiled.clear()
