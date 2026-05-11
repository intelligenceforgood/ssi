"""Google Drive OSINT scraper — placeholder.

Drive metadata scraping requires Android OAuth master tokens which are
not yet supported in the SSI auth pipeline.  This module is a forward
declaration so that the package structure is ready for Phase 2.

See: planning/tasks/google-osint-implementation.md § "Out of Scope"
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class GoogleDriveScraper:
    """Placeholder for Google Drive metadata scraping (not yet implemented)."""

    async def resolve_file(self, file_id: str) -> None:
        """Not yet implemented — requires Android OAuth."""
        logger.debug(
            "GoogleDriveScraper.resolve_file(%s) called but Drive " "scraping is not yet implemented",
            file_id,
        )
        return None
