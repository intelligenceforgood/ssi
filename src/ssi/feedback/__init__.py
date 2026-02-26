"""Investigation outcome feedback loop.

Tracks whether evidence produced by SSI investigations leads to
actionable outcomes (takedowns, prosecutions, intel sharing).
Stores feedback in a local SQLite database and exposes an API-friendly
interface for recording and querying outcomes.

The feedback data is used to:

1. Measure SSI effectiveness (success metrics from the proposal).
2. Weight future classification confidence (sites similar to
   prosecuted ones get a confidence boost).
3. Identify investigation patterns that produce the best evidence.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class OutcomeType(str, Enum):
    """Possible outcomes of an investigation."""

    PENDING = "pending"
    TAKEDOWN_REQUESTED = "takedown_requested"
    TAKEDOWN_COMPLETED = "takedown_completed"
    REFERRED_TO_LEA = "referred_to_lea"
    PROSECUTION_INITIATED = "prosecution_initiated"
    PROSECUTION_COMPLETED = "prosecution_completed"
    INTEL_SHARED = "intel_shared"
    FALSE_POSITIVE = "false_positive"
    NO_ACTION = "no_action"


class FeedbackRecord(BaseModel):
    """A single feedback entry for an investigation."""

    feedback_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    outcome: OutcomeType = OutcomeType.PENDING
    notes: str = ""
    lea_partner: str = ""
    case_reference: str = ""
    submitted_by: str = ""
    submitted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = Field(default_factory=dict)


class FeedbackStats(BaseModel):
    """Aggregated feedback statistics."""

    total_investigations: int = 0
    total_feedback: int = 0
    outcomes: dict[str, int] = Field(default_factory=dict)
    prosecution_rate: float = 0.0
    takedown_rate: float = 0.0
    false_positive_rate: float = 0.0
    avg_days_to_outcome: float = 0.0


class FeedbackStore:
    """SQLite-backed feedback store for investigation outcomes.

    Args:
        db_path: Path to the SQLite database file.
    """

    _CREATE_TABLE = """
        CREATE TABLE IF NOT EXISTS feedback (
            feedback_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            outcome TEXT NOT NULL DEFAULT 'pending',
            notes TEXT DEFAULT '',
            lea_partner TEXT DEFAULT '',
            case_reference TEXT DEFAULT '',
            submitted_by TEXT DEFAULT '',
            submitted_at TEXT NOT NULL,
            metadata TEXT DEFAULT '{}',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """

    _CREATE_INDEX = """
        CREATE INDEX IF NOT EXISTS idx_feedback_investigation
        ON feedback(investigation_id)
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            from ssi.settings import get_settings

            settings = get_settings()
            db_path = Path(settings.evidence.output_dir) / "feedback.db"

        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create the feedback table if it doesn't exist."""
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(self._CREATE_TABLE)
            conn.execute(self._CREATE_INDEX)
            conn.commit()

    def record(self, feedback: FeedbackRecord) -> str:
        """Store a new feedback record.

        Args:
            feedback: The feedback to record.

        Returns:
            The feedback_id.
        """
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                """
                INSERT INTO feedback
                    (feedback_id, investigation_id, outcome, notes,
                     lea_partner, case_reference, submitted_by,
                     submitted_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    feedback.feedback_id,
                    feedback.investigation_id,
                    feedback.outcome.value,
                    feedback.notes,
                    feedback.lea_partner,
                    feedback.case_reference,
                    feedback.submitted_by,
                    feedback.submitted_at,
                    json.dumps(feedback.metadata, default=str),
                ),
            )
            conn.commit()

        logger.info(
            "Recorded feedback %s for investigation %s: %s",
            feedback.feedback_id,
            feedback.investigation_id,
            feedback.outcome.value,
        )
        return feedback.feedback_id

    def update_outcome(
        self,
        investigation_id: str,
        outcome: OutcomeType,
        *,
        notes: str = "",
        case_reference: str = "",
    ) -> bool:
        """Update the outcome of the most recent feedback for an investigation.

        Args:
            investigation_id: The SSI investigation ID.
            outcome: The new outcome.
            notes: Additional notes.
            case_reference: External case reference number.

        Returns:
            True if a record was updated.
        """
        with sqlite3.connect(str(self._db_path)) as conn:
            cursor = conn.execute(
                """
                UPDATE feedback
                SET outcome = ?, notes = CASE WHEN ? != '' THEN ? ELSE notes END,
                    case_reference = CASE WHEN ? != '' THEN ? ELSE case_reference END
                WHERE feedback_id = (
                    SELECT feedback_id FROM feedback
                    WHERE investigation_id = ?
                    ORDER BY submitted_at DESC
                    LIMIT 1
                )
                """,
                (outcome.value, notes, notes, case_reference, case_reference, investigation_id),
            )
            conn.commit()
            updated = cursor.rowcount > 0

        if updated:
            logger.info("Updated outcome for investigation %s: %s", investigation_id, outcome.value)
        return updated

    def get_feedback(self, investigation_id: str) -> list[FeedbackRecord]:
        """Retrieve all feedback for an investigation.

        Args:
            investigation_id: The SSI investigation ID.

        Returns:
            List of feedback records, newest first.
        """
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM feedback
                WHERE investigation_id = ?
                ORDER BY submitted_at DESC
                """,
                (investigation_id,),
            ).fetchall()

        return [
            FeedbackRecord(
                feedback_id=row["feedback_id"],
                investigation_id=row["investigation_id"],
                outcome=OutcomeType(row["outcome"]),
                notes=row["notes"],
                lea_partner=row["lea_partner"],
                case_reference=row["case_reference"],
                submitted_by=row["submitted_by"],
                submitted_at=row["submitted_at"],
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            )
            for row in rows
        ]

    def get_stats(self) -> FeedbackStats:
        """Compute aggregated feedback statistics.

        Returns:
            A ``FeedbackStats`` with counts and rates.
        """
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.row_factory = sqlite3.Row

            # Count outcomes
            rows = conn.execute(
                "SELECT outcome, COUNT(*) as cnt FROM feedback GROUP BY outcome"
            ).fetchall()
            outcomes = {row["outcome"]: row["cnt"] for row in rows}

            # Total unique investigations with feedback
            total_inv = conn.execute(
                "SELECT COUNT(DISTINCT investigation_id) as cnt FROM feedback"
            ).fetchone()["cnt"]

            # Total feedback records
            total_fb = conn.execute("SELECT COUNT(*) as cnt FROM feedback").fetchone()["cnt"]

        prosecutions = outcomes.get("prosecution_initiated", 0) + outcomes.get("prosecution_completed", 0)
        takedowns = outcomes.get("takedown_requested", 0) + outcomes.get("takedown_completed", 0)
        false_positives = outcomes.get("false_positive", 0)

        return FeedbackStats(
            total_investigations=total_inv,
            total_feedback=total_fb,
            outcomes=outcomes,
            prosecution_rate=prosecutions / total_inv if total_inv > 0 else 0.0,
            takedown_rate=takedowns / total_inv if total_inv > 0 else 0.0,
            false_positive_rate=false_positives / total_fb if total_fb > 0 else 0.0,
        )
