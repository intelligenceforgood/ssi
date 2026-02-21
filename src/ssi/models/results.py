"""Result models for scam site investigation.

Lightweight data classes capturing the outcome of an agent run: status,
wallets found, screenshots captured, token usage, and metrics.

``WalletEntry`` is defined in ``ssi.wallet.models`` and re-exported here
for backward compatibility.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ssi.wallet.models import WalletEntry  # noqa: F401 — re-export


class SiteStatus(str, Enum):
    """Outcome status for a processed site."""

    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    ERROR = "error"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"
    EMAIL_VERIFICATION_REQUIRED = "email_verification_required"
    REFERRAL_CODE_REQUIRED = "referral_code_required"
    BROKEN_DEPOSIT_PAGE = "broken_deposit_page"


@dataclass
class SiteResult:
    """Complete outcome from processing a single scam site."""

    site_url: str = ""
    site_id: str = ""
    run_id: str = ""
    status: SiteStatus = SiteStatus.IN_PROGRESS
    wallets: list[WalletEntry] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)
    actions_taken: int = 0
    error_message: str = ""
    notes: str = ""
    skip_reason: str = ""

    # LLM usage
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0

    # Metrics summary from MetricsCollector
    metrics: dict[str, Any] = field(default_factory=dict)

    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for JSON output."""
        return {
            "site_url": self.site_url,
            "site_id": self.site_id,
            "run_id": self.run_id,
            "status": self.status.value,
            "wallets": [w.to_dict() for w in self.wallets],
            "screenshots": self.screenshots,
            "actions_taken": self.actions_taken,
            "error_message": self.error_message,
            "notes": self.notes,
            "skip_reason": self.skip_reason,
            "llm_calls": self.llm_calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
            "metrics": self.metrics,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
