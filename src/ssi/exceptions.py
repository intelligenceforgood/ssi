"""SSI-specific exception hierarchy."""

from __future__ import annotations


class SSIError(Exception):
    """Base exception for all SSI-specific errors."""


class BudgetExceededError(SSIError):
    """Raised when an investigation exceeds its per-investigation cost budget.

    Attributes:
        spent_usd: Accumulated cost so far.
        budget_usd: The configured budget cap.
    """

    def __init__(self, spent_usd: float, budget_usd: float) -> None:
        self.spent_usd = spent_usd
        self.budget_usd = budget_usd
        super().__init__(
            f"Investigation cost ${spent_usd:.4f} exceeded budget ${budget_usd:.4f}"
        )


class ConcurrentLimitError(SSIError):
    """Raised when the server has reached the maximum number of concurrent investigations."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        super().__init__(
            f"Concurrent investigation limit ({limit}) reached. Try again later."
        )
