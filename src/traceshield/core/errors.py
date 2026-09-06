"""Exception hierarchy for TraceShield.

The engine runs inside somebody else's telemetry export path, so almost nothing here is
allowed to escape to a caller. These exceptions exist so that internal failures carry
structured context to the fail-closed handler in the engine, not so that they can be
propagated. See docs/Architecture.md invariant 5.
"""

from __future__ import annotations


class TraceShieldError(Exception):
    """Base class for every error raised inside TraceShield."""


class PolicyError(TraceShieldError):
    """A policy document is invalid.

    Raised at policy construction, which happens at configuration time rather than in the
    export path, so this one is intended to reach the caller and fail fast.
    """


class BudgetExceededError(TraceShieldError):
    """A traversal or parsing budget was exhausted.

    Carries the budget name rather than any part of the offending value, because the value
    is exactly what must not appear in diagnostics.
    """

    def __init__(self, budget: str, limit: int) -> None:
        super().__init__(f"traversal budget {budget!r} exceeded (limit {limit})")
        self.budget = budget
        self.limit = limit
