"""The governance error taxonomy.

Every failure the wrapper recognises descends from :class:`GovernanceError`, so a
caller can ``except GovernanceError`` once and never have a tool slip through on
an unclassified exception. The moat depends on it: an *unexpected* exception
inside ``govern()`` is wrapped here and audited as a denial — never swallowed,
never a ``NullGovernanceProvider`` fall-through (loopay ``scheduler.py:29-30``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the Decision type is only needed for annotations
    from .protocols import Decision


class GovernanceError(RuntimeError):
    """Base for every governance failure. Fail-closed: if you see this, the
    guarded tool did NOT run."""


class GovernanceDenied(GovernanceError):
    """A policy decided the action is not allowed. Carries the decision that
    blocked it so the reason survives into the caller and the audit trail."""

    def __init__(self, decision: "Decision") -> None:
        self.decision = decision
        reason = getattr(decision, "reason", str(decision))
        super().__init__(reason)


class GovernanceNotConfigured(GovernanceError):
    """The wrapper was asked to start in an insecure configuration (strict mode
    with zero rules, no audit sink). Raised at startup, not request time."""
