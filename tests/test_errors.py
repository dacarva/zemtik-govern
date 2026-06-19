"""S2 — the governance error taxonomy (E2 fail-closed foundation).

One base, ``GovernanceError``, so a caller can catch every recognised failure in
one place and never let a tool slip through on an unclassified exception.
"""

import pytest

from zemtik_govern.errors import (
    GovernanceDenied,
    GovernanceError,
    GovernanceNotConfigured,
)


def test_denied_and_not_configured_are_governance_errors():
    """Both concrete failures descend from the single base."""
    assert issubclass(GovernanceDenied, GovernanceError)
    assert issubclass(GovernanceNotConfigured, GovernanceError)


def test_denied_carries_the_decision_that_blocked_it():
    """A deny is explainable after the fact: the Decision rides on the error."""
    decision = object()  # any object; the taxonomy must not constrain its type here
    err = GovernanceDenied(decision)
    assert err.decision is decision
    assert isinstance(err, GovernanceError)
