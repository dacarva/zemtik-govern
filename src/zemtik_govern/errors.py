"""The governance error taxonomy.

Every failure the wrapper recognises descends from :class:`GovernanceError`, so a
caller can ``except GovernanceError`` once and never have a tool slip through on
an unclassified exception. The moat depends on it: an *unexpected* exception
inside ``govern()`` is wrapped here and audited as a denial — never swallowed,
never a ``NullGovernanceProvider`` fall-through (the prior ungoverned scheduler
path this wrapper replaces).

**Catchable, not just readable (D8).** Every governance exception carries a
stable ``.code`` and an optional ``.guard`` so a caller branches on the *code*,
never on a brittle message substring::

    try:
        await gov.govern(ctx)
    except GovernanceError as e:
        if e.code == "decision_budget_exceeded":
            metrics.budget_breach(e.guard, e.limit_seconds, e.elapsed_seconds)
        log.warning("blocked", code=e.code, audit_id=e.audit_id)

**Audit correlation (D9).** Every exception also carries ``.audit_id`` — the id
of the audit row written for this blocked outcome (``None`` only when the failure
happened before any row could be written). It is the same id exposed as
``Decision.audit_id`` on an allowed result, so a log line and the tamper-evident
trail line up without guesswork. See ``docs/operations.md`` ("Correlating logs to
the audit trail").
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the Decision type is only needed for annotations
    from .protocols import Decision


class GovernanceError(RuntimeError):
    """Base for every governance failure. Fail-closed: if you see this, the
    guarded tool did NOT run.

    ``code`` is a stable, machine-branchable identifier (class-level default,
    overridable per instance); ``guard`` names the seam that blocked when one is
    responsible (``"budget"``, ``"injection"``, ``"idempotency"``…) or ``None``;
    ``audit_id`` back-links to the audit row written for this outcome.
    """

    #: Stable, machine-branchable identifier. Subclasses override; a bare
    #: ``GovernanceError`` may pass ``code=`` to specialise without a new class.
    code: str = "governance_error"
    #: The guard/seam responsible, when one is. ``None`` for unattributed faults.
    guard: str | None = None

    def __init__(
        self,
        *args: object,
        code: str | None = None,
        guard: str | None = None,
        audit_id: str | None = None,
    ) -> None:
        super().__init__(*args)
        if code is not None:
            self.code = code
        if guard is not None:
            self.guard = guard
        #: Id of the audit row for this blocked outcome (D9); ``None`` if the
        #: failure preceded any audit write.
        self.audit_id = audit_id


class GovernanceDenied(GovernanceError):
    """A policy decided the action is not allowed. Carries the decision that
    blocked it so the reason survives into the caller and the audit trail.

    ``code`` is ``"policy_denied"`` for an ordinary policy deny and
    ``"system_denied"`` for a fail-closed system deny; ``guard`` mirrors the
    decision's ``denial_kind`` and ``audit_id`` mirrors its ``audit_event_id``,
    so a caught deny correlates to the trail without re-deriving anything.
    """

    code = "policy_denied"

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        reason = getattr(decision, "reason", str(decision))
        kind = getattr(decision, "denial_kind", None)
        code = "system_denied" if kind == "system" else "policy_denied"
        super().__init__(
            reason,
            code=code,
            guard=kind,
            audit_id=getattr(decision, "audit_event_id", None),
        )


class DecisionBudgetExceeded(GovernanceError):
    """The per-call decision budget was breached: identity + policy did not
    resolve within ``limit_seconds``. A fail-closed system fault, NOT an allow.

    Catchable by ``code == "decision_budget_exceeded"`` (D8). The message states
    the remedy (D6) so an operator is not left guessing how to raise the bound,
    and ``limit_seconds`` / ``elapsed_seconds`` carry the numbers for metrics.
    """

    code = "decision_budget_exceeded"
    guard = "budget"

    def __init__(
        self,
        limit_seconds: float,
        elapsed_seconds: float | None = None,
        *,
        audit_id: str | None = None,
    ) -> None:
        self.limit_seconds = limit_seconds
        self.elapsed_seconds = elapsed_seconds
        message = (
            f"decision budget of {limit_seconds}s exceeded; raise "
            "decision_budget_seconds, or set it to null to opt out when an "
            "upstream caller enforces its own deadline"
        )
        super().__init__(message, audit_id=audit_id)


class GovernanceNotConfigured(GovernanceError):
    """The wrapper was asked to start in an insecure configuration (strict mode
    with zero rules, no audit sink). Raised at startup, not request time."""

    code = "not_configured"
