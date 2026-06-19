"""S2/S3 — the public contract: the enriched Decision and the three seams (E8)."""

import dataclasses

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.protocols import (
    AuditEntry,
    AuditSink,
    Decision,
    IdentityProvider,
    PolicyEngine,
)


def test_decision_is_frozen_and_carries_enriched_fields():
    """A Decision is a value with correlation/denial metadata, not just a bool —
    so a caller and the audit trail can explain it without re-deriving it."""
    d = Decision(
        allowed=False,
        action="deny",
        matched_rule=None,
        reason="deny-by-default: no policy rule matched",
        denial_kind="policy",
        correlation_id="c1",
        policy_id="p1",
        policy_version="1.0",
        audit_event_id="e1",
    )
    assert d.allowed is False
    assert d.denial_kind == "policy"
    assert d.correlation_id == "c1"
    assert d.audit_event_id == "e1"
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.allowed = True


def test_audit_entry_maps_a_decision_to_audit_vocabulary():
    """Candidate 2/3: the audit schema is a typed value, and the decision→verbs
    mapping (tool_invoked/tool_blocked, success/denied) lives here — not inline in
    the orchestrator."""
    ctx = GovernanceContext(action="tool.run", subject="agent-1")

    allow = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
    e = AuditEntry.from_decision(ctx, "did:mesh:agent-1", allow)
    assert e.event_type == "tool_invoked"
    assert e.outcome == "success"
    assert e.agent_did == "did:mesh:agent-1"
    assert e.action == "tool.run"
    assert e.policy_decision == "ok"

    deny = Decision(
        allowed=False, action="deny", matched_rule=None,
        reason="deny-by-default", denial_kind="policy",
    )
    d = AuditEntry.from_decision(ctx, "did:mesh:agent-1", deny)
    assert d.event_type == "tool_blocked"
    assert d.outcome == "denied"

    # explicit outcome wins (the fail-closed system-error path)
    err = AuditEntry.from_decision(ctx, "did:mesh:agent-1", deny, outcome="error")
    assert err.outcome == "error"


def test_seams_are_runtime_checkable_protocols():
    """Any object with the right async shape satisfies the seam — the swap-in
    story, with no base class to inherit."""

    class _Id:
        async def identify(self, subject):
            return "did:mesh:" + subject

    class _Pol:
        async def evaluate(self, ctx):
            return None

    class _Aud:
        async def write(self, entry):
            return "e1"

    assert isinstance(_Id(), IdentityProvider)
    assert isinstance(_Pol(), PolicyEngine)
    assert isinstance(_Aud(), AuditSink)
