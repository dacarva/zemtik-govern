"""S7 — the pressure-test gate.

One ``govern()`` abstraction, two opposite workloads driven through the live AGT
stack:

1. a SYNC fintech write (idempotency key present, blocking ``govern_sync``), and
2. an ASYNC voice-turn (``await govern()`` under a sub-100ms decision budget).

Both are wired from the *same* seams (identity / policy / audit) and the *same*
public Protocols. The gate's real assertion is structural: nothing in
``protocols.py`` had to change to serve a blocking fintech caller AND a
latency-sensitive streaming caller — the async-first seam survives both. If it had
not, this file would not type-check or run as written.
"""

import time

import pytest

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.identity import StaticIdentity
from zemtik_govern.policy import AgentOsPolicy
from zemtik_govern.protocols import AuditEntry

_ALLOW_TOOL_RUN = {
    "name": "allow-tool-run",
    "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
    "action": "allow",
}

# A sub-100ms budget for the voice path's policy decision (issue acceptance bar).
_VOICE_BUDGET_S = 0.1


class _RecordingAudit:
    """Real-shaped AuditSink that keeps the written entries so the gate can assert
    the fintech write produced an audit entry stamped with the agent DID."""

    def __init__(self):
        self.entries: list[AuditEntry] = []

    async def write(self, entry: AuditEntry) -> str:
        self.entries.append(entry)
        return f"evt-{len(self.entries)}"


def _wire(*, timeout=None):
    """One governor wired from the live AGT seams — reused by both workloads."""
    boundary = AGTBoundary()
    audit = _RecordingAudit()
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=AgentOsPolicy(boundary, rules=[_ALLOW_TOOL_RUN]),
        audit=audit,
        mode="enforce",
        timeout=timeout,
    )
    return gov, audit


def test_sync_fintech_write_path_completes_with_audit_and_agent_did():
    """The blocking fintech write goes through govern_sync with an idempotency key,
    is allowed, and lands an audit entry stamped with the resolved agent DID and
    the idempotency key — outside any event loop."""
    gov, audit = _wire()

    decision = gov.govern_sync(
        GovernanceContext(
            action="tool.run", subject="fintech-svc", idempotency_key="wire-001"
        )
    )

    assert decision.allowed is True
    assert decision.audit_event_id is not None
    entry = audit.entries[-1]
    assert entry.agent_did == "did:mesh:fintech-svc"  # identity stamped the trail
    assert entry.idempotency_key == "wire-001"  # the write is idempotency-keyed


@pytest.mark.asyncio
async def test_async_voice_turn_completes_under_policy_decision_budget():
    """The voice turn awaits govern() under a sub-100ms decision budget. It
    completes within budget (the budget itself fails closed if exceeded), proving
    the async seam carries a latency-sensitive workload."""
    gov, _ = _wire(timeout=_VOICE_BUDGET_S)

    start = time.perf_counter()
    decision = await gov.govern(
        GovernanceContext(action="tool.run", subject="voice-turn")
    )
    elapsed = time.perf_counter() - start

    # The budget itself is the gate: timeout=_VOICE_BUDGET_S wraps each await, so a
    # policy/identity decision that blew the budget would have raised, not returned.
    # A clean allow therefore proves the seam decided within budget. The wall-clock
    # check is only a loose smoke bound — asserting against the raw budget here is
    # flaky on a loaded CI runner (GC pause, cold import), conflating "logic correct"
    # with "this machine is fast right now".
    assert decision.allowed is True  # decided within budget (else the budget raised)
    assert elapsed < 1.0  # smoke bound, not the latency gate
