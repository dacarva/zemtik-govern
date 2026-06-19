"""S3 — the orchestration core (E2): identity → policy → audit, audit every
outcome, fail-closed on engine error, sync nested-loop guard (E3).

These use lightweight fakes for the three seams so the test pins ORDER and
CONTROL FLOW, not AGT internals (those are covered by the e2e test).
"""

import asyncio

import pytest

from zemtik_govern.core import ZemtikGovern
from zemtik_govern.context import GovernanceContext
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.protocols import Decision


class _RecordingSeams:
    """Fakes that append their name to a shared trace as they run."""

    def __init__(self, trace, *, decision=None, policy_raises=False):
        self.trace = trace
        self._decision = decision or Decision(
            allowed=True, action="allow", matched_rule="r", reason="ok"
        )
        self._policy_raises = policy_raises
        self.entries = []

    async def identify(self, subject):
        self.trace.append("identity")
        return "did:mesh:" + subject

    async def evaluate(self, ctx):
        self.trace.append("policy")
        if self._policy_raises:
            raise ValueError("boom inside the engine")
        return self._decision

    async def write(self, entry):
        self.trace.append("audit")
        self.entries.append(entry)
        return "evt-1"


def _ctx():
    return GovernanceContext(action="tool.run", subject="agent-1")


@pytest.mark.asyncio
async def test_govern_runs_identity_then_policy_then_audit():
    trace = []
    seams = _RecordingSeams(trace)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)
    await gov.govern(_ctx())
    assert trace == ["identity", "policy", "audit"]


@pytest.mark.asyncio
async def test_govern_raises_denied_and_audits_the_denial():
    """A policy deny is audited (no unlogged denial) THEN raised — and the audit
    runs before the raise, so the trail records every outcome."""
    trace = []
    denial = Decision(
        allowed=False, action="deny", matched_rule=None,
        reason="deny-by-default", denial_kind="policy",
    )
    seams = _RecordingSeams(trace, decision=denial)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)
    with pytest.raises(GovernanceDenied) as exc:
        await gov.govern(_ctx())
    # the raised decision is the denial, enriched with its audit id
    assert exc.value.decision.denial_kind == "policy"
    assert exc.value.decision.reason == "deny-by-default"
    assert exc.value.decision.audit_event_id == "evt-1"
    assert trace == ["identity", "policy", "audit"]
    assert seams.entries[-1].outcome == "denied"


@pytest.mark.asyncio
async def test_govern_fails_closed_when_engine_errors():
    """An unexpected exception inside the engine becomes a GovernanceError, is
    audited as a system denial, and the tool never runs — no silent swallow."""
    trace = []
    seams = _RecordingSeams(trace, policy_raises=True)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)
    with pytest.raises(GovernanceError) as exc:
        await gov.govern(_ctx())
    assert isinstance(exc.value.__cause__, ValueError)  # original is preserved
    assert "audit" in trace  # the system denial was recorded
    assert seams.entries[-1].outcome == "error"


def test_govern_sync_runs_outside_an_event_loop():
    """The sync entry point drives the async core when no loop is running."""
    seams = _RecordingSeams([])
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)
    decision = gov.govern_sync(_ctx())
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_govern_sync_inside_a_running_loop_raises():
    """Calling the sync entry point from inside a loop raises rather than nesting
    asyncio.run — no deadlock, no silently-dropped governance."""
    seams = _RecordingSeams([])
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)
    with pytest.raises(GovernanceError):
        gov.govern_sync(_ctx())
