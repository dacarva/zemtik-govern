"""Slice 2 — core façade instrumentation, Red→Green steps 9–17.

Fail-open matrix: a governor's decision, raise, `.audit_id`, and mode must be
byte-identical whether the tracer is a no-op or a maximally hostile fake that
explodes at every point in the span lifecycle — `.trace()`, `__enter__`,
`__exit__`, or the masking thunk itself. Plus budget isolation (span latency
must never trip the decision budget), nesting under a real budget race,
the sync path, and the replay/conflict trace shapes. All fixtures here are
injected fakes and run in the langfuse-free job.
"""

from __future__ import annotations

import pytest

from zemtik_govern import core as core_module
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceError
from zemtik_govern.identity import AgentRef
from zemtik_govern.observability import NoOpTracer
from zemtik_govern.protocols import Decision

from ._fakes import (
    ExplodingEnterTracer,
    ExplodingExitTracer,
    ExplodingTracer,
    RecordingTracer,
    RootOnceExplodingTracer,
    SlowTracer,
)

_ALLOW = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
_DENY = Decision(
    allowed=False,
    action="deny",
    matched_rule=None,
    reason="deny-by-default",
    denial_kind="policy",
)


class _Seams:
    def __init__(self, *, decision: Decision):
        self._decision = decision

    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)

    async def evaluate(self, ctx):
        return self._decision

    async def write(self, entry):
        return "evt-1"


def _ctx():
    return GovernanceContext(action="tool.run", subject="agent-1")


async def _outcome(gov):
    """Return a comparable outcome: the Decision, or (code, audit_id) for a raise."""
    try:
        decision = await gov.govern(_ctx())
        return ("allow", decision.allowed, decision.action, decision.reason)
    except GovernanceError as exc:
        return ("raise", exc.code, exc.audit_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", [_ALLOW, _DENY])
@pytest.mark.parametrize(
    "hostile_tracer",
    [ExplodingTracer(), ExplodingEnterTracer(), ExplodingExitTracer()],
    ids=["exploding_trace", "exploding_enter", "exploding_exit"],
)
async def test_fail_open_hostile_tracer_matches_noop_baseline(decision, hostile_tracer):
    """Steps 9, 11, 12: an exploding `.trace()`/`__enter__`/`__exit__` leaves the
    decision/raise/mode byte-identical to the NoOpTracer baseline, using the
    same allow/deny golden fixtures."""
    baseline_gov = ZemtikGovern(
        identity=_Seams(decision=decision),
        policy=_Seams(decision=decision),
        audit=_Seams(decision=decision),
        tracer=NoOpTracer(),
    )
    hostile_gov = ZemtikGovern(
        identity=_Seams(decision=decision),
        policy=_Seams(decision=decision),
        audit=_Seams(decision=decision),
        tracer=hostile_tracer,
    )
    baseline = await _outcome(baseline_gov)
    hostile = await _outcome(hostile_gov)
    assert baseline == hostile


@pytest.mark.asyncio
async def test_fail_open_exploding_masking_matches_noop_baseline(monkeypatch):
    """Step 10: a masking/attr-assembly bug is swallowed the same way a hostile
    tracer is — the decision is unaffected."""
    seams = _Seams(decision=_ALLOW)
    baseline_gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=NoOpTracer())
    baseline = await _outcome(baseline_gov)

    def _boom(*_a, **_kw):
        raise RuntimeError("boom: masking")

    # core.py imports safe_trace_attrs_decision via a direct `from ... import`,
    # binding the function into core's own module namespace — patching the
    # attribute on the `masking` module would miss that binding and leave
    # core.py calling the real, non-raising function. Patch core's own
    # reference so this test actually exercises the _span_set guard.
    monkeypatch.setattr(core_module, "safe_trace_attrs_decision", _boom)
    tracer = RecordingTracer()
    seams2 = _Seams(decision=_ALLOW)
    exploding_masking_gov = ZemtikGovern(
        identity=seams2, policy=seams2, audit=seams2, tracer=tracer
    )
    exploded = await _outcome(exploding_masking_gov)
    assert baseline == exploded


@pytest.mark.asyncio
async def test_span_whose_parent_failed_to_open_stays_untraced_not_a_new_root():
    """A nested _traced() call must distinguish 'no parent at all' (safe to open
    a fresh root) from 'the parent span failed to open' (must stay untraced,
    not open a disconnected new root). Only the root's single failed .trace()
    call should ever happen — the nested "identity" span must never re-invoke
    .trace() once its parent has already failed."""
    tracer = RootOnceExplodingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    decision = await gov.govern(_ctx())
    assert decision.allowed is True
    assert tracer.calls == ["govern"]


def test_govern_sync_does_not_mark_spans_errored_from_its_own_loop_check():
    """Regression: govern_sync() detects "no running loop" via its own
    ``try: asyncio.get_running_loop() except RuntimeError: return
    asyncio.run(...)`` — for the entire dynamic extent of that asyncio.run()
    call, sys.exc_info() still reflects that ALREADY-HANDLED RuntimeError
    (Python's exception-context tracking is stack-wide, not block-local).
    _traced() must not hand that stale, unrelated exception to a span's
    __exit__ just because governance happened to run via govern_sync() rather
    than `await govern()` — every span opened during a successful sync call
    must close clean, not be mislabeled as failed."""
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    decision = gov.govern_sync(_ctx())
    assert decision.allowed is True
    root = tracer.roots[-1]
    assert root.exit_exc_type is None
    assert all(child.exit_exc_type is None for child in root.children)


@pytest.mark.asyncio
async def test_budget_isolation_slow_tracer_does_not_trip_the_decision_budget():
    """Step 13: span-open latency sits OUTSIDE _with_budget's race — a slow
    tracer must not turn an otherwise-fast allow into a DecisionBudgetExceeded."""
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(
        identity=seams,
        policy=seams,
        audit=seams,
        tracer=SlowTracer(delay=0.3),
        timeout=0.05,
    )
    decision = await gov.govern(_ctx())
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_nesting_holds_under_a_real_budget_race():
    """Step 14: identity/policy nesting still holds when _with_budget's
    asyncio.wait/ensure_future path actually executes (a real, generous
    timeout configured), not just the timeout=None shortcut."""
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer, timeout=5.0)
    await gov.govern(_ctx())
    root = tracer.roots[0]
    assert root.children[0].name == "identity"
    assert root.children[1].name == "policy"


def test_sync_path_fail_open_matches_async_noop_baseline():
    """Step 15: govern_sync() gets the same fail-open guarantee as govern().

    A plain (non-async) test function: govern_sync() refuses to run inside an
    already-running event loop (see test_core.py), so this must NOT be a
    pytest.mark.asyncio coroutine — it drives asyncio.run() itself, exactly
    like a real sync fintech-write caller would.
    """
    seams = _Seams(decision=_ALLOW)
    baseline_gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=NoOpTracer())
    baseline_decision = baseline_gov.govern_sync(_ctx())
    baseline = (
        "allow",
        baseline_decision.allowed,
        baseline_decision.action,
        baseline_decision.reason,
    )

    seams2 = _Seams(decision=_ALLOW)
    hostile_gov = ZemtikGovern(
        identity=seams2, policy=seams2, audit=seams2, tracer=ExplodingExitTracer()
    )
    hostile_decision = hostile_gov.govern_sync(_ctx())
    hostile = ("allow", hostile_decision.allowed, hostile_decision.action, hostile_decision.reason)
    assert baseline == hostile


@pytest.mark.asyncio
async def test_replay_emits_one_root_with_no_identity_or_policy_children():
    """Step 16: a replayed decision's root span is annotated replayed=True and
    has NO identity/policy children (that branch never calls _evaluate_and_audit)."""
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    ctx = GovernanceContext(action="tool.run", subject="agent-1", idempotency_key="k1")
    await gov.govern(ctx)
    await gov.govern(ctx)
    replay_root = tracer.roots[-1]
    assert replay_root.attrs["replayed"] is True
    assert replay_root.children == []


@pytest.mark.asyncio
async def test_conflict_still_emits_a_new_root_span():
    """Step 17: same key, different payload -> a NEW root span, annotated
    event="idempotency_conflict", and a GovernanceError with that code."""
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    ctx1 = GovernanceContext(
        action="tool.run", subject="agent-1", payload={"n": 1}, idempotency_key="k1"
    )
    ctx2 = GovernanceContext(
        action="tool.run", subject="agent-1", payload={"n": 2}, idempotency_key="k1"
    )
    await gov.govern(ctx1)
    with pytest.raises(GovernanceError) as exc_info:
        await gov.govern(ctx2)
    assert exc_info.value.code == "idempotency_conflict"
    assert len(tracer.roots) == 2
    assert tracer.roots[-1].attrs["event"] == "idempotency_conflict"
