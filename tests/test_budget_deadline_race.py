"""#34 — budget deadline-race + per-key idempotency locking.

Two coupled hardenings of ``core.py``'s budget/lock region:

1. **Deadline-race budget.** ``asyncio.wait_for`` only times out if the inner
   coroutine lets its cancellation propagate. A *cancel-swallowing* engine that
   catches ``CancelledError`` and returns an allow makes ``wait_for`` hand that
   allow back AFTER the budget was already blown — a fail-closed bypass. The race
   must never read the engine's result once the timer has won (premise P4).

2. **Per-key locking.** A single global idempotency lock serialises EVERY keyed
   request, so one slow key blocks unrelated keys (head-of-line blocking on the
   latency path). Distinct keys must evaluate concurrently, and the per-key lock
   map must clean itself up so it does not become a new unbounded map.
"""

import asyncio

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceError
from zemtik_govern.identity import AgentRef
from zemtik_govern.protocols import Decision

_ALLOW = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")


class _Identity:
    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)


class _RecordingAudit:
    def __init__(self):
        self.entries = []

    async def write(self, entry):
        self.entries.append(entry)
        return f"evt-{len(self.entries)}"


class _CancelSwallowingPolicy:
    """The adversarial engine: it sleeps past the deadline, and if cancelled it
    SWALLOWS the cancellation and returns an allow anyway. Under ``wait_for`` this
    allow leaks back post-deadline; under a deadline-race it must be discarded."""

    def __init__(self):
        self.returned_allow = False

    async def evaluate(self, ctx):
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            # Swallow the cancel — the exact "well-intentioned but wrong" engine
            # the deadline-race is built to defend against.
            pass
        self.returned_allow = True
        return _ALLOW


@pytest.mark.asyncio
async def test_cancel_swallowing_engine_past_deadline_still_denies():
    """Engine swallows CancelledError and returns an allow after the budget is
    blown → the governor STILL denies fail-closed. The post-deadline allow is
    never observed (P4): a slow, cancel-swallowing engine cannot become an
    implicit allow."""
    policy = _CancelSwallowingPolicy()
    audit = _RecordingAudit()
    gov = ZemtikGovern(
        identity=_Identity(), policy=policy, audit=audit, timeout=0.01
    )

    with pytest.raises(GovernanceError):
        await gov.govern(GovernanceContext(action="tool.run", subject="agent-1"))

    assert audit.entries[-1].outcome == "error"  # the breach was audited


# --- per-key locking: distinct keys evaluate concurrently --------------------


class _GatedPolicy:
    """Key ``"slow"`` parks until key ``"fast"`` runs and releases it. If both keys
    share ONE lock, ``"fast"`` can never run while ``"slow"`` holds it → deadlock.
    Per-key locks let them proceed independently."""

    def __init__(self):
        self.slow_holds_lock = asyncio.Event()
        self.release = asyncio.Event()

    async def evaluate(self, ctx):
        if ctx.idempotency_key == "slow":
            self.slow_holds_lock.set()
            await self.release.wait()
        else:
            self.release.set()
        return _ALLOW


@pytest.mark.asyncio
async def test_distinct_keys_evaluate_concurrently_no_head_of_line_block():
    """Two distinct idempotency keys evaluate concurrently: a slow key does not
    block an unrelated key on the latency path. A single global lock would
    deadlock (the fast key can never release the slow one it is queued behind)."""
    policy = _GatedPolicy()
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=_RecordingAudit())

    slow = asyncio.ensure_future(
        gov.govern(
            GovernanceContext(
                action="tool.run",
                subject="agent-1",
                idempotency_key="slow",
                payload={"k": "slow"},
            )
        )
    )
    await asyncio.wait_for(policy.slow_holds_lock.wait(), timeout=1.0)

    # The fast key must run to completion WHILE slow is parked, then release it.
    fast_decision = await asyncio.wait_for(
        gov.govern(
            GovernanceContext(
                action="tool.run",
                subject="agent-1",
                idempotency_key="fast",
                payload={"k": "fast"},
            )
        ),
        timeout=1.0,
    )
    slow_decision = await asyncio.wait_for(slow, timeout=1.0)

    assert fast_decision.allowed is True
    assert slow_decision.allowed is True


@pytest.mark.asyncio
async def test_per_key_lock_map_is_cleaned_up_after_calls():
    """The per-key lock map must not leak: after a keyed call settles (allow,
    deny, or fault) its lock entry is gone, so the map cannot grow unbounded with
    one entry per key ever seen."""
    gov = ZemtikGovern(identity=_Identity(), policy=_CountingAllow(), audit=_RecordingAudit())

    await gov.govern(
        GovernanceContext(
            action="tool.run",
            subject="agent-1",
            idempotency_key="k1",
            payload={"n": 1},
        )
    )
    # The ledger remembers the decision (for replay); the LOCK map does not.
    assert gov._idem_locks == {}


class _CountingAllow:
    async def evaluate(self, ctx):
        return _ALLOW


class _BoomPolicy:
    async def evaluate(self, ctx):
        raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_per_key_lock_cleaned_up_after_a_fault():
    """A system fault still releases the per-key lock entry — a failing key must
    not leave a permanent entry (and a wedged lock) behind."""
    gov = ZemtikGovern(identity=_Identity(), policy=_BoomPolicy(), audit=_RecordingAudit())

    with pytest.raises(GovernanceError):
        await gov.govern(
            GovernanceContext(
                action="tool.run",
                subject="agent-1",
                idempotency_key="kf",
                payload={"n": 1},
            )
        )
    assert gov._idem_locks == {}
    assert gov._idem_lock_waiters == {}


@pytest.mark.asyncio
async def test_per_key_lock_cleaned_up_when_caller_is_cancelled():
    """A caller cancelled mid-evaluation releases its per-key lock entry too — the
    async-context-manager exit runs on cancellation, so a cancelled request cannot
    strand the map or wedge the key for later callers."""
    policy = _GatedPolicy()
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=_RecordingAudit())

    parked = asyncio.ensure_future(
        gov.govern(
            GovernanceContext(
                action="tool.run",
                subject="agent-1",
                idempotency_key="slow",
                payload={"k": "slow"},
            )
        )
    )
    await asyncio.wait_for(policy.slow_holds_lock.wait(), timeout=1.0)
    parked.cancel()
    with pytest.raises(asyncio.CancelledError):
        await parked

    assert gov._idem_locks == {}
    assert gov._idem_lock_waiters == {}
