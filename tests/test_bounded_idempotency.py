"""#35 — bounded idempotency caches + two-level (key, mode, killswitch) keying.

The decision ledger and the proxy's effect-dedup slots stop being unbounded
process-local dicts: both ride ONE shared :class:`BoundedTTLDict`, so unique-key
traffic can no longer grow them without bound, and a stale decision expires and
re-evaluates. Eviction is consistent across the two concerns (one record holds
both the decision and the effect future), so a recycled key can never pass fresh
governance and still collect a *previous* request's tool result.

Two-level keying keeps killswitch authority: the cached-decision REPLAY lookup
keys on ``(key, mode, killswitch_state)`` so a key ledgered before the killswitch
flipped re-enforces under the fallback; conflict detection stays keyed on the
fingerprint alone so a recycled key with a changed payload is still caught.
"""

import asyncio

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import Killswitch, ZemtikGovern
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.identity import AgentRef
from zemtik_govern.protocols import Decision

_ALLOW = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
_DENY = Decision(
    allowed=False, action="deny", matched_rule="d", reason="no", denial_kind="policy"
)


class _Identity:
    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)


class _RecordingAudit:
    def __init__(self):
        self.entries = []

    async def write(self, entry):
        self.entries.append(entry)
        return f"evt-{len(self.entries)}"


class _CountingAllow:
    def __init__(self):
        self.calls = 0

    async def evaluate(self, ctx):
        self.calls += 1
        return _ALLOW


def _ctx(key, n):
    return GovernanceContext(
        action="tool.run", subject="agent-1", idempotency_key=key, payload={"n": n}
    )


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def tick(self, dt):
        self.now += dt


@pytest.mark.asyncio
async def test_streaming_unique_keys_keeps_the_ledger_at_the_cap():
    """N unique keys must not grow the decision ledger to O(N): the bounded cache
    holds at most the configured cap."""
    gov = ZemtikGovern(
        identity=_Identity(),
        policy=_CountingAllow(),
        audit=_RecordingAudit(),
        idem_max_entries=3,
    )
    for i in range(50):
        await gov.govern(_ctx(f"k{i}", i))

    assert len(gov._idem_cache) <= 3


@pytest.mark.asyncio
async def test_ttl_expired_decision_re_evaluates():
    """Past the TTL the ledgered decision is gone, so the same key re-evaluates
    (the engine is asked again) instead of replaying a stale verdict."""
    clk = _Clock()
    policy = _CountingAllow()
    gov = ZemtikGovern(
        identity=_Identity(),
        policy=policy,
        audit=_RecordingAudit(),
        idem_ttl_seconds=10.0,
        time_fn=clk,
    )
    await gov.govern(_ctx("k", 1))
    assert policy.calls == 1

    clk.tick(5.0)
    await gov.govern(_ctx("k", 1))  # inside TTL -> replay, no re-eval
    assert policy.calls == 1

    clk.tick(20.0)
    await gov.govern(_ctx("k", 1))  # expired -> re-eval
    assert policy.calls == 2


@pytest.mark.asyncio
async def test_eviction_does_not_orphan_an_in_flight_effect():
    """An in-flight effect future pins its cache entry: streaming another key
    cannot evict (and orphan) the running effect. It still completes exactly
    once."""
    started = asyncio.Event()
    release = asyncio.Event()
    runs = []

    async def tool():
        runs.append(True)
        started.set()
        await release.wait()
        return "done"

    gov = ZemtikGovern(
        identity=_Identity(),
        policy=_CountingAllow(),
        audit=_RecordingAudit(),
        idem_max_entries=1,
    )

    def factory_for(key):
        return lambda *a, **k: GovernanceContext(
            action="tool.run", subject="agent-1", idempotency_key=key, payload={}
        )

    parked_proxy = gov.proxy(tool, action="x", subject="x", context_factory=factory_for("slow"))
    parked = asyncio.ensure_future(parked_proxy())
    await asyncio.wait_for(started.wait(), timeout=1.0)

    # Stream another keyed decision through the SAME governor (cap=1). The parked
    # effect's entry must survive eviction because its future is still in flight.
    await gov.govern(_ctx("other", 9))

    release.set()
    assert await asyncio.wait_for(parked, timeout=1.0) == "done"
    assert runs == [True]  # ran exactly once; never orphaned/restarted


@pytest.mark.asyncio
async def test_consistent_eviction_no_stale_effect_on_a_recycled_key():
    """When a key's entry is evicted, BOTH its decision and its cached effect go
    together. A later DIFFERENT request that recycles the key therefore re-runs and
    gets the FRESH tool result — never the evicted request's stale result."""
    counter = {"n": 0}

    def tool():
        counter["n"] += 1
        return counter["n"]

    gov = ZemtikGovern(
        identity=_Identity(),
        policy=_CountingAllow(),
        audit=_RecordingAudit(),
        idem_max_entries=1,
    )

    def factory(key, payload):
        return lambda *a, **k: GovernanceContext(
            action="tool.run", subject="agent-1", idempotency_key=key, payload=payload
        )

    k_p1 = gov.proxy(tool, action="x", subject="x", context_factory=factory("K", {"p": 1}))
    first = await k_p1()  # returns 1, cached under K
    assert first == 1

    # Push a different key through; cap=1 evicts K's (now-complete) record entirely.
    other = gov.proxy(tool, action="x", subject="x", context_factory=factory("OTHER", {"p": 9}))
    await other()

    # Recycle key K for a DIFFERENT request (changed payload). With consistent
    # eviction K's stale effect is gone, so this returns the fresh result.
    k_p2 = gov.proxy(tool, action="x", subject="x", context_factory=factory("K", {"p": 2}))
    recycled = await k_p2()
    assert recycled == 3  # fresh run (3rd call), NOT the stale cached 1


@pytest.mark.asyncio
async def test_killswitch_engaged_after_ledgering_re_enforces_under_fallback():
    """A key ledgered as ALLOW under the primary engine must NOT replay that allow
    once the killswitch is engaged: the replay key includes killswitch state, so a
    post-flip duplicate re-evaluates under the (denying) fallback."""
    ks = Killswitch()

    class _DenyFallback:
        async def evaluate(self, ctx):
            return _DENY

    gov = ZemtikGovern(
        identity=_Identity(),
        policy=_CountingAllow(),
        audit=_RecordingAudit(),
        mode="enforce",
        fallback=_DenyFallback(),
        killswitch=ks,
    )
    ctx = GovernanceContext(
        action="tool.run", subject="agent-1", idempotency_key="K", payload={"n": 1}
    )
    d = await gov.govern(ctx)
    assert d.allowed is True  # primary allowed, ledgered under killswitch=off

    ks.engage()
    with pytest.raises(GovernanceDenied):
        await gov.govern(ctx)  # re-enforced under fallback, NOT replayed as allow


@pytest.mark.asyncio
async def test_recycled_key_different_payload_and_mode_is_a_conflict_not_fresh_eval():
    """Two-level keying must not let a changed mode mask a recycled-key conflict:
    a key reused with a DIFFERENT payload (different fingerprint) is a conflict and
    fails closed, even if the governor's mode changed between the two calls."""
    audit = _RecordingAudit()
    policy = _CountingAllow()
    gov = ZemtikGovern(
        identity=_Identity(), policy=policy, audit=audit, mode="enforce"
    )
    await gov.govern(_ctx("K", 1))  # fingerprint of payload {"n":1}
    calls_after_first = policy.calls

    gov._mode = "shadow"  # mode changed -> a different replay bucket...
    with pytest.raises(GovernanceError):
        await gov.govern(_ctx("K", 2))  # ...but the payload differs -> CONFLICT

    assert policy.calls == calls_after_first  # never re-evaluated as fresh
    assert audit.entries[-1].outcome == "error"
