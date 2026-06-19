"""S3 — _GovernedProxy: no ungoverned path to a wrapped tool.

The acceptance criterion: a disallowed call is blocked end-to-end — the wrapped
callable never runs. An allowed call passes through and returns its result; async
tools are awaited.
"""

import asyncio

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.identity import AgentRef
from zemtik_govern.protocols import Decision


class _Seams:
    def __init__(self, *, decision=None, policy_raises=False):
        self._decision = decision or Decision(
            allowed=True, action="allow", matched_rule="r", reason="ok"
        )
        self._policy_raises = policy_raises

    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)

    async def evaluate(self, ctx):
        if self._policy_raises:
            raise ValueError("boom")
        return self._decision

    async def write(self, entry):
        return "evt-1"


def _gov(**kw):
    seams = _Seams(**kw)
    return ZemtikGovern(identity=seams, policy=seams, audit=seams)


@pytest.mark.asyncio
async def test_allowed_call_runs_the_tool():
    ran = []

    def tool(x):
        ran.append(x)
        return x * 2

    proxy = _gov().proxy(tool, action="tool.run", subject="agent-1")
    result = await proxy(21)
    assert result == 42
    assert ran == [21]


@pytest.mark.asyncio
async def test_denied_call_never_runs_the_tool():
    ran = []

    def tool():
        ran.append(True)
        return "should not happen"

    denial = Decision(
        allowed=False, action="deny", matched_rule=None,
        reason="deny-by-default", denial_kind="policy",
    )
    proxy = _gov(decision=denial).proxy(tool, action="wire.transfer", subject="agent-1")
    with pytest.raises(GovernanceDenied):
        await proxy()
    assert ran == []  # the tool was never invoked


@pytest.mark.asyncio
async def test_engine_error_fails_closed_and_tool_never_runs():
    ran = []

    def tool():
        ran.append(True)

    proxy = _gov(policy_raises=True).proxy(tool, action="tool.run", subject="agent-1")
    with pytest.raises(GovernanceError):
        await proxy()
    assert ran == []


@pytest.mark.asyncio
async def test_async_tool_is_awaited():
    async def tool(x):
        return x + 1

    proxy = _gov().proxy(tool, action="tool.run", subject="agent-1")
    assert await proxy(9) == 10


@pytest.mark.asyncio
async def test_default_context_carries_action_subject_and_call_args():
    seen = {}

    class _CapturingSeams(_Seams):
        async def evaluate(self, ctx):
            seen["action"] = ctx.action
            seen["subject"] = ctx.subject
            seen["payload"] = {k: dict(v) if hasattr(v, "items") else list(v)
                               for k, v in ctx.payload.items()}
            return self._decision

    seams = _CapturingSeams()
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)
    proxy = gov.proxy(lambda *a, **k: "ok", action="tool.run", subject="agent-1")
    await proxy(1, k=2)
    assert seen["action"] == "tool.run"
    assert seen["subject"] == "agent-1"
    assert seen["payload"] == {"args": [1], "kwargs": {"k": 2}}


@pytest.mark.asyncio
async def test_context_factory_returning_wrong_type_is_refused():
    proxy = _gov().proxy(
        lambda: "ok",
        action="tool.run",
        subject="agent-1",
        context_factory=lambda: {"not": "a context"},  # wrong type
    )
    with pytest.raises(GovernanceError, match="must return a GovernanceContext"):
        await proxy()


# --- Effect-idempotency: a keyed duplicate must NOT re-execute the tool --------


def _keyed_factory(key, **payload):
    """A context_factory that stamps an idempotency_key (the default ctx has none)."""

    def factory(*args, **kwargs):
        return GovernanceContext(
            action="wire.transfer",
            subject="agent-1",
            idempotency_key=key,
            payload=payload or {"args": list(args)},
        )

    return factory


@pytest.mark.asyncio
async def test_keyed_duplicate_does_not_re_execute_the_tool():
    """A sequential duplicate under the same idempotency_key returns the FIRST
    call's cached result and never runs the tool a second time — a replayed wire
    transfer must not move money twice."""
    runs = []

    def tool():
        runs.append(True)
        return len(runs)  # 1 on the only real execution

    proxy = _gov().proxy(
        tool, action="x", subject="x", context_factory=_keyed_factory("wire-1")
    )
    first = await proxy()
    second = await proxy()

    assert runs == [True]  # the tool ran exactly once
    assert first == second == 1  # the duplicate got the cached effect


@pytest.mark.asyncio
async def test_concurrent_keyed_duplicates_execute_the_tool_once():
    """Two concurrent calls sharing one idempotency_key resolve to a single tool
    execution — the second waits on the in-flight effect rather than starting its
    own (the race the slot-reservation closes)."""
    runs = []

    async def tool():
        runs.append(True)
        await asyncio.sleep(0)  # force interleaving
        return "done"

    proxy = _gov().proxy(
        tool, action="x", subject="x", context_factory=_keyed_factory("wire-2")
    )
    a, b = await asyncio.gather(proxy(), proxy())

    assert runs == [True]  # exactly one execution despite two concurrent calls
    assert a == b == "done"


@pytest.mark.asyncio
async def test_distinct_keys_each_execute_the_tool():
    """Different idempotency keys are different requests — each runs the tool."""
    runs = []

    def tool():
        runs.append(True)
        return len(runs)

    gov = _gov()
    p1 = gov.proxy(tool, action="x", subject="x", context_factory=_keyed_factory("k-a"))
    p2 = gov.proxy(tool, action="x", subject="x", context_factory=_keyed_factory("k-b"))
    await p1()
    await p2()

    assert runs == [True, True]  # one execution per distinct key


@pytest.mark.asyncio
async def test_failed_tool_is_not_cached_so_a_retry_re_runs():
    """A tool that raises is left un-cached: the effect cache holds only successful
    results, so a retry under the same key actually re-runs rather than replaying
    the failure forever."""
    runs = []

    def tool():
        runs.append(True)
        if len(runs) == 1:
            raise RuntimeError("tool boom")
        return "ok"

    proxy = _gov().proxy(
        tool, action="x", subject="x", context_factory=_keyed_factory("wire-3")
    )
    with pytest.raises(RuntimeError, match="tool boom"):
        await proxy()
    result = await proxy()

    assert runs == [True, True]  # the failure was not cached; the retry re-ran
    assert result == "ok"


@pytest.mark.asyncio
async def test_cancelled_first_caller_does_not_cache_a_failed_effect():
    """If the first keyed caller is cancelled while the tool is in flight and the
    orphaned effect then fails, the failure must NOT stay cached: a later retry
    under the same key re-runs. Cleanup is tied to the effect's lifetime, not the
    cancelled caller's."""
    runs = []
    started = asyncio.Event()
    release = asyncio.Event()

    async def tool():
        runs.append(True)
        started.set()
        await release.wait()
        if len(runs) == 1:
            raise RuntimeError("first run fails")
        return "ok"

    proxy = _gov().proxy(
        tool, action="x", subject="x", context_factory=_keyed_factory("wire-cancel")
    )

    first = asyncio.ensure_future(proxy())
    await started.wait()  # the effect is in flight
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    release.set()  # let the orphaned effect resume and fail
    for _ in range(5):  # let the task finish and its done-callback evict the slot
        await asyncio.sleep(0)

    # retry under the same key: the cached failure was evicted, so the tool re-runs
    result = await proxy()
    assert result == "ok"
    assert runs == [True, True]  # the failure was not cached


@pytest.mark.asyncio
async def test_context_factory_overrides_default_context():
    seen = {}

    class _CapturingSeams(_Seams):
        async def evaluate(self, ctx):
            seen["action"] = ctx.action
            seen["payload"] = dict(ctx.payload)
            return self._decision

    seams = _CapturingSeams()
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)

    def factory(amount):
        return GovernanceContext(
            action="wire.transfer", subject="agent-1", payload={"amount": amount}
        )

    def tool(amount):
        return amount

    proxy = gov.proxy(tool, action="ignored", subject="ignored", context_factory=factory)
    await proxy(500)
    assert seen["action"] == "wire.transfer"
    assert seen["payload"] == {"amount": 500}
