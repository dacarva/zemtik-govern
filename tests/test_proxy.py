"""S3 — _GovernedProxy: no ungoverned path to a wrapped tool.

The acceptance criterion: a disallowed call is blocked end-to-end — the wrapped
callable never runs. An allowed call passes through and returns its result; async
tools are awaited.
"""

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.protocols import Decision


class _Seams:
    def __init__(self, *, decision=None, policy_raises=False):
        self._decision = decision or Decision(
            allowed=True, action="allow", matched_rule="r", reason="ok"
        )
        self._policy_raises = policy_raises

    async def identify(self, subject):
        return "did:mesh:" + subject

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
