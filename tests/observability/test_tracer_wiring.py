"""Slice 0 — wiring the Tracer seam through the core and the registry.

A prefactor: the core now holds a Tracer (default NoOpTracer) and the registry
can register one. This must be ZERO behavior change — a governor built the old
way decides exactly as before — while a provided tracer is threaded through.
"""

from __future__ import annotations

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied
from zemtik_govern.identity import AgentRef
from zemtik_govern.observability import NoOpTracer, Tracer
from zemtik_govern.protocols import Decision
from zemtik_govern.registry import GovernanceRegistry


class _Seams:
    """Satisfies identity / policy / audit at once."""

    def __init__(self, *, decision: Decision):
        self._decision = decision

    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)

    async def evaluate(self, ctx):
        return self._decision

    async def write(self, entry):
        return "evt-1"


_ALLOW = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
_DENY = Decision(
    allowed=False,
    action="deny",
    matched_rule=None,
    reason="deny-by-default",
    denial_kind="policy",
)


def _ctx():
    return GovernanceContext(action="tool.run", subject="agent-1")


def test_core_defaults_to_a_noop_tracer() -> None:
    gov = ZemtikGovern(
        identity=_Seams(decision=_ALLOW),
        policy=_Seams(decision=_ALLOW),
        audit=_Seams(decision=_ALLOW),
    )
    assert isinstance(gov.tracer, NoOpTracer)


def test_core_stores_an_injected_tracer() -> None:
    class _RecordingTracer:
        def trace(self, name, **attrs):
            return NoOpTracer().trace(name)

    t = _RecordingTracer()
    assert isinstance(t, Tracer)
    gov = ZemtikGovern(
        identity=_Seams(decision=_ALLOW),
        policy=_Seams(decision=_ALLOW),
        audit=_Seams(decision=_ALLOW),
        tracer=t,
    )
    assert gov.tracer is t


@pytest.mark.asyncio
async def test_default_tracer_leaves_allow_decision_unchanged() -> None:
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)
    decision = await gov.govern(_ctx())
    assert decision.allowed is True
    assert decision.action == "allow"
    assert decision.reason == "ok"


@pytest.mark.asyncio
async def test_default_tracer_leaves_deny_decision_unchanged() -> None:
    seams = _Seams(decision=_DENY)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)
    with pytest.raises(GovernanceDenied):
        await gov.govern(_ctx())


def test_registry_register_tracer_threads_it_into_the_core() -> None:
    seam = _Seams(decision=_ALLOW)
    t = NoOpTracer()
    gov = (
        GovernanceRegistry()
        .register_identity(seam)
        .register_policy(seam)
        .register_audit(seam)
        .register_tracer(t)
        .build()
    )
    assert gov.tracer is t


def test_registry_without_register_tracer_defaults_to_noop() -> None:
    # A registry built without register_tracer leaves the core's NoOpTracer default —
    # observability off, and the `if self._tracer is not None` build branch is exercised.
    seam = _Seams(decision=_ALLOW)
    gov = (
        GovernanceRegistry()
        .register_identity(seam)
        .register_policy(seam)
        .register_audit(seam)
        .build()
    )
    assert isinstance(gov.tracer, NoOpTracer)
