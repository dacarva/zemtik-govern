"""S4 — operational safety modes: shadow / enforce + the kill-switch.

Shadow observes without enforcing; enforce denies; the kill-switch reverts to the
prior *governed* fallback path (never allow-all). Lightweight fakes for the seams
pin the control flow, not AGT internals.
"""

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import Killswitch, ZemtikGovern
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.identity import AgentRef
from zemtik_govern.protocols import Decision

_ALLOW = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
_DENY = Decision(
    allowed=False, action="deny", matched_rule=None,
    reason="deny-by-default", denial_kind="policy",
)


class _Seams:
    """Identity + audit fakes with a fixed policy decision; records entries."""

    def __init__(self, decision=_ALLOW):
        self._decision = decision
        self.entries = []

    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)

    async def evaluate(self, ctx):
        return self._decision

    async def write(self, entry):
        self.entries.append(entry)
        return "evt-1"


def _ctx():
    return GovernanceContext(action="tool.run", subject="agent-1")


@pytest.mark.asyncio
async def test_enforce_mode_denies():
    """enforce mode raises GovernanceDenied on a blocked action and stamps the
    mode on the audit entry."""
    seams = _Seams(decision=_DENY)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, mode="enforce")
    with pytest.raises(GovernanceDenied):
        await gov.govern(_ctx())
    assert seams.entries[-1].mode == "enforce"


@pytest.mark.asyncio
async def test_shadow_mode_no_enforce():
    """shadow mode logs the would-be denial, does NOT raise, and the wrapped tool
    still executes — surfacing false-denies on live traffic without blocking it."""
    seams = _Seams(decision=_DENY)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, mode="shadow")

    ran = []
    tool = gov.proxy(lambda: ran.append("ran"), action="tool.run", subject="agent-1")
    await tool()

    assert ran == ["ran"]  # the tool executed despite the deny
    assert seams.entries[-1].mode == "shadow"  # distinction is observable
    assert seams.entries[-1].outcome == "denied"  # the would-be deny is recorded


class _FallbackPolicy:
    """The prior governed path: it still governs — here it denies."""

    async def evaluate(self, ctx):
        return Decision(
            allowed=False, action="deny", matched_rule=None,
            reason="fallback governed deny", denial_kind="policy",
        )


@pytest.mark.asyncio
async def test_killswitch_reverts_governed():
    """Flipping the kill-switch routes evaluation to the prior governed fallback
    path — which denies — proving it reverts to governance, not to allow-all."""
    seams = _Seams(decision=_ALLOW)  # wrapper policy would ALLOW
    ks = Killswitch()
    gov = ZemtikGovern(
        identity=seams, policy=seams, audit=seams,
        mode="enforce", fallback=_FallbackPolicy(), killswitch=ks,
    )

    # switch off: the wrapper's own policy allows
    allowed = await gov.govern(_ctx())
    assert allowed.allowed is True

    # switch on: routed to the governed fallback, which denies (not allow-all)
    ks.engage()
    with pytest.raises(GovernanceDenied) as exc:
        await gov.govern(_ctx())
    assert exc.value.decision.reason == "fallback governed deny"

    # switch back off: routing reverts to the wrapper's own policy, which allows
    ks.disengage()
    restored = await gov.govern(_ctx())
    assert restored.allowed is True


@pytest.mark.asyncio
async def test_killswitch_without_fallback_fails_closed():
    """Engaging the switch with no governed fallback wired must never silently
    allow-all — it fails closed as a system denial."""
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(
        identity=seams, policy=seams, audit=seams,
        mode="enforce", killswitch=Killswitch(engaged=True),
    )
    with pytest.raises(GovernanceError):
        await gov.govern(_ctx())
    assert seams.entries[-1].outcome == "error"
