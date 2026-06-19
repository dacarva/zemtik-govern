"""S3 — the policy core (E2 deny-by-default, E8 Decision mapping).

The moat: raw AGT ``PolicyEvaluator`` returns ``allowed=True`` when no rule
matches (fail-OPEN — verified in S1's conformance test). ``AgentOsPolicy`` is the
adapter that turns that into deny-by-default before any decision leaves the
wrapper. These tests run against the REAL pinned AGT through the boundary.
"""

import pytest

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.context import GovernanceContext
from zemtik_govern.policy import AgentOsPolicy


def _allow_rule(action: str):
    return {
        "name": f"allow-{action}",
        "condition": {"field": "action", "operator": "eq", "value": action},
        "action": "allow",
    }


def _deny_rule(action: str):
    return {
        "name": f"deny-{action}",
        "condition": {"field": "action", "operator": "eq", "value": action},
        "action": "deny",
    }


@pytest.mark.asyncio
async def test_policy_denies_by_default_when_no_rule_matches():
    """AGT fails open here; the wrapper must deny. This is the whole moat."""
    policy = AgentOsPolicy(AGTBoundary(), rules=[_allow_rule("tool.run")])
    decision = await policy.evaluate(
        GovernanceContext(action="something.unlisted", subject="agent-1")
    )
    assert decision.allowed is False
    assert decision.denial_kind == "policy"
    assert decision.matched_rule is None


@pytest.mark.asyncio
async def test_policy_allows_when_a_rule_matches():
    """A matching allow rule lets it through; the matched rule is reported."""
    policy = AgentOsPolicy(AGTBoundary(), rules=[_allow_rule("tool.run")])
    decision = await policy.evaluate(
        GovernanceContext(action="tool.run", subject="agent-1")
    )
    assert decision.allowed is True
    assert decision.denial_kind is None
    assert decision.matched_rule is not None


@pytest.mark.asyncio
async def test_policy_denies_when_a_rule_denies():
    """An explicit deny rule is a policy deny (distinct from deny-by-default)."""
    policy = AgentOsPolicy(
        AGTBoundary(), rules=[_allow_rule("tool.run"), _deny_rule("transfer")]
    )
    decision = await policy.evaluate(
        GovernanceContext(action="transfer", subject="agent-1")
    )
    assert decision.allowed is False
    assert decision.denial_kind == "policy"
    assert decision.matched_rule is not None
