"""End-to-end: one wired ``govern()`` path across REAL pinned AGT.

Identity (StaticIdentity) → policy (AgentOsPolicy, deny-by-default) → audit
(AgentMeshAudit, Merkle-chained), run through ZemtikGovern. Proves the seams fit
together against the live AGT surface, not just against fakes — the S3
pressure-test in miniature.
"""

import pytest

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.audit import AgentMeshAudit
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied
from zemtik_govern.identity import StaticIdentity
from zemtik_govern.policy import AgentOsPolicy


def _wire():
    boundary = AGTBoundary()
    rules = [
        {
            "name": "allow-tool-run",
            "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
            "action": "allow",
        }
    ]
    audit = AgentMeshAudit(boundary)
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=AgentOsPolicy(boundary, rules=rules),
        audit=audit,
    )
    return gov, audit


@pytest.mark.asyncio
async def test_e2e_allow_then_deny_with_verifiable_audit():
    gov, audit = _wire()

    # allow path — matched rule, returns a Decision stamped with its audit id
    allowed = await gov.govern(GovernanceContext(action="tool.run", subject="loopay-1"))
    assert allowed.allowed is True
    assert allowed.audit_event_id is not None

    # deny path — deny-by-default raises, but the denial is audited first
    with pytest.raises(GovernanceDenied) as exc:
        await gov.govern(GovernanceContext(action="wire.transfer", subject="loopay-1"))
    assert exc.value.decision.denial_kind == "policy"

    # the tamper-evident chain holds across both outcomes (>=2 entries)
    ok, err = audit.verify_integrity()
    assert ok, err
    assert audit.get_proof(allowed.audit_event_id) is not None
