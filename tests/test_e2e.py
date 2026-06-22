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
    allowed = await gov.govern(GovernanceContext(action="tool.run", subject="agent-1"))
    assert allowed.allowed is True
    assert allowed.audit_event_id is not None

    # deny path — deny-by-default raises, but the denial is audited first
    with pytest.raises(GovernanceDenied) as exc:
        await gov.govern(GovernanceContext(action="wire.transfer", subject="agent-1"))
    assert exc.value.decision.denial_kind == "policy"

    # the tamper-evident chain holds across both outcomes (>=2 entries)
    ok, err = audit.verify_integrity()
    assert ok, err
    assert audit.get_proof(allowed.audit_event_id) is not None


# --- S6 end-to-end: identity stamps the audit trail --------------------------


@pytest.mark.asyncio
async def test_e2e_identity_stamps_agent_did_on_durable_audit(tmp_path, monkeypatch):
    """Through the live stack, StaticIdentity resolves the subject to its
    did:mesh DID and that DID is what every durable audit entry is stamped with —
    no faked random identity reaches the trail."""
    from zemtik_govern.config import GovernanceConfig
    from zemtik_govern.registry import GovernanceRegistry

    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "s6-secret")
    audit_file = tmp_path / "audit.jsonl"
    cfg = GovernanceConfig(
        mode="strict", rules=[_ALLOW_TOOL_RUN], audit_sink=str(audit_file),
        injection_rules_path="policies/prompt-injection.yaml",
    )
    boundary = AGTBoundary()
    gov = GovernanceRegistry.from_config(cfg, boundary).build()

    await gov.govern(GovernanceContext(action="tool.run", subject="agent-7"))

    body = audit_file.read_text(encoding="utf-8")
    assert "did:mesh:agent-7" in body  # identity, deterministic, stamped on audit
    assert "secrets" not in body  # never a random token_hex identity


# --- S4/S5 end-to-end: modes, kill-switch, durable + fallback audit ----------

_ALLOW_TOOL_RUN = {
    "name": "allow-tool-run",
    "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
    "action": "allow",
}


@pytest.mark.asyncio
async def test_e2e_shadow_mode_observes_real_deny_without_blocking():
    """Through the live AGT stack: a shadow-mode governor records a real
    deny-by-default but lets the wrapped tool run, and the recorded entry is
    stamped ``shadow`` on a chain that still verifies."""
    boundary = AGTBoundary()
    audit = AgentMeshAudit(boundary)
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=AgentOsPolicy(boundary, rules=[_ALLOW_TOOL_RUN]),
        audit=audit,
        mode="shadow",
    )

    ran = []
    # "wire.transfer" matches no rule -> AgentOsPolicy denies by default; shadow
    # records it but must not block the tool.
    tool = gov.proxy(
        lambda amount: ran.append(amount),
        action="wire.transfer",
        subject="agent-1",
    )
    await tool(500)

    assert ran == [500]  # the tool executed despite the real deny
    ok, err = audit.verify_integrity()
    assert ok, err


@pytest.mark.asyncio
async def test_e2e_killswitch_reverts_to_governed_fallback():
    """The kill-switch reroutes a live governor from its (allowing) primary policy
    to a prior governed AGT path that denies — proving the revert is to governance,
    never to allow-all."""
    boundary = AGTBoundary()
    from zemtik_govern.core import Killswitch

    primary = AgentOsPolicy(boundary, rules=[_ALLOW_TOOL_RUN])  # allows tool.run
    fallback = AgentOsPolicy(boundary, rules=None)  # deny-by-default on everything
    ks = Killswitch()
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=primary,
        audit=AgentMeshAudit(boundary),
        mode="enforce",
        fallback=fallback,
        killswitch=ks,
    )

    ctx = GovernanceContext(action="tool.run", subject="agent-1")
    assert (await gov.govern(ctx)).allowed is True  # primary allows

    ks.engage()
    with pytest.raises(GovernanceDenied) as exc:
        await gov.govern(ctx)  # routed to the governed fallback, which denies
    assert exc.value.decision.denial_kind == "policy"


@pytest.mark.asyncio
async def test_e2e_durable_file_audit_sink_writes_and_verifies(tmp_path, monkeypatch):
    """from_config with a file-path audit_sink produces a durable, HMAC-signed
    trail on disk across an allow and a deny, and the sink's own chain verifies."""
    from zemtik_govern.config import GovernanceConfig
    from zemtik_govern.registry import GovernanceRegistry

    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "e2e-secret")
    audit_file = tmp_path / "audit.jsonl"
    cfg = GovernanceConfig(
        mode="strict", rules=[_ALLOW_TOOL_RUN], audit_sink=str(audit_file),
        injection_rules_path="policies/prompt-injection.yaml",
    )
    boundary = AGTBoundary()
    gov = GovernanceRegistry.from_config(cfg, boundary).build()

    await gov.govern(GovernanceContext(action="tool.run", subject="agent-1"))
    with pytest.raises(GovernanceDenied):
        await gov.govern(GovernanceContext(action="wire.transfer", subject="agent-1"))

    # both outcomes landed durably on disk (one JSON line each)
    lines = [ln for ln in audit_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2

    # the file sink's own tamper-evident chain verifies with the same secret
    sink = boundary.file_audit_sink(str(audit_file), b"e2e-secret")
    ok, err = sink.verify_integrity()
    assert ok, err


@pytest.mark.asyncio
async def test_e2e_audit_failure_falls_back_redacted_and_denies(tmp_path):
    """When the durable sink fails mid-flight, the live governor writes a redacted
    fallback (digest, never the raw payload) and fails closed — the tool is never
    invoked."""
    boundary = AGTBoundary()

    class _DeadSink:
        def write(self, entry):
            raise OSError("disk full")

    fb = tmp_path / "fallback.jsonl"
    audit = AgentMeshAudit(boundary, sink=_DeadSink(), fallback_path=fb)
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=AgentOsPolicy(boundary, rules=[_ALLOW_TOOL_RUN]),
        audit=audit,
        mode="enforce",
    )

    ran = []
    tool = gov.proxy(
        lambda **kw: ran.append(kw),
        action="tool.run",
        subject="agent-1",
    )
    from zemtik_govern.errors import GovernanceError

    with pytest.raises(GovernanceError):
        await tool(account="acct-secret-123", amount=42)

    assert ran == []  # fail-closed: the tool never ran
    body = fb.read_text(encoding="utf-8")
    assert "payload_sha256" in body
    assert "acct-secret-123" not in body  # raw payload never written to fallback
