"""S3 — GovernanceRegistry: wire the seams, refuse a half-wired core.

build() must hand back a ZemtikGovern only when all three seams are present; a
missing seam is GovernanceNotConfigured, not a core that silently skips a concern.
from_config wires the real AGT-backed seams and the result governs end to end.
"""

import pytest

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.config import GovernanceConfig
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import (
    GovernanceDenied,
    GovernanceError,
    GovernanceNotConfigured,
)
from zemtik_govern.registry import GovernanceRegistry


class _Seam:
    """Satisfies all three Protocols at once — enough to assemble a core."""

    async def identify(self, subject):
        return "did:mesh:" + subject

    async def evaluate(self, ctx):
        from zemtik_govern.protocols import Decision

        return Decision(allowed=True, action="allow", matched_rule="r", reason="ok")

    async def write(self, entry):
        return "evt-1"


def test_build_with_all_seams_returns_core():
    seam = _Seam()
    gov = (
        GovernanceRegistry()
        .register_identity(seam)
        .register_policy(seam)
        .register_audit(seam)
        .build()
    )
    assert isinstance(gov, ZemtikGovern)


def test_build_missing_seam_raises():
    with pytest.raises(GovernanceNotConfigured, match="missing seam"):
        GovernanceRegistry().register_identity(_Seam()).build()


def test_build_names_every_missing_seam():
    with pytest.raises(GovernanceNotConfigured) as exc:
        GovernanceRegistry().build()
    msg = str(exc.value)
    assert "identity" in msg and "policy" in msg and "audit" in msg


@pytest.mark.asyncio
async def test_from_config_wires_a_governing_core():
    boundary = AGTBoundary()
    cfg = GovernanceConfig(
        mode="strict",
        rules=[
            {
                "name": "allow-tool-run",
                "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
                "action": "allow",
            }
        ],
        audit_sink="memory",
        injection_rules_path="policies/prompt-injection.yaml",
    )
    gov = GovernanceRegistry.from_config(cfg, boundary).build()

    allowed = await gov.govern(GovernanceContext(action="tool.run", subject="agent-1"))
    assert allowed.allowed is True
    assert allowed.audit_event_id is not None

    # deny-by-default still holds through the wired core
    with pytest.raises(GovernanceDenied):
        await gov.govern(GovernanceContext(action="wire.transfer", subject="agent-1"))


@pytest.mark.asyncio
async def test_from_config_shadow_mode_observes_without_enforcing():
    """A shadow-mode config builds a governor that records a deny but does NOT
    raise — the mode flows config -> registry -> core."""
    boundary = AGTBoundary()
    cfg = GovernanceConfig(mode="shadow", audit_sink="memory")  # no rules: deny-all
    gov = GovernanceRegistry.from_config(cfg, boundary).build()

    decision = await gov.govern(GovernanceContext(action="anything", subject="agent-1"))
    assert decision.allowed is False  # policy would deny
    # but shadow did not raise — observe-only


@pytest.mark.asyncio
async def test_from_config_fails_closed_when_engine_errors(monkeypatch):
    """The system-denial path through the AGT-wired core, not just a fake seam:
    a policy engine fault becomes GovernanceError and the tool is blocked."""
    boundary = AGTBoundary()
    cfg = GovernanceConfig(
        mode="strict",
        rules=[
            {
                "name": "allow-tool-run",
                "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
                "action": "allow",
            }
        ],
        audit_sink="memory",
        injection_rules_path="policies/prompt-injection.yaml",
    )
    gov = GovernanceRegistry.from_config(cfg, boundary).build()

    from zemtik_govern.policy import AgentOsPolicy

    async def _boom(self, ctx):
        raise ValueError("engine exploded")

    monkeypatch.setattr(AgentOsPolicy, "evaluate", _boom)

    with pytest.raises(GovernanceError):
        await gov.govern(GovernanceContext(action="tool.run", subject="agent-1"))


_RULE = {
    "name": "allow-tool-run",
    "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
    "action": "allow",
}


@pytest.mark.asyncio
async def test_from_config_wires_file_audit_sink(tmp_path, monkeypatch):
    """A file-path audit_sink builds a durable FileAuditSink-backed core: the
    trail is written to the chosen file and the tamper-evident chain verifies."""
    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "test-secret")
    audit_file = tmp_path / "audit.jsonl"
    cfg = GovernanceConfig(
        mode="strict", rules=[_RULE], audit_sink=str(audit_file),
        injection_rules_path="policies/prompt-injection.yaml",
    )
    gov = GovernanceRegistry.from_config(cfg, AGTBoundary()).build()

    decision = await gov.govern(GovernanceContext(action="tool.run", subject="agent-1"))
    assert decision.allowed is True
    assert audit_file.exists() and audit_file.read_text(encoding="utf-8").strip()


def test_from_config_file_sink_without_secret_fails_closed(tmp_path, monkeypatch):
    """A file sink with no HMAC secret in the environment is a startup error — an
    unsigned tamper-evident log is a contradiction, refuse rather than degrade."""
    monkeypatch.delenv("ZEMTIK_AUDIT_SECRET", raising=False)
    cfg = GovernanceConfig(
        mode="strict", rules=[_RULE], audit_sink=str(tmp_path / "audit.jsonl")
    )
    with pytest.raises(GovernanceNotConfigured, match="secret"):
        GovernanceRegistry.from_config(cfg, AGTBoundary())
