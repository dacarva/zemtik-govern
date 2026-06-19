"""S5 — the audit package: a thin adapter over agentmesh's Merkle-chained log,
plus the redacted emergency fallback channel.

The adapter MUST convert a deeply-frozen GovernanceContext payload back to a plain
dict before agentmesh serializes it — agentmesh hashes entries with
``json.dumps``, which rejects ``MappingProxyType``. The fallback channel records a
metadata-only, redacted record if the primary sink ever fails, while the denial
invariant still holds: the guarded tool never runs.
"""

import stat

import pytest

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.audit import AgentMeshAudit
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceError
from zemtik_govern.protocols import AuditEntry, Decision

_ALLOW = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")


class _BrokenSink:
    """An agentmesh sink whose write always fails — simulates a dead primary."""

    def write(self, entry):
        raise OSError("disk full")


def _frozen_ctx():
    # nested dict -> deep-frozen into nested MappingProxyType by GovernanceContext
    return GovernanceContext(
        action="tool.run",
        subject="loopay-1",
        payload={"amount": 5, "meta": {"currency": "USD"}},
        idempotency_key="idem-1",
        ts="2026-06-18T00:00:00Z",
    )


@pytest.mark.asyncio
async def test_adapter_converts_frozen_payload_and_audit_verifies():
    """A deeply-frozen payload writes through the real memory sink without a
    serialization error, and the tamper-evident chain verifies."""
    audit = AgentMeshAudit(AGTBoundary())
    ctx = _frozen_ctx()
    # write twice: a Merkle proof needs a chain (>=2 leaves)
    first = await audit.write(AuditEntry.from_decision(ctx, "did:mesh:loopay-1", _ALLOW))
    await audit.write(AuditEntry.from_decision(ctx, "did:mesh:loopay-1", _ALLOW))
    assert first
    ok, err = audit.verify_integrity()
    assert ok, err
    assert audit.get_proof(first) is not None

    # fidelity: the payload was thawed to a real nested dict, not stringified —
    # the bytes policy saw are the bytes audit recorded.
    stored = audit._log.get_entry(first)
    assert stored.data["payload"] == {"amount": 5, "meta": {"currency": "USD"}}
    assert isinstance(stored.data["payload"]["meta"], dict)


class _AllowSeams:
    async def identify(self, subject):
        return "did:mesh:" + subject

    async def evaluate(self, ctx):
        return _ALLOW


@pytest.mark.asyncio
async def test_audit_sink_failure_still_denies(tmp_path):
    """If the primary sink raises, govern() fails closed with a GovernanceError and
    the guarded tool never runs — the denial invariant holds even when audit can't."""
    audit = AgentMeshAudit(
        AGTBoundary(), sink=_BrokenSink(), fallback_path=tmp_path / "fb.jsonl"
    )
    seams = _AllowSeams()
    gov = ZemtikGovern(identity=seams, policy=seams, audit=audit)

    ran = []
    tool = gov.proxy(lambda: ran.append("ran"), action="tool.run", subject="agent-1")
    with pytest.raises(GovernanceError):
        await tool()
    assert ran == []  # tool never executed


@pytest.mark.asyncio
async def test_fallback_redacts_payload(tmp_path):
    """The fallback record carries payload_sha256 but NEVER the raw payload."""
    fb = tmp_path / "fb.jsonl"
    audit = AgentMeshAudit(AGTBoundary(), sink=_BrokenSink(), fallback_path=fb)
    ctx = _frozen_ctx()  # payload {amount: 5, meta: {currency: USD}}
    with pytest.raises(GovernanceError):
        await audit.write(AuditEntry.from_decision(ctx, "did:mesh:loopay-1", _ALLOW))

    body = fb.read_text(encoding="utf-8")
    assert "payload_sha256" in body
    assert "idem-1" in body  # metadata kept
    # raw payload values must be absent
    assert "USD" not in body
    assert '"amount"' not in body


def test_fallback_file_is_owner_only(tmp_path):
    """The fallback file is created mode 0600 — no group/other access."""
    from zemtik_govern.audit import emit_fallback

    fb = tmp_path / "fb.jsonl"
    entry = AuditEntry.from_decision(_frozen_ctx(), "did:mesh:x", _ALLOW)
    emit_fallback(entry, OSError("boom"), path=fb)
    mode = stat.S_IMODE(fb.stat().st_mode)
    assert mode == 0o600
