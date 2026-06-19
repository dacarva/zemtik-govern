"""TDD: AuditReader — reads a durable audit trail and exposes typed records,
chain verification, and Merkle inclusion proofs.

Red→Green cycles:
  1. records() returns typed AuditRecord objects
  2. verify() passes on intact trail, fails when an entry is deleted
  3. proof(entry_id) returns a verifiable Merkle dict
  4. Wrong HMAC secret → verify() fails
"""
import pytest

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.audit import AgentMeshAudit
from zemtik_govern.audit.reader import AuditReader, AuditRecord
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied
from zemtik_govern.identity import StaticIdentity
from zemtik_govern.policy import AgentOsPolicy

_SECRET = b"test-hmac-secret"
_RULES = [
    {
        "name": "allow-tool-run",
        "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
        "action": "allow",
    }
]


async def _write_trail(path, *, rules=_RULES, secret=_SECRET):
    """Write a 3-entry trail: allow, deny, allow. Returns the gov + event ids."""
    boundary = AGTBoundary()
    file_sink = boundary.file_audit_sink(str(path), secret)
    audit = AgentMeshAudit(boundary, sink=file_sink)
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=AgentOsPolicy(boundary, rules=rules),
        audit=audit,
        mode="strict",
    )
    d1 = await gov.govern(GovernanceContext(action="tool.run", subject="alice"))
    try:
        await gov.govern(GovernanceContext(action="wire.transfer", subject="bob"))
    except GovernanceDenied:
        pass
    d3 = await gov.govern(GovernanceContext(action="tool.run", subject="charlie"))
    return boundary, d1.audit_event_id, d3.audit_event_id


# ---------------------------------------------------------------------------
# Cycle 1 — records() returns typed AuditRecord objects
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_records_returns_typed_audit_records(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    boundary, _, _ = await _write_trail(audit_file)

    reader = AuditReader(audit_file, boundary, _SECRET)
    records = reader.records()

    assert len(records) == 3
    for r in records:
        assert isinstance(r, AuditRecord)
        assert r.entry_id
        assert r.agent_did.startswith("did:mesh:")
        assert r.action
        assert r.outcome in ("success", "denied", "error", "replay")
        assert r.timestamp


@pytest.mark.asyncio
async def test_records_maps_fields_correctly(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    boundary, _, _ = await _write_trail(audit_file)

    reader = AuditReader(audit_file, boundary, _SECRET)
    records = reader.records()

    allow_rec = records[0]
    deny_rec  = records[1]

    assert allow_rec.agent_did == "did:mesh:alice"
    assert allow_rec.action == "tool.run"
    assert allow_rec.outcome == "success"
    assert allow_rec.event_type == "tool_invoked"
    assert "allow-tool-run" in (allow_rec.policy_decision or "")

    assert deny_rec.agent_did == "did:mesh:bob"
    assert deny_rec.action == "wire.transfer"
    assert deny_rec.outcome == "denied"
    assert deny_rec.event_type == "tool_blocked"


@pytest.mark.asyncio
async def test_records_payload_is_dict(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    boundary, _, _ = await _write_trail(audit_file)

    reader = AuditReader(audit_file, boundary, _SECRET)
    records = reader.records()

    for r in records:
        assert isinstance(r.payload, dict)


# ---------------------------------------------------------------------------
# Cycle 2 — verify() passes on intact trail, fails when entry is deleted
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_returns_true_on_intact_trail(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    boundary, _, _ = await _write_trail(audit_file)

    reader = AuditReader(audit_file, boundary, _SECRET)
    ok, err = reader.verify()

    assert ok is True
    assert err is None


@pytest.mark.asyncio
async def test_verify_detects_deleted_entry(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    boundary, _, _ = await _write_trail(audit_file)

    # Delete the middle entry (the denial)
    lines = [ln for ln in audit_file.read_text().splitlines() if ln.strip()]
    assert len(lines) == 3
    lines.pop(1)  # remove entry #2
    audit_file.write_text("\n".join(lines) + "\n")

    # Fresh reader sees the tampered file
    fresh_boundary = AGTBoundary()
    reader = AuditReader(audit_file, fresh_boundary, _SECRET)
    ok, err = reader.verify()

    assert ok is False


# ---------------------------------------------------------------------------
# Cycle 3 — proof(entry_id) returns a verifiable Merkle dict
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proof_returns_dict_with_expected_keys(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    boundary, event_id, _ = await _write_trail(audit_file)

    reader = AuditReader(audit_file, boundary, _SECRET)
    p = reader.proof(event_id)

    assert isinstance(p, dict)
    assert "merkle_root" in p
    assert "merkle_proof" in p
    assert "verified" in p
    assert "entry" in p


@pytest.mark.asyncio
async def test_proof_is_verified(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    boundary, event_id, _ = await _write_trail(audit_file)

    reader = AuditReader(audit_file, boundary, _SECRET)
    p = reader.proof(event_id)

    assert p["verified"] is True
    assert p["merkle_root"]


@pytest.mark.asyncio
async def test_proof_sibling_path_is_list(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    boundary, event_id, _ = await _write_trail(audit_file)

    reader = AuditReader(audit_file, boundary, _SECRET)
    p = reader.proof(event_id)

    assert isinstance(p["merkle_proof"], list)
    assert len(p["merkle_proof"]) > 0


# ---------------------------------------------------------------------------
# Cycle 4 — wrong HMAC secret → verify() fails
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_fails_with_wrong_secret(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    boundary, _, _ = await _write_trail(audit_file)

    wrong_boundary = AGTBoundary()
    reader = AuditReader(audit_file, wrong_boundary, b"wrong-secret")
    ok, _ = reader.verify()

    assert ok is False
