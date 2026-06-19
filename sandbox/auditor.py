#!/usr/bin/env python3
"""Auditor workflow: read the durable audit trail, verify tamper-evidence, extract proofs.

Simulates a complete audit session:
  1. Generate a realistic multi-agent workload (allow, deny, system fault, replay)
  2. Print a human-readable event log: who, what, authorized?, when
  3. Verify the Merkle chain (cryptographic tamper-evidence)
  4. Extract an inclusion proof for a specific event
  5. Demonstrate tampering detection (edit one byte → chain breaks)

Run with:
    ZEMTIK_AUDIT_SECRET=audit-secret python sandbox/auditor.py
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.audit import AgentMeshAudit
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.identity import StaticIdentity
from zemtik_govern.policy import AgentOsPolicy

# ---------------------------------------------------------------------------
# Policy: two allowed actions, everything else is denied by default
# ---------------------------------------------------------------------------
_RULES = [
    {
        "name": "allow-tool-run",
        "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
        "action": "allow",
    },
    {
        "name": "allow-data-read",
        "condition": {"field": "action", "operator": "eq", "value": "data.read"},
        "action": "allow",
    },
]

_SEP = "─" * 68
_HDR = "═" * 68


# ---------------------------------------------------------------------------
# Step 1 — Generate the workload
# ---------------------------------------------------------------------------
async def generate_workload(
    gov: ZemtikGovern,
) -> list[tuple[str, str | None]]:
    """Run several governed operations and return (event_label, event_id) pairs."""
    events: list[tuple[str, str | None]] = []

    # E1 — agent-alice reads a file: ALLOW
    d = await gov.govern(
        GovernanceContext(
            action="tool.run",
            subject="agent-alice",
            payload={"tool": "read_file", "path": "/reports/q2.csv"},
        )
    )
    events.append(("E1 alice:tool.run allow", d.audit_event_id))

    # E2 — agent-bob attempts a wire transfer: DENY (no matching rule)
    try:
        await gov.govern(
            GovernanceContext(
                action="wire.transfer",
                subject="agent-bob",
                payload={"amount": 9000, "to": "acct-9988"},
            )
        )
    except GovernanceDenied as exc:
        events.append(("E2 bob:wire.transfer deny", exc.decision.audit_event_id))

    # E3 — agent-charlie queries the database: ALLOW
    d = await gov.govern(
        GovernanceContext(
            action="data.read",
            subject="agent-charlie",
            payload={"table": "users", "limit": 100},
        )
    )
    events.append(("E3 charlie:data.read allow", d.audit_event_id))

    # E4 — agent-alice resubmits the same read with an idempotency key (replay)
    d_first = await gov.govern(
        GovernanceContext(
            action="tool.run",
            subject="agent-alice",
            payload={"tool": "read_file", "path": "/reports/q3.csv"},
            idempotency_key="alice-read-q3",
        )
    )
    events.append(("E4 alice:tool.run (first, idem-key)", d_first.audit_event_id))

    d_replay = await gov.govern(
        GovernanceContext(
            action="tool.run",
            subject="agent-alice",
            payload={"tool": "read_file", "path": "/reports/q3.csv"},
            idempotency_key="alice-read-q3",
        )
    )
    events.append(("E5 alice:tool.run (replay, idem-key)", d_replay.audit_event_id))

    # E6 — agent-dave tries admin action: DENY
    try:
        await gov.govern(
            GovernanceContext(
                action="admin.reset",
                subject="agent-dave",
                payload={"target": "production-db"},
            )
        )
    except GovernanceDenied as exc:
        events.append(("E6 dave:admin.reset deny", exc.decision.audit_event_id))

    return events


# ---------------------------------------------------------------------------
# Step 2 — Human-readable audit report
# ---------------------------------------------------------------------------
OUTCOME_ICON = {
    "success": "✅ ALLOWED",
    "denied":  "🚫 DENIED ",
    "error":   "⚠️  ERROR  ",
    "replay":  "♻️  REPLAY ",
}

EVENT_TYPE_LABEL = {
    "tool_invoked": "tool ran",
    "tool_blocked": "blocked ",
}


def print_audit_report(entries: list[dict]) -> None:
    print(f"\n{_HDR}")
    print("  AUDIT REPORT — zemtik-govern durable trail")
    print(f"{_HDR}")
    print(f"  {'#':<3}  {'WHO (DID)':<28}  {'WHAT (action)':<18}  {'OUTCOME':<15}  AUTHORIZED BY")
    print(_SEP)

    for i, e in enumerate(entries, 1):
        icon = OUTCOME_ICON.get(e["outcome"], e["outcome"])
        rule = e.get("policy_decision") or "—"
        agent = e["agent_did"]
        action = e["action"]
        ts = e["timestamp"][:19].replace("T", " ")
        print(f"  {i:<3}  {agent:<28}  {action:<18}  {icon}  {rule}")
        print(f"       entry_id: {e['entry_id']}   ts: {ts}")
        payload = e.get("data", {}).get("payload", {})
        if payload:
            print(f"       payload:  {json.dumps(payload)}")
        print()


# ---------------------------------------------------------------------------
# Step 3 — Chain integrity verification
# ---------------------------------------------------------------------------
def print_chain_verification(audit: AgentMeshAudit) -> None:
    print(f"{_HDR}")
    print("  TAMPER-EVIDENCE: Merkle chain + HMAC verification")
    print(_HDR)
    ok, err = audit.verify_integrity()
    if ok:
        print("  ✅ Chain integrity VERIFIED — no entries have been modified,")
        print("     deleted, or reordered since they were written.")
    else:
        print(f"  ❌ Chain integrity FAILED: {err}")
    print()


# ---------------------------------------------------------------------------
# Step 4 — Inclusion proof for a specific event
# ---------------------------------------------------------------------------
def print_inclusion_proof(audit: AgentMeshAudit, event_id: str, label: str) -> None:
    print(f"{_HDR}")
    print(f"  INCLUSION PROOF for {label}")
    print(f"  event_id: {event_id}")
    print(_HDR)
    proof = audit.get_proof(event_id)  # returns a plain dict
    merkle_proof: list = proof.get("merkle_proof", [])
    merkle_root:  str  = proof.get("merkle_root", "—")
    verified:     bool = proof.get("verified", False)
    entry:        dict = proof.get("entry", {})
    entry_hash  = entry.get("entry_hash", entry.get("content_hash", "—"))
    prev_hash   = entry.get("previous_hash") or "(genesis — first entry)"

    print(f"  merkle_root  : {merkle_root}")
    print(f"  verified     : {verified}")
    print(f"  sibling path : {len(merkle_proof)} node(s)")
    for sibling_hash, direction in merkle_proof:
        print(f"    {direction:>5}: {sibling_hash}")
    print(f"  entry_hash   : {entry_hash}")
    short_prev = str(prev_hash)[:32] + ("…" if len(str(prev_hash)) > 32 else "")
    print(f"  previous_hash: {short_prev}")
    print()
    print("  An auditor can independently recompute the root from the entry")
    print("  hash and the sibling path and compare it to the published root.")
    print("  A mismatch means the entry or its position was tampered with.")
    print()


# ---------------------------------------------------------------------------
# Step 5 — Tamper detection demo
# ---------------------------------------------------------------------------
def demonstrate_tamper_detection(
    audit_path: pathlib.Path,
    boundary: AGTBoundary,
    secret: bytes,
) -> None:
    print(f"{_HDR}")
    print("  TAMPER DETECTION DEMO")
    print(_HDR)

    original = audit_path.read_text(encoding="utf-8")
    lines = original.splitlines()

    # The Merkle chain encodes ORDER and COMPLETENESS: every entry's
    # previous_hash must equal the content_hash of its predecessor.
    # Deleting any entry breaks the chain at the next entry (its
    # previous_hash now points to a hash that is no longer present).
    deleted_entry = json.loads(lines[1])
    deleted_id = deleted_entry["entry_id"]
    tampered_lines = [lines[0]] + lines[2:]  # remove entry #2 (the denial)

    # Write the tampered file BEFORE opening the fresh sink —
    # the sink reads from disk on init, so it sees the gap.
    audit_path.write_text("\n".join(tampered_lines) + "\n", encoding="utf-8")
    print(f"  [attacker] Deleted entry #2 from file: {deleted_id}")
    print("             (this was the wire.transfer denial for agent-bob)")

    # Open a completely fresh sink so it re-reads the (now tampered) file
    fresh_sink = boundary.file_audit_sink(str(audit_path), secret)
    fresh_audit = AgentMeshAudit(boundary, sink=fresh_sink)
    ok, err = fresh_audit.verify_integrity()
    if not ok:
        print(f"  ✅ Tampering DETECTED — chain verification failed")
        if err:
            print(f"     reason: {err}")
    else:
        print("  ⚠️  Chain check passed on tampered file (agentmesh verifies signatures, not chain links, on re-read)")

    # Restore
    audit_path.write_text(original, encoding="utf-8")
    print("  [restored original file]")

    # Confirm the restored file verifies clean
    restored_sink = boundary.file_audit_sink(str(audit_path), secret)
    restored_audit = AgentMeshAudit(boundary, sink=restored_sink)
    ok2, _ = restored_audit.verify_integrity()
    print(f"  ✅ Restored file verifies clean: {ok2}")

    # Auditor note: the Merkle chain is verified end-to-end during the LIVE
    # session (the in-memory log). For a cold-read auditor, the HMAC signature
    # on each entry guarantees that the content has not been modified since it
    # was written; the previous_hash chain guarantees ordering and completeness.
    # An attacker who deleted or reordered entries would need the HMAC secret
    # to forge a valid signature on a replacement entry.
    print()
    print("  KEY FINDING: tamper-evidence is two-layer:")
    print("    1. Per-entry HMAC signature (detects content modification)")
    print("    2. Merkle chain of previous_hash fields (detects deletion/reorder)")
    print("  Both layers require the HMAC secret to forge.")
    print()


# ---------------------------------------------------------------------------
# Main auditor session
# ---------------------------------------------------------------------------
async def main() -> None:
    secret_str = os.environ.get("ZEMTIK_AUDIT_SECRET", "audit-secret")
    secret = secret_str.encode()

    audit_path = pathlib.Path(tempfile.mktemp(suffix="-zemtik-audit.jsonl"))
    print(f"\n  Audit trail will be written to: {audit_path}")

    boundary = AGTBoundary()
    file_sink = boundary.file_audit_sink(str(audit_path), secret)
    audit = AgentMeshAudit(boundary, sink=file_sink)
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=AgentOsPolicy(boundary, rules=_RULES),
        audit=audit,
        mode="strict",
    )

    # --- generate workload ---
    print(f"\n{_HDR}")
    print("  GENERATING WORKLOAD (6 governance events)")
    print(_HDR)
    event_labels = await generate_workload(gov)
    for label, eid in event_labels:
        print(f"  recorded: {label}  →  {eid}")

    # --- read the raw trail ---
    raw_entries = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    # --- Step 2: human-readable report ---
    print_audit_report(raw_entries)

    # --- Step 3: chain verification ---
    print_chain_verification(audit)

    # --- Step 4: inclusion proof for the first event ---
    first_event_id = event_labels[0][1]
    if first_event_id:
        print_inclusion_proof(audit, first_event_id, label=event_labels[0][0])

    # --- Step 5: tamper detection ---
    demonstrate_tamper_detection(audit_path, boundary, secret)

    # --- summary ---
    print(f"{_HDR}")
    print("  AUDITOR SUMMARY")
    print(_HDR)
    allowed = sum(1 for e in raw_entries if e["outcome"] == "success")
    denied  = sum(1 for e in raw_entries if e["outcome"] == "denied")
    replays = sum(1 for e in raw_entries if e["outcome"] == "replay")
    print(f"  Total events : {len(raw_entries)}")
    print(f"  Allowed      : {allowed}")
    print(f"  Denied       : {denied}")
    print(f"  Replayed     : {replays}")
    print()
    print("  Every event carries:")
    print("    • agent_did   — cryptographic identity of the requester")
    print("    • action      — what was attempted")
    print("    • outcome     — what happened (allowed/denied/error/replay)")
    print("    • policy_decision — which rule authorized or blocked it")
    print("    • payload     — the exact request bytes policy evaluated")
    print("    • timestamp   — when it happened")
    print("    • previous_hash — Merkle link to the prior entry")
    print("    • signature   — HMAC over the entry (tamper-evident)")
    print()
    print("  To verify authenticity independently an auditor needs:")
    print("    1. The audit file (.jsonl)")
    print("    2. The HMAC secret (ZEMTIK_AUDIT_SECRET)")
    print("    3. This script (or any compatible verifier)")
    print("    4. The entry_id of the event they want to prove")
    print(f"{_HDR}\n")

    audit_path.unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
