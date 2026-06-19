#!/usr/bin/env python
"""S1 spike — verify the live AGT surface and emit the compat map.

Run: `python spike/verify_agt_signatures.py`  (venv active)

This is the half-day spike from the design doc, kept executable so the compat
map never drifts from prose. It goes through the single AGT boundary, confirms
all three governed concerns (policy / audit / identity), and prints the
agent_os -> agentmesh map that the wrapper's core relies on.

The hard assertions here mirror tests/test_agt_conformance.py; this file is the
human-readable companion (run it, read the report) while the tests are the CI
gate.
"""

from __future__ import annotations

import importlib.metadata as metadata

from zemtik_govern._agt import AGT_PINS, AGTBoundary


def main() -> int:
    print("=" * 70)
    print("zemtik-govern S1 spike — AGT signature + compat verification")
    print("=" * 70)

    # 1. Pins: distribution metadata is authoritative, NOT module.__version__.
    import agent_os
    import agentmesh

    print("\n[1] Version reality check")
    for dist in AGT_PINS:
        print(f"    {dist:<22} dist={metadata.version(dist)}  (pinned {AGT_PINS[dist]})")
    print(f"    agent_os.__version__  = {getattr(agent_os, '__version__', '?')}  <- LAGS, do not trust")
    print(f"    agentmesh.__version__ = {getattr(agentmesh, '__version__', '?')}  <- LAGS, do not trust")

    boundary = AGTBoundary()  # asserts pins; raises AGTVersionError on drift
    print("    -> AGTBoundary() constructed; pins asserted via importlib.metadata")

    # 2. Policy concern (agent_os).
    print("\n[2] Policy  — agent_os.policies.PolicyEvaluator")
    decision = boundary._policy_evaluator().evaluate({"action": "tool.run", "subject": "agent-1"})
    print("    evaluate(ctx: dict) -> PolicyDecision{allowed, matched_rule, action, reason}")
    print(f"    empty-policy decision.allowed = {decision.allowed}")
    assert decision.allowed is True, "expected AGT allow-by-default"
    print("    !! FINDING: AGT is fail-OPEN by default. Wrapper imposes deny-by-default (S3).")

    # 3. Audit concern (agentmesh).
    print("\n[3] Audit   — agentmesh.governance.audit.AuditLog (Merkle-chained)")
    did = boundary.mint_did("agent-1")
    log = boundary.audit_log()
    entry = log.log(event_type="tool_invoked", agent_did=did, action="tool.run", outcome="success")
    # Merkle proof needs >=2 leaves (a single-leaf chain has no sibling path).
    log.log(event_type="tool_blocked", agent_did=did, action="tool.run", outcome="denied")
    ok, err = log.verify_integrity()
    print("    log(event_type, agent_did, action, resource=, data=, outcome=,")
    print("        policy_decision=, trace_id=) -> AuditEntry")
    print(f"    verify_integrity() -> ({ok}, {err!r});  get_proof(id) -> {'dict' if log.get_proof(entry.entry_id) else None}")
    assert ok, err

    # 4. Identity concern (agentmesh) + the identity->audit compat point.
    print("\n[4] Identity — agentmesh.identity.AgentDID")
    print(f"    mint_did('agent-1') -> {did!r}")
    print("    AuditEntry.agent_did is required -> identity MUST run before audit")
    print(f"    stamped entry.agent_did = {entry.agent_did!r}")
    assert entry.agent_did == did

    # 5. The compat map the core depends on.
    print("\n[5] agent_os -> agentmesh compat map")
    print("    subject (ctx dict)        --identity-->  did:mesh:<id>  (str)")
    print("    PolicyDecision.allowed    --core------>  allow / fail-closed deny")
    print("    PolicyDecision.reason     --audit------>  AuditLog.log(policy_decision=...)")
    print("    did:mesh:<id>             --audit------>  AuditLog.log(agent_did=...)")
    print("    order: identity -> policy -> audit  (audit stamps EVERY outcome)")

    print("\nOK — all three concerns verified through the single boundary.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
