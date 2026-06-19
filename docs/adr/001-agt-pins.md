# ADR 001 — AGT pins and verified surface

- Status: Accepted
- Date: 2026-06-18
- Slice: S1 (AGT boundary + spike)

## Context

zemtik-govern is a security wrapper around Microsoft AGT. Two AGT distributions
supply the governed concerns: `agent-os-kernel` (policy) and `agentmesh-platform`
(audit + identity). The wrapper's safety guarantees depend on exact AGT
signatures and defaults. A silent AGT upgrade that changed a default — most
critically, the policy fail-open default — would breach the moat without any
code in this repo changing.

This ADR records the pinned versions and the surface the wrapper was verified
against, so a future AGT bump fails CI here (`tests/test_agt_conformance.py`)
before it reaches the governance core.

## Decision

Pin both distributions exactly. `AGTBoundary` asserts the pins at construction
via `importlib.metadata.version`, raising `AGTVersionError` on any drift.

```
agent-os-kernel    == 3.7.0
agentmesh-platform == 3.7.0
```

### Why distribution metadata, not `module.__version__`

The installed module attributes lag the packaging version and must NOT be
trusted:

| source                   | reports |
|--------------------------|---------|
| `agent-os-kernel` (dist) | 3.7.0   |
| `agent_os.__version__`   | 3.2.2   |
| `agentmesh-platform`     | 3.7.0   |
| `agentmesh.__version__`  | 3.6.0   |

`importlib.metadata.version("agent-os-kernel")` reads the authoritative
distribution version that pip/uv resolved. Trusting `__version__` would silently
accept a wrong build.

## Verified surface (spike output, pinned versions)

Captured from `spike/verify_agt_signatures.py` against the pins above. The same
facts are pinned as CI assertions in `tests/test_agt_conformance.py`.

### Policy — `agent_os.policies.PolicyEvaluator`

- `PolicyEvaluator(policies=None, root_dir=None)`
- `evaluate(context: dict) -> PolicyDecision{allowed, matched_rule, action, reason}`
- `load_policies(directory)`
- **FINDING (moat-critical): AGT is fail-OPEN.** An evaluator with no matching
  rule returns `allowed=True` (`matched_rule is None`). The design doc's claim of
  "deny-by-default (keep)" is FALSE. The wrapper imposes deny-by-default itself in
  `AgentOsPolicy` (S3). `tests/test_agt_conformance.py::test_agt_policy_is_allow_by_default_NOT_deny`
  guards this assumption against silent rot.

### Audit — `agentmesh.governance.audit.AuditLog` (Merkle-chained)

- `log(event_type, agent_did, action, resource=, data=, outcome=, policy_decision=, trace_id=) -> AuditEntry`
- `verify_integrity() -> (ok: bool, err: str | None)`
- `get_proof(entry_id) -> dict` (needs ≥2 leaves for a sibling path)

### Identity — `agentmesh.identity.AgentDID`

- `AgentDID(unique_id=...)` → `did:mesh:<unique_id>` string form
- `AuditEntry.agent_did` is required → **identity MUST run before audit**

## agent_os → agentmesh → wrapper compat map

Also recorded in code as `AGT_COMPAT_MAP` in `src/zemtik_govern/_agt.py`.

| AGT field / call                | maps to                                                    |
|---------------------------------|------------------------------------------------------------|
| `PolicyDecision.allowed`        | `Decision.allowed` — ONLY when `matched_rule is not None`   |
| `PolicyDecision.matched_rule`   | `Decision.matched_rule`                                     |
| `PolicyDecision.action`         | `Decision.action`                                           |
| `PolicyDecision.reason`         | `Decision.reason` / `AuditLog.log(policy_decision=...)`     |
| `AgentDID(unique_id)`           | `did:mesh:<id>` / `AuditLog.log(agent_did=...)`             |

Order: identity → policy → audit (audit stamps EVERY outcome).

## Consequences

- Any AGT drift from these pins is a hard failure at `AGTBoundary` construction
  and at CI conformance time — never a silent behavioural change.
- Re-run `spike/verify_agt_signatures.py` and update this ADR when intentionally
  bumping either pin.
