# Domain glossary — zemtik-govern

Names for the good seams. Use these terms in tests, reviews, and code — not
"component", "service", "handler".

- **AGTBoundary** — the single sanctioned door to Microsoft AGT. The only place
  `agent_os` / `agentmesh` are imported; asserts pinned distribution versions at
  construction. The raw, fail-OPEN policy evaluator is private behind it.
- **GovernanceContext** — one governed request, frozen and recursively
  deep-frozen. The bytes policy evaluates are provably the bytes audit records.
- **Decision** — the wrapper's own policy verdict (NOT AGT's `PolicyDecision`).
  Enriched: `denial_kind` (policy vs system), `correlation_id`, `audit_event_id`,
  `replayed` (True when served from the idempotency ledger, not freshly evaluated —
  a direct `govern`/`govern_sync` caller gates its own side effect on `allowed and
  not replayed`).
- **AgentOsPolicy** — the policy core. The ONLY public door to a policy decision;
  imposes **deny-by-default** over AGT's fail-open evaluator. This is the moat.
- **AuditEntry** — the typed audit record shared by the orchestrator (writer) and
  the audit sink (reader). `from_decision` owns the decision→audit-vocabulary
  mapping (`tool_invoked`/`tool_blocked`, `success`/`denied`/`error`).
- **AgentMeshAudit** — adapter over agentmesh's Merkle-chained `AuditLog`; the one
  place that knows agentmesh's kwarg names.
- **AgentRef** — the typed value the identity seam returns (not a bare string).
  v0.1 carries only the `did:mesh:<subject>` string; it is the seam where issuer /
  key / claims attach in v0.2 without changing the `IdentityProvider` contract.
- **StaticIdentity** — v0.1 identity stub; resolves a subject to an `AgentRef`
  carrying its `did:mesh:`. `IdentityProvider.identify` returns this `AgentRef`.
- **ZemtikGovern** — the orchestration core. Runs identity → policy → audit,
  fail-closed: any engine fault is a system denial, audited then re-raised; the
  tool never runs.
