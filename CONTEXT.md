# Domain glossary — zemtik-govern

Names for the good seams. Use these terms in tests, reviews, and code — not
"component", "service", "handler".

- **AGTBoundary** — the single sanctioned door to Microsoft AGT. The only place
  `agent_os` / `agentmesh` are imported; asserts pinned distribution versions at
  construction. The raw, fail-OPEN policy evaluator is private behind it.
- **GovernanceContext** — one governed request, frozen and recursively
  deep-frozen. The bytes policy evaluates are provably the bytes audit records.
- **Decision** — the wrapper's own policy verdict (NOT AGT's `PolicyDecision`).
  Enriched: `denial_kind` (policy vs system), `correlation_id`, `audit_event_id`.
- **AgentOsPolicy** — the policy core. The ONLY public door to a policy decision;
  imposes **deny-by-default** over AGT's fail-open evaluator. This is the moat.
- **AuditEntry** — the typed audit record shared by the orchestrator (writer) and
  the audit sink (reader). `from_decision` owns the decision→audit-vocabulary
  mapping (`tool_invoked`/`tool_blocked`, `success`/`denied`/`error`).
- **AgentMeshAudit** — adapter over agentmesh's Merkle-chained `AuditLog`; the one
  place that knows agentmesh's kwarg names.
- **StaticIdentity** — v0.1 identity stub; resolves a subject to its `did:mesh:`.
- **ZemtikGovern** — the orchestration core. Runs identity → policy → audit,
  fail-closed: any engine fault is a system denial, audited then re-raised; the
  tool never runs.
