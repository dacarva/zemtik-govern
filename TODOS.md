# TODOS

Tracked follow-ups, grouped by component then priority (P0 highest → P4),
Completed at the bottom. Sprint slices S4–S8 live as GitHub issues #4–#8.

## Audit (S5)

- **Durable file audit sink**
  **Priority:** P1
  `registry._build_audit` only wires the in-memory Merkle log (`audit_sink:
  "memory"`); any other value is rejected as unsupported. In-memory means the
  trail is lost on restart, so `strict` mode is not yet production-durable. Wire
  the agentmesh `FileAuditSink` and accept a file-path `audit_sink`. Tracked by #5.

## Policy / Decision (S4)

- **Populate Decision enrichment fields**
  **Priority:** P2
  `Decision.correlation_id`, `policy_id`, `policy_version` are declared and
  documented but never set by any producer. Thread `correlation_id` from the
  context and `policy_id`/`policy_version` from the matched policy document, or
  drop the fields until wired. Surfaced by review (maintainability + red-team).

## CI / supply chain

- **Pin GitHub Actions to commit SHAs**
  **Priority:** P2
  `actions/checkout@v4` and `astral-sh/setup-uv@v5` use mutable tags. For a
  project whose pitch is supply-chain integrity, pin third-party actions to full
  commit SHAs. Surfaced by the Codex adversarial review.

## Testing / tooling

- **Resolve pydantic `json_encoders` deprecation warning**
  **Priority:** P4
  `test_agt_boundary` emits a `PydanticDeprecatedSince20` warning from the AGT
  surface (`json_encoders` deprecated, removed in Pydantic V3). Track for the
  next AGT pin bump; revisit via the conformance gate.

## Completed

- **S1: AGT boundary + spike** — pins asserted, compat map + ADR, conformance gate.
- **S2: Scaffold** — errors, async protocols, frozen context, config + example
  yaml, pinned deps, supply-chain CI. **Completed:** Unreleased (2026-06-18)
- **S3: Policy core** — orchestration order, deny-by-default, fail-closed (incl.
  identity faults), enriched Decision, registry, `_GovernedProxy`.
  **Completed:** Unreleased (2026-06-18)
