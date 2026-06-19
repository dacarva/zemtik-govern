# TODOS

Tracked follow-ups, grouped by component then priority (P0 highest → P4),
Completed at the bottom. Sprint slices S4–S8 live as GitHub issues #4–#8.

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
- **S4: Kill-switch + shadow/enforce modes** — `mode` on `ZemtikGovern`
  (shadow observes without enforcing; enforce/strict raise), mode stamped on the
  audit entry, `Killswitch` reverting to a governed fallback (never allow-all),
  mode threaded config → registry → core. **Completed:** Unreleased (2026-06-18)
- **S5: Audit + redacted emergency fallback** — `audit/` package; Merkle adapter
  thaws the frozen payload before hashing; redacted metadata-only fallback
  (0600 file + stderr, `payload_sha256`, never raw payload) failing closed as
  `GovernanceError`; durable HMAC-signed `FileAuditSink` wired from a file-path
  `audit_sink` + `$ZEMTIK_AUDIT_SECRET`. **Completed:** Unreleased (2026-06-18)
