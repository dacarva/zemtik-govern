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
  **Documented (2026-06-19)**: field comments in `protocols.py` now explicitly
  state "reserved; always ``None`` in v0.1" so integrators do not write code
  expecting live data.

## Idempotency / core (S7 hardening)

- **Bound the idempotency ledger**
  **Priority:** P1
  `core.py` `_idem_ledger` is an unbounded, process-local `dict` keyed on the
  caller-supplied `idempotency_key`. Normal unique-key traffic grows it forever
  (memory leak); a malicious caller streaming unique keys is a DoS. Add an
  LRU/TTL bound (window-matched, e.g. 24h). Evicting a still-replayable key only
  costs a deterministic re-evaluation, which is safe. Surfaced by Claude + Codex
  adversarial review.

- **Per-key idempotency locking**
  **Priority:** P2
  `_idem_lock` is one global `asyncio.Lock` held across identity + policy + audit,
  so every keyed call serialises against every other keyed call (head-of-line
  blocking on the latency-sensitive path). Lock per key (or an in-flight
  `dict[str, Future]`) so distinct keys evaluate concurrently and only true
  duplicates wait. Surfaced by adversarial review.

- **Decision budget is not a hard fail-closed boundary**
  **Priority:** P2
  `asyncio.wait_for` cancels the engine coroutine on timeout, but an engine that
  swallows `CancelledError` can still return a value (verified: a callee catching
  cancellation returned an allow after the budget). Document the cancellation-
  safety contract for `identify`/`evaluate`, and/or treat a budget breach as a
  deny regardless of the coroutine's eventual return. Also: the budget wraps each
  await separately (identity, then policy) and excludes lock-wait + audit, so
  total wall-clock can exceed `timeout`. Surfaced by adversarial review.
  **Documented (2026-06-19)**: `_with_budget` docstring in `core.py` now
  explains the cancellation-safety assumption and the known limitation. The code
  issue (an engine swallowing `CancelledError`) is not yet fixed.

- **Replay pins the first decision across mode/killswitch changes**
  **Priority:** P3
  A ledgered decision replays under the live `mode`/killswitch, mixing a cached
  allow/deny with current enforcement — a killswitch engaged after a key is
  ledgered cannot revert that key. Either key the ledger on
  `(idempotency_key, mode, killswitch_state)` or document + test the intentional
  first-decision pinning and re-enforce under the stored mode. Surfaced by
  adversarial review.

## Idempotency / core (S6–S7 ship review)

- **Fingerprint rejects ambiguous payloads instead of coercing**
  **Priority:** P2
  `_request_fingerprint` serialises with `json.dumps(..., default=str)`. Two
  distinct non-JSON-native payload values that stringify identically collapse to
  the same SHA-256, so a key reused with the same action+subject but a different
  custom-object payload that stringifies the same is replayed as a duplicate
  rather than detected as a conflict. The *raw-exception* half (an
  un-serialisable payload escaping the fail-closed boundary) is now fixed —
  fingerprint failures audit + raise `GovernanceError`. The remaining work is the
  collision: drop `default=str` for a strict encoder, or validate payloads as
  JSON-native at `GovernanceContext` construction. Surfaced by security + red-team
  + Codex review.

- **Wire the decision budget through config/registry**
  **Priority:** P2
  `ZemtikGovern(timeout=...)` exists but `GovernanceConfig`/`GovernanceRegistry`
  never set it, so the default is `None` (no bound) for every config-built
  governor. Combined with the single global `_idem_lock`, one hung keyed request
  can stall all keyed governance in-process. Thread a `decision_budget` config
  field → registry → core so deployments actually get the voice-path bound.
  Surfaced by Codex review.

- **Cancellation is not audited**
  **Priority:** P3
  `_evaluate_and_audit` catches `except Exception`, which does NOT catch
  `asyncio.CancelledError` (a `BaseException`). A client that cancels mid-identity
  or mid-policy on the direct or non-keyed proxy path leaves no audit entry for
  the attempted governed action — fail-closed (the tool never runs) but a gap in
  the "every outcome audited" contract. Either audit the cancellation or document
  it as an explicitly un-audited abort. Surfaced by Codex review.

- **Fingerprint trust anchor should be the resolved DID, not the raw subject**
  **Priority:** P3
  `_request_fingerprint` binds the key to `ctx.subject` (raw, unverified) because
  fingerprinting runs before identity resolution. Benign while `StaticIdentity`
  is an exact identity map; the moment a real provider canonicalises (case-fold,
  alias→DID) two subjects mapping to one DID become a false conflict, and casing
  variants could evade conflict detection. Fingerprint over the resolved DID
  (identity-before-fingerprint) or document the exact-map assumption. Surfaced by
  red-team review.

- **Replay audit entry is orphaned from the returned decision**
  **Priority:** P3
  The replay path writes a fresh `outcome="replay"` entry but discards its event
  id and returns the cached decision, whose `audit_event_id` still points at the
  original entry. A forensic reader sees a replay row with no link to the decision
  the caller received. Stamp the replay decision with the replay entry's id.
  Surfaced by red-team review.

- **Conflict-path audit failure masks GovernanceError**
  **Priority:** P3
  In the idempotency-conflict branch, if `audit.write()` itself raises (sink
  down), the raw sink exception propagates instead of the intended
  `GovernanceError` — still fail-closed, but callers distinguishing governance
  faults from infra faults mis-route it. Either wrap it like `_evaluate_and_audit`
  or accept the codebase-wide pattern that audit failures propagate (the
  fallback-protected sink already converts to `GovernanceError`). Surfaced by
  red-team review.

- **Fingerprint hot-path allocation on the voice path**
  **Priority:** P4
  `_request_fingerprint` calls `ctx.to_dict()` to read only `["payload"]`, but
  `to_dict()` eagerly thaws BOTH payload and `extra` (the thawed `extra` is
  discarded). On every keyed call on the latency-sensitive voice path this is a
  wasted deep-copy. Thaw payload directly. Also: the full `json.dumps` + sha256
  runs even on the replay-hit case; cache the fingerprint on the frozen context if
  voice payloads grow. Surfaced by performance review.

## CI / supply chain

- **Supply-chain CI — hash-pinned lockfile + pip-audit gate** (issue #24)
  **Priority:** P1
  Generate hash-pinned lockfile (`pip-compile --generate-hashes`), add
  `pip-audit` CI step that fails on known CVEs, gate merges on a clean report.
  A governance wrapper must be supply-chain clean — a compromised dep could
  subvert the identity→policy→audit pipeline silently. Deferred from sprint
  plan E7.
  **Completed:** v0.0.1.0 (2026-06-19) — `requirements-dev.lock` with `--require-hashes`
  install is wired in CI; `pip-audit` OSV gate runs against `requirements.lock`.

- **Adversarial test matrix — E9** (issue #25)
  **Priority:** P1
  Tests for TOCTOU on `GovernanceContext` immutability under concurrent access,
  policy bypass attempts (injected subject, malformed action, payload mutation),
  audit chain integrity after crash/recovery, and idempotency key collision
  attacks. Deferred from sprint plan E9.

- **Pin GitHub Actions to commit SHAs**
  **Priority:** P2
  `actions/checkout@v4` and `astral-sh/setup-uv@v5` use mutable tags. For a
  project whose pitch is supply-chain integrity, pin third-party actions to full
  commit SHAs. Surfaced by the Codex adversarial review.

## LangChain Integration (S9 — DX sprint)

- **Compatibility matrix: govern_tool() across Python and LangChain versions**
  **Priority:** P2
  Run govern_tool() tests across Python 3.11/3.12, langchain-core 1.0–1.4 minor
  versions, sync @tool, async @tool, StructuredTool, BaseTool subclass, and
  plain Callable. Low urgency for v0.1 (happy path tested on current versions);
  important before marketing as a drop-in wrapper. Currently tested only on
  Python 3.11 and langchain-core 1.4.x. Surfaced by Codex eng review.

- **Document on_denied="tool_message" safety model**
  **Priority:** P3
  When govern_tool() returns a ToolMessage("tool call denied"), the LangGraph
  agent can continue, retry with different args, or route to another tool — it
  is NOT blocked at the application level. Document the intended safety model in
  docs/integrations/langchain.md: on_denied="tool_message" is safe when the
  graph has a human-in-the-loop, a retry counter, or a downstream hard limit.
  Operators who need enforcement must use on_denied="raise". The audit trail
  records every denial regardless. Surfaced by Codex eng review (finding #8).

- **Shadow-mode testing pattern in langchain integration guide**
  **Priority:** P3
  Document mode:shadow as the recommended test pattern for langchain integration
  tests: use a test govern.yaml with mode:shadow to observe what would be denied
  without enforcement. Without this, developers either skip governance in tests
  (unsafe: the tool actually runs ungoverned) or use mode:strict (which fails
  tests on valid denials and makes CI fragile). Add a "Testing" section to
  docs/integrations/langchain.md. Surfaced by DX review.

- **Measure TTHW with real developer onboarding sessions after PyPI launch**
  **Priority:** P2
  After zemtik-govern v0.1 is published to PyPI, run 3 developer onboarding
  sessions (video or async) with LangChain developers who haven't seen the
  project before. Measure actual TTHW against the <2-minute champion-tier
  target. Record where each developer pauses, questions, or makes a mistake.
  Use findings to iterate on README and examples before 1.0. Competitive
  baseline: NeMo Guardrails ~8 min, Guardrails.ai ~5 min. Surfaced by DX
  review (Pass 8). Triggered by: PyPI publication complete.

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
- **S6: Identity — StaticIdentity stub** — `identity/` package; `StaticIdentity`
  resolves a subject to a typed `AgentRef` (`did:mesh:<subject>`, minted behind the
  boundary), `IdentityProvider.identify` returns it, core stamps `agent_did`
  identity-first; Protocol is the only public seam. **Completed:** Unreleased
  (2026-06-18)
- **S7: Adversarial matrix + pressure-test gate** — five-scenario
  `test_adversarial.py` (payload immutability, concurrent idempotency-key replay,
  policy/identity timeouts fail-closed, Merkle verify after crash-recovery) plus
  `test_pressure.py` driving one governor through a sync fintech write and an async
  sub-100ms voice turn; added an idempotency replay guard and a per-call decision
  budget to `core.py`, no `protocols.py` change. **Completed:** Unreleased
  (2026-06-18)
