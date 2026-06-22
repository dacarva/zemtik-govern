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

## Idempotency / core (S6–S7 ship review)

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
  (2026-06-20) — gap closed: `requirements-all.lock` hash-pins the
  `langchain`/`mcp`/`openai` extras; the CI `test` job installs from it with
  `--require-hashes` and the `supply-chain` job audits it too. Lockfile
  regeneration is documented in `docs/operations.md`.

- **Adversarial test matrix — E9** (issue #25)
  **Priority:** P1
  Tests for TOCTOU on `GovernanceContext` immutability under concurrent access,
  policy bypass attempts (injected subject, malformed action, payload mutation),
  audit chain integrity after crash/recovery, and idempotency key collision
  attacks. Deferred from sprint plan E9.
  **Completed:** v0.2.0.0 (2026-06-20) — `tests/test_adversarial_e9.py` adds the
  four E9 attack classes (concurrent-mutation TOCTOU, injected-subject /
  malformed-action / mid-evaluation payload-mutation bypass, tamper-after-
  recovery detection, concurrent idempotency-key collision).

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

## Output Rail Layer (nemo-integration — deferred from C0)

Deferred during the 2026-06-22 CEO review (SELECTIVE EXPANSION). C0 ships the
concrete `OutputClassifier` seam + regex PII rail; these are the follow-ons.
Full record: `~/.gstack/projects/zemtik-govern/ceo-plans/2026-06-22-nemo-output-rail-layer.md`.

- **C1: provider-neutral `Rail` protocol + `Verdict` enum + ensemble combiner**
  **Priority:** P2
  Extract the `Rail` protocol (`async screen(text, ctx) -> Verdict{severity,
  confidence, field, kind, reason}`, no-echo safe), a zemtik-native `Verdict.severity`
  enum (providers map their labels in), and an ensemble combiner (highest-severity
  wins, threshold-gated, fail-closed; a provider without confidence treated as 1.0).
  Refit the regex PII rail AND the existing AGT injection classifier onto it. Build
  ONLY when a genuine 2nd OUTPUT rail exists — the combiner has no real operand until
  then (CEO review cross-model finding: AGT=input-side, regex PII=output-side, never
  combine on one text). **Depends on:** a 2nd output rail (Presidio PII is the natural
  trigger). **Effort:** L (human) → M (CC).

- **Presidio PII provider behind `[pii]` extra + extras-CI matrix**
  **Priority:** P2
  Presidio + spaCy model (~560MB) as the higher-accuracy PII provider behind a
  `[pii]` optional extra, in its own boundary module pinned via `importlib.metadata`
  (mirror `AGTBoundary`). Extend CI to test the default-install path AND each extra so
  a heavy-dep regression can't leak into the default tier. This is the genuine 2nd
  output rail that makes the C1 ensemble real. **Depends on:** C1 contract (or co-built
  with it). **Effort:** M.

- **Jailbreak perplexity rail behind `[jailbreak]` extra**
  **Priority:** P3
  Copy NeMo's perplexity heuristic algorithm (length/prefix/suffix formulas +
  thresholds), supply our own perplexity model (not GPT-2-large), behind a
  `[jailbreak]` extra in its own pinned boundary module. Shadow-mode default (fuzzy
  rail). **Depends on:** C1 `Rail` contract. **Effort:** L (human) → M (CC).

- **Topical rail (policy-keyed)**
  **Priority:** P3
  "Banking agent refuses medical advice" — a policy keyed on a classified topic,
  fitting the existing policy seam (no Colang). **Blocked by:** an unresolved design
  question — where does DETERMINISTIC topic classification come from? (keyword/regex
  is deterministic; an LLM classifier is not, violating the core constraint). Needs a
  mini-design before building. **Effort:** M.

- **Chunked / streaming output screening**
  **Priority:** P3
  v1 DENIES streaming/generator returns by default (fail-closed). Chunked screening
  is the follow-up; it reintroduces the output-deny asymmetry (emitted tokens can't be
  recalled) so streaming protection is inherently best-effort. **Depends on:** the C0
  seam. **Effort:** L.

- **Per-action `to_text()` extractor hook for non-JSON tool returns**
  **Priority:** P3
  C0's output text-extraction contract is fail-closed: `str`/`bytes` screened
  directly, JSON-native values via strict projection, **any other type denied**
  (ORM rows, dataclasses, numpy, custom objects). Survey at review time confirmed
  zero current tools and the LangChain/MCP target (str returns) are blocked, so
  this is deferred. The hook lets an operator register a deterministic,
  side-effect-free `to_text(result) -> str` per action so object-returning tools
  can be screened without the operator pre-wrapping them. Trust note: operator
  code must be deterministic or it breaks the screen==cache invariant. Surfaced by
  the 2026-06-22 eng review (cross-model #3). **Depends on:** C0 seam. **Effort:** S/M.

## Testing / tooling

- **Resolve pydantic `json_encoders` deprecation warning**
  **Priority:** P4
  `test_agt_boundary` emits a `PydanticDeprecatedSince20` warning from the AGT
  surface (`json_encoders` deprecated, removed in Pydantic V3). Track for the
  next AGT pin bump; revisit via the conformance gate.

## Completed

- **Bound the idempotency ledger** (P1) — `BoundedTTLDict` (LRU + lazy TTL) backs
  both the decision ledger and the proxy effect-dedup slots; an in-flight effect
  vetoes eviction so a running tool call is never orphaned. **Completed:** v0.3.0.0
  (2026-06-22) — #35.
- **Per-key idempotency locking** (P2) — `_idem_locks: dict[str, Lock]` with
  waiter-count cleanup; distinct keys evaluate concurrently, only true duplicates
  wait. **Completed:** v0.3.0.0 (2026-06-22) — #34.
- **Decision budget is not a hard fail-closed boundary** (P2) — `_with_budget` is a
  deadline race that decides on the timer and never reads a post-breach engine
  result, so a cancel-swallowing engine cannot leak an allow; raises
  `DecisionBudgetExceeded`. **Completed:** v0.3.0.0 (2026-06-22) — #34.
- **Replay pins the first decision across mode/killswitch changes** (P3) — replay
  keys on `(mode, killswitch_state)`; a key allowed before the killswitch flipped
  re-evaluates under the fallback. **Completed:** v0.3.0.0 (2026-06-22) — #35.
- **Fingerprint rejects ambiguous payloads instead of coercing** (P2) — strict
  `_request_fingerprint` (no `default=str`, `allow_nan=False`, string-only keys,
  bounded depth); a stringify collision is now an audited conflict, never a false
  replay. **Completed:** v0.3.0.0 (2026-06-22) — #32.
- **Wire the decision budget through config/registry** (P2) — `decision_budget_seconds`
  threaded config → registry → core (default 5.0s); a config-built governor is
  never silently unbounded. **Completed:** v0.3.0.0 (2026-06-22) — #33.

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
