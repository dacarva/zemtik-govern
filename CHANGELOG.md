# Changelog

All notable changes to zemtik-govern are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project versions
via `pyproject.toml` (currently `0.4.0.0`).

## [0.4.0.0] - 2026-06-22 — output-governance rail layer (C0)

The first output-governance rail: a post-invocation seam that screens a tool's
**return value** for PII inside `proxy()`, complementing the input pipeline
(identity → policy → audit). Opt-in (`output_screening: true`), fail-closed, and
no-echo throughout.

### Added

- **Output-governance seam — read-deny path (#39).** After a governed tool
  returns, `proxy()` projects its value to text and screens it through the
  configured output rails. A `read`-classified tool whose output trips an enforce
  rail has its value **withheld** and `OutputGovernanceDenied` raised. Ships ONE
  concrete rail, `RegexPIIClassifier` (name `pii`): linear-time, ReDoS-safe
  anchored patterns for email/SSN/card/phone, NFKC-normalised before scan. An
  unscreenable return (custom object, non-UTF-8 bytes, oversized, over-deep) is a
  fail-closed deny. Config: `output_screening`, `tool_io_map` (action → read|write,
  unmapped → write), `rails` (per-rail `threshold` + `mode`).
- **Write-deny path + `RedactedOutput` sentinel (#40).** A `write`-classified tool
  (its side effect already executed) whose output trips an enforce rail **returns**
  a frozen `RedactedOutput` sentinel and writes a HIGH-severity
  `output_denied_redacted` audit row. The sentinel is spare on `str`/`repr`/`format`
  (returns `<output redacted: audit_id=…>`) and poison on attribute/item/iter
  access (`RedactedOutputAccessError`); `audit_id` back-links to the row (D9).
- **Discoverability — startup banner + warn-once (#42).** The startup log line
  announces active rail names/modes and the `tool_io_map`. When the seam is active
  and an action is absent from `tool_io_map`, a one-time WARNING per action fires
  (caught in dev/staging before a forgotten read tool ships as a silently-redacted
  write).
- **`gov.unwrap()` + per-rail output shadow mode (#41).** `unwrap(result)`
  collapses the read-raises / write-returns asymmetry into one contract — clean
  value through, `RedactedOutput` raises `OutputGovernanceDenied` (carrying the
  sentinel's `audit_id`). Each rail honors its own `mode`: a `shadow` rail observes
  a would-deny (`output_would_deny`) without enforcing, for an observe→enforce
  rollout independent of the global mode.
- **Output-seam documentation (#43).** `zemtik.example.yaml` annotates
  `output_screening`, `tool_io_map`, and `rails` with an observe→enforce onboarding
  block. `docs/configuration-reference.md`, `docs/integration-guide.md`,
  `docs/architecture.md`, and the README document the fields, the `gov.unwrap()`
  caller contract, `OutputGovernanceDenied` / `RedactedOutputAccessError`, the
  audit-name→effect mapping, and the proxy()-only scope.
- **Sandbox S16 — output PII redaction** (`sandbox/qa_demo.py`). A write-classified
  tool returning PII is redacted: `RedactedOutput` returned (not raised),
  HIGH-severity `output_denied_redacted` row, `audit_id` correlated to the row (D9),
  raw PII not recoverable via `str()` (D6 no-echo), Merkle chain verifies. Suite
  covers S1–S16 (16 passed).
- **E2E output-seam probe (`sandbox/e2e_openai_governed.py`).** A deterministic P6
  probe drives the output seam on the real three-seam pipeline: a read tool raises
  and withholds, a write tool returns `RedactedOutput` correlated by `audit_id` to
  a HIGH-severity row, `unwrap()` collapses to a raise, a clean output passes
  verbatim, and the write side effect is proven to have run exactly once. No-echo is
  asserted across the caller surfaces, the full audit row, and the durable signed
  JSONL trail. Documented in the README and `docs/sandbox.md`.

---

## [0.3.0.0] - 2026-06-22

### BREAKING

- **Fail-closed defaults are now ON by default.** A config-built governor
  (`GovernanceRegistry.from_config`) in `strict`/`enforce` mode now wires a
  mandatory prompt-injection guard (using AGT's own vetted detection config by
  default — no rule file required), runs with a **5.0s `decision_budget_seconds`**
  by default, and bounds both idempotency caches (10000 entries / 3600s TTL). The
  guard is on whether or not you configure it; an upgrade does not need a rule
  file to get protection.

  **Migration.** (1) Nothing required for the injection guard — it activates with
  AGT's defaults. Set `injection_rules_path` only to pin a version or diverge, or
  run `injection: {mode: shadow}` for one release to observe would-denies first.
  (2) If a latency-sensitive path cannot tolerate the 5s budget, set
  `decision_budget_seconds` explicitly (it is now unit-suffixed — seconds, not
  ms) or `null` to opt out when an upstream caller enforces its own deadline.
  (3) Watch for the one-line startup log `zemtik-govern active | … | injection
  detection: ON (AGT) | …` to confirm what activated. Full notes in
  `docs/operations.md` ("Upgrading to fail-closed defaults").

### Added

- **AGT-native prompt-injection guard (#36).** A mandatory, fail-closed injection
  screen folded into the policy seam and wrapped around the SELECTED engine —
  primary AND killswitch fallback — so it cannot be bypassed during a killswitch
  emergency. Strict, size-bounded, off-loop projection (an attacker `__str__` is
  never invoked); a hit is a D6 no-echo policy deny naming the field only. By
  default the guard uses AGT's own vetted `PromptInjectionConfig()` detection
  rules, passed explicitly (warning-free, no in-repo copy to maintain — it tracks
  the pinned AGT wheel). Set `injection_rules_path` to a file only to pin a
  version or diverge; `policies/prompt-injection.yaml` is an optional, ready-to-
  edit snapshot of those defaults. Swap the whole classifier via the
  `InjectionClassifier` Protocol.
- **Bounded idempotency caches + two-level keying (#35).** The decision ledger and
  the proxy effect-dedup slots share ONE bounded LRU+TTL cache, so unique-key
  traffic cannot grow them without bound and they evict consistently. Replay keys
  on `(mode, killswitch_state)`; conflict keys on the request fingerprint alone.
  An in-flight effect future vetoes eviction so a running tool call is never
  orphaned (incl. across TTL expiry).
- **Decision-budget deadline race + strict fingerprint (#34/#32).** The per-call
  budget decides on the timer, not the engine, so a cancel-swallowing engine
  cannot leak a post-breach allow. The idempotency fingerprint is strict (no
  `default=str`, `allow_nan=False`, string-only keys, bounded nesting depth), so a
  stringify collision can never become a false replay.
- **Catchable governance errors (D8).** Every `GovernanceError` carries a stable
  `.code` (e.g. `decision_budget_exceeded`, `idempotency_conflict`,
  `policy_denied`) and an optional `.guard`; the budget breach is its own
  `DecisionBudgetExceeded` with `.limit_seconds` / `.elapsed_seconds`. Branch on
  the code, never on a message substring.
- **Audit correlation (D9).** An allowed `Decision` exposes `.audit_id` and every
  raised governance exception carries the SAME id, so a log line and the
  tamper-evident audit row line up. See `docs/operations.md`.
- **Per-guard shadow modes (D10).** `injection.mode` / `budget.mode` =
  `enforce|shadow` scope the global shadow machinery to one guard for an
  observe-then-enforce upgrade — run a new guard in shadow, watch the would-denies,
  then flip to enforce.
- **Unit-suffixed config names + reserved confidence floor (D5).**
  `decision_budget_seconds`, `idempotency_ttl_seconds`, and the off-by-default
  `injection_confidence_floor` (0.0) are documented in
  `docs/configuration-reference.md`.
- **Active-guard startup log (D4/D7)** and an `InjectionClassifier` swap example
  in `docs/integration-guide.md`.

## [0.2.0.0] - 2026-06-20

### Added
- **Staged dogfood cutover demo** (`sandbox/dogfood_cutover.py`) — run a simulated
  fintech agent with seven governed call sites through a real two-phase rollout:
  Phase A (shadow) records what the governor *would* deny while enforcing nothing,
  Phase B (enforce) blocks the privileged money-path writes. Verdicts are identical
  across phases (zero false-denies), the kill-switch reverts to a prior governed
  path (never allow-all), and both HMAC-signed Merkle audit trails re-verify. Run
  it with `ZEMTIK_AUDIT_SECRET=dogfood-secret python sandbox/dogfood_cutover.py`;
  see `docs/sandbox.md`.
- **E9 adversarial test matrix** (`tests/test_adversarial_e9.py`) — concurrent
  TOCTOU on a frozen context, policy-bypass attempts (injected subject, malformed
  and unicode actions, mid-evaluation payload mutation), tamper-after-crash-recovery
  detection, and concurrent idempotency-key collisions. Hardens the guarantees the
  three-seam pipeline already makes by trying to break them.

### Changed
- **CI installs and audits the full dependency set, hash-pinned.** The `test` job
  now installs from `requirements-all.lock` (runtime + dev + `langchain`/`mcp`/`openai`
  extras) with `--require-hashes`, so the integration surface is as supply-chain
  verified as the core. The `supply-chain` job runs a second `pip-audit` over the
  full lock, so a CVE in an integration dependency fails the build too. The previous
  unpinned extras install is gone. See `docs/operations.md` for lockfile regeneration.

### Added
- **`govern_tool()` and `govern_tools()`** (`zemtik_govern.langchain`) — wrap any
  LangChain `BaseTool` or callable with the full three-seam governance pipeline.
  Install with `pip install zemtik-govern[langchain]`. Supports sync (`invoke`) and
  async (`ainvoke`) execution, configurable denial modes (`on_denied="raise"` or
  `"tool_message"`), and lazy ZemtikGovern initialization on first call.
- **`@governed` decorator** — config-based decoration for `@tool` functions.
  Apply outer (`@governed`) after inner (`@tool`); wrong order raises `GovernanceError`
  at decoration time with a clear redirect message.
- **`GovernedToolNode`** — composition-based drop-in for LangGraph's `ToolNode`.
  Wraps tools via `govern_tool()` at init; catches `GovernanceDenied` and
  `GovernanceError` per tool call and returns a denial `ToolMessage` with the
  correct `tool_call_id` instead of crashing the graph.
- **`govern_tool_node()`** — function shorthand for `GovernedToolNode(...)`.
- **LangSmith governance trace** — `govern_tool()` emits `governance.decision`,
  `governance.rule`, and `governance.subject` into LangChain callbacks when the
  caller passes a `RunnableConfig` with callbacks configured. Zero overhead when
  callbacks are absent.
- **`GovernedMCPServer`** (`zemtik_govern.mcp`) — governed MCP tool server; any
  MCP client (Claude, Cursor, Continue) gets the three-seam pipeline on every tool
  call. Install with `pip install zemtik-govern[mcp]`. Supports async and sync
  tool callables and `on_denied="raise"` or `"error_response"`.
- **`zemtik init langchain` CLI** — `python -m zemtik_govern init langchain`
  introspects tool schemas and generates a starter `govern.yaml` with all tools
  denied by default. Pass `--tools-module my_agent.tools` to auto-generate
  commented allow rules; `--output govern.yaml` to write to a file.
- **`ZEMTIK_DEV` observability** — set `ZEMTIK_DEV=1` to emit a colored per-call
  governance log to `stderr`: `[ZEMTIK] ALLOW read_file | subject=agent-1 | rule=allow-tools | 12ms`.
  Denied calls include the rule name and reason. Zero overhead in production
  (`ZEMTIK_DEV=0`, `false`, or unset disables completely).
- **Examples and integration guide** — `examples/langchain_minimal.py` (10-line
  quickstart), `examples/langgraph_toolnode.py` (drop-in ToolNode demo), and
  `docs/integrations/langchain.md` (full guide with Error Reference section).
- **LangChain-first README** — quick start (pip install + 4 lines of Python +
  5-line govern.yaml) is Section 1; AGT-native API is Section 2.
- **CI integration test guard** — `tests/test_readme_quickstart.py` executes the
  exact README code snippet in CI so a doc/code drift breaks the build.
- **`CONTRIBUTING.md`** and **`.github/ISSUE_TEMPLATE/bug_report.md`** — minimal
  contributor guide and structured bug report template.

### Fixed
- **`ZEMTIK_DEV=0` incorrectly enabled dev mode** — `bool("0")` is truthy in
  Python; `_is_dev_mode()` now checks the value against `"0"`, `"false"`, `"no"`,
  and `""` so disabling dev mode works as expected.
- **`GovernedToolNode` crashed on governance system faults** — `GovernanceError`
  (AGT version mismatch, lazy-init failure, identity/policy timeout) now produces a
  `ToolMessage("tool call blocked: governance error")` instead of propagating
  unhandled out of `__call__`.
- **LangSmith callback error blocked tool execution** — a `BaseCallbackHandler`
  error after an ALLOW audit entry could prevent the tool from running, creating a
  divergence between the audit trail and actual execution. Callback errors are now
  suppressed (logged at DEBUG) so the tool always runs after an audited allow.
- **CI missing optional extras** — `requirements-dev.lock` covers pytest/ruff only;
  the `langchain` and `mcp` extras are now installed separately in CI so
  integration tests run rather than fail at collection.
- **LLM-controlled tool name reflected in error message** — `GovernedToolNode`
  now returns `"tool call blocked: unknown tool"` (not `f"unknown tool: {name}"`)
  to prevent LLM-crafted tool names from appearing in ToolMessage content.

## [0.0.1.0] - 2026-06-19

### Added
- **LangChain and MCP integration scaffolding** — `zemtik_govern.langchain`,
  `zemtik_govern.mcp`, and `zemtik_govern.cli` package directories with
  optional dependency groups (`pip install zemtik-govern[langchain]` and
  `[mcp]`). Implementation stubs are in place for the upcoming
  `govern_tool()` API (issue #15) and `GovernedMCPServer` (issue #20).
- **`zemtik init langchain` CLI** — `python -m zemtik_govern.cli init langchain`
  scaffolds a `govern.yaml` from LangChain tool introspection. Pass
  `--tools-module my_agent.tools` to auto-generate commented-out allow rules
  for each discovered tool; `--output govern.yaml` to write to a file instead
  of stdout. Developer-only: `--tools-module` accepts arbitrary import paths.
- **`tests/mcp/`** — test directory scaffolding mirroring `tests/langchain/`.

### Fixed
- **`AuditReader.proof()` hash-stripping bypass** — `_hash()` now returns
  `None` (not `""`) when both `entry_hash` and `content_hash` are absent,
  preventing a tampered trail with empty hash fields from passing chain
  verification via the `"" == ""` shortcut.
- **`AuditReader.proof()` split HMAC trust** — `verified` in the proof result
  now requires both chain-link integrity AND HMAC verification, matching the
  stronger guarantee of `verify()`. Previously a trail with a wrong HMAC secret
  could return `proof()['verified'] = True`.
- **`AuditReader.proof()` `merkle_proof` None tuples** — hash slots in the
  returned proof list now fall back to `""` when a hash field is absent,
  preventing `AttributeError` for callers iterating the proof.

## [Unreleased]

### Documentation sprint (2026-06-19)

Comprehensive documentation added in this sprint:

- **`docs/architecture.md`** — three-seam design diagram, idempotency model,
  fail-closed guarantee, deny-by-default moat, AGT boundary, startup validation.
- **`docs/integration-guide.md`** — quickstart, all usage patterns (async,
  sync, proxy, context factory, shadow, kill-switch, budget), custom seam
  examples, and error handling reference.
- **`docs/configuration-reference.md`** — full YAML field reference, mode
  matrix, env vars (`ZEMTIK_AUDIT_SECRET`, `ZEMTIK_AUDIT_FALLBACK`), startup
  validation rules, and runtime parameters.
- **`docs/operations.md`** — deployment checklist, durable audit configuration,
  integrity verification, emergency fallback channel, kill-switch wiring, shadow
  rollout procedure, monitoring signals, and known operational limits.
- **`docs/api-reference.md`** — full public API: `ZemtikGovern`, `Killswitch`,
  `GovernanceContext`, `Decision`, `AuditEntry`, protocols, config, registry,
  errors, and audit.

### Added (audit-reader-feature)

- **`AuditReader` / `AuditRecord`** (`audit/reader.py`) — cold-read auditor module.
  Reads a durable `.jsonl` trail written by `AgentMeshAudit` without touching an
  active session. Three capabilities: `records()` returns all entries as typed
  `AuditRecord` frozen dataclasses; `verify()` re-runs the two-layer tamper-evidence
  check (HMAC signature + Merkle `previous_hash` chain) via a fresh `FileAuditSink`;
  `proof(entry_id)` returns a chain inclusion proof an auditor can verify
  independently — every `previous_hash` link from genesis to the target entry.
  Cold-read isolation is explicit: a new sink is opened per `verify()` call so
  in-memory session state never hides a tampered file. Exported from
  `zemtik_govern.audit`.
- **`sandbox/qa_demo.py`** — manual QA script exercising all 10 stated security
  guarantees of the three-seam pipeline (deny-by-default, fail-closed identity/
  policy faults, shadow mode, idempotency replay/conflict, proxy effect-idempotency,
  context immutability, durable Merkle-verified audit).
- **`sandbox/auditor.py`** — end-to-end auditor workflow demo: generates a
  6-event governed workload, prints a human-readable event log (who, what,
  authorized by, when), verifies the Merkle chain, extracts an inclusion proof for
  a specific event, and demonstrates tamper detection (deletion of any entry breaks
  the chain at the successor's `previous_hash`).

---

S1–S7 of the governance wrapper: the AGT boundary, the M0 skeleton, and the
fail-closed policy core, plus config/registry/proxy wiring and a hardened CI
supply-chain gate — now with operational safety modes (S4), the durable,
fallback-protected audit trail (S5), the typed identity seam (S6), and the
adversarial + pressure-test gate that proves the abstraction survives both a
blocking fintech write and a latency-sensitive voice turn (S7).

### Added

- **Identity seam** (S6, `identity/`) — `identity.py` becomes a package.
  `StaticIdentity` now resolves a subject to a typed `AgentRef` (`did:mesh:<subject>`,
  minted behind the AGT boundary) instead of a bare string, replacing a faked
  random per-call identity. `IdentityProvider.identify` returns `AgentRef`; the
  core stamps `agent_did` from it onto every audit entry, identity-first. The
  Protocol is the only public interface — `StaticIdentity` is an impl detail a
  real Ed25519/`did:web` provider swaps for without touching the core.
- **Idempotency replay guard** (S7, `core.py`) — `govern()` serialises calls on
  `idempotency_key` so a concurrent duplicate is a deterministic *replay*
  (recorded with a `replay` outcome, re-applying the original decision), never a
  silently re-evaluated fresh request. The key is bound to a request fingerprint
  (action + subject + payload): a key reused for a *different* request is a
  conflict, audited and failed closed — it never replays a prior allow onto an
  unevaluated action, and the conflict entry is stamped with the unidentified DID
  (the conflicting request was never identity-resolved, so it is never attributed
  to the first key holder). `_GovernedProxy` extends this from decision- to
  *effect*-idempotency: a keyed duplicate (sequential or concurrent) re-runs
  `govern()` for the audit/replay/conflict trail but returns the first call's
  cached result instead of invoking the tool again, so a replayed wire transfer
  cannot move money twice. A denial or a tool failure is left un-cached so a retry
  re-runs. A *direct* `govern`/`govern_sync` caller (no proxy) gets the same
  protection via `Decision.replayed`: it is `True` when the decision was served
  from the ledger, so the caller gates its own side effect on `allowed and not
  replayed`. The keyed path also fingerprints inside the fail-closed boundary — a
  payload that cannot be serialised is an audited `GovernanceError`, never a raw
  exception that skips the trail. v0.1 ledger/effect-cache are
  in-memory/process-local (bounding tracked in `TODOS.md`).
- **Per-call decision budget** (S7, `core.py`) — `ZemtikGovern(timeout=...)` bounds
  identity + policy with `asyncio.wait_for`; a timeout is a system fault that flows
  through the existing fail-closed path (audited, then denied — the tool never
  runs), so a hung engine can never stall the voice path or become an implicit allow.
- **Adversarial matrix + pressure-test gate** (S7, `tests/`) —
  `test_adversarial.py` pins five break-it scenarios (deep-nested payload
  immutability, concurrent duplicate idempotency keys, policy/identity timeouts,
  Merkle verify after crash-recovery from the file sink); `test_pressure.py` drives
  one governor through a sync `govern_sync` fintech write and an async sub-100ms
  voice turn, confirming the async-first Protocols serve both with no `protocols.py`
  change.
- **Operational modes + kill-switch** (S4, `core.py`) — `ZemtikGovern` takes a
  `mode`: `shadow` records a would-be denial but does NOT enforce it (the tool
  still runs, surfacing false-denies on live traffic), while `enforce`/`strict`
  raise `GovernanceDenied`. The mode is stamped on every `AuditEntry` so the
  distinction is observable. `Killswitch` reverts a running governor to its prior
  governed fallback path — never to allow-all; engaging it with no fallback wired
  fails closed. Mode flows config → `registry.register_mode` → core.
- **Audit package** (S5, `audit/`) — `audit.py` becomes a package. `log.py` is the
  Merkle-chained adapter (now thaws the frozen `MappingProxyType` payload to a
  plain dict before agentmesh's json-based hashing) re-exposing
  `verify_integrity`/`get_proof`. `fallback.py` is the emergency channel: if the
  primary sink raises, a redacted, metadata-only record (`payload_sha256`, never
  the raw payload) is written to a fixed-path file (mode `0600`) and stderr, then
  the write fails closed as `GovernanceError` — the denial invariant holds even
  when audit cannot. The fallback record's `err` field is the exception TYPE
  only (never `str(exc)`), so a sink that embeds the failing payload in its
  message can't smuggle it into the redacted trail; the file open uses
  `O_NOFOLLOW` so a pre-planted symlink can't redirect the `0600` chmod/append.
- **Durable file audit sink** (S5, `_agt.py`, `registry.py`) — a file-path
  `audit_sink` now wires agentmesh's HMAC-signed `FileAuditSink`; the signing key
  is read from `$ZEMTIK_AUDIT_SECRET` (never the config file) and a file sink
  without it refuses to start.

- **AGT boundary** (`_agt.py`) — the single sanctioned import of `agent_os` /
  `agentmesh`, asserting pinned distribution versions at construction via
  `importlib.metadata`. `AGT_COMPAT_MAP` documents the `PolicyDecision` →
  `Decision` mapping; `docs/adr/001-agt-pins.md` records the pins and verified
  surface (including the moat-critical finding that raw AGT fails OPEN).
- **Config** (`config.py` + `zemtik.example.yaml`) — `GovernanceConfig` parses
  YAML and refuses insecure shapes at startup with `GovernanceNotConfigured`:
  every mode requires an audit sink; `strict`/`enforce` additionally require a
  policy source (inline rules or a non-empty `policy_dir`). Rule/field shapes are
  validated; `enforce` is validated identically to `strict`.
- **Registry** (`registry.py`) — `GovernanceRegistry` wires identity/policy/audit
  into a `ZemtikGovern`; `build()` refuses a half-wired core, `from_config()`
  honours the configured `audit_sink` (rejecting not-yet-supported file sinks
  rather than silently defaulting to in-memory).
- **Policy core** (`core.py`, `policy.py`) — `ZemtikGovern.govern()` orchestrates
  identity → policy → audit, fail-closed: a fault in identity OR policy is a
  system denial, audited (unidentified DID when identity is what failed) then
  re-raised — the tool never runs. `AgentOsPolicy` imposes deny-by-default over
  AGT's fail-open evaluator.
- **Governed proxy** (`_GovernedProxy`, `ZemtikGovern.proxy()`) — wraps a callable
  so every call passes through `govern()` first; a deny means the tool is never
  invoked. Async tools are awaited; `context_factory` return type is validated.
- **Frozen context** (`context.py`) — `GovernanceContext` deep-freezes nested
  `payload`/`extra`, closing the decision→audit TOCTOU.
- **Async protocols + errors** (`protocols.py`, `errors.py`) — runtime-checkable
  `PolicyEngine`/`IdentityProvider`/`AuditSink`, enriched `Decision`, typed
  `AuditEntry`, and the `GovernanceError` taxonomy.
- **Audit + identity** (`audit.py`, `identity.py`) — `AgentMeshAudit` adapter over
  agentmesh's Merkle-chained `AuditLog`; `StaticIdentity` v0.1 stub.
- **Supply-chain CI** (`.github/workflows/ci.yml`) — hash-pinned install from a
  dev lockfile (`requirements-dev.lock`, covering pytest/ruff), ruff as a hard
  lint gate, AGT conformance + e2e tests, and a version-pinned `pip-audit` OSV
  gate against `requirements.lock`.
- **Tests** — 96 passing across boundary, conformance, context, errors,
  protocols, policy, core, e2e, config, registry, proxy, modes, audit
  (incl. fallback redaction + symlink-refusal regressions), identity, the
  adversarial matrix, and the pressure-test gate — now covering effect-idempotent
  proxy replay (sequential + concurrent + cancellation), the direct-caller replay
  signal, deny-replay, un-cached system errors, and fingerprint fail-closed.

### Notes / deferred

- `Decision.correlation_id` / `policy_id` / `policy_version` are reserved
  enrichment fields, not yet populated (S4/S5).
- Audit sink supports only `"memory"` (in-memory Merkle log) in v0.1; the durable
  file sink lands in S5. See `TODOS.md`.
