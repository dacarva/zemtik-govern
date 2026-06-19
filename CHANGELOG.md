# Changelog

All notable changes to zemtik-govern are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project versions
via `pyproject.toml` (currently `0.1.0.dev0`, pre-release).

## [0.0.1.0] - 2026-06-19

### Added
- **LangChain and MCP integration scaffolding** — `zemtik_govern.langchain`,
  `zemtik_govern.mcp`, and `zemtik_govern.cli` package directories with
  optional dependency groups (`pip install zemtik-govern[langchain]` and
  `[mcp]`). Implementation stubs are in place for the upcoming
  `govern_tool()` API (issue #15) and `GovernedMCPServer` (issue #20).
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
