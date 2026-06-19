# Changelog

All notable changes to zemtik-govern are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project versions
via `pyproject.toml` (currently `0.1.0.dev0`, pre-release).

## [Unreleased]

S1–S5 of the governance wrapper: the AGT boundary, the M0 skeleton, and the
fail-closed policy core, plus config/registry/proxy wiring and a hardened CI
supply-chain gate — now with operational safety modes (S4) and the durable,
fallback-protected audit trail (S5).

### Added

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
- **Tests** — 75 passing across boundary, conformance, context, errors,
  protocols, policy, core, e2e, config, registry, proxy, modes, and audit
  (incl. fallback redaction + symlink-refusal regressions).

### Notes / deferred

- `Decision.correlation_id` / `policy_id` / `policy_version` are reserved
  enrichment fields, not yet populated (S4/S5).
- Audit sink supports only `"memory"` (in-memory Merkle log) in v0.1; the durable
  file sink lands in S5. See `TODOS.md`.
