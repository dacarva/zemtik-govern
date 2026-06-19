# Changelog

All notable changes to zemtik-govern are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project versions
via `pyproject.toml` (currently `0.1.0.dev0`, pre-release).

## [Unreleased]

S1–S3 of the governance wrapper: the AGT boundary, the M0 skeleton, and the
fail-closed policy core, plus config/registry/proxy wiring and a hardened CI
supply-chain gate.

### Added

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
- **Tests** — 59 passing across boundary, conformance, context, errors,
  protocols, policy, core, e2e, config, registry, and proxy.

### Notes / deferred

- `Decision.correlation_id` / `policy_id` / `policy_version` are reserved
  enrichment fields, not yet populated (S4/S5).
- Audit sink supports only `"memory"` (in-memory Merkle log) in v0.1; the durable
  file sink lands in S5. See `TODOS.md`.
