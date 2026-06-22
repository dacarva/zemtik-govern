# API Reference — zemtik-govern

All public symbols are exported from `zemtik_govern.__init__`.

---

## Core

### `ZemtikGovern`

The orchestration core. Runs identity → policy → audit in that fixed order.

```python
ZemtikGovern(
    identity: IdentityProvider,
    policy: PolicyEngine,
    audit: AuditSink,
    *,
    mode: str = "enforce",
    fallback: PolicyEngine | None = None,
    killswitch: Callable[[], bool] | None = None,
    timeout: float | None = None,
)
```

**Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `identity` | `IdentityProvider` | Resolves subject strings to `AgentRef` DIDs. |
| `policy` | `PolicyEngine` | Evaluates a frozen context to a `Decision`. |
| `audit` | `AuditSink` | Records every outcome; called on allow, deny, and system error. |
| `mode` | `str` | `"strict"` / `"enforce"` raise on deny; `"shadow"` records but does not enforce. |
| `fallback` | `PolicyEngine \| None` | Alternate engine when `killswitch` is engaged. Engaging with no fallback fails closed. |
| `killswitch` | `Callable[[], bool] \| None` | Zero-arg callable returning `True` when engaged. Typically a `Killswitch` instance. |
| `timeout` | `float \| None` | Per-call decision budget (seconds) for identity + policy. A breach is a system denial. `None` means no budget. |

**Prefer `GovernanceRegistry.from_config()` over constructing directly** — it
wires the v0.1 stack from a validated config and handles audit sink selection.

---

#### `async govern(ctx: GovernanceContext) → Decision`

Run the three-seam pipeline for one governed request.

Raises `GovernanceDenied` if policy denies and the mode enforces.
Raises `GovernanceError` on any system fault (identity failure, policy engine
error, timeout, audit sink failure). In all failure cases the tool **never runs**.

---

#### `govern_sync(ctx: GovernanceContext) → Decision`

Synchronous entry point. Internally calls `asyncio.run(self.govern(ctx))`.

Raises `GovernanceError` if called inside a running event loop (would deadlock).
Use `await govern(ctx)` from async callers.

---

#### `proxy(fn, *, action, subject, context_factory=None) → _GovernedProxy`

Wrap a callable so every invocation passes through `govern()` first.

```python
governed_search = gov.proxy(search_fn, action="tool.search", subject="agent-42")
result = await governed_search(query="climate data")
```

The `context_factory` argument (optional) is a callable that receives the same
`*args, **kwargs` as the proxy call and must return a `GovernanceContext`. If it
returns any other type, `GovernanceError` is raised and the tool never runs.
`context_factory` is trusted integrator wiring — its values are not validated
beyond the return type.

The returned proxy is async. Callers that go through `proxy()` get
**effect-idempotency for free** and do not need to check `Decision.replayed`.

When `output_screening` is enabled, the proxy also screens the tool's return: a
READ action raises `OutputGovernanceDenied` on a rail hit, a WRITE action returns
a `RedactedOutput` sentinel. Wrap the result in `unwrap()` for a uniform contract.
See **Output Governance** below.

---

### `Killswitch`

An operator-flippable revert flag.

```python
ks = Killswitch(engaged=False)
ks.engage()      # route to fallback on next govern() call
ks.disengage()   # restore primary policy path
bool(ks())       # current state
```

Passed as the `killswitch` parameter to `ZemtikGovern`. Any zero-arg callable
returning `bool` satisfies the slot.

---

## Registry

### `GovernanceRegistry`

Collects the three seams and builds the core.

```python
GovernanceRegistry()
    .register_mode("strict")
    .register_identity(my_identity)
    .register_policy(my_policy)
    .register_audit(my_audit)
    .build()  # → ZemtikGovern
```

#### `classmethod from_config(config: GovernanceConfig, boundary: AGTBoundary) → GovernanceRegistry`

Wire the v0.1 default stack from a validated config:
- `StaticIdentity` (identity)
- `AgentOsPolicy` with deny-by-default (policy)
- `AgentMeshAudit` Merkle-chained (audit); durable + HMAC-signed if `audit_sink` is a file path

#### `build() → ZemtikGovern`

Return a fully-wired core. Raises `GovernanceNotConfigured` if any seam is not registered.

#### `register_mode(mode: str) → GovernanceRegistry`
#### `register_identity(impl: IdentityProvider) → GovernanceRegistry`
#### `register_policy(impl: PolicyEngine) → GovernanceRegistry`
#### `register_audit(impl: AuditSink) → GovernanceRegistry`

All four return `self` for chaining. The env var name for the audit HMAC secret is
exposed as `GovernanceRegistry._AUDIT_SECRET_ENV` (`"ZEMTIK_AUDIT_SECRET"`).

---

## Value Types

### `GovernanceContext`

```python
@dataclass(frozen=True)
class GovernanceContext:
    action: str
    subject: str
    payload: Mapping[str, Any] = {}
    idempotency_key: str | None = None
    ts: str | None = None
    extra: Mapping[str, Any] = {}
```

`payload` and `extra` are **deep-frozen** at construction: dicts →
`MappingProxyType`, lists → `tuple`, sets → `frozenset`, recursively. Sets of
unhashable values (e.g. dicts) raise `TypeError` at construction.

#### `to_dict() → dict`

Thaw to a plain, mutable, JSON-serializable dict for AGT calls.

---

### `Decision`

```python
@dataclass(frozen=True)
class Decision:
    allowed: bool
    action: str                    # "allow" | "deny" | "error"
    matched_rule: str | None
    reason: str
    denial_kind: str | None        # "policy" | "system" | None when allowed
    correlation_id: str | None     # reserved — always None in v0.1
    policy_id: str | None          # reserved — always None in v0.1
    policy_version: str | None     # reserved — always None in v0.1
    audit_event_id: str | None     # set by govern() after audit.write()
    replayed: bool                 # True when served from the idempotency ledger

    @property
    def audit_id(self) -> str | None: ...   # public alias for audit_event_id (D9)
```

**`Decision.audit_id`** — the public, guard-agnostic name for `audit_event_id`.
The SAME id rides a raised exception's `.audit_id`, so an allowed result and a
blocked one correlate to the audit trail identically. See `docs/operations.md`
("Correlating logs to the audit trail").

**`Decision.replayed`** — direct `govern()` / `govern_sync()` callers **must**
check this before executing their own side effects:

```python
decision = await gov.govern(ctx)
if decision.allowed and not decision.replayed:
    do_write()   # guard prevents double-send on retry
```

Callers using `proxy()` get effect-idempotency automatically and do not need this
check.

**Reserved fields** (`correlation_id`, `policy_id`, `policy_version`) are declared
for future use and are always `None` in v0.1. Do not write code that reads them
expecting live data.

---

### `AuditEntry`

```python
@dataclass(frozen=True)
class AuditEntry:
    event_type: str          # "tool_invoked" | "tool_blocked"
    agent_did: str
    action: str
    outcome: str             # "success" | "denied" | "error" | "replay"
    policy_decision: str | None
    mode: str | None
    payload: Mapping[str, Any]
    idempotency_key: str | None
    ts: str | None
```

#### `classmethod from_decision(ctx, agent_did, decision, outcome=None, mode=None) → AuditEntry`

Build an audit entry from a governance decision. `outcome` defaults to
`"success"` / `"denied"` for ordinary allow/deny; special cases pass explicit
values (`"error"`, `"replay"`).

---

### `AgentRef`

```python
@dataclass(frozen=True)
class AgentRef:
    did: str   # e.g. "did:mesh:agent-42"
```

The value returned by `IdentityProvider.identify`. In v0.1 carries only the DID;
v0.2 will add issuer, key, and claims without changing the seam contract.

---

## Protocol Seams

All three are `typing.Protocol` with `runtime_checkable`. Any object with the right
shape satisfies the seam — no inheritance required.

### `IdentityProvider`

```python
async def identify(self, subject: str) -> AgentRef: ...
```

### `PolicyEngine`

```python
async def evaluate(self, ctx: GovernanceContext) -> Decision: ...
```

Implementations **must** impose deny-by-default. Passing the AGT no-match
(`matched_rule is None`) case through as an allow is a moat breach.

### `AuditSink`

```python
async def write(self, entry: AuditEntry) -> str: ...   # returns entry_id
```

---

## v0.1 Implementations

### `StaticIdentity(boundary: AGTBoundary)`

Maps every subject deterministically to `did:mesh:<subject>`. Cannot fail in v0.1.

### `AgentOsPolicy(boundary, rules=None, root_dir=None)`

Deny-by-default wrapper over AGT's evaluator. `rules` is a list of inline rule
dicts; `root_dir` is a directory of policy files. In shadow mode, `rules=None` is
valid (no enforcement).

### `AgentMeshAudit(boundary, sink=None, *, fallback_path=None)`

Merkle-chained audit adapter. On primary-sink failure, routes to the redacted
fallback channel then raises `GovernanceError`.

#### `verify_integrity() → (bool, str | None)`

Verify the Merkle chain. Returns `(True, None)` on success; `(False, reason)` on
any tamper or gap detected.

#### `get_proof(entry_id: str) → dict`

Return a Merkle proof for a written entry. Requires at least two entries in the
log for a sibling path to exist.

### `AuditReader(path, boundary, secret)`

Cold-read auditor module. Reads a durable `.jsonl` trail written by
`AgentMeshAudit` without touching an active session.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `str \| Path` | Path to the `.jsonl` audit file. |
| `boundary` | `AGTBoundary` | Used to open a fresh `FileAuditSink` for HMAC verification. |
| `secret` | `bytes \| str` | HMAC secret (`$ZEMTIK_AUDIT_SECRET`). |

#### `records() → list[AuditRecord]`

Return all entries in the trail as a list of typed, frozen `AuditRecord`
dataclasses. Fields: `entry_id`, `agent_did`, `action`, `outcome`, `event_type`,
`policy_decision`, `timestamp`, `payload`.

#### `verify() → (bool, str | None)`

Verify the Merkle chain + HMAC signatures by opening a fresh `FileAuditSink` on
the file. Returns `(True, None)` when the chain is intact; `(False, reason)` when
any entry has been modified, deleted, reordered, or when the HMAC secret is wrong.
Cold-read isolation: a new sink is created on every call so in-memory state never
masks a tampered file.

#### `proof(entry_id: str) → dict`

Return a chain inclusion proof for `entry_id`. The dict contains:

| Key | Description |
|-----|-------------|
| `entry` | The raw entry dict from the file. |
| `merkle_proof` | List of `(entry_hash, entry_id)` tuples from genesis to the target. |
| `merkle_root` | `entry_hash` of the last entry in the trail. |
| `verified` | `True` when every `previous_hash` link from genesis to this entry is intact AND the full HMAC chain (`verify()`) passes. A wrong secret or tampered payload fails both. |

An auditor can independently verify: for each consecutive pair in `merkle_proof`,
the second entry's `previous_hash` must equal the first entry's hash.

### `AuditRecord`

Frozen dataclass representing one entry from the durable audit trail.

```python
@dataclass(frozen=True)
class AuditRecord:
    entry_id: str
    agent_did: str
    action: str
    outcome: str          # "success" | "denied" | "error" | "replay"
    event_type: str       # "tool_invoked" | "tool_blocked"
    policy_decision: str | None
    timestamp: str
    payload: dict
```

---

## Output Governance

The output seam (#39–#43) screens a tool's **return value** after it runs. Opt in
with `output_screening: true` and classify each action as `read` or `write` via
`tool_io_map`. Enforcement is asymmetric: a READ-classified tool's offending
return **raises** `OutputGovernanceDenied` (caller never sees the value); a
WRITE-classified tool already ran, so `proxy()` **returns** a `RedactedOutput`
sentinel instead of the value. See `docs/architecture.md` (output seam) and
`docs/integration-guide.md` (wiring) for the full design.

### `OutputClassifier` (Protocol)

```python
@runtime_checkable
class OutputClassifier(Protocol):
    name: str
    async def screen(self, text: str, ctx: GovernanceContext) -> OutputVerdict: ...
```

Screens projected output text for one class of leak. Async so a concrete
implementation may offload to a thread pool.

### `OutputVerdict`

```python
@dataclass(frozen=True)
class OutputVerdict:
    is_match: bool
    rail: str | None = None     # the firing rail
    reason: str | None = None   # safe summary — NEVER the matched text
```

The no-echo-safe outcome of screening one tool return.

### `RegexPIIClassifier(*, threshold=0.0, mode="enforce")`

The C0 default PII rail and a concrete `OutputClassifier`. Scans output for
email / SSN / payment-card / phone shapes with linear-time (ReDoS-safe) anchored
regexes. A regex hit is binary (confidence `1.0`); `mode` is `"enforce"` or
`"shadow"` (a shadow match is observed but not enforced).

### `RedactedOutput`

```python
@dataclass(frozen=True)
class RedactedOutput:
    audit_id: str
```

The sentinel `proxy()` returns when a WRITE-classified tool's output trips an
enforce rail. **Two halves:** SPARE methods (`str`/`repr`/`format`) return the
marker `"<output redacted: audit_id=…>"` so structured logging never crashes;
POISON methods (attribute access other than `audit_id`, item access, iteration)
raise `RedactedOutputAccessError`. Equality is type-only. `audit_id` back-links
to the `output_denied_redacted` audit row.

### `ZemtikGovern.unwrap(result) → Any`

Collapses the read-deny-raises / write-deny-returns asymmetry into one call.
Returns `result` unchanged when it is not a `RedactedOutput`; raises
`OutputGovernanceDenied` (carrying the sentinel's `audit_id`) when it is. Wrap
every governed result in it for a uniform contract.

```python
result = await governed_write(...)
value  = gov.unwrap(result)   # raises if result was redacted
```

---

## CLI

### `zemtik init langchain`

Scaffold a `govern.yaml` from LangChain tool introspection.

```bash
# Minimal govern.yaml — no tools introspected:
python -m zemtik_govern.cli init langchain

# Introspect tools from a module and write to stdout:
python -m zemtik_govern.cli init langchain --tools-module my_agent.tools

# Write directly to a file:
python -m zemtik_govern.cli init langchain --tools-module my_agent.tools --output govern.yaml
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--tools-module MODULE` | `None` | Dotted Python module path to import for tool introspection. |
| `--output FILE` | stdout | Write YAML to `FILE` instead of stdout. |

**stdout / stderr discipline:** YAML goes to stdout only (supports shell redirection). Warnings and errors go to stderr. An import failure prints an error to stderr and exits with code 1 without writing any YAML to stdout.

**Security note:** `--tools-module` accepts arbitrary Python import paths. This is a developer-only command — never expose it to untrusted input in production.

The generated file uses `mode: strict`, `audit_sink: memory`, and commented-out rules (one per discovered tool). Uncomment and adjust rules before deploying.


---

## AGT Boundary

### `AGTBoundary(pins: dict[str, str] = AGT_PINS)`

Assert pinned AGT distribution versions at construction. Raises `AGTVersionError`
on any mismatch or missing distribution.

```python
AGT_PINS = {
    "agent-os-kernel": "3.7.0",
    "agentmesh-platform": "3.7.0",
}
```

`AGT_COMPAT_MAP` documents how AGT's `PolicyDecision` fields map to `Decision`
fields and how `AgentDID` maps to the `did:mesh:` string stamped on audit entries.

---

## Configuration

### `GovernanceConfig`

```python
@dataclass(frozen=True)
class GovernanceConfig:
    mode: str = "strict"
    rules: tuple[dict, ...] = ()
    policy_dir: str | None = None
    audit_sink: str | None = None
    # Output-governance seam (#39–#43) — opt-in, proxy() only:
    output_screening: bool = False                 # screen every tool return through the rails
    tool_io_map: Mapping[str, str] = {}            # action → "read" | "write"
    rails: tuple[RailConfig, ...] = ()             # per-rail threshold + mode
```

See `docs/configuration-reference.md` for the full field list (decision budget,
idempotency bounds, injection guard, and the output-seam fields) and YAML examples.

### `RailConfig`

```python
@dataclass(frozen=True)
class RailConfig:
    name: str                  # rail to enable; C0 ships "pii"
    threshold: float = 0.0     # 0.0–1.0 minimum confidence; regex PII rail is binary
    mode: str = "enforce"      # "enforce" | "shadow" (observe without enforcing)
```

One output rail's tuning. A typo'd `mode` or out-of-range `threshold` is a
startup error (fail-closed). See `docs/configuration-reference.md` (`rails`).

#### `classmethod load(path: str | Path) → GovernanceConfig`

Read and validate a YAML config file. Raises `GovernanceNotConfigured` on any
read, parse, or validation error.

#### `classmethod from_mapping(data: Mapping) → GovernanceConfig`

Build from a parsed dict. Validates field types and delegates to `__post_init__`
for mode/sink/policy-source checks.

---

## Errors

All errors subclass `GovernanceError`. When any of these is raised, the guarded
tool **did not run**. Every instance carries a stable `.code` (branch on it, not
on the message), an optional `.guard`, and an `.audit_id` that matches the written
audit row.

| Exception | `.code` | Meaning |
|-----------|---------|---------|
| `GovernanceError` | `governance_error`, `engine_error`, `idempotency_conflict`, `idempotency_fingerprint_error` | Base class; system fault in a seam (engine failure, idempotency key reuse, unserialisable payload). |
| `GovernanceDenied(decision)` | `policy_denied` / `system_denied` | Policy (or fail-closed system) deny. Carries `.decision`; `.guard` mirrors `denial_kind`. |
| `DecisionBudgetExceeded` | `decision_budget_exceeded` | Identity+policy did not resolve in time. Carries `.limit_seconds` / `.elapsed_seconds`; `.guard == "budget"`. |
| `OutputGovernanceDenied` | `output_denied` | An output rail tripped on a READ-classified tool's return value; the value is withheld. The tool already ran (output-deny asymmetry). Carries `.rail`; `.guard == "output"`. |
| `RedactedOutputAccessError` | `output_redacted_access` | A caller tried to read data from a `RedactedOutput` sentinel (a WRITE-classified tool's output was redacted). Carries `.audit_id`; `.guard == "output"`. |
| `GovernanceNotConfigured` | `not_configured` | Insecure startup config or missing seam. Raised at boot. |
| `AGTVersionError` | — | AGT distribution pin mismatch. Raised at `AGTBoundary()` construction. |

```python
try:
    decision = await gov.govern(ctx)
except GovernanceDenied as exc:
    # policy said no; exc.decision has the rule/reason
    log.warning("denied: %s code=%s audit_id=%s", exc.decision.reason, exc.code, exc.audit_id)
except GovernanceError as exc:
    # system fault; tool was blocked; branch on the stable code, not the message
    if exc.code == "decision_budget_exceeded":
        metrics.budget_breach(exc.limit_seconds, exc.elapsed_seconds)
    raise
```
