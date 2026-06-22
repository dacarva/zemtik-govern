# Configuration Reference — zemtik-govern

## YAML config file

```yaml
# zemtik.yaml

mode: strict          # strict | shadow | enforce
audit_sink: memory    # "memory" or a file path

rules:
  - name: allow-tool-run
    condition:
      field: action
      operator: eq
      value: tool.run
    action: allow

# policy_dir: ./policies   # alternative to inline rules
```

Load it with:

```python
from zemtik_govern import GovernanceConfig
config = GovernanceConfig.load("zemtik.yaml")
```

---

## Field Reference

### `mode`

Controls whether denials are enforced and what sources are required.

| Value | Denials enforced | Policy source required | Audit required | Notes |
|-------|-----------------|------------------------|----------------|-------|
| `strict` | Yes | Yes | Yes | Secure default |
| `enforce` | Yes | Yes | Yes | Identical validation to `strict`; used for kill-switch wiring |
| `shadow` | No | No | Yes | Observe denies without blocking tools |

Shadow mode is for safe rollout: run on live traffic to surface false-denies before
switching to `enforce`. Do not leave production running in shadow indefinitely —
tools run uninspected.

**Startup error**: any other value raises `GovernanceNotConfigured`.

---

### `audit_sink`

Where the tamper-evident audit trail is written.

| Value | Behaviour |
|-------|-----------|
| `"memory"` or omitted | In-memory Merkle-chained log (default). Process-local; not durable across restarts. |
| A file path string | Durable, HMAC-signed `FileAuditSink` at that path. Requires `$ZEMTIK_AUDIT_SECRET` in the environment. |

Every mode requires an `audit_sink`. Omitting it is a startup error
(`GovernanceNotConfigured`).

A file sink without `$ZEMTIK_AUDIT_SECRET` refuses to start — an unsigned
tamper-evident log is a contradiction, not a degraded mode.

---

### `rules`

A list of inline AGT policy rule dicts. Each rule must be a mapping with at least:

```yaml
rules:
  - name: allow-tool-run        # unique rule name (required)
    condition:
      field: action             # context field to match on
      operator: eq              # eq | neq | in | prefix | ...
      value: tool.run           # value to compare
    action: allow               # allow | deny
```

Rules are evaluated in order by AGT's `PolicyEvaluator`. The **deny-by-default
moat** means any action not matched by an `allow` rule is denied, regardless of
order.

Required in `strict` and `enforce` modes unless `policy_dir` is set.

---

### `policy_dir`

A directory path from which AGT loads policy files. Must exist and contain at
least one file for `strict`/`enforce` modes.

```yaml
policy_dir: ./policies
```

Can be used instead of or alongside inline `rules`. An empty directory in an
enforcing mode is a startup error.

---

### `decision_budget_seconds`

The per-call decision budget, **in seconds**, for the identity + policy path.
Threaded from config → registry → `ZemtikGovern(timeout=)`, so a config-built
governor is bounded by default rather than silently running unbounded.

```yaml
# default: 5.0 — lower it on latency-sensitive (e.g. voice) paths
decision_budget_seconds: 5.0
```

| Value | Meaning |
|-------|---------|
| omitted | defaults to `5.0` seconds |
| a positive number | that many seconds |
| `null` | **opt out** — no budget; only safe when an upstream caller enforces its own deadline |
| `0`, negative, or non-numeric | startup error (`GovernanceNotConfigured`) — a non-positive budget would deny all traffic |

**Unit is in the name** (`_seconds`) on purpose: it kills the seconds-vs-milliseconds
1000× footgun at the call site.

**Budget semantics — what it covers (v0.2):** the budget wraps **each** awaited
seam call *individually* — the identity resolve and the policy evaluation — via an
explicit **deadline race** (not `asyncio.wait_for`). The race decides on the timer,
never on the engine: once the budget is blown the engine is cancelled and its
result is **never observed**, so a *cancel-swallowing* engine that returns an allow
after the deadline cannot turn a breached budget into an implicit allow (#34, T2).
A breach is a **system fault** routed through the fail-closed path — audited, then
`GovernanceError`; the tool never runs.

It remains **per-await, not yet end-to-end**: it does NOT bound idempotency
lock-wait, injection projection, executor queue time, or the audit write.
(Idempotency locking is now **per-key** (#34, T-LOCK), so a slow key no longer
head-of-line-blocks unrelated keys, but the budget still does not span lock-wait.)
Promoting this to a single **end-to-end deadline** across the whole `govern()` call
(so the SLA also accounts for lock-wait + audit + injection) is future work.

---

### `idempotency_max_entries` / `idempotency_ttl_seconds`

Bound the idempotency caches (#35). The decision ledger and the proxy's
effect-dedup slots share **one** bounded LRU+TTL cache (`BoundedTTLDict`, stdlib
`OrderedDict` — no new dependency), so unique-key traffic can no longer grow them
without bound (a DoS / memory-leak surface) and a stale decision expires and
re-evaluates.

```yaml
# defaults: 10000 entries, 3600s (1h) TTL
idempotency_max_entries: 10000
idempotency_ttl_seconds: 3600.0
```

| Field | Value | Meaning |
|-------|-------|---------|
| `idempotency_max_entries` | positive int | LRU cap; oldest **evictable** entry is dropped past the cap |
| `idempotency_ttl_seconds` | positive number | a ledgered decision past this age re-evaluates instead of replaying |
| `idempotency_ttl_seconds` | `null` | no expiry (LRU-only) |
| either, `0`/negative/non-numeric | — | startup error (`GovernanceNotConfigured`) |

The two concerns ride one cache **record** per key, so they evict **consistently**:
a record holding an **in-flight effect future** vetoes its own eviction (a running
tool call with concurrent waiters is never orphaned), and an evicted key removes
its decision *and* its cached effect together — a recycled key can never pass
fresh governance and still collect a previous request's tool result.

**Two-level keying:** the cached-decision **replay** lookup keys on `(key, mode,
killswitch_state)`, so a decision ledgered before the killswitch flipped
re-enforces under the fallback rather than replaying its stale allow. **Conflict
detection** stays keyed on the request **fingerprint** alone, so a recycled key
with a changed payload is still caught regardless of the mode/killswitch bucket.

---

### `injection_rules_path`

**Optional** path to a prompt-injection rule file (#36), loaded through
`AGTBoundary` into AGT's `PromptInjectionDetector(injection_config=...)`. Leave it
unset and the guard uses AGT's own vetted `PromptInjectionConfig()` defaults,
passed explicitly — warning-free, and tracking the pinned AGT wheel with no
in-repo file to maintain. Set it only to pin a version or diverge.

```yaml
# optional — omit to use AGT's vetted defaults
injection_rules_path: policies/prompt-injection.yaml
```

| Mode | Behaviour |
|------|-----------|
| `strict` / `enforce` | Guard is **always on**. With no path it uses AGT's explicit defaults; with a path the file must exist and contain a `detection_patterns` section, else startup is a `GovernanceNotConfigured` error. Neither path is the bare sample-rule fall-back. |
| `shadow` | Optional; if given, still loaded and validated; if omitted, the guard is not wired (observe-only mode). |

The screen is **mandatory and fail-closed**, folded into the **policy seam**: a hit
is a *policy* deny. It wraps the engine `_select_engine()` returns, so the
**primary policy AND the killswitch fallback** are both guarded — engaging the
killswitch cannot bypass the screen (T1).

Operational properties:

- **D6 no-echo** — a deny names the offending **field**, the injection type, and the
  threat level only; never the raw payload, matched patterns, or decoded bytes.
- **Strict projection** — the payload is projected with strict `json.dumps` (no
  `default=str`), so an attacker-controlled `__str__` is never invoked; a
  non-JSON-native leaf fails closed.
- **Bounded executor** — small fields scan inline (skip the thread-hop on voice
  payloads); larger ones offload to a **dedicated** bounded `ThreadPoolExecutor` (a
  scan storm cannot starve the shared default pool); oversized fields are **denied
  unscanned**.
- A forced detector fault propagates and fails closed (system deny → `GovernanceError`).

---

### `injection.mode` / `budget.mode` (per-guard shadow)

Scope the shadow stance to ONE guard (D10) — the observe-then-enforce upgrade
path. Independent of the global `mode`: even in `enforce` you can run a *new* guard
in `shadow` for one release, watch the would-denies in the log, then flip it on.

```yaml
injection:
  mode: shadow          # observe injection would-denies; do NOT block yet
  confidence_floor: 0.0 # reserved paranoid dial; off by default (see below)
budget:
  mode: enforce         # block on a budget breach (the default)
```

Flat keys (`injection_mode: shadow`, `budget_mode: enforce`) are also accepted.

| Field | Values | Default | Behaviour |
|-------|--------|---------|-----------|
| `injection.mode` | `enforce` \| `shadow` | `enforce` | `shadow`: an injection hit is logged as a would-deny (field only, no payload echo) but the request still reaches the inner engine. |
| `budget.mode` | `enforce` \| `shadow` | `enforce` | `shadow`: a budget breach is logged as a would-breach but the engine result is used — no fail-closed deny while observing. |

A typo'd stance (`injection.mode: loose`) is a startup error
(`GovernanceNotConfigured`), not a silent fall-through.

### `injection_confidence_floor`

```yaml
injection_confidence_floor: 0.0   # off by default
```

A paranoid-mode dial, **off by default** (`0.0` = every detection counts).
Reserved: the shipped AGT screen does not yet surface a per-detection confidence
to compare against, so a non-zero floor is validated (must be in `[0.0, 1.0]`) and
documented but is **not yet load-bearing**. The name and the off-by-default
contract are stable now so a future paranoid-mode release does not change config
shape. Also accepted nested as `injection: {confidence_floor: …}`.

---

## Environment Variables

### `ZEMTIK_AUDIT_SECRET`

HMAC signing key for file audit sinks. Required when `audit_sink` is a file path.

```bash
export ZEMTIK_AUDIT_SECRET='your-signing-key'
```

- Read from the environment at startup, never from the config file.
- A file sink without it raises `GovernanceNotConfigured` at startup.
- Used to HMAC-sign each audit entry for tamper detection.

### `ZEMTIK_AUDIT_FALLBACK`

Override the path for the emergency redacted fallback file. Defaults to
`zemtik-govern-audit-fallback.jsonl` in the current working directory.

The fallback file is created with mode `0600` (owner-read/write only) and opened
with `O_NOFOLLOW` to prevent symlink redirection attacks.

---

## `GovernanceConfig` Python API

```python
@dataclass(frozen=True)
class GovernanceConfig:
    mode: str = "strict"
    rules: tuple[dict, ...] = ()
    policy_dir: str | None = None
    audit_sink: str | None = None
    decision_budget_seconds: float | None = 5.0
    idempotency_max_entries: int = 10000
    idempotency_ttl_seconds: float | None = 3600.0
    injection_rules_path: str | None = None
    injection_mode: str = "enforce"          # per-guard shadow (D10)
    budget_mode: str = "enforce"             # per-guard shadow (D10)
    injection_confidence_floor: float = 0.0  # reserved; off by default (D5)
```

### `classmethod load(path: str | Path) → GovernanceConfig`

Read and validate a YAML config file. Any read or parse failure is a startup error
(`GovernanceNotConfigured`), not a `None`-returning silent skip.

### `classmethod from_mapping(data: Mapping) → GovernanceConfig`

Build from a pre-parsed dict (e.g. from `yaml.safe_load`). Validates field types
before `__post_init__` validates the config shape.

---

## Startup Validation Rules

`GovernanceConfig.__post_init__` raises `GovernanceNotConfigured` if any of these
fail:

| Check | Condition |
|-------|-----------|
| Valid mode | `mode` must be one of `{strict, shadow, enforce}` |
| Rule shapes | Every entry in `rules` must be a `Mapping` |
| Audit sink required | `audit_sink` must be set (all modes) |
| Policy source required | `strict` / `enforce` need `rules` OR a non-empty `policy_dir` |
| Non-empty `policy_dir` | If set, the directory must exist and contain at least one file |

These checks run at parse time — an insecure config never reaches the orchestrator.

---

## `ZemtikGovern` Runtime Parameters

These are not in the YAML file; pass them to `ZemtikGovern()` or via
`GovernanceRegistry`:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | `float \| None` | `None` | Per-call decision budget (seconds) for identity + policy. Wired through `GovernanceConfig` via the `decision_budget_seconds` field (above) — a config-built governor receives it, defaulting to `5.0`; pass `timeout=` directly only when constructing `ZemtikGovern` by hand. |
| `mode` | `str` | `"enforce"` | Runtime mode; overrides the mode the registry sets. |
| `fallback` | `PolicyEngine \| None` | `None` | Policy engine to use when kill-switch is engaged. |
| `killswitch` | `Callable[[], bool] \| None` | `None` | Zero-arg callable; `True` means use fallback engine. |
