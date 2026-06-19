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
| `timeout` | `float \| None` | `None` | Per-call decision budget (seconds) for identity + policy. Not currently wired through `GovernanceConfig` (see `TODOS.md` P2). |
| `mode` | `str` | `"enforce"` | Runtime mode; overrides the mode the registry sets. |
| `fallback` | `PolicyEngine \| None` | `None` | Policy engine to use when kill-switch is engaged. |
| `killswitch` | `Callable[[], bool] \| None` | `None` | Zero-arg callable; `True` means use fallback engine. |
