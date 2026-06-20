# Operations Guide — zemtik-govern

## Deployment Checklist

- [ ] `agent-os-kernel==3.7.0` and `agentmesh-platform==3.7.0` installed exactly
- [ ] `mode`, `audit_sink`, and `rules` configured in `zemtik.yaml`
- [ ] `ZEMTIK_AUDIT_SECRET` set in the environment (required for file audit sinks)
- [ ] `timeout` wired into `ZemtikGovern` for latency-sensitive paths
- [ ] AGT conformance tests pass: `pytest tests/test_agt_conformance.py`

---

## Durable Audit (Production)

### Configure a file sink

```yaml
# zemtik.yaml
mode: strict
audit_sink: /var/log/zemtik-audit.jsonl
rules: [...]
```

```bash
export ZEMTIK_AUDIT_SECRET='your-signing-key'
```

The file sink is:
- **HMAC-signed**: each entry carries an HMAC of its content + the previous
  entry's hash (Merkle-chained), keyed by `$ZEMTIK_AUDIT_SECRET`.
- **Hash-chained**: a break in the chain is detectable by `verify_integrity()`.
- **Append-only**: opened in append mode; existing entries are not rewritten.

### Verify integrity

```python
from zemtik_govern import AGTBoundary, GovernanceConfig, GovernanceRegistry

config = GovernanceConfig.load("zemtik.yaml")
boundary = AGTBoundary()
registry = GovernanceRegistry.from_config(config, boundary)
gov_audit = registry._audit   # AgentMeshAudit instance

ok, err = gov_audit.verify_integrity()
if not ok:
    raise RuntimeError(f"audit chain broken: {err}")
```

Run integrity checks:
- After each incident response investigation
- Before archiving or rotating the audit log
- On backup restoration to verify the backup is intact

### Merkle proofs

```python
entry_id = "..."   # from Decision.audit_event_id or the audit log
proof = gov_audit.get_proof(entry_id)
```

Returns a dict containing the sibling hashes needed to reproduce the root hash.
**Requires at least two entries** in the log for a sibling path to exist.

What proofs provide: cryptographic evidence that a specific entry was recorded and
not modified. They do not provide non-repudiation (signing key is shared).

### Cold-read auditor workflow

An auditor who receives a `.jsonl` file and the HMAC secret but has no access to
the live process can use `AuditReader` for all three operations:

```python
from zemtik_govern._agt import AGTBoundary
from zemtik_govern.audit import AuditReader

reader = AuditReader("path/to/audit.jsonl", AGTBoundary(), secret="your-signing-key")

# 1. Verify the full chain (HMAC + previous_hash links) from disk
ok, err = reader.verify()
assert ok, f"chain broken: {err}"

# 2. Read all entries as typed records
for r in reader.records():
    print(r.timestamp, r.agent_did, r.action, r.outcome, r.policy_decision)

# 3. Prove a specific event by its entry_id
proof = reader.proof("audit_36f55e0aaea34730")
assert proof["verified"]
```

`verify()` opens a fresh `FileAuditSink` on each call — in-memory session state
never hides a tampered file. `proof()` builds a chain inclusion proof by traversing
`previous_hash` links from genesis to the target entry; an auditor can verify it
independently without the running process.

Run `sandbox/auditor.py` for a full demo (workload generation → report → chain
verification → inclusion proof → tamper detection):

```bash
ZEMTIK_AUDIT_SECRET=your-signing-key python sandbox/auditor.py
```

---

## Emergency Fallback Channel

When the primary audit sink fails, zemtik-govern writes a **redacted,
metadata-only** record to two destinations before raising `GovernanceError`:

1. **stderr** (first — more reliable than the filesystem)
2. **A fallback file** at `$ZEMTIK_AUDIT_FALLBACK` (default:
   `zemtik-govern-audit-fallback.jsonl` in cwd)

### What the fallback record contains

| Field | Value |
|-------|-------|
| `action` | The governed action |
| `agent_did` | The resolved DID |
| `outcome` | `denied`, `error`, etc. |
| `idempotency_key` | If present |
| `ts` | Timestamp from context |
| `err_type` | Exception type (not message — prevents payload smuggling) |
| `payload_sha256` | SHA-256 digest of the payload |

The raw `payload` is **never written** to the fallback. The SHA-256 digest lets an
operator correlate the fallback record with the original request without leaking
sensitive data.

### Fallback file security

- Created with mode `0600` (owner-read/write only).
- Opened with `O_NOFOLLOW` to prevent symlink redirection to another file.
- `emit_fallback` never raises — stderr cannot fail like the filesystem.

### What to do when fallback fires

1. Check for audit sink errors (filesystem full, permissions, network issue).
2. Find the fallback record in `$ZEMTIK_AUDIT_FALLBACK` or stderr.
3. Correlate the `payload_sha256` with your request logs to identify the request.
4. Restore the primary sink, then restart the process.

---

## Kill-Switch

The kill-switch reverts a running governor to a prior governed fallback policy
**without any allow-all bypass**.

### Wire it before starting

```python
from zemtik_govern import Killswitch, ZemtikGovern

ks = Killswitch()
gov = ZemtikGovern(
    identity=identity,
    policy=new_policy,
    audit=audit,
    fallback=old_policy,   # must be a valid PolicyEngine
    killswitch=ks,
)
```

### Engage / disengage

```python
# Revert to prior policy (e.g. after a bad deploy)
ks.engage()

# Restore new policy after the fix is confirmed
ks.disengage()
```

### Audit stamp

Every audit entry's `mode` field reflects which engine was used. When the
kill-switch is engaged, the mode is stamped on the entry so the enforcement switch
is observable in the audit trail.

### Safety guarantee

Engaging the kill-switch with no `fallback` wired raises `GovernanceError` (audited
as a system denial) — the tool is blocked. There is no path to allow-all.

---

## Shadow Mode Rollout

Use shadow mode to deploy governance without blocking traffic, then observe before
switching to enforce.

### Step 1: Deploy in shadow

```yaml
mode: shadow
audit_sink: memory    # or a file path for durable observation
```

Tools still run; all denies are recorded in the audit trail.

### Step 2: Observe the audit trail

Monitor `outcome=denied` entries in the trail. Each has:
- `action` — the tool action that would have been blocked
- `policy_decision` — the reason (e.g. "deny-by-default: no policy rule matched")
- `agent_did` — which agent triggered the deny

Add `allow` rules for any legitimate actions that are being denied.

### Step 3: Switch to enforce

```yaml
mode: enforce     # or strict — both enforce denials
audit_sink: memory
rules: [...]      # updated after shadow observation
```

Restart the process. Denials are now enforced — `GovernanceDenied` is raised and
tools are blocked.

---

## Monitoring

### What to alert on

| Signal | What it means |
|--------|--------------|
| `GovernanceError` from `audit.write` | Primary audit sink down — check fallback file |
| Elevated `GovernanceDenied` rate | Rule coverage gap or active attack — review deny audit entries |
| `AGTVersionError` at startup | Pin mismatch — do not start; fix environment |
| Fallback file growing | Primary sink repeatedly failing |

### Key audit entry fields for dashboards

| Field | Use |
|-------|-----|
| `outcome` | `success` / `denied` / `error` / `replay` — rates per type |
| `denial_kind` | `policy` vs `system` — distinguishes expected denies from faults |
| `mode` | `shadow` / `enforce` / `strict` — enforcement state |
| `agent_did` | Attribution — which agent is most denied |
| `action` | Which operations are most blocked |
| `idempotency_key` | `replay` rate — indicator of retry behaviour |

---

## Supply Chain — Regenerating the Lockfiles

CI installs only hash-pinned dependencies and fails the build on any known CVE
(the `supply-chain` job runs `pip-audit` against the locks). Three lockfiles are
maintained, all generated with `uv pip compile --generate-hashes`:

| Lockfile | Scope | Regenerate with |
|----------|-------|-----------------|
| `requirements.lock` | runtime only | `uv pip compile pyproject.toml --generate-hashes -o requirements.lock` |
| `requirements-dev.lock` | runtime + dev tooling | `uv pip compile pyproject.toml --extra dev --generate-hashes -o requirements-dev.lock` |
| `requirements-all.lock` | runtime + dev + `langchain`/`mcp`/`openai` extras | `uv pip compile pyproject.toml --extra dev --extra langchain --extra mcp --extra openai --generate-hashes -o requirements-all.lock` |

The CI `test` job installs from `requirements-all.lock` with `--require-hashes`,
so the langchain/mcp/openai integration surface is as supply-chain-verified as
the core. After bumping a dependency range in `pyproject.toml`, regenerate all
three and verify:

```bash
uvx pip-audit@2.10.1 --require-hashes --requirement requirements.lock --strict
uvx pip-audit@2.10.1 --require-hashes --requirement requirements-all.lock --strict
```

Both must exit `0` before the change can merge.

## Known Operational Limits (v0.1)

These are tracked in `TODOS.md` with priority labels.

### Unbounded idempotency ledger (P1)

`ZemtikGovern._idem_ledger` is an in-memory dict. On high-volume keyed traffic,
it grows without bound — a memory-leak risk and a potential DoS vector (an
attacker streaming unique idempotency keys can exhaust process memory).

**Mitigation until fixed**: limit keyed request volume, or restart the process on
a schedule. A bounded LRU store or durable ledger plugs in here without changing
the `govern()` contract.

### Global idempotency lock (P2)

A single `asyncio.Lock` serialises all keyed `govern()` calls. On concurrent
traffic with different idempotency keys, this causes head-of-line blocking — one
slow evaluation stalls all other keyed calls.

**Mitigation**: use unkeyed `govern()` calls (no `idempotency_key`) for
high-concurrency paths where replay detection is not required.

### Decision budget not wired through config (P2)

The `timeout` parameter exists on `ZemtikGovern` but is not read from
`GovernanceConfig` or `zemtik.yaml`. Default deployments have no decision budget
(unbounded identity + policy latency).

**Mitigation**: pass `timeout=<seconds>` directly to `ZemtikGovern()`.

### `StaticIdentity` is a stub (v0.1)

`StaticIdentity` maps subjects to DIDs deterministically without any
cryptographic verification. It is a placeholder for a real Ed25519/did:web
provider. Do not rely on the identity seam for authentication in production until
a real provider is wired.
