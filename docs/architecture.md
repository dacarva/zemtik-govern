# Architecture — zemtik-govern

## Purpose

zemtik-govern is a governance layer that sits in front of every tool an agent is
allowed to call. Its job is to ensure that **no tool invocation goes unidentified,
unevaluated, or unrecorded**. The core invariant: every outcome (allow, deny, or
system error) is audited before the caller sees a result.

## The Three-Seam Design

Three seams run in a fixed order on every call:

```
Caller
  │
  ▼
ZemtikGovern.govern(ctx)
  │
  ├─► [1] IdentityProvider.identify(subject) ──► AgentRef (DID)
  │         StaticIdentity → AGTBoundary.mint_did()
  │
  ├─► [2] PolicyEngine.evaluate(ctx) ──────────► Decision
  │         AgentOsPolicy → AGTBoundary._policy_evaluator()
  │              └─ MOAT: no-match → deny (not AGT's default allow)
  │
  └─► [3] AuditSink.write(entry) ──────────────► entry_id
            AgentMeshAudit → AGTBoundary.audit_log()
                 └─ on failure: emit_fallback() then GovernanceError
```

### Why the order is fixed

- **Identity first**: the DID is policy's attribution key and audit's stamp field.
  Computing policy before identity would leave the audit entry unattributed.
- **Policy second**: the decision being audited must come from the seam that
  governs — not from a cached or replayed value — so audit records the actual verdict.
- **Audit last**: every audit entry stamps the final policy decision, including
  decisions made during idempotency replay or conflict detection.

### Seam contracts

All three seams are `typing.Protocol` (duck-typed). No base class is required; any
object with the right `async def` shape satisfies the seam. v0.1 ships:

| Seam | v0.1 implementation | Pluggable replacement |
|------|---------------------|-----------------------|
| `IdentityProvider` | `StaticIdentity` | Ed25519/did:web provider |
| `PolicyEngine` | `AgentOsPolicy` | Any deny-by-default evaluator |
| `AuditSink` | `AgentMeshAudit` | Any durable, tamper-evident sink |

## Fail-Closed Guarantee

Any exception raised during identity **or** policy is:

1. Caught in `_evaluate_and_audit`
2. Wrapped as a system `Decision` (`denial_kind="system"`)
3. Written to the audit sink (stamped with `did:mesh:unidentified` if identity failed)
4. Re-raised as `GovernanceError`

The wrapped tool **never runs** on a governance fault. There is no fall-through,
no `NullGovernanceProvider`, no silent skip.

If the audit sink itself fails during a primary write, `emit_fallback` records a
redacted, metadata-only entry to a file + stderr, then `GovernanceError` is raised.
The tool is still blocked even when the primary sink is down.

## The Deny-by-Default Moat

AGT's native `PolicyEvaluator` **allows** when no rule matches
(`matched_rule is None` → `allowed=True`). This is AGT's documented default.

`AgentOsPolicy.evaluate` (`policy.py`) overrides this: when `matched_rule is None`,
it returns a `policy` denial instead of delegating to AGT's verdict. This is the
deny-by-default moat — any action not explicitly permitted is denied, regardless
of what AGT would do.

`tests/test_agt_conformance.py` pins AGT's fail-open behaviour in CI so a future
AGT upgrade that silently fixes this cannot erode the moat undetected.

## The AGT Boundary

`_agt.py` is the only module in `src/` that imports `agent_os` or `agentmesh`.
`AGTBoundary`:

1. Asserts pinned distribution versions via `importlib.metadata` at construction
   (not `module.__version__`, which lags the packaging version).
2. Exposes private `_policy_document` / `_policy_evaluator` only to `AgentOsPolicy`
   and the conformance tests — not to the rest of the codebase.
3. Exposes `audit_log`, `file_audit_sink`, and `mint_did` for the audit and
   identity seams.

Any AGT version mismatch raises `AGTVersionError` at startup, before any request
is processed.

## GovernanceContext Immutability

`GovernanceContext` deep-freezes its `payload` and `extra` fields on construction:

- dicts → `MappingProxyType` (read-only at top level)
- lists/tuples → `tuple`
- sets → `frozenset`
- recursively at every nesting depth

This closes a TOCTOU window: a mutable payload could be modified between the
`policy.evaluate(ctx)` call and the `audit.write(entry)` call. With deep-freezing,
the bytes policy evaluates are provably the bytes audit records.

`to_dict()` thaws the context back to plain Python for AGT calls (which use
`json.dumps` internally and reject `MappingProxyType`).

**Constraint**: `frozenset` of unhashable values (e.g. dicts) will raise `TypeError`
at context construction. Payloads must contain only JSON-serializable, hashable leaf
values if they contain sets.

## Idempotency

### Decision-level idempotency (`govern()`)

When `ctx.idempotency_key` is set:

1. A fingerprint is computed: `SHA256(action + subject + sorted_json(payload))`.
   `ts` and `extra` are excluded — a retried request keeps its identity even if the
   clock moves.
2. The fingerprint is checked against the in-memory `_idem_ledger` under a global
   `asyncio.Lock` so concurrent submissions with the same key are serialised.

| State | What happens |
|-------|-------------|
| Key not seen before | Evaluate fully, cache `(fingerprint, did, decision)` |
| Same key, same fingerprint | Replay: return cached decision flagged `replayed=True` |
| Same key, different fingerprint | Conflict: audit as `error`, raise `GovernanceError` |

A conflict means the caller is reusing an idempotency key for a different request —
a potential bypass attempt. The tool never runs and the original decision is never
replayed onto the new action.

### Effect-level idempotency (`proxy()`)

The `_GovernedProxy` also dedupes the **side effect** (the tool call itself), not
just the governance decision:

- First call: govern + invoke, cache the `asyncio.Future` result.
- Duplicate (sequential or concurrent): govern (audits the replay), return the
  cached result without re-invoking the tool.
- A denial or tool exception evicts the slot so a retry re-runs.

Direct `govern()` callers must gate their own side effects on
`decision.allowed and not decision.replayed`.

### Known limits (v0.1)

- `_idem_ledger` is unbounded in-memory — a P1 memory-leak risk on high-volume
  keyed traffic (see `TODOS.md`).
- A single global `asyncio.Lock` serialises ALL keyed calls — a P2 head-of-line
  blocking concern; per-key locking is the fix.

## Operational Modes

| Mode | Denials enforced | Policy source required | Audit required |
|------|-----------------|------------------------|----------------|
| `strict` | Yes | Yes | Yes |
| `enforce` | Yes | Yes | Yes |
| `shadow` | No | No | Yes |

Shadow mode records denials but does not raise `GovernanceDenied` — the guarded
tool still runs. Use it to surface false-denies on live traffic before switching
to `enforce`. Shadow still requires an audit sink; observing into nowhere is not
observing.

## Kill-Switch

`Killswitch` is a zero-arg callable that returns `True` when engaged.
`ZemtikGovern._select_engine()` routes to `_fallback` instead of `_policy` when
the switch is engaged. Engaging with no `fallback` wired raises `GovernanceError`
(audited denial) — there is no allow-all bypass.

## Decision Budget

An optional `timeout` (seconds) wraps identity + policy in `asyncio.wait_for`.
A timeout is a system fault: audited as a denial, `GovernanceError` raised, tool
blocked. In v0.1 the budget is not threaded through `GovernanceConfig` — it must
be passed to `ZemtikGovern` directly (see `TODOS.md` P2).

Note: `asyncio.wait_for` cancels the coroutine on timeout. An engine that catches
`CancelledError` and returns a value anyway would produce a result after the budget
has been declared breached. This is a known limitation; a guard is tracked in
`TODOS.md`.

## Startup Validation

Two fail-at-startup contracts prevent a misconfigured wrapper from silently
accepting requests:

1. **`GovernanceConfig.__post_init__`** raises `GovernanceNotConfigured` if:
   - The mode is not one of `{strict, shadow, enforce}`.
   - No audit sink is configured (all modes require one).
   - An enforcing mode has no policy source (rules or non-empty `policy_dir`).

2. **`GovernanceRegistry.build()`** raises `GovernanceNotConfigured` if any seam
   is not registered.

Both checks run at startup, never at request time.
