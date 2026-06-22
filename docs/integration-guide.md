# Integration Guide — zemtik-govern

## Prerequisites

- Python 3.11+
- `agent-os-kernel==3.7.0` and `agentmesh-platform==3.7.0` installed exactly
  (zemtik-govern asserts these at startup)

## Installation

```bash
uv venv .venv --python 3.11
source .venv/bin/activate
uv pip install -e ".[dev]"     # dev extras include pytest, ruff
```

## Quickstart

### 1. Write a config file

```bash
cp zemtik.example.yaml zemtik.yaml
# edit zemtik.yaml
```

Minimum viable config (strict mode, in-memory audit):

```yaml
mode: strict
audit_sink: memory
rules:
  - name: allow-tool-run
    condition:
      field: action
      operator: eq
      value: tool.run
    action: allow
```

### 2. Set the audit secret (for durable audit)

```bash
export ZEMTIK_AUDIT_SECRET='your-hmac-key'
# only needed when audit_sink is a file path
```

### 3. Build the governed stack

```python
from zemtik_govern import AGTBoundary, GovernanceConfig, GovernanceRegistry

config = GovernanceConfig.load("zemtik.yaml")
boundary = AGTBoundary()                               # asserts AGT pins
gov = GovernanceRegistry.from_config(config, boundary).build()
```

`GovernanceRegistry.from_config` wires the v0.1 stack:
- `StaticIdentity` (identity seam)
- `AgentOsPolicy` with deny-by-default (policy seam)
- `AgentMeshAudit` Merkle-chained (audit seam); durable + HMAC-signed if
  `audit_sink` is a file path

---

## Usage Patterns

### Async path (voice / streaming)

```python
from zemtik_govern import GovernanceContext, GovernanceDenied, GovernanceError

ctx = GovernanceContext(
    action="tool.run",
    subject="agent-42",
    payload={"tool": "search", "query": "climate data"},
)

try:
    decision = await gov.govern(ctx)
except GovernanceDenied as exc:
    # policy said no; tool never ran
    print("denied:", exc.decision.reason)
    return
except GovernanceError:
    # system fault; tool was blocked; investigate audit trail
    raise

# tool is now allowed — call it
result = run_search(ctx.payload)
```

### Sync path (fintech write)

```python
decision = gov.govern_sync(ctx)     # runs asyncio.run() internally
```

`govern_sync` raises `GovernanceError` if called inside a running event loop.
From async callers, always `await gov.govern(ctx)`.

### Checking `replayed` (prevent double-write)

When using idempotency keys with `govern()` / `govern_sync()` directly, gate side
effects on `decision.replayed`:

```python
ctx = GovernanceContext(
    action="payment.send",
    subject="agent-7",
    payload={"amount": 100, "to": "acct-B"},
    idempotency_key="txn-abc123",
)

decision = await gov.govern(ctx)
if decision.allowed and not decision.replayed:
    send_payment(...)   # guard prevents double-send on retry
```

On a retry with the same `idempotency_key` and identical
`action`/`subject`/`payload`, `govern()` returns the cached `Decision` with
`replayed=True` — no re-evaluation, no double-send.

### Proxy pattern (preferred for tools)

The proxy closes the ungoverned-call gap: callers receive the proxy, never the raw
callable.

```python
governed_search = gov.proxy(
    search_fn,
    action="tool.search",
    subject="agent-42",
)

result = await governed_search(query="climate data")
```

The proxy:
- Raises `GovernanceDenied` / `GovernanceError` before invoking `search_fn`.
- Handles effect-idempotency automatically — callers do not need to check
  `Decision.replayed`.
- Works with both sync and async wrapped callables.

### Dynamic action/subject (context factory)

```python
def make_ctx(*args, **kwargs):
    return GovernanceContext(
        action=f"tool.{kwargs['tool_name']}",
        subject=kwargs['agent_id'],
        payload=kwargs,
        idempotency_key=kwargs.get('request_id'),
    )

governed_tool = gov.proxy(
    run_tool,
    action="",          # overridden by factory
    subject="",         # overridden by factory
    context_factory=make_ctx,
)

result = await governed_tool(tool_name="search", agent_id="agent-7", request_id="req-1")
```

The `context_factory` receives the same `*args, **kwargs` as the proxy call and
must return a `GovernanceContext`. If it returns the wrong type, `GovernanceError`
is raised and the tool never runs.

### Shadow mode (safe rollout)

```yaml
# zemtik.yaml
mode: shadow
audit_sink: memory
```

In shadow mode, all denials are **recorded but not enforced** — the tool still
runs. Use this to surface false-denies on live traffic before switching to
`enforce`. Shadow mode still requires an `audit_sink`.

### Kill-switch (operational revert)

```python
from zemtik_govern import Killswitch, ZemtikGovern

ks = Killswitch()
gov = ZemtikGovern(
    identity=...,
    policy=new_policy,
    audit=...,
    fallback=old_policy,   # prior governed path — never allow-all
    killswitch=ks,
)

# To revert to the prior policy:
ks.engage()

# To restore the new policy:
ks.disengage()
```

Engaging the kill-switch with no `fallback` wired raises `GovernanceError` — there
is no allow-all bypass.

### Decision budget (latency-sensitive paths)

```python
gov = ZemtikGovern(
    identity=...,
    policy=...,
    audit=...,
    timeout=0.05,   # 50 ms budget for identity + policy combined
)
```

A timeout is treated as a system fault: audited as a denial, `GovernanceError`
raised, tool blocked.

---

## Implementing Custom Seams

Any object with the right `async def` shape satisfies the Protocol — no base class
required.

### Custom `PolicyEngine`

```python
class MyPolicy:
    async def evaluate(self, ctx: GovernanceContext) -> Decision:
        if ctx.action in self._allowed:
            return Decision(
                allowed=True,
                action="allow",
                matched_rule="custom-allow",
                reason="explicitly allowed",
            )
        # MUST deny on no-match — never pass through to an allow
        return Decision(
            allowed=False,
            action="deny",
            matched_rule=None,
            reason="deny-by-default",
            denial_kind="policy",
        )
```

### Custom `AuditSink`

```python
class MyAudit:
    async def write(self, entry: AuditEntry) -> str:
        # Must return a stable entry ID
        entry_id = str(uuid.uuid4())
        my_store.append(entry_id, entry)
        return entry_id
```

### Custom `IdentityProvider`

```python
class MyIdentity:
    async def identify(self, subject: str) -> AgentRef:
        did = await resolve_did_web(subject)
        return AgentRef(did=did)
```

### Swapping the injection classifier

The injection screen is a pluggable seam: `InjectionClassifier` is a Protocol, and
the shipped `AgtInjectionClassifier` is just the default. To run your own detector
(a hosted model, a regex pack, a different vendor), implement `screen` and pass the
instance to `ZemtikGovern(injection_classifier=…)` — it wraps the SELECTED engine,
so your classifier guards the primary policy AND the killswitch fallback alike.

```python
from zemtik_govern.injection import InjectionVerdict
from zemtik_govern.context import GovernanceContext


class MyClassifier:
    """Any object with this async `screen` satisfies InjectionClassifier."""

    async def screen(self, ctx: GovernanceContext) -> InjectionVerdict:
        for field, value in ctx.payload.items():
            if await my_detector.is_injection(value):
                # D6 no-echo: name the FIELD, never the raw payload text.
                return InjectionVerdict(
                    is_injection=True,
                    field=str(field),
                    injection_type="custom",
                    threat_level="high",
                )
        return InjectionVerdict(is_injection=False, reason="clean")


gov = ZemtikGovern(
    identity=my_identity,
    policy=my_policy,
    audit=my_audit,
    injection_classifier=MyClassifier(),   # swapped in
    # injection_mode="shadow",  # optional: observe would-denies before enforcing
)
```

On construction the governor logs one line naming the active guards (logger
`zemtik_govern`, INFO) — look for `injection detection: ON (AGT, enforce)` (or your
classifier) to confirm the swap took. The `injection_confidence_floor` config dial
is **off by default** (`0.0`) and reserved; see the configuration reference.

---

## Error Handling Reference

Every governance exception subclasses `GovernanceError` and carries a stable
`.code` (branch on it, never on the message) and an `.audit_id` that matches the
written audit row (and `Decision.audit_id` on an allowed result).

| Exception | `.code` | Meaning | Tool ran? |
|-----------|---------|---------|-----------|
| `GovernanceDenied` | `policy_denied` / `system_denied` | Policy (or fail-closed system) deny. `.decision` has the reason; `.guard` mirrors `denial_kind`. | No |
| `DecisionBudgetExceeded` | `decision_budget_exceeded` | Identity+policy did not resolve in time. `.limit_seconds` / `.elapsed_seconds`; `.guard == "budget"`. | No |
| `GovernanceError` | `idempotency_conflict`, `idempotency_fingerprint_error`, `engine_error`, `governance_error` | System fault in a seam (idempotency key reuse, unserialisable payload, engine failure). | No |
| `GovernanceNotConfigured` | `not_configured` | Bad startup config or missing seam. Fix before retry. | No |
| `AGTVersionError` | — | AGT pin mismatch. Fix environment before retry. | No |

```python
try:
    decision = await gov.govern(ctx)
except GovernanceError as e:
    if e.code == "decision_budget_exceeded":
        metrics.budget_breach(e.limit_seconds, e.elapsed_seconds)
    log.warning("blocked", code=e.code, guard=e.guard, audit_id=e.audit_id)
    raise
```

All governance exceptions mean the tool **did not run**.

---

## Integration Checklist

- [ ] AGT pins installed at exact versions (`agent-os-kernel==3.7.0`, `agentmesh-platform==3.7.0`)
- [ ] All modes need `audit_sink`; enforcing modes (`strict`, `enforce`) need policy rules
- [ ] `ZEMTIK_AUDIT_SECRET` set when `audit_sink` is a file path
- [ ] Direct `govern()` callers gate side effects on `allowed and not replayed`
- [ ] `proxy()` callers get effect-idempotency automatically — no extra guard needed
- [ ] `context_factory` functions return `GovernanceContext`, never a plain dict
