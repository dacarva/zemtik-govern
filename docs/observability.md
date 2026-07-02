# Observability (optional Langfuse extension)

> **Status:** in progress. This guide is built up slice-by-slice. Today it
> documents the **Tracer seam** (Slice 0), the **Langfuse boundary** (Slice 1),
> and **core façade instrumentation + masking** (Slice 2). Config wiring,
> prompts, and evals land in later slices.

`zemtik-govern` can emit telemetry to [Langfuse](https://langfuse.com) —
self-hosted or cloud — as an **optional extension that is OFF by default**.

The **library itself is LLM-agnostic**: it governs *other* agents' tool calls and
never imports or calls a model. So its own contribution to a trace is the
**governance pipeline** — one `govern()` call becomes a Langfuse **trace** whose
seams (identity → policy → audit, plus the injection / output guards) are nested
**spans/observations**.

But a real deployment (see `sandbox/e2e_openai_governed.py`) *does* run an LLM, and
the model call is the most valuable thing to trace. So the architecture uses **two
trace producers under one root** (see "Two trace producers" below): the core `Tracer`
seam emits governance spans, while the **LLM generation** is captured at the
agent-loop layer via Langfuse's LangChain callback — both attached to a single
`agent-run` trace. The core library stays LLM-agnostic; generation tracing lives in
the integration layer (`zemtik_govern/langchain/`), so any LangChain user gets a full
`generation → tool-call → identity/policy/audit` tree.

## Design invariants

- **Governance fails closed; telemetry fails open.** No observability code path may
  raise into `govern()` or change a decision, its raised exception, its `audit_id`,
  or the mode. The tamper-evident `AuditSink` remains the audit of record; Langfuse
  is observability only.
- **Off by default, zero-cost when off.** A governor built without a tracer holds a
  `NoOpTracer` and behaves byte-for-byte as it did before the seam existed.
- **Isolated behind one boundary.** Only a single module will ever import
  `langfuse`, and only when observability is explicitly enabled. Importing
  `zemtik_govern.observability` pulls in **no** third-party dependency.

## Two trace producers, one root

When an LLM agent is in the loop, a single `agent-run` trace has two contributors:

| Producer | What it emits | Where it lives | Mechanism |
|----------|---------------|----------------|-----------|
| Core `Tracer` seam | governance spans (identity → policy → audit, injection/output) | the library (LLM-agnostic) | the `Tracer` Protocol below |
| LLM generation | model call: prompt, model, tokens, cost | the agent-loop / integration layer | Langfuse's LangChain `CallbackHandler` |

Both attach to the **same root** via OpenTelemetry context propagation: the agent
loop opens the root trace, the generation lands under it through the callback, and
each governed tool call — which runs *inside* that loop — nests its governance spans
under the same root. The result is one tree:

```
agent-run
├─ generation (gpt-…, tokens, cost)         ← LangChain callback
└─ tool-call: transfer_funds
   ├─ identity
   ├─ policy   (allowed=false, denial_kind=policy)
   └─ audit    (audit_event_id=…)            ← core Tracer seam
```

The core library never imports an LLM SDK; the generation-tracing helper is an opt-in
part of `zemtik_govern/langchain/`, consumed by `sandbox/e2e_openai_governed.py`.

## The Tracer seam (Slice 0)

The seam is a duck-typed `Protocol`, mirroring the governance seams — any object of
the right shape is a tracer, with no base class to inherit:

```python
from zemtik_govern.observability import Tracer, NoOpTracer

class Tracer(Protocol):
    def trace(self, name: str, **attrs) -> ContextManager[Span]: ...

class Span(Protocol):
    def set(self, **attrs) -> None: ...          # attach masked, safe attributes
    def span(self, name: str) -> ContextManager[Span]: ...  # nested child span
```

The default `NoOpTracer` returns spans whose `set`/`span`/`__enter__`/`__exit__`
do nothing and never raise.

A tracer can be wired either directly or through the registry:

```python
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.registry import GovernanceRegistry
from zemtik_govern.observability import NoOpTracer

# Direct — keyword-only, defaults to NoOpTracer:
gov = ZemtikGovern(identity=..., policy=..., audit=..., tracer=NoOpTracer())

# Or via the registry builder:
gov = (
    GovernanceRegistry()
    .register_identity(...)
    .register_policy(...)
    .register_audit(...)
    .register_tracer(NoOpTracer())
    .build()
)

gov.tracer  # read-only accessor for the wired tracer
```

See `tests/observability/` for the seam contract and the zero-behavior-change
guarantees.

## The Langfuse boundary (Slice 1)

Mirroring `_agt.py`, exactly one module — `observability/_langfuse.py` — is
allowed to import `langfuse`. `LangfuseBoundary` is the one object that owns
the SDK:

```python
from zemtik_govern.observability._langfuse import LangfuseBoundary

boundary = LangfuseBoundary(
    public_key="pk-...",
    secret_key="sk-...",
    host="https://cloud.langfuse.com",  # or your self-hosted URL
)
boundary.client  # the underlying langfuse.Langfuse instance
```

- **Major-version gate, not exact-pin.** The `[langfuse]` extra is range-pinned
  (`langfuse>=4.12,<5`) like every other optional extra in this repo; the
  boundary asserts `major == 4` at construction and raises
  `LangfuseVersionError` on drift. See
  [ADR 002](adr/002-langfuse-pin.md) for why this differs from the AGT
  boundary's exact pin.
- **Missing SDK is a boot error.** If observability is enabled but `langfuse`
  isn't installed, construction raises `GovernanceNotConfigured` naming the
  `[langfuse]` extra — a packaging mistake, caught at startup.
- **Isolated `TracerProvider`.** The boundary builds its own
  `TracerProvider` and passes it to the `Langfuse` client explicitly, so
  enabling telemetry never mutates process-global OpenTelemetry state.
- **A masking hook is always registered** (identity by default). Slice 2 wires
  the real no-echo masking discipline through it.

Install the extra to use it:

```bash
pip install 'zemtik-govern[langfuse]'
```

To check the boundary against a real self-hosted or cloud backend (auth,
a flushed trace, and the mask hook actually running), see
[`sandbox/langfuse_boundary_smoke.py`](../sandbox/langfuse_boundary_smoke.py)
in [Sandbox & Demos](sandbox.md#langfuse_boundary_smokepy--langfuse-boundary-connectivity-check).

The `[langfuse]` extra is not yet wired into `GovernanceConfig` or
`GovernanceRegistry` — that lands in Slice 3, alongside the startup contract
for missing/invalid credentials (degrade to `NoOpTracer` + a one-time
warning, never block boot).

## Core façade instrumentation (Slice 2)

`ZemtikGovern` now emits masked spans through whatever `Tracer` it holds — a
`NoOpTracer` by default (no behavior change at all), a `LangfuseTracer` when
observability is wired. One `govern()` call produces this tree:

```
govern                              ← root, opened by govern()/proxy()
├─ identity
└─ policy   (allowed=…, denial_kind=…, rule=…, audit_event_id=…)
```

A `proxy()` call additionally screens the tool's return value, nested as a
sibling under the SAME root:

```
govern
├─ identity
├─ policy
└─ output   (event=…, rail=…)
```

### Where spans come from

- **The root (`"govern"`) is opened by the caller** — `govern()` for a direct
  call, `_GovernedProxy` for a `proxy()` call — not by the internal pipeline
  method itself. This is why a `proxy()` call's `output` span lands as a
  sibling of `identity`/`policy` under one root: the root has to stay open
  across both the governance decision *and* the later output screen, which
  happen in two separate calls.
- **`identity` and `policy`** are two separate sibling spans opened inside the
  identity→policy sequence, each a direct child of whatever's currently open.
  Span open/close sits **outside** the decision-budget race (`_with_budget`) —
  a slow tracer can never trip `DecisionBudgetExceeded`.
- **`output`** only appears for `proxy()` calls (bare `govern()`/`govern_sync()`
  never screen output) and is annotated at the single chokepoint every output
  branch (allow / read-deny / write-redact / rail-fault / shadow would-deny)
  already funnels through.
- **Replay** (`idempotency_key`, cached decision): exactly ONE root span,
  annotated `replayed=true`, with **no** `identity`/`policy` children — that
  code path never re-runs governance, so no child span is ever opened.
- **A fingerprint failure or an idempotency-key conflict** still gets a root
  span (annotated `event="idempotency_fingerprint_error"` /
  `event="idempotency_conflict"`) even though neither path reaches the
  identity/policy sequence — security-relevant outcomes are traced even when
  they short-circuit before evaluation.

### Fail-open, defense-in-depth

Two independent layers, so governance is safe regardless of which `Tracer` is
installed — even a maximally hostile one:

1. **The core guard** (`core.py::_traced`/`_span_set`) — the ONLY place
   `core.py` ever calls a tracer/span method. Every open (`.trace()`/`.span()`/
   `__enter__`), attribute assembly, and close (`__exit__`) is individually
   wrapped so no exception from any of them — nor from the masking function
   itself — ever reaches `govern()`. The governed body's own exceptions
   (`GovernanceDenied`, `DecisionBudgetExceeded`, an identity/policy fault)
   propagate through completely unmodified; the guard only *observes* them to
   tell a healthy span how the block ended.
2. **The façade guard** (`LangfuseTracer`'s own `_safe` wrapping) — a second,
   independent layer so a real SDK error is cheap and contained even before it
   would reach layer 1.

`tests/observability/test_core_tracing_failopen.py` proves this against
injected hostile fakes (exploding `.trace()`/`__enter__`/`__exit__`/masking, a
slow tracer racing the decision budget) — decisions, raised exceptions,
`audit_id`, and mode are byte-identical to the `NoOpTracer` baseline in every
case, entirely without the `[langfuse]` extra installed.

### Masking (`observability/masking.py`)

The first span ever emitted is already masked — never a later layer. Every
attribute comes from one of three pure functions, and none of them ever see
`ctx.payload` or a tool's raw output:

- `safe_trace_attrs_root(ctx, *, mode)` → `action`, `mode`.
- `safe_trace_attrs_decision(decision, *, emit_rule_names=True)` → `action`,
  `allowed`, `denial_kind`, the matched rule's *name* (or an opaque id),
  `audit_event_id`, plus an injection annotation (below).
- `safe_trace_attrs_output(*, event, rail, severity=None)` → the output rail's
  *name* and outcome, never the screened value.

**Injection annotation, no new hook.** The prompt-injection guard is folded
into the policy engine (`GuardedEngine`, in `injection.py`) rather than being
a separate seam `core.py` can instrument directly. An enforce-mode hit already
produces an already-safe, fixed-shape deny reason (field *name* + AGT's
type/threat labels, never payload); `safe_trace_attrs_decision` regex-parses
that exact shape into `injection` / `injection.type` / `injection.threat` /
`injection.field` attributes on the `policy` span. **Caveat:** `GuardedEngine`'s
**shadow-mode** would-deny does not produce this Decision shape at all (it
logs and delegates to the inner engine) — a shadow-mode injection hit has no
span annotation today, only the existing log line.

See `tests/observability/test_core_tracing.py` for the masking / no-echo /
injection-annotation assertions, and `tests/observability/_fakes.py` for the
recording and hostile fake tracers the test suite drives.

## Tracing an LLM agent (LangChain) — Slice 2b

`zemtik_govern.langchain.langfuse_callback(boundary)` builds Langfuse's native
LangChain `CallbackHandler`, bound to an already-constructed `LangfuseBoundary`.
Add it to a run's `callbacks` alongside a `Tracer`-instrumented `ZemtikGovern`
(built with a `LangfuseTracer` over the *same* boundary) and the model call and
every governed tool call inside that run land under one shared trace:

```python
from zemtik_govern.observability._langfuse import LangfuseBoundary
from zemtik_govern.observability.tracer import LangfuseTracer
from zemtik_govern.langchain import langfuse_callback, govern_tool

boundary = LangfuseBoundary(public_key=..., secret_key=..., host=...)
gov = GovernanceRegistry.from_config(config, agt).register_tracer(
    LangfuseTracer(boundary)
).build()
handler = langfuse_callback(boundary)

governed_tool = govern_tool(my_tool, govern=gov)

# Pass `handler` (and propagate the same `config`) through the whole run —
# LangChain forwards `callbacks`/parent-run-id automatically to nested
# `.invoke()` calls made with that config, which is what keeps the OTel
# context (and therefore the trace id) shared:
model.invoke(messages, config={"callbacks": [handler]})
governed_tool.invoke(args, config={"callbacks": [handler]})
```

```
agent-run
├─ <model-name>  (langfuse.observation.type=generation, model + token usage)   ← LangChain callback
└─ govern
   ├─ identity
   └─ policy   (allowed=…, denial_kind=…, audit_event_id=…)                    ← core Tracer seam
```

**Ownership boundary:** the core library never imports an LLM SDK or
`langchain`/`langfuse.langchain` — `langfuse_callback` lives under the optional
`langchain` extra, and the only module that imports `langfuse` anywhere is
still `observability/_langfuse.py` (`LangfuseBoundary.langchain_callback_handler()`
is the sanctioned lazy-import point; `langfuse_callback` just calls it,
duck-typed, the same discipline `LangfuseTracer` already follows).

**Fail-open.** If the boundary can't build a real callback handler — the SDK
extras are missing, the client is misconfigured, construction raises for any
reason — `langfuse_callback` degrades to an inert `BaseCallbackHandler`
subclass (every hook a no-op) instead of raising. A broken observability
integration never changes a governed tool call's decision or result.

**Note on the `langchain` extra:** `langfuse.langchain.CallbackHandler`
unconditionally does `import langchain` (not just `langchain_core`) to check
the installed major version. The `langchain` extra therefore pins the full
`langchain` package (`langchain>=1.0.0,<2.0.0`) alongside `langchain-core` and
`langgraph`.

See `tests/langchain/test_langfuse_callback.py` for the generation-span,
shared-trace-id, and fail-open assertions (all `importorskip`-guarded for
`langfuse` + `langchain`).
