# Observability (optional Langfuse extension)

> **Status:** in progress. This guide is built up slice-by-slice. Today it
> documents the **Tracer seam** (Slice 0) and the **Langfuse boundary** (Slice 1).
> Core façade instrumentation, config wiring, masking, prompts, and evals land
> in later slices.

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
warning, never block boot). Core façade instrumentation (the actual
identity/policy/audit/output spans) lands in Slice 2.
