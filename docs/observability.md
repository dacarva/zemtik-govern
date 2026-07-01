# Observability (optional Langfuse extension)

> **Status:** in progress. This guide is built up slice-by-slice. Today it
> documents the **Tracer seam** (Slice 0). Tracing, config, masking, prompts, and
> evals land in later slices.

`zemtik-govern` can emit governance-pipeline telemetry to
[Langfuse](https://langfuse.com) — self-hosted or cloud — as an **optional
extension that is OFF by default**. It is not an LLM application (the wrapper
governs *other* agents' tool calls and never calls a model), so "tracing" here
means turning one `govern()` call into a Langfuse **trace** whose seams
(identity → policy → audit, plus the injection / output guards) are nested
**spans/observations**.

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
