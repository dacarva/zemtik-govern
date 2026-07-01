# ADR 002 — Langfuse major-version pin and boundary

- Status: Accepted
- Date: 2026-07-01
- Slice: Slice 1 (Langfuse boundary + `[langfuse]` extra)

## Context

`zemtik-govern` is adding an optional, OFF-by-default observability extension
that emits governance-pipeline telemetry to [Langfuse](https://langfuse.com).
The extension must never become a second load-bearing dependency the way AGT
is: telemetry fails open, governance fails closed (see
`docs/observability.md`). That asymmetry shapes how this boundary is pinned,
in contrast to ADR 001's exact AGT pins.

## Decision

Range-pin the `[langfuse]` extra rather than exact-pin it:

```
langfuse >= 4.12, < 5
```

This matches the precedent every other optional extra in this repo already
follows (`langchain`, `openai`, `mcp` are all ranges) — only the load-bearing
AGT core deps use `==`. Reproducibility still comes from the exact `==` +
hash pin recorded in `requirements-all.lock` (how every lock in this repo
works); the range in `pyproject.toml` just avoids per-patch CI churn against a
fast-moving v4 SDK.

`LangfuseBoundary` (`src/zemtik_govern/observability/_langfuse.py`) asserts
**major-version compatibility** (`major == 4`) at construction via
`importlib.metadata.version("langfuse")` — a compatibility check, not an
exact-match assertion. `src/zemtik_govern/_agt.py::assert_pins` is exact-match
by design (AGT is load-bearing); reusing that helper here would misrepresent
a range-pinned, fail-open extra as if it were exact-pinned. A future exact-pin
decision would revisit this ADR, not silently repurpose `assert_pins`.

### Why distribution metadata, not `langfuse.__version__`

Same discipline as ADR 001: `importlib.metadata.version` reads the
authoritative distribution version pip/uv resolved, independent of whatever a
module happens to report as `__version__`.

### Isolated `TracerProvider`, never the global one

`LangfuseBoundary` constructs its own `opentelemetry.sdk.trace.TracerProvider`
and passes it explicitly to the `Langfuse` client constructor
(`tracer_provider=`). Verified against the installed SDK
(`langfuse/_client/resource_manager.py::_init_tracer_provider`): the SDK only
calls `opentelemetry.trace.set_tracer_provider(...)` — mutating **global**
OTel state — when the caller did **not** supply a `tracer_provider`. Passing
our own keeps `zemtik-govern`'s telemetry wiring fully disconnected from any
other OpenTelemetry-instrumented library sharing the process.
`tests/observability/test_langfuse_boundary.py::test_boundary_constructs_without_registering_a_global_tracer_provider`
pins this fact against the real SDK.

### Masking hook wired at construction, not deferred

The boundary accepts a `mask` callable (the SDK's legacy `MaskFunction` hook —
`(*, data, **kwargs) -> Any`) and always registers one (an identity no-op by
default). Slice 2 replaces the default with the real no-echo masking
discipline; the boundary's job in this slice is only to prove the hook is
reachable and actually invoked by the SDK
(`test_boundary_mask_hook_scrubs_a_known_raw_value`), not to implement the
masking policy itself.

### `GovernanceNotConfigured` on a missing SDK, never a silent NoOp

If observability is enabled but the `langfuse` package is not installed, the
boundary raises `GovernanceNotConfigured` naming the `[langfuse]` extra to
install. This is the one Langfuse-related error that blocks at boot — it is a
packaging/deploy mistake (the operator asked for a feature and didn't install
its dependency), not a runtime telemetry fault. Contrast with Slice 3's
startup contract: enabled + extra present + missing/invalid/unreachable
creds degrades to `NoOpTracer` with a one-time warning and does **not** block
boot (invariant 5 of the observability plan) — only the missing-extra case is
a hard failure, and only here in the boundary, not scattered across config
validation.

## Consequences

- A `langfuse` major bump (v5) is a hard failure at `LangfuseBoundary`
  construction, never a silent behavioral drift — mirrors ADR 001's intent
  with a compatibility check suited to a range-pinned, non-load-bearing dep.
- CI gains a dedicated langfuse-free job
  (`test-observability-langfuse-free` in `.github/workflows/ci.yml`) that
  installs `requirements-dev.lock` (core + dev tooling only) and runs
  `tests/observability/`, proving the NoOp/fail-open contract holds without
  the extra ever being installed.
- The langfuse-carrying supply-chain audit (`requirements-all.lock`, which
  pulls in the OpenTelemetry + gRPC/protobuf stack) runs in a separate,
  `continue-on-error: true` job (`supply-chain-extras`) so a CVE in that
  ecosystem surfaces as a signal to review, not a blocked core release.
