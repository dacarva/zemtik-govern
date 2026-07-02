"""Slice 2 — LangfuseTracer conformance: a few `importorskip`-guarded tests
against the real SDK, wiring a real `LangfuseBoundary`. Deliberately NOT where
the fail-open matrix runs (that's `tests/observability/test_core_tracing_failopen.py`,
against fakes, langfuse-free) — this file only proves the façade actually opens
and nests real observations and stays fail-open on a broken boundary/client.
"""

from __future__ import annotations

import pytest

from zemtik_govern.observability.tracer import LangfuseTracer


def test_langfuse_tracer_opens_a_real_root_and_nested_span():
    pytest.importorskip("langfuse")
    from zemtik_govern.observability._langfuse import LangfuseBoundary

    boundary = LangfuseBoundary(
        public_key="pk-tracer-test",
        secret_key="sk",
        host="http://localhost:3000",
    )
    tracer = LangfuseTracer(boundary)
    with tracer.trace("root") as root:
        root.set(action="tool.run")
        with root.span("child") as child:
            child.set(allowed=True)


def test_langfuse_tracer_is_fail_open_on_a_broken_boundary():
    """A boundary whose client blows up on open never raises into the caller —
    the façade's own _safe wrapping (defense-in-depth layer 2b)."""

    class _ExplodingClient:
        def start_as_current_observation(self, **kwargs):
            raise RuntimeError("boom: sdk exploded")

    class _FakeBoundary:
        client = _ExplodingClient()

    tracer = LangfuseTracer(_FakeBoundary())
    with tracer.trace("root") as root:
        root.set(action="tool.run")  # must not raise even though open "failed"
        with root.span("child") as child:
            child.set(allowed=True)
