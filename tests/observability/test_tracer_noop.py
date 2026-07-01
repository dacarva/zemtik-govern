"""Slice 0 — the Tracer seam and its default NoOpTracer.

The Tracer is the observability seam: a duck-typed Protocol (like identity /
policy / audit) whose default implementation does nothing and — critically —
can never raise into the governed path. These tests pin that contract at the
public seam: a NoOpTracer opens a trace, opens nested spans, and accepts
attribute sets, all as no-ops that return without error.
"""

from __future__ import annotations

from zemtik_govern.observability import NoOpTracer, Tracer


def test_noop_tracer_satisfies_the_tracer_protocol() -> None:
    # The default tracer is a structural Tracer — no base class to inherit.
    assert isinstance(NoOpTracer(), Tracer)


def test_noop_trace_is_a_context_manager_yielding_a_span() -> None:
    tracer = NoOpTracer()
    with tracer.trace("govern") as span:
        # The yielded span is truthy and usable; entering never raises.
        assert span is not None


def test_noop_span_set_and_nested_span_are_no_ops_that_never_raise() -> None:
    tracer = NoOpTracer()
    with tracer.trace("govern") as root:
        # Setting attributes is a no-op and returns None.
        assert root.set(action="read", allowed=True) is None
        # A nested span is itself a no-op context manager.
        with root.span("identity") as child:
            assert child.set(did="did:mesh:alice") is None


def test_noop_span_exit_swallows_and_never_propagates() -> None:
    # __exit__ must return False-y "don't suppress" for the governed block's own
    # exceptions, but the span's own machinery must never itself raise. Here we
    # confirm a clean enter/exit cycle completes without error.
    tracer = NoOpTracer()
    cm = tracer.trace("govern")
    span = cm.__enter__()
    assert span is not None
    # Exiting with no active exception returns without raising.
    cm.__exit__(None, None, None)
