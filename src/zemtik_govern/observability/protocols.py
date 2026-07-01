"""The observability seam — the Tracer the core drives, and the Span it hands back.

Duck-typed like the three governance seams (identity / policy / audit): a
:class:`typing.Protocol`, so any object of the right shape is a tracer — the
default :class:`~zemtik_govern.observability.tracer.NoOpTracer` today, a
Langfuse-backed tracer later, with no base class to inherit.

The contract is deliberately tiny and **synchronous**: opening/closing a span is
a cheap call, while the governed ``await`` work happens inside the ``with`` block.
Keeping the tracer sync means it is not another async seam and ``govern_sync``
keeps working unchanged.

Fail-open is the seam's defining property: no tracer method — and no span
``__enter__``/``__exit__`` — may raise into the governed path. The core guards
every call site as well (defense in depth), but a conforming tracer never leaks.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Span(Protocol):
    """A single observation in a trace. Records safe attributes and opens nested
    child spans. Every method is a no-op-safe call that must never raise."""

    def set(self, **attrs: Any) -> None:
        """Attach masked, safe attributes to this span (never raw payload)."""
        ...

    def span(self, name: str) -> AbstractContextManager[Span]:
        """Open a nested child span as a context manager.

        Callers MUST use ``with span.span(name) as child: ...`` — the return is a
        context manager to be entered, never an already-live span. (``NoOpTracer``
        happens to return an entered singleton, so the two are interchangeable
        today, but a real ``LangfuseTracer`` returns a fresh, non-entered CM; the
        core-level ``_traced`` guard relies on the ``with`` contract.)
        """
        ...

    def __enter__(self) -> Span: ...

    def __exit__(self, *exc: object) -> bool: ...


@runtime_checkable
class Tracer(Protocol):
    """Opens the root observation for one governed call. The default
    implementation does nothing; a Langfuse tracer emits spans/observations."""

    def trace(self, name: str, **attrs: Any) -> AbstractContextManager[Span]:
        """Open the root trace/observation for a governed call."""
        ...
