"""Tracer implementations. Slice 0 ships only the default :class:`NoOpTracer`.

The NoOpTracer is the zero-dependency default the core holds when observability
is off. Every method returns a no-op span whose ``set``/``span``/``__enter__``/
``__exit__`` do nothing and never raise — so a governor with the default tracer
behaves byte-for-byte as it did before the seam existed.
"""

from __future__ import annotations

from typing import Any


class _NoOpSpan:
    """A span that records nothing. Reused for the root and every child so the
    no-op path allocates nothing beyond one shared instance."""

    __slots__ = ()

    def set(self, **attrs: Any) -> None:
        return None

    def span(self, name: str) -> _NoOpSpan:
        return self

    def __enter__(self) -> _NoOpSpan:
        return self

    def __exit__(self, *exc: object) -> bool:
        # Never suppress the governed block's own exceptions; never raise our own.
        return False


_NOOP_SPAN = _NoOpSpan()


class NoOpTracer:
    """The default tracer: observability off. Opens no-op spans that never raise."""

    __slots__ = ()

    def trace(self, name: str, **attrs: Any) -> _NoOpSpan:
        return _NOOP_SPAN
