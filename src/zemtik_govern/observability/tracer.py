"""Tracer implementations. Slice 0 shipped the default :class:`NoOpTracer`;
Slice 2 adds :class:`LangfuseTracer`, the façade wrapping a
:class:`~zemtik_govern.observability._langfuse.LangfuseBoundary`.

The NoOpTracer is the zero-dependency default the core holds when observability
is off. Every method returns a no-op span whose ``set``/``span``/``__enter__``/
``__exit__`` do nothing and never raise — so a governor with the default tracer
behaves byte-for-byte as it did before the seam existed.

``LangfuseTracer`` never imports ``langfuse`` itself — it is handed an already-
constructed boundary and only calls attributes/methods on it, duck-typed, so
this module stays outside the single-import-boundary rule (``_langfuse.py`` is
still the only module that ever imports the SDK). Every method here is wrapped
in ``_safe`` — defense-in-depth (invariant 2b): the core's own ``_traced``/
``_span_set`` guard (invariant 2a, in ``core.py``) is what actually protects
``govern()`` regardless of what this façade does; this layer just keeps SDK
errors from being expensive or noisy.
"""

from __future__ import annotations

import logging
from typing import Any

_LOG = logging.getLogger("zemtik_govern.observability")


def _safe(fn: Any, *, default: Any) -> Any:
    try:
        return fn()
    except Exception:
        _LOG.debug("Langfuse façade call failed; falling back to no-op", exc_info=True)
        return default


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


class _LangfuseSpanAdapter:
    """Adapts a real langfuse observation object (``update``/
    ``start_as_current_observation``) to this package's ``Span`` protocol
    (``set``/``span``)."""

    def __init__(self, real_span: Any) -> None:
        self._real = real_span

    def set(self, **attrs: Any) -> None:
        _safe(lambda: self._real.update(metadata=attrs), default=None)

    def span(self, name: str) -> _LangfuseSpanCM:
        real_cm = _safe(
            lambda: self._real.start_as_current_observation(name=name, as_type="span"),
            default=None,
        )
        return _LangfuseSpanCM(real_cm)

    def __enter__(self) -> _LangfuseSpanAdapter:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class _LangfuseSpanCM:
    """Wraps a real langfuse observation context manager (or ``None`` when
    opening it already failed) so ``__enter__``/``__exit__`` never raise —
    falling back to the shared ``_NOOP_SPAN`` sentinel on any SDK failure.
    Defense-in-depth alongside ``core.py``'s own ``_traced`` guard, which is
    what actually protects ``govern()`` regardless of this class."""

    def __init__(self, real_cm: Any) -> None:
        self._real_cm = real_cm

    def __enter__(self) -> Any:
        if self._real_cm is None:
            return _NOOP_SPAN
        real_span = _safe(lambda: self._real_cm.__enter__(), default=None)
        if real_span is None:
            return _NOOP_SPAN
        return _LangfuseSpanAdapter(real_span)

    def __exit__(self, *exc: object) -> bool:
        if self._real_cm is not None:
            _safe(lambda: self._real_cm.__exit__(*exc), default=False)
        return False


class LangfuseTracer:
    """The observability-on ``Tracer``: opens real Langfuse observations via a
    :class:`~zemtik_govern.observability._langfuse.LangfuseBoundary`.

    Takes an already-constructed boundary (this module never imports
    ``langfuse`` itself) and only calls ``boundary.client``'s public SDK
    surface, duck-typed."""

    def __init__(self, boundary: Any) -> None:
        self._boundary = boundary

    def trace(self, name: str, **attrs: Any) -> _LangfuseSpanCM:
        real_cm = _safe(
            lambda: self._boundary.client.start_as_current_observation(name=name, as_type="span"),
            default=None,
        )
        return _LangfuseSpanCM(real_cm)
