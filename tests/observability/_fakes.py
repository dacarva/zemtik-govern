"""Shared Slice 2 test fakes — NOT a test module (no ``test_`` prefix, not
collected by pytest).

A capture-list ``RecordingTracer``/``RecordedSpan`` pair (per the plan's steer
away from ``MagicMock`` — see ``tests/langchain/test_langsmith_trace.py`` for
what we deliberately did NOT copy), plus a family of hostile fake ``Tracer``
implementations for the fail-open matrix. Each hostile fake fails at exactly
one point in the span lifecycle (``trace()``, ``__enter__``, ``__exit__``) so
a failing fail-open test pinpoints which guard clause regressed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RecordedSpan:
    name: str
    attrs: dict[str, Any] = field(default_factory=dict)
    children: list[RecordedSpan] = field(default_factory=list)
    closed: bool = False


class _RecordingSpanCM:
    """A FRESH instance per ``.span()``/``.trace()`` call — never a shared
    singleton — matching a real tracer's contract (see ``NoOpTracer``'s own
    docstring warning that its shared-singleton shortcut is a trap for a
    stricter future guard)."""

    def __init__(self, recorded: RecordedSpan) -> None:
        self._recorded = recorded

    def set(self, **attrs: Any) -> None:
        self._recorded.attrs.update(attrs)

    def span(self, name: str) -> _RecordingSpanCM:
        child = RecordedSpan(name=name)
        self._recorded.children.append(child)
        return _RecordingSpanCM(child)

    def __enter__(self) -> _RecordingSpanCM:
        return self

    def __exit__(self, *exc: object) -> bool:
        self._recorded.closed = True
        return False


class RecordingTracer:
    """Records every root span opened via ``.trace(...)``. ``self.roots`` is
    the full history across every ``govern()``/``proxy()`` call made with this
    tracer instance — tests index the LAST root for the call under test."""

    def __init__(self) -> None:
        self.roots: list[RecordedSpan] = []

    def trace(self, name: str, **attrs: Any) -> _RecordingSpanCM:
        root = RecordedSpan(name=name, attrs=dict(attrs))
        self.roots.append(root)
        return _RecordingSpanCM(root)


class ExplodingTracer:
    """Raises the instant a root span is requested."""

    def trace(self, name: str, **attrs: Any):
        raise RuntimeError("boom: trace")


class _EnterBoomSpan:
    def __enter__(self):
        raise RuntimeError("boom: enter")

    def __exit__(self, *exc: object) -> bool:
        return False


class ExplodingEnterTracer:
    """The context manager opens fine; ``__enter__`` itself raises."""

    def trace(self, name: str, **attrs: Any) -> _EnterBoomSpan:
        return _EnterBoomSpan()


class _ExitBoomSpan:
    def __enter__(self) -> _ExitBoomSpan:
        return self

    def set(self, **attrs: Any) -> None:
        return None

    def span(self, name: str) -> _ExitBoomSpan:
        return _ExitBoomSpan()

    def __exit__(self, *exc: object) -> bool:
        raise RuntimeError("boom: exit")


class ExplodingExitTracer:
    """Enter and use are fine; ``__exit__`` raises (e.g. a flush failure)."""

    def trace(self, name: str, **attrs: Any) -> _ExitBoomSpan:
        return _ExitBoomSpan()


class SlowTracer:
    """A slow SYNC span open (blocks inside ``.trace()``) — proves span
    lifecycle sits outside ``_with_budget``'s race: the decision budget must be
    blind to this latency."""

    def __init__(self, delay: float) -> None:
        self._delay = delay

    def trace(self, name: str, **attrs: Any) -> _RecordingSpanCM:
        time.sleep(self._delay)
        return _RecordingSpanCM(RecordedSpan(name=name, attrs=dict(attrs)))
