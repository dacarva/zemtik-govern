"""The immutable governance context — one call's request, frozen."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any


def _deep_freeze(value: Any) -> Any:
    """A deeply-immutable view of *value*: dicts → read-only ``MappingProxyType``,
    sequences → tuples, sets → frozensets, scalars unchanged. Mutable at no depth.

    **Constraint**: sets (and frozensets) whose elements are unhashable (e.g.
    dicts, lists) will raise ``TypeError`` at construction time because
    ``frozenset()`` requires hashable elements.  Callers must ensure that any set
    in *value* contains only JSON-serializable, hashable leaf values (strings,
    numbers, booleans, ``None``).  This is a programmer-error constraint — a
    ``TypeError`` from a dict-containing set is not a governance event and is not
    wrapped in :class:`~zemtik_govern.errors.GovernanceError`.  See also:
    :class:`GovernanceContext` docstring.
    """
    if isinstance(value, Mapping):
        return MappingProxyType({k: _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_deep_freeze(v) for v in value)
    return value


def _thaw(value: Any) -> Any:
    """Inverse of :func:`_deep_freeze`: plain, mutable, JSON-serializable Python."""
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, (tuple, list, frozenset, set)):
        return [_thaw(v) for v in value]
    return value


@dataclass(frozen=True)
class GovernanceContext:
    """One governed request. Frozen; payload/extra deep-frozen on construction.

    **Constraint on sets**: if ``payload`` or ``extra`` contain a ``set`` or
    ``frozenset``, every element must be hashable (strings, numbers, booleans,
    ``None``).  A set containing a ``dict`` or ``list`` will cause
    :func:`_deep_freeze` to raise ``TypeError`` during ``__post_init__``.  This
    is a programmer error — convert dicts inside sets to tuples of pairs or
    similar hashable representations before constructing the context.
    """

    action: str
    subject: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    idempotency_key: str | None = None
    ts: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # frozen=True blocks rebinding fields; deep-freeze blocks mutating what
        # they point at. object.__setattr__ is the sanctioned hatch in a frozen
        # dataclass's own __post_init__.
        object.__setattr__(self, "payload", _deep_freeze(dict(self.payload)))
        object.__setattr__(self, "extra", _deep_freeze(dict(self.extra)))

    def to_dict(self) -> dict[str, Any]:
        """A plain, mutable, JSON-serializable dict for AGT policy + audit.

        ``action``/``subject`` sit at the top level so policy rule conditions
        (which key on ``field``) match them directly.
        """
        return {
            "action": self.action,
            "subject": self.subject,
            "idempotency_key": self.idempotency_key,
            "ts": self.ts,
            "payload": _thaw(self.payload),
            "extra": _thaw(self.extra),
        }
