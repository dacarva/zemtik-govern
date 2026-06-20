"""The one bounded cache primitive — LRU cap + lazy TTL, no new dependency (#35).

Both idempotency caches (the decision ledger and the proxy's effect-dedup slots)
are unbounded process-local dicts in v0.1 — a DoS surface and a memory leak under
unique-key traffic. :class:`BoundedTTLDict` replaces both with one shared type: a
stdlib :class:`~collections.OrderedDict` used as an LRU plus a manual,
lazily-checked TTL.

Two deliberate properties make it safe for the effect cache:

- **Eviction can be vetoed.** An ``is_evictable`` predicate guards each entry; an
  entry it rejects (an in-flight effect future that still has concurrent waiters)
  is skipped and the next-oldest evictable entry goes instead. If *nothing* is
  evictable the map is allowed to exceed its cap rather than orphan live work —
  the cap bounds evictable garbage, it is never a license to drop a running
  effect.
- **Time is injected.** ``time_fn`` defaults to :func:`time.monotonic` (immune to
  wall-clock jumps) but tests crank a fake clock for deterministic expiry.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable, Iterator
from typing import Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class BoundedTTLDict(Generic[K, V]):
    """An LRU-bounded, TTL-expiring mapping. Not thread-safe; the governor drives
    it under the asyncio single thread (and the per-key idempotency lock)."""

    def __init__(
        self,
        *,
        maxsize: int,
        ttl_seconds: float | None,
        time_fn: Callable[[], float] = time.monotonic,
        is_evictable: Callable[[V], bool] | None = None,
    ) -> None:
        if maxsize < 1:
            raise ValueError(f"maxsize must be >= 1, got {maxsize}")
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._time = time_fn
        self._is_evictable = is_evictable or (lambda _v: True)
        # key -> (expires_at | None, value). Ordered by recency: front = LRU.
        self._data: OrderedDict[K, tuple[float | None, V]] = OrderedDict()

    def _expired(self, expires_at: float | None) -> bool:
        return expires_at is not None and self._time() >= expires_at

    def get(self, key: K, default: V | None = None) -> V | None:
        """Return the live value for *key*, marking it most-recently-used. An
        expired entry is dropped and reads as absent (the caller re-evaluates)."""
        entry = self._data.get(key)
        if entry is None:
            return default
        expires_at, value = entry
        if self._expired(expires_at):
            del self._data[key]
            return default
        self._data.move_to_end(key)
        return value

    def peek(self, key: K, default: V | None = None) -> V | None:
        """Like :meth:`get` but does NOT refresh recency — a cleanup path must not
        keep an entry alive merely by inspecting it. Still honours TTL."""
        entry = self._data.get(key)
        if entry is None:
            return default
        expires_at, value = entry
        if self._expired(expires_at):
            del self._data[key]
            return default
        return value

    def set(self, key: K, value: V) -> None:
        """Insert or update *key*, mark it most-recently-used, then evict down to
        the cap (skipping vetoed entries)."""
        expires_at = None if self._ttl is None else self._time() + self._ttl
        self._data[key] = (expires_at, value)
        self._data.move_to_end(key)
        self._evict_to_cap()

    def _evict_to_cap(self) -> None:
        # Walk oldest -> newest, evicting the first evictable entry each pass until
        # at/under cap. An entry whose predicate vetoes (in-flight effect) is
        # skipped; if a full pass finds nothing evictable, stop — exceeding the cap
        # beats orphaning live work.
        while len(self._data) > self._maxsize:
            victim: K | None = None
            for k, (expires_at, value) in self._data.items():
                # Expired entries are always reclaimable regardless of the veto.
                if self._expired(expires_at) or self._is_evictable(value):
                    victim = k
                    break
            if victim is None:
                return
            del self._data[victim]

    def delete(self, key: K) -> None:
        """Remove *key* if present; a no-op otherwise."""
        self._data.pop(key, None)

    def __contains__(self, key: object) -> bool:
        entry = self._data.get(key)  # type: ignore[arg-type]
        if entry is None:
            return False
        if self._expired(entry[0]):
            del self._data[key]  # type: ignore[arg-type]
            return False
        return True

    def __len__(self) -> int:
        """Number of currently-stored entries (expired-but-unswept included; they
        are reclaimed lazily on access). Live under steady traffic."""
        return len(self._data)

    def keys(self) -> Iterator[K]:
        return iter(list(self._data.keys()))
