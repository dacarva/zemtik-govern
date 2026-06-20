"""#35 — the shared bounded LRU + TTL primitive backing both idempotency caches.

``BoundedTTLDict`` is the ONE cache type used by both the decision ledger and the
proxy's effect-dedup slots. It must:

- cap entries (LRU eviction) so unique-key traffic cannot grow it without bound;
- expire entries after a config TTL so a stale decision re-evaluates;
- SKIP eviction of an entry an ``is_evictable`` predicate vetoes (an in-flight
  effect future must never be orphaned), evicting the next candidate instead.

Time is injected so the tests drive expiry deterministically (no sleeps).
"""

from zemtik_govern._cache import BoundedTTLDict


def _clock():
    """A hand-cranked monotonic clock: returns the current value; bump via .tick."""

    class _C:
        def __init__(self):
            self.now = 0.0

        def __call__(self):
            return self.now

        def tick(self, dt):
            self.now += dt

    return _C()


def test_caps_entries_with_lru_eviction():
    """Inserting past the cap evicts the least-recently-used entry, so a stream of
    unique keys keeps the map at the cap — not O(N)."""
    c = BoundedTTLDict(maxsize=2, ttl_seconds=None)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)  # evicts "a" (LRU)

    assert len(c) == 2
    assert c.get("a") is None
    assert c.get("b") == 2
    assert c.get("c") == 3


def test_get_refreshes_recency_so_lru_picks_the_truly_oldest():
    """A ``get`` marks an entry recently-used, so the next eviction picks the other
    one. Proves LRU semantics, not insertion-order FIFO."""
    c = BoundedTTLDict(maxsize=2, ttl_seconds=None)
    c.set("a", 1)
    c.set("b", 2)
    assert c.get("a") == 1  # "a" now most-recently used; "b" is the LRU
    c.set("c", 3)  # evicts "b"

    assert c.get("b") is None
    assert c.get("a") == 1
    assert c.get("c") == 3


def test_ttl_expired_entry_is_gone_on_access():
    """Past the TTL an entry reads as absent, so the caller re-evaluates
    deterministically rather than serving a stale decision."""
    clk = _clock()
    c = BoundedTTLDict(maxsize=8, ttl_seconds=10.0, time_fn=clk)
    c.set("k", "v")

    clk.tick(9.0)
    assert c.get("k") == "v"  # still inside the window
    clk.tick(2.0)  # now 11s old > 10s TTL
    assert c.get("k") is None
    assert "k" not in c


def test_eviction_skips_a_vetoed_entry_and_takes_the_next():
    """An entry the ``is_evictable`` predicate vetoes (e.g. an in-flight effect
    future) is never evicted; eviction falls through to the next-oldest evictable
    entry instead."""
    pinned = {"a"}  # pretend "a" holds an in-flight (not-done) future
    c = BoundedTTLDict(
        maxsize=2, ttl_seconds=None, is_evictable=lambda v: v not in pinned
    )
    c.set("a", "a")  # oldest, but pinned
    c.set("b", "b")
    c.set("c", "c")  # would evict "a", but it's pinned -> evict "b"

    assert c.get("a") == "a"  # survived despite being LRU
    assert c.get("b") is None  # the next-oldest evictable went instead
    assert c.get("c") == "c"


def test_all_entries_vetoed_does_not_orphan_just_exceeds_cap_temporarily():
    """If every entry is pinned (all in-flight), eviction cannot proceed: the map
    is allowed to exceed the cap rather than orphan a running effect. The cap is a
    bound on *evictable* garbage, never a license to drop live work."""
    c = BoundedTTLDict(maxsize=1, ttl_seconds=None, is_evictable=lambda v: False)
    c.set("a", "a")
    c.set("b", "b")  # nothing evictable -> both retained

    assert c.get("a") == "a"
    assert c.get("b") == "b"


def test_peek_does_not_refresh_recency():
    """``peek`` reads without marking recently-used, so eviction order is
    unchanged — used by cleanup paths that must not keep an entry alive merely by
    looking at it."""
    c = BoundedTTLDict(maxsize=2, ttl_seconds=None)
    c.set("a", 1)
    c.set("b", 2)
    assert c.peek("a") == 1  # peek, not get
    c.set("c", 3)  # "a" is still the LRU -> evicted

    assert c.get("a") is None
    assert c.get("b") == 2
