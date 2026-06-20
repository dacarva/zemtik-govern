"""The orchestration core — one ``govern()`` call, fail-closed.

Order is fixed (A2): identity → policy → audit. Identity first because policy may
key on the subject and every audit entry is stamped with the DID. Audit last
because it records the final decision — EVERY outcome, including fail-closed
denials. Any unexpected exception is wrapped as :class:`GovernanceError`, audited
as a denial, and re-raised — the tool never runs (no ungoverned fall-through to
the tool on a governance fault).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import inspect
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from ._cache import BoundedTTLDict
from .context import GovernanceContext
from .errors import GovernanceDenied, GovernanceError
from .protocols import (
    AuditEntry,
    AuditSink,
    Decision,
    IdentityProvider,
    PolicyEngine,
)

# Stamped on the audit entry when identity itself fails — we still record the
# blocked outcome, we just have no resolved DID to attribute it to.
_UNIDENTIFIED_DID = "did:mesh:unidentified"

# Recorded when an idempotency key is reused for a different request. A system
# denial: the request was never evaluated, it was rejected as a key conflict.
_IDEM_CONFLICT = Decision(
    allowed=False,
    action="error",
    matched_rule=None,
    reason="idempotency key reused for a different request",
    denial_kind="system",
)

# Defaults for the bounded idempotency cache when a governor is built by hand
# (not from config). The config path threads its own (validated) values.
from .config import (  # noqa: E402  (placed here to keep the constant next to use)
    _DEFAULT_IDEM_MAX_ENTRIES,
    _DEFAULT_IDEM_TTL_SECONDS,
)


@dataclass
class _IdemRecord:
    """One idempotency key's cache entry, shared by both concerns (#35).

    ``fingerprint`` binds the key to the ONE request it was minted for (``None``
    until the first evaluation — a slot a proxy reserved for an in-flight effect
    before governance has run). ``decisions`` is the two-level inner map: it keys
    each cached verdict on ``(mode, killswitch_state)`` so a decision ledgered
    under one operational stance is never replayed under another (killswitch
    authority). ``effect`` holds the proxy's in-flight-or-completed tool result
    future; an entry whose effect is not yet done vetoes eviction so a running
    effect with concurrent waiters is never orphaned.
    """

    fingerprint: str | None
    decisions: dict[tuple[str, bool], tuple[str, Decision]] = field(default_factory=dict)
    effect: asyncio.Future | None = None

    def is_evictable(self) -> bool:
        # A completed (or absent) effect evicts freely; an in-flight effect pins
        # the whole record so its decision and result stay consistent.
        return self.effect is None or self.effect.done()


def _assert_json_native(value: Any) -> None:
    """Reject anything the old ``default=str`` encoder would have LOSSILY coerced:
    non-string mapping keys and any non-JSON-native leaf (tuple, set, bytes,
    ``datetime``, ``Decimal``, a custom object…). Two distinct such values could
    stringify alike and collapse to one fingerprint — a false replay. Floats are
    left for ``allow_nan=False`` below to police (NaN/Inf). Raises ``TypeError``,
    which the keyed fail-closed boundary in :meth:`ZemtikGovern.govern` catches,
    audits, and re-raises as :class:`GovernanceError` — the tool never runs."""
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(f"non-string mapping key: {k!r}")
            _assert_json_native(v)
    elif isinstance(value, list):
        for v in value:
            _assert_json_native(v)
    elif isinstance(value, (str, int, float)) or value is None:
        # bool is a subclass of int — admitted here, as JSON-native.
        return
    else:
        raise TypeError(f"non-JSON-native value: {type(value).__name__}")


def _request_fingerprint(ctx: GovernanceContext) -> str:
    """A stable hash of the part of the request policy actually decides on —
    action, subject, payload. Binds an idempotency key to ONE request so a key
    reused for a different action/subject/payload is detected as a conflict.
    ``ts`` and ``extra`` are excluded: a retried request keeps its identity even
    if the clock or out-of-band metadata moved.

    Strict by design (#32): no ``default=`` fallback (so a non-serialisable
    payload is rejected, never lossily stringified), ``allow_nan=False`` (NaN/Inf
    are rejected, not emitted as non-standard tokens), and string-only mapping
    keys (``json.dumps`` would silently coerce ``int``/``bool`` keys to strings,
    collapsing ``{1: …}`` and ``{"1": …}``). Rejection happens at THIS seam,
    inside the fail-closed boundary, so it is audited as a conflict/error — a
    construction-time reject would never reach ``govern()`` to be recorded."""
    payload = ctx.to_dict()["payload"]
    _assert_json_native(payload)
    canonical = json.dumps(
        {"action": ctx.action, "subject": ctx.subject, "payload": payload},
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()

# Shadow mode observes without enforcing; every other mode enforces (raises on a
# deny). Kept as a set so a typo in a mode string enforces by default — the safe
# direction. Config validates the mode string at startup (GovernanceNotConfigured).
_SHADOW = "shadow"


class Killswitch:
    """An operator-flippable revert flag.

    When engaged, :class:`ZemtikGovern` routes evaluation back to the prior
    governed fallback path instead of the wrapper's own policy — never to
    allow-all. Callable so the core only depends on ``() -> bool``; a real
    deployment may swap in any callable reading a per-env flag.
    """

    def __init__(self, engaged: bool = False) -> None:
        """Start in the given state (default: not engaged)."""
        self.engaged = engaged

    def engage(self) -> None:
        """Activate the switch: route to fallback on the next governance call."""
        self.engaged = True

    def disengage(self) -> None:
        """Deactivate: restore the primary policy path."""
        self.engaged = False

    def __call__(self) -> bool:
        return self.engaged


class ZemtikGovern:
    """Wires the three seams and runs them in the sanctioned order."""

    def __init__(
        self,
        identity: IdentityProvider,
        policy: PolicyEngine,
        audit: AuditSink,
        *,
        mode: str = "enforce",
        fallback: PolicyEngine | None = None,
        killswitch: Callable[[], bool] | None = None,
        timeout: float | None = None,
        idem_max_entries: int = _DEFAULT_IDEM_MAX_ENTRIES,
        idem_ttl_seconds: float | None = _DEFAULT_IDEM_TTL_SECONDS,
        time_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Args:
            identity: Resolves subject strings to :class:`AgentRef` DIDs.
            policy: Evaluates a frozen context to a :class:`Decision`.
            audit: Records every outcome; called on allow, deny, and system error.
            mode: ``"strict"`` / ``"enforce"`` raise on deny; ``"shadow"`` records
                but does not enforce.
            fallback: Alternate :class:`PolicyEngine` to use when *killswitch* is
                engaged. Engaging with no fallback fails closed.
            killswitch: Zero-arg callable returning ``True`` when the switch is
                engaged. Typically a :class:`Killswitch` instance.
            timeout: Per-call decision budget (seconds) shared across identity +
                policy. A breach is a system denial, not an allow. ``None`` means
                no budget (not recommended for latency-sensitive paths).
        """
        self._identity = identity
        self._policy = policy
        self._audit = audit
        self._mode = mode
        self._fallback = fallback
        self._killswitch = killswitch
        # Per-call decision budget (seconds) for identity + policy. The latency-
        # sensitive voice path needs a bound; a hung engine must never stall the
        # caller indefinitely. A timeout is a system fault, so it flows through the
        # same fail-closed path as any other engine error: audited, then denied.
        self._timeout = timeout
        # Idempotency replay guard. A duplicate idempotency_key must resolve to the
        # SAME decision it did the first time — a replayed fintech write is not a
        # new request. The lock serialises same-key calls so two concurrent
        # submissions can't both slip through as fresh evaluations. v0.1 keeps the
        # ledger in memory (process-local, unbounded); a durable store plugs in
        # here in v0.2 without changing the govern() contract.
        # Per-key idempotency locks (#34, T-LOCK / Codex #10). One global lock
        # would serialise EVERY keyed request, so a slow key head-of-line-blocks
        # unrelated keys on the latency path. A per-key map lets distinct keys
        # evaluate concurrently while still serialising same-key duplicates. The
        # companion waiter-count map drives cleanup so the lock map does not become
        # a new unbounded map: an entry lives only while a coroutine holds-or-waits
        # on it, and is deleted the moment the last one releases (success, failure,
        # OR cancel — the async-context-manager exit runs on all three).
        self._idem_locks: dict[str, asyncio.Lock] = {}
        self._idem_lock_waiters: dict[str, int] = {}
        # key -> _IdemRecord. ONE bounded LRU+TTL cache (#35) backs BOTH the
        # decision ledger and the proxy's effect-dedup slots, so neither grows
        # without bound under unique-key traffic and the two evict CONSISTENTLY
        # (one record per key holds both). The fingerprint inside each record binds
        # the key to the ONE request it was minted for: an idempotency key
        # identifies a request, it is not a bearer token that replays a prior allow
        # onto any action. A key reused with a different action/subject/payload is a
        # conflict, not a duplicate, and fails closed rather than bypassing policy.
        # Eviction skips a record whose effect future is still in flight so a
        # running tool call with concurrent waiters is never orphaned.
        self._idem_cache: BoundedTTLDict[str, _IdemRecord] = BoundedTTLDict(
            maxsize=idem_max_entries,
            ttl_seconds=idem_ttl_seconds,
            time_fn=time_fn,
            is_evictable=lambda record: record.is_evictable(),
        )

    async def govern(self, ctx: GovernanceContext) -> Decision:
        key = ctx.idempotency_key
        if key is None:
            _, decision = await self._evaluate_and_audit(ctx)
            return self._enforce(decision)

        # Idempotent path: serialise on the key so a concurrent duplicate is a
        # deterministic replay, never silently evaluated as a brand-new request.
        # Fingerprint INSIDE the fail-closed boundary: a payload we cannot
        # canonically serialise cannot be safely matched against the ledger, so a
        # fingerprint failure is a system denial (audited, then GovernanceError) —
        # never a raw exception that skips the trail.
        try:
            fingerprint = _request_fingerprint(ctx)
        except Exception as exc:
            denial = Decision(
                allowed=False,
                action="error",
                matched_rule=None,
                reason=f"idempotency fingerprint failed: {exc}",
                denial_kind="system",
            )
            await self._audit.write(
                AuditEntry.from_decision(
                    ctx, _UNIDENTIFIED_DID, denial, outcome="error", mode=self._mode
                )
            )
            raise GovernanceError(
                "idempotency fingerprint failed; tool blocked"
            ) from exc
        async with self._key_lock(key):
            record = self._idem_cache.get(key)
            if record is not None and record.fingerprint is not None:
                if record.fingerprint != fingerprint:
                    # Same key, different request: a conflict, not a duplicate.
                    # Conflict detection keys on the FINGERPRINT alone (#35, A1), so
                    # a recycled key with a changed payload is caught regardless of
                    # the mode/killswitch bucket. Replaying the prior decision here
                    # would let an ungoverned action ride a recycled key past policy.
                    # Fail closed: audit the conflict and raise — the tool never
                    # runs, policy is never bypassed. The conflicting request was
                    # never identity-resolved, so it is NOT attributable to the prior
                    # key holder: stamp the reserved unidentified DID, never the
                    # cached (first-caller) DID.
                    await self._audit.write(
                        AuditEntry.from_decision(
                            ctx,
                            _UNIDENTIFIED_DID,
                            _IDEM_CONFLICT,
                            outcome="error",
                            mode=self._mode,
                        )
                    )
                    raise GovernanceError(
                        "idempotency key reused for a different request; tool blocked"
                    )
                # Same request: the REPLAY lookup keys on (mode, killswitch_state)
                # (#35, two-level keying) so a decision ledgered under one stance is
                # never replayed under another — a key allowed before the killswitch
                # flipped re-evaluates under the fallback rather than replaying its
                # stale allow.
                replay_key = self._replay_key()
                cached = record.decisions.get(replay_key)
                if cached is not None:
                    did, decision = cached
                    # Genuine duplicate: record the REPLAY (not a second
                    # success/denied) so the trail shows it was recognised, then
                    # re-apply enforcement. Flag the returned decision as a replay so
                    # a DIRECT govern caller can skip re-running its own side effect.
                    await self._audit.write(
                        AuditEntry.from_decision(
                            ctx, did, decision, outcome="replay", mode=self._mode
                        )
                    )
                    return self._enforce(replace(decision, replayed=True))
                # Same request, new (mode, killswitch) stance: fall through to a
                # fresh evaluation and cache it under this stance's bucket.
            did, decision = await self._evaluate_and_audit(ctx)
            # Cache only a completed evaluation; a fail-closed system error raises
            # out of _evaluate_and_audit and is left un-cached so a retry re-runs.
            self._store_decision(key, fingerprint, did, decision)
            return self._enforce(decision)

    async def _evaluate_and_audit(
        self, ctx: GovernanceContext
    ) -> tuple[str, Decision]:
        """Identity → policy → audit, inside the fail-closed boundary.

        A fault in EITHER identity or policy is a system denial, audited then
        re-raised as :class:`GovernanceError`. Identity is no exception — an
        unaudited, unwrapped identity failure would be a hole in the "every outcome
        audited" contract. If identity is what failed we have no DID, so the audit
        entry is stamped with the reserved unidentified DID. Returns
        ``(did, decision)`` with the decision enriched with its audit id; does NOT
        enforce (the caller decides whether a deny raises).
        """
        did = _UNIDENTIFIED_DID
        try:
            did = (await self._with_budget(self._identity.identify(ctx.subject))).did
            decision = await self._with_budget(self._select_engine().evaluate(ctx))
        except Exception as exc:
            # Fail-closed: the tool never runs; the original exception is preserved.
            denial = Decision(
                allowed=False,
                action="error",
                matched_rule=None,
                reason=f"engine error: {exc}",
                denial_kind="system",
            )
            await self._audit.write(
                AuditEntry.from_decision(
                    ctx, did, denial, outcome="error", mode=self._mode
                )
            )
            raise GovernanceError("governance engine failed; tool blocked") from exc

        event_id = await self._audit.write(
            AuditEntry.from_decision(ctx, did, decision, mode=self._mode)
        )
        return did, replace(decision, audit_event_id=event_id)

    def _ks_state(self) -> bool:
        """The killswitch's current engaged state as a plain bool — part of the
        two-level replay key so a decision is replayed only under the SAME stance.
        A killswitch that raises is treated as engaged (fail toward the fallback);
        the actual fault surfaces from ``_select_engine`` during evaluation."""
        if self._killswitch is None:
            return False
        try:
            return bool(self._killswitch())
        except Exception:
            return True

    def _replay_key(self) -> tuple[str, bool]:
        """The inner two-level key for the decision-replay lookup: ``(mode,
        killswitch_state)``. Conflict detection does NOT use this — only replay."""
        return (self._mode, self._ks_state())

    def _store_decision(
        self, key: str, fingerprint: str, did: str, decision: Decision
    ) -> None:
        """Cache a freshly-evaluated decision under ``key`` and the current stance.

        Reuses an existing record (e.g. a slot a proxy reserved for an in-flight
        effect) so the decision and the effect share ONE record and evict together.
        """
        record = self._idem_cache.get(key)
        if record is None:
            record = _IdemRecord(fingerprint=fingerprint)
            self._idem_cache.set(key, record)
        else:
            record.fingerprint = fingerprint
        record.decisions[self._replay_key()] = (did, decision)

    # --- effect-dedup slots shared with _GovernedProxy (#35) -------------------
    # The proxy's per-key effect future lives in the SAME bounded cache record as
    # the decision, so one eviction removes both — a recycled key can never pass
    # fresh governance and still collect a previous request's cached tool result.

    def _effect_get(self, key: str) -> asyncio.Future | None:
        record = self._idem_cache.get(key)
        return record.effect if record is not None else None

    def _effect_reserve(self, key: str, fut: asyncio.Future) -> None:
        """Reserve the in-flight effect slot for ``key`` BEFORE governance runs, so
        a concurrent duplicate waits on the same execution. Creates a fingerprint-
        less placeholder record if none exists yet."""
        record = self._idem_cache.get(key)
        if record is None:
            record = _IdemRecord(fingerprint=None)
            self._idem_cache.set(key, record)
        record.effect = fut

    def _effect_clear(self, key: str, fut: asyncio.Future) -> None:
        """Drop a failed/cancelled effect from its record (peek: do not refresh
        recency). The cached DECISION is left intact so a retry replays governance
        and re-runs only the tool; a placeholder record with nothing left is
        deleted so it does not linger."""
        record = self._idem_cache.peek(key)
        if record is not None and record.effect is fut:
            record.effect = None
            if record.fingerprint is None and not record.decisions:
                self._idem_cache.delete(key)

    @contextlib.asynccontextmanager
    async def _key_lock(self, key: str):
        """Serialise same-key requests on a lock unique to *key*, while distinct
        keys stay independent. The waiter count is bumped BEFORE the first await so
        a concurrent same-key caller is guaranteed to find (and reuse) the live
        entry rather than mint a second lock — safe because asyncio runs this
        get-or-create + increment without interleaving. On exit (normal, error, or
        cancellation) the count is decremented and the entry deleted once it hits
        zero, so the map holds only currently-contended keys."""
        lock = self._idem_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._idem_locks[key] = lock
        self._idem_lock_waiters[key] = self._idem_lock_waiters.get(key, 0) + 1
        try:
            async with lock:
                yield
        finally:
            self._idem_lock_waiters[key] -= 1
            if self._idem_lock_waiters[key] == 0:
                del self._idem_lock_waiters[key]
                del self._idem_locks[key]

    async def _with_budget(self, coro):
        """Await *coro* under the configured decision budget. With no budget, a
        plain await; with one, an explicit **deadline race** between the engine and
        a timer. A breach raises ``TimeoutError`` — an ordinary exception caught by
        the fail-closed boundary above.

        Why a race and not ``asyncio.wait_for`` (#34, T2 / Codex #1): ``wait_for``
        only surfaces a ``TimeoutError`` if the inner coroutine lets its
        cancellation *propagate*. A *well-intentioned-but-wrong* engine that
        catches ``CancelledError`` and returns a value anyway makes ``wait_for``
        hand that value back AFTER the budget was already blown — a post-breach
        result, the exact fail-closed bypass the budget exists to close.

        The race closes it by deciding on the TIMER, not on the engine: if the
        timer is among the completed tasks, the budget is breached, full stop. The
        engine is cancelled and its result is **never observed** (premise P4) — a
        cancel-swallowing engine cannot turn a breached budget into an allow. Only
        when the engine wins outright (timer not yet fired) is its result read.
        """
        if self._timeout is None:
            return await coro
        engine_task = asyncio.ensure_future(coro)
        timer = asyncio.ensure_future(asyncio.sleep(self._timeout))
        try:
            done, _pending = await asyncio.wait(
                {engine_task, timer}, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.CancelledError:
            # This coroutine itself was cancelled (e.g. an outer budget/caller):
            # tear both children down before propagating so neither is orphaned.
            engine_task.cancel()
            timer.cancel()
            raise
        # Decide on the timer, never the engine. If the timer fired, the budget is
        # breached even if the engine ALSO finished in the same wakeup — we do not
        # read engine_task.result() on a breach (P4).
        if timer in done:
            engine_task.cancel()
            # Drain the cancelled engine so a swallowed cancel (it returns a value
            # or raises) cannot surface as an unretrieved task exception. Its
            # outcome is discarded either way — the budget already lost.
            with contextlib.suppress(BaseException):
                await engine_task
            raise TimeoutError(f"decision budget of {self._timeout}s exceeded")
        # Engine won the race. Cancel the now-moot timer and return the result.
        timer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await timer
        return engine_task.result()

    def _enforce(self, decision: Decision) -> Decision:
        # Shadow mode observes only: the denial is recorded but NOT enforced, so the
        # caller's tool still runs. Every other mode enforces the deny.
        if not decision.allowed and self._mode != _SHADOW:
            raise GovernanceDenied(decision)
        return decision

    def _select_engine(self) -> PolicyEngine:
        """The policy engine for this call. Normally the wrapper's own policy; with
        the kill-switch engaged, the prior governed fallback path instead — never
        allow-all. Engaging the switch with no fallback wired is a fail-closed
        error (caught by ``govern`` and audited as a system denial), not a bypass.
        """
        if self._killswitch is not None and self._killswitch():
            if self._fallback is None:
                raise GovernanceError(
                    "kill-switch engaged with no governed fallback; refusing to allow-all"
                )
            return self._fallback
        return self._policy

    # NOTE: the decision→audit-vocabulary mapping that used to live here as
    # _entry() now lives on AuditEntry.from_decision — audit language stays in the
    # audit concern; this core is pure orchestration.

    def govern_sync(self, ctx: GovernanceContext) -> Decision:
        """Synchronous entry point for non-async callers (the fintech write path).

        Refuses to run inside an already-running event loop — nesting
        ``asyncio.run`` would deadlock, and silently skipping governance is not an
        option. Async callers must ``await govern()`` instead.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.govern(ctx))
        raise GovernanceError(
            "govern_sync() called inside a running event loop; await govern() instead"
        )

    def proxy(
        self,
        fn: Callable[..., Any],
        *,
        action: str,
        subject: str,
        context_factory: Callable[..., GovernanceContext] | None = None,
    ) -> _GovernedProxy:
        """Wrap *fn* so every call passes through ``govern()`` first.

        The returned proxy is what an agent is handed — never the raw callable —
        so there is no ungoverned path to the tool. A deny (policy or system)
        propagates out of the call and ``fn`` never runs.
        """
        return _GovernedProxy(
            self, fn, action=action, subject=subject, context_factory=context_factory
        )


class _GovernedProxy:
    """A callable that runs ``govern()`` before the wrapped tool, every time.

    Closes the ungoverned-call gap: if the decision is a deny, ``GovernanceDenied``
    (or ``GovernanceError`` on a system fault) is raised and the wrapped callable
    is never invoked. On allow, the call goes through and its result is returned
    (awaited if the wrapped callable is async).

    Effect-idempotency: when the context carries an ``idempotency_key``, the proxy
    dedupes the *side effect*, not just the governance decision. The first keyed
    call runs the tool once and caches its result; a duplicate (sequential OR
    concurrent) re-runs ``govern()`` — so the replay is still audited and a key
    reused for a different request still fails closed — but returns the cached
    result instead of invoking the tool again. The in-flight result is held as a
    future, so a second submission that arrives before the first completes awaits
    the same execution rather than starting its own. A denial or a tool failure is
    left un-cached, so a later retry re-evaluates and re-runs (the cache holds only
    successful effects). v0.1 keeps this cache in memory/process-local and
    unbounded; bounding rides the same ledger-bounding work tracked in ``TODOS.md``.

    Trust boundary (v0.1): the proxy governs the *public* call path. The wrapped
    callable is held on a single-underscore private (``_fn``); reaching past it is
    the same out-of-band move as reaching ``AGTBoundary._policy_evaluator`` and is
    out of the threat model. ``context_factory`` is trusted wiring written by the
    integrator — it MAY derive ``action``/``subject``/``payload`` from the call
    args (that is its purpose); it is validated only for return TYPE, not value.
    """

    def __init__(
        self,
        gov: ZemtikGovern,
        fn: Callable[..., Any],
        *,
        action: str,
        subject: str,
        context_factory: Callable[..., GovernanceContext] | None = None,
    ) -> None:
        self._gov = gov
        self._fn = fn
        self._action = action
        self._subject = subject
        self._context_factory = context_factory
        # The per-key effect future lives in the governor's bounded idempotency
        # cache (#35), NOT a proxy-local dict, so it is bounded and evicts in
        # lockstep with the matching decision (no stale-effect-on-fresh-key). Dedupes
        # the EFFECT: a keyed duplicate returns the cached/in-flight result instead
        # of re-invoking the tool. Only successful effects stay cached (failures and
        # denies are cleared), so a retry of a transient fault re-runs.

    def _build_ctx(
        self, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> GovernanceContext:
        """Build the governance context for a call.

        Delegates to *context_factory* when provided; falls back to wrapping
        args/kwargs in a plain payload dict. Raises :class:`GovernanceError` if
        the factory returns the wrong type — a mis-shaped context would be
        governed under unknown values, which is worse than refusing the call.
        """
        if self._context_factory is not None:
            ctx = self._context_factory(*args, **kwargs)
            if not isinstance(ctx, GovernanceContext):
                # A factory that returns the wrong shape would be governed under
                # unknown values — refuse rather than route around the policy key.
                raise GovernanceError(
                    "context_factory must return a GovernanceContext, got "
                    f"{type(ctx).__name__}"
                )
            return ctx
        return GovernanceContext(
            action=self._action,
            subject=self._subject,
            payload={"args": list(args), "kwargs": dict(kwargs)},
        )

    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Govern then invoke. Raises on deny before the wrapped callable runs."""
        ctx = self._build_ctx(args, kwargs)
        key = ctx.idempotency_key
        if key is None:
            await self._gov.govern(ctx)  # raises on deny -> the tool never runs
            return await self._invoke(args, kwargs)

        inflight = self._gov._effect_get(key)
        if inflight is not None:
            # A prior call with this key is in flight or done. Run govern() so the
            # duplicate is audited as a replay (and a key reused for a DIFFERENT
            # request still fails closed before we touch the cached effect), then
            # return the SAME result without re-invoking the tool. ``shield`` so this
            # caller's cancellation can't cancel the shared execution.
            await self._gov.govern(ctx)
            return await asyncio.shield(inflight)

        # First call for this key. Create the effect task synchronously so the slot
        # is reserved BEFORE any await — a concurrent duplicate then sees it and
        # waits on the same execution instead of racing into a second tool call.
        task: asyncio.Future[Any] = asyncio.ensure_future(
            self._effect(ctx, args, kwargs)
        )
        self._gov._effect_reserve(key, task)
        task.add_done_callback(self._evict_failed_effect(key))
        # ``shield`` so this caller's cancellation can't cancel the shared effect;
        # the task runs to completion once and the done-callback (not this caller)
        # owns slot cleanup.
        return await asyncio.shield(task)

    def _evict_failed_effect(
        self, key: str
    ) -> Callable[[asyncio.Future[Any]], None]:
        """Done-callback that drops a failed effect from the cache so a later retry
        re-runs. Tied to the TASK's lifetime, not any caller's: if the first caller
        is cancelled while the effect is still running, this still fires when the
        effect finishes — a cancelled caller can't leave a failed effect cached.
        Reading ``exception()`` here also retrieves it, so an orphaned failure does
        not surface as a stray 'task exception was never retrieved'."""

        def _evict(task: asyncio.Future[Any]) -> None:
            # Only a SUCCESSFUL effect stays cached; a cancel or an exception clears
            # the effect slot (the shared record's decision is left intact for a
            # replay). The governor guards against a same-key task having already
            # replaced this slot.
            if task.cancelled() or task.exception() is not None:
                self._gov._effect_clear(key, task)

        return _evict

    async def _effect(
        self, ctx: GovernanceContext, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> Any:
        """Govern then invoke for the first caller on a keyed request.

        Only successful results are cached; a denial or tool exception propagates
        and evicts the slot so a retry re-runs both governance and the tool.
        """
        await self._gov.govern(ctx)  # raises on deny -> the tool never runs
        return await self._invoke(args, kwargs)

    async def _invoke(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        """Call the wrapped function, awaiting if it returns a coroutine."""
        result = self._fn(*args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result
