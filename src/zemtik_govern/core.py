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
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from ._cache import BoundedTTLDict
from .context import GovernanceContext
from .errors import (
    DecisionBudgetExceeded,
    GovernanceDenied,
    GovernanceError,
    OutputGovernanceDenied,
)
from .injection import GuardedEngine, InjectionClassifier
from .observability import NoOpTracer, Tracer
from .output import (
    IO_READ,
    IO_WRITE,
    OutputClassifier,
    OutputExtractionError,
    extract_text,
    resolve_io,
)
from .protocols import (
    AuditEntry,
    AuditSink,
    Decision,
    IdentityProvider,
    PolicyEngine,
)

# One-line startup log of active guards (D4/D7): an upgrade that flips fail-closed
# defaults ON must SAY so, loudly, once per governor — a silent default flip burns
# upgrade trust. Logged at INFO under the package logger so an operator sees
# "injection detection: ON (AGT)" without the wrapper printing on a library import.
_LOG = logging.getLogger("zemtik_govern")

# Per-guard operational stance (D10). ``enforce`` blocks; ``shadow`` observes a
# would-deny without enforcing it — the observe-then-enforce upgrade path. These
# scope the existing global shadow machinery to ONE guard so an integrator can run
# the injection screen (or the budget) in shadow for a release, watch the
# would-denies, then flip to enforce. Independent of the global ``mode``.
_GUARD_ENFORCE = "enforce"
_GUARD_SHADOW = "shadow"

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


# Hard cap on payload nesting depth for the fingerprint walk. An attacker-deep
# payload would otherwise blow the Python stack (``RecursionError``) inside the
# recursive walk before ``json.dumps`` ever runs. We deny it explicitly instead:
# a ``TypeError`` here is caught by the keyed fail-closed boundary and audited as
# a system error (tool blocked), so the deny is a clean verdict, not a stack trace.
_MAX_PAYLOAD_DEPTH = 64


def _assert_json_native(value: Any, _depth: int = 0) -> None:
    """Reject anything the old ``default=str`` encoder would have LOSSILY coerced:
    non-string mapping keys and any non-JSON-native leaf (tuple, set, bytes,
    ``datetime``, ``Decimal``, a custom object…). Two distinct such values could
    stringify alike and collapse to one fingerprint — a false replay. Floats are
    left for ``allow_nan=False`` below to police (NaN/Inf). Raises ``TypeError``,
    which the keyed fail-closed boundary in :meth:`ZemtikGovern.govern` catches,
    audits, and re-raises as :class:`GovernanceError` — the tool never runs.

    Depth is bounded (``_MAX_PAYLOAD_DEPTH``) so a pathologically nested payload is
    an explicit deny, not an uncaught ``RecursionError``."""
    if _depth > _MAX_PAYLOAD_DEPTH:
        raise TypeError(f"payload nesting exceeds maximum depth {_MAX_PAYLOAD_DEPTH}")
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(f"non-string mapping key: {k!r}")
            _assert_json_native(v, _depth + 1)
    elif isinstance(value, list):
        for v in value:
            _assert_json_native(v, _depth + 1)
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
        injection_classifier: InjectionClassifier | None = None,
        injection_mode: str = _GUARD_ENFORCE,
        budget_mode: str = _GUARD_ENFORCE,
        output_classifiers: list[OutputClassifier] | None = None,
        tool_io_map: Mapping[str, str] | None = None,
        tracer: Tracer | None = None,
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
        # Mandatory, fail-closed prompt-injection guard (#36). When wired, it wraps
        # whatever _select_engine() returns — primary AND killswitch fallback — so
        # the screen cannot be bypassed during a killswitch emergency (T1). None
        # only in hand-built cores with no injection concern; from_config always
        # wires it in non-shadow modes.
        self._injection_classifier = injection_classifier
        # Per-guard shadow stance (D10). ``injection_mode``/``budget_mode`` =
        # ``enforce|shadow`` scope the global shadow machinery to ONE guard: an
        # integrator runs the new guard in shadow for a release, observes the
        # would-denies in the log/audit, then flips to enforce. Default enforce —
        # the secure default; shadow is the explicit, temporary opt-out.
        self._injection_mode = injection_mode
        self._budget_mode = budget_mode
        # Output-governance seam (#39, C0). When wired, proxy() screens each tool
        # RETURN value through these classifiers after the tool runs, inside the
        # effect path — so the screened value is what gets cached and a replay never
        # re-leaks the unscreened original. Direct govern()/govern_sync() callers
        # stay input-only (premise 2). ``tool_io_map`` classifies each action
        # read|write (default write = fail-closed); a read-deny withholds the value
        # and raises, a write-deny is the C1/#40 RedactedOutput path. Empty/None
        # classifiers => the seam is inert and proxy() returns the raw value.
        self._output_classifiers = list(output_classifiers or [])
        self._tool_io_map = dict(tool_io_map or {})
        # Warn-once registry for unmapped actions (Issue #42). When the output seam
        # is active and _screen_output sees an action absent from _tool_io_map, it
        # must warn ONCE — an action that silently defaults to write (fail-closed) is
        # a MISCLASSIFIED tool waiting to be caught. But repeating the same warning
        # on every call creates alert fatigue that operators learn to ignore. One
        # warning per novel action is the right trust signal: it fires immediately on
        # the first real call (when the operator can still fix the map before prod)
        # and stays silent thereafter. asyncio is single-threaded so a plain set is
        # safe without a lock.
        self._output_warned_actions: set[str] = set()
        # Optional observability seam (fail-OPEN telemetry, the inverse of the
        # fail-CLOSED governance seams). Defaults to a NoOpTracer so a governor
        # built without observability behaves byte-for-byte as before. Later slices
        # add a core-level guard around every tracer call so no tracer — not even a
        # hostile one — can break govern(); the tracer object itself is never
        # imported from Langfuse here (that lives behind the observability boundary).
        self._tracer: Tracer = tracer if tracer is not None else NoOpTracer()
        # The injected clock, reused by the budget guard to measure elapsed time
        # for a breach (and for a shadow-mode would-breach observation).
        self._time_fn = time_fn
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
        self._log_active_guards(idem_max_entries, idem_ttl_seconds)

    @property
    def tracer(self) -> Tracer:
        """The observability tracer this governor drives (a ``NoOpTracer`` unless
        one was wired). Read-only: the tracer is fixed at construction, like the
        seams."""
        return self._tracer

    def _log_active_guards(self, idem_max_entries: int, idem_ttl_seconds: float | None) -> None:
        """Announce the active guards once, at construction (D4/D7). Names whether
        injection detection is ON, the decision budget, and the cache caps — so an
        upgrade that activates fail-closed defaults is visible, not silent.

        Issue #42 — output seam discoverability: when output classifiers are wired,
        also announces the active rail names/modes AND the tool_io_map so an operator
        immediately sees what is classified and what will default to write (fail-closed).
        The governor has no inventory of every possible action at construction time
        (proxies are created lazily, and rails are PII classifiers that carry no
        action names), so listing "unclassified actions" verbatim is not buildable.
        The faithful, testable equivalent: surface the KNOWN io_map (so the operator
        sees what IS declared) and state the fail-closed default — unmapped actions
        default to write — so misclassified tools are caught at operator review time,
        not silently in production."""
        injection = (
            f"ON (AGT, {self._injection_mode})" if self._injection_classifier is not None else "OFF"
        )
        budget = f"{self._timeout}s ({self._budget_mode})" if self._timeout is not None else "OFF"
        _LOG.info(
            "zemtik-govern active | mode: %s | injection detection: %s | "
            "decision budget: %s | idempotency: cap=%s ttl=%s",
            self._mode,
            injection,
            budget,
            idem_max_entries,
            idem_ttl_seconds,
        )
        if self._output_classifiers:
            # Surface each rail's name; per-rail mode shown alongside the global
            # mode in the banner so an operator sees shadow vs. enforce per rail.
            rail_names = ", ".join(getattr(c, "name", "?") for c in self._output_classifiers)
            # io_map lists explicitly classified actions; every unmapped action defaults
            # to write (fail-closed). Both facts are surfaced here so an operator can
            # spot a READ tool that was forgotten from the map before it ships and
            # silently produces RedactedOutput in production.
            io_map_repr = "{" + ", ".join(f"{k}: {v}" for k, v in self._tool_io_map.items()) + "}"
            _LOG.info(
                "output screening: ON (rails=%s, mode=%s) | "
                "io_map=%s | unmapped actions default to write (fail-closed)",
                rail_names,
                self._mode,
                io_map_repr,
            )

    async def govern(self, ctx: GovernanceContext) -> Decision:
        """Public entry point: identity → policy → audit, returns the Decision.

        Delegates to :meth:`_govern_with_did`, which also surfaces the resolved DID
        for the proxy's output seam to attribute its audit rows to (so an output
        allow/deny is stamped with the SAME agent the input row names, not the
        reserved unidentified DID). Direct callers only need the Decision."""
        _did, decision = await self._govern_with_did(ctx)
        return decision

    async def _govern_with_did(self, ctx: GovernanceContext) -> tuple[str, Decision]:
        """The full govern pipeline, returning ``(did, enforced_decision)``.

        The DID is the identity-resolved subject (or the reserved unidentified DID
        on a replay whose original resolved it). A deny still raises out of
        ``_enforce`` exactly as before — the tuple is only returned on a non-raising
        outcome (allow, or a shadow-mode observed would-deny), which is the only
        case the output seam runs in anyway."""
        key = ctx.idempotency_key
        if key is None:
            did, decision = await self._evaluate_and_audit(ctx)
            return did, self._enforce(decision)

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
            event_id = await self._audit.write(
                AuditEntry.from_decision(
                    ctx, _UNIDENTIFIED_DID, denial, outcome="error", mode=self._mode
                )
            )
            raise GovernanceError(
                "idempotency fingerprint failed; tool blocked",
                code="idempotency_fingerprint_error",
                guard="idempotency",
                audit_id=event_id,
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
                    event_id = await self._audit.write(
                        AuditEntry.from_decision(
                            ctx,
                            _UNIDENTIFIED_DID,
                            _IDEM_CONFLICT,
                            outcome="error",
                            mode=self._mode,
                        )
                    )
                    raise GovernanceError(
                        "idempotency key reused for a different request; tool blocked",
                        code="idempotency_conflict",
                        guard="idempotency",
                        audit_id=event_id,
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
                    return did, self._enforce(replace(decision, replayed=True))
                # Same request, new (mode, killswitch) stance: fall through to a
                # fresh evaluation and cache it under this stance's bucket.
            did, decision = await self._evaluate_and_audit(ctx)
            # Cache only a completed evaluation; a fail-closed system error raises
            # out of _evaluate_and_audit and is left un-cached so a retry re-runs.
            self._store_decision(key, fingerprint, did, decision)
            return did, self._enforce(decision)

    async def _evaluate_and_audit(self, ctx: GovernanceContext) -> tuple[str, Decision]:
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
            event_id = await self._audit.write(
                AuditEntry.from_decision(ctx, did, denial, outcome="error", mode=self._mode)
            )
            # A budget breach already carries its own stable code/guard and the
            # remedy message (D6/D8); attach the audit id and re-raise it unchanged
            # so a caller can branch on ``code == "decision_budget_exceeded"`` and
            # read ``limit_seconds``/``elapsed_seconds`` — wrapping it would erase
            # all of that behind a generic engine-failed string.
            if isinstance(exc, DecisionBudgetExceeded):
                exc.audit_id = event_id
                raise
            raise GovernanceError(
                "governance engine failed; tool blocked",
                code="engine_error",
                audit_id=event_id,
            ) from exc

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

    def _store_decision(self, key: str, fingerprint: str, did: str, decision: Decision) -> None:
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
        a timer. A breach raises :class:`DecisionBudgetExceeded` (carrying
        ``limit_seconds``/``elapsed_seconds`` and the remedy message) — an ordinary
        exception caught by the fail-closed boundary above, which audits it and
        re-raises it unchanged so a caller can branch on its ``.code``. In
        ``budget_mode == "shadow"`` the breach is observed (logged) but not raised.

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
        if self._budget_mode == _GUARD_SHADOW:
            # Observe-only (D10): measure the seam, record a would-breach, but never
            # enforce — the engine runs to completion and its result is used. The
            # observe-then-enforce upgrade path: watch the would-denies for a
            # release before flipping budget_mode to enforce. NOTE: shadow also
            # forfeits hang-protection — there is no timer, so a genuinely
            # non-returning engine hangs the governor indefinitely rather than
            # breaching. Shadow is a temporary observation stance, not a free one.
            start = self._time_fn()
            result = await coro
            elapsed = self._time_fn() - start
            if elapsed > self._timeout:
                _LOG.warning(
                    "decision budget WOULD breach (shadow): limit=%ss elapsed=%.4fs",
                    self._timeout,
                    elapsed,
                )
            return result
        start = self._time_fn()
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
            raise DecisionBudgetExceeded(self._timeout, elapsed_seconds=self._time_fn() - start)
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
            engine: PolicyEngine = self._fallback
        else:
            engine = self._policy
        # Wrap the SELECTED engine so the injection screen guards primary AND
        # fallback alike (#36, T1). The guard presents as a PolicyEngine, so an
        # injection hit is a policy deny folded into this seam (P2).
        if self._injection_classifier is not None:
            return GuardedEngine(engine, self._injection_classifier, mode=self._injection_mode)
        return engine

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

    async def _screen_output(self, result: Any, did: str, ctx: GovernanceContext) -> Any:
        """Screen a tool's return value through the output rails, fail-closed (#39/#40).

        Runs INSIDE proxy()'s effect path so the screened value is what gets cached.
        With no classifiers wired the seam is inert — the raw value passes through.
        Otherwise the value is projected to text (the C0 extraction contract) and
        each rail screens it.

        **Read path (IO_READ, ENFORCE hit):** withhold the value and raise
        :class:`OutputGovernanceDenied`; the error's ``audit_id`` back-links to the
        ``output_denied_raised`` row. An allowed output emits ``output_allowed``.

        **Write path (IO_WRITE, ENFORCE hit, #40):** the side effect already
        happened (the design's output-deny asymmetry). Instead of raising we:
        1. Write a HIGH-severity ``output_denied_redacted`` audit row.
        2. Return a :class:`~zemtik_govern.output.RedactedOutput` sentinel
           (spare str/repr, poison getattr/iter/getitem) so the offending value
           never reaches the caller but structured logging never crashes either.

        **Rail fault on write:** if ``classifier.screen()`` itself raises on a
        WRITE tool, the response is the same as an ENFORCE hit — return
        ``RedactedOutput`` with ``rail="rail_fault"`` and a HIGH-severity row.
        On a READ tool a classifier fault re-raises (fail closed).

        Shadow (observe-only): when the global mode is ``shadow`` OR a rail's own
        mode is ``shadow``, that rail's match is OBSERVED — an ``output_would_deny``
        row is written and the value is returned unblocked. Global shadow makes
        EVERY rail (and extraction failures) observe-only, mirroring the input-side
        ``_enforce`` contract so a whole-governor shadow rollout never hard-blocks.

        ``did`` is the identity-resolved subject, threaded from ``govern`` so output
        rows are attributed to the SAME agent the input row names.
        """
        if not self._output_classifiers:
            return result
        global_shadow = self._mode == _SHADOW
        # Warn-once for actions absent from _tool_io_map (Issue #42). An action not
        # in the map silently defaults to write (fail-closed), which is the right
        # security posture — but a READ tool the operator forgot to classify becomes
        # a write tool, and its PII output will be silently redacted (RedactedOutput)
        # in production rather than being caught and fixed at development time. The
        # warn fires on the FIRST call for each novel unmapped action so the operator
        # sees it immediately in dev/staging logs, before it ships. Subsequent calls
        # for the SAME action are silent (alert fatigue defeats the purpose). A plain
        # set is safe because asyncio is single-threaded.
        if ctx.action not in self._tool_io_map and ctx.action not in self._output_warned_actions:
            self._output_warned_actions.add(ctx.action)
            _LOG.warning(
                "output seam: action %r is unmapped in tool_io_map — "
                "defaulting to write (fail-closed). Add it to tool_io_map "
                "to suppress this warning and confirm the classification.",
                ctx.action,
            )
        io = resolve_io(self._tool_io_map, ctx.action)
        try:
            text = extract_text(result)
        except OutputExtractionError as exc:
            # An unscreenable return (custom object, non-UTF-8 bytes, oversized, a
            # generator/iterator) is a screening failure governed by the GLOBAL mode:
            # under global shadow it is observed (value returned); otherwise it is a
            # fail-closed deny. The message names the offending type, never the value.
            if global_shadow:
                await self._write_output(ctx, did, event="would_deny", rail="extraction")
                _LOG.warning("output extraction WOULD deny (shadow): %s", exc)
                return result
            event_id = await self._write_output(ctx, did, event="denied_raised", rail="extraction")
            raise OutputGovernanceDenied(
                f"tool output could not be screened; blocked. {exc}",
                rail="extraction",
                audit_id=event_id,
            ) from exc
        observed_would_deny = False
        for classifier in self._output_classifiers:
            # --- Rail fault handling: classifier.screen() may itself raise. ----
            # On a WRITE tool: return RedactedOutput + HIGH audit (same as an
            # ENFORCE hit) — the side effect already happened and we must never
            # pass through an unscreened value. On a READ tool: re-raise so the
            # fail-closed guarantee holds for the read path.
            try:
                verdict = await classifier.screen(text, ctx)
            except Exception as exc:  # noqa: BLE001 — intentional broad catch
                rail_name = getattr(classifier, "name", "unknown")
                _LOG.error(
                    "output rail %r raised during screen(); treating as deny. %s",
                    rail_name,
                    exc,
                )
                if io == IO_WRITE:
                    event_id = await self._write_output(
                        ctx, did, event="denied_redacted", rail="rail_fault", severity="HIGH"
                    )
                    from .output import RedactedOutput
                    return RedactedOutput(audit_id=event_id)
                # Read tool: re-raise (fail closed).
                event_id = await self._write_output(
                    ctx, did, event="denied_raised", rail="rail_fault"
                )
                raise OutputGovernanceDenied(
                    f"output rail {rail_name!r} raised during screening; "
                    f"blocked fail-closed. {exc}",
                    rail="rail_fault",
                    audit_id=event_id,
                ) from exc

            if not verdict.is_match:
                continue
            rail_shadow = global_shadow or getattr(classifier, "mode", _GUARD_ENFORCE) == _SHADOW
            if rail_shadow:
                # Observe-only: record the would-deny (no value echo) and keep
                # scanning — the value is returned unless a later ENFORCE rail fires.
                await self._write_output(ctx, did, event="would_deny", rail=verdict.rail)
                _LOG.warning("output rail %r WOULD deny (shadow): %s", verdict.rail, verdict.reason)
                observed_would_deny = True
                continue
            if io == IO_READ:
                # Read path: withhold the value and raise. No-echo: name the
                # rail + the tunable knob, never the value (D6).
                event_id = await self._write_output(
                    ctx, did, event="denied_raised", rail=verdict.rail
                )
                raise OutputGovernanceDenied(
                    f"output blocked by the {verdict.rail!r} rail "
                    f"({verdict.reason}); tune it via rails."
                    f"{verdict.rail}.threshold/mode",
                    rail=verdict.rail,
                    audit_id=event_id,
                )
            # Write path (#40): the side effect already happened. Return the
            # redaction sentinel + write a HIGH-severity audit row. The caller
            # never receives the offending value (no-echo, D6), and structured
            # logging (str/repr of the sentinel) never crashes.
            event_id = await self._write_output(
                ctx, did, event="denied_redacted", rail=verdict.rail, severity="HIGH"
            )
            from .output import RedactedOutput
            return RedactedOutput(audit_id=event_id)
        # No ENFORCE rail fired. Record ``output_allowed`` only when the output was
        # genuinely clean; a shadow-observed would-deny already has its own row.
        if not observed_would_deny:
            await self._write_output(ctx, did, event="allowed", rail=None)
        return result

    async def _write_output(
        self,
        ctx: GovernanceContext,
        did: str,
        *,
        event: str,
        rail: str | None,
        severity: str | None = None,
    ) -> str:
        """Write one output-seam audit row and return its id so a raised exception
        or a returned sentinel correlates to it via ``.audit_id``.

        ``event`` is one of ``allowed`` / ``denied_raised`` / ``would_deny`` /
        ``denied_redacted`` (the #40 write-tool path). ``severity`` is ``"HIGH"``
        for the ``denied_redacted`` and rail-fault events so a SIEM consumer can
        filter on severity without inspecting ``event_type``.
        """
        return await self._audit.write(
            AuditEntry.from_output(
                ctx, did, event=event, rail=rail, mode=self._mode, severity=severity
            )
        )

    def unwrap(self, result: Any) -> Any:
        """Collapse the read-deny-raises / write-deny-returns asymmetry into one call.

        The output seam has two enforcement shapes:

        * **Read-classified tools** raise :class:`~zemtik_govern.errors.OutputGovernanceDenied`
          directly from ``proxy()`` when an enforce rail fires — the caller never
          receives the offending value.
        * **Write-classified tools** *return* a
          :class:`~zemtik_govern.output.RedactedOutput` sentinel so the already-
          executed side effect can be logged/tracked, but the redacted value must
          never be used downstream.

        ``unwrap()`` bridges that asymmetry: wrap **every** governed result in it
        and the caller sees a uniform contract — clean value through, denied value
        raises — without needing to ``isinstance``-check for the sentinel::

            result = await proxy_write()
            value  = gov.unwrap(result)   # raises if result is RedactedOutput

        **No-echo (D6):** the message names the contract ("output was redacted")
        and the ``audit_id`` back-link, never the withheld value itself.

        Args:
            result: The value returned by a governed proxy call.

        Returns:
            *result* unchanged when it is **not** a
            :class:`~zemtik_govern.output.RedactedOutput`.

        Raises:
            :class:`~zemtik_govern.errors.OutputGovernanceDenied`: when *result*
            is a :class:`~zemtik_govern.output.RedactedOutput` sentinel, carrying
            the sentinel's ``audit_id`` so the caller can correlate to the audit
            trail without re-deriving anything.
        """
        from .output import RedactedOutput

        if isinstance(result, RedactedOutput):
            # Use object.__getattribute__ to bypass the sentinel's poison
            # __getattr__ hook — audit_id is a frozen dataclass field stored in
            # __dict__, but we play it safe in case the sentinel is partially
            # constructed (e.g. in tests).
            try:
                aid = object.__getattribute__(result, "audit_id")
            except AttributeError:
                aid = None
            raise OutputGovernanceDenied(
                "output was redacted by an output rail; the value is withheld "
                f"(audit_id={aid!r}); check the audit trail for details",
                audit_id=aid,
            )
        return result

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

    def _build_ctx(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> GovernanceContext:
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
                    f"context_factory must return a GovernanceContext, got {type(ctx).__name__}"
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
            # Capture the resolved DID (xmodel #1) so the output seam attributes its
            # events to the same agent the input row names. A2: the non-keyed path
            # gets output screening but NOT effect-idempotency (documented, mirrors
            # the existing replay tradeoff).
            did, _decision = await self._gov._govern_with_did(ctx)  # raises on deny
            return await self._invoke(args, kwargs, did, ctx)

        # INVARIANT (single-tool-run): there must be NO await between this
        # _effect_get returning None and the _effect_reserve below in the
        # first-call branch. asyncio runs that check-then-reserve without
        # interleaving, so a concurrent same-key duplicate is guaranteed to see
        # either the reserved future here or wait on the key lock — never to race
        # into a second tool invocation. Moving an await between them reopens a
        # two-tool-run window. Keep them adjacent.
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
        task: asyncio.Future[Any] = asyncio.ensure_future(self._effect(ctx, args, kwargs))
        self._gov._effect_reserve(key, task)
        task.add_done_callback(self._evict_failed_effect(key))
        # ``shield`` so this caller's cancellation can't cancel the shared effect;
        # the task runs to completion once and the done-callback (not this caller)
        # owns slot cleanup.
        return await asyncio.shield(task)

    def _evict_failed_effect(self, key: str) -> Callable[[asyncio.Future[Any]], None]:
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
        did, _decision = await self._gov._govern_with_did(ctx)  # raises on deny
        return await self._invoke(args, kwargs, did, ctx)

    async def _invoke(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        did: str,
        ctx: GovernanceContext,
    ) -> Any:
        """Call the wrapped function (awaiting a coroutine return), then screen its
        output through the governor's rails (#39) before handing it back.

        The screen runs HERE — inside the effect path shared by the keyed and
        non-keyed callers — so the screened value is the one cached for a keyed
        replay; the unscreened original never leaks on replay. The resolved ``did``
        is threaded so output events are attributed to the governed agent."""
        result = self._fn(*args, **kwargs)
        if inspect.isawaitable(result):
            result = await result
        return await self._gov._screen_output(result, did, ctx)
