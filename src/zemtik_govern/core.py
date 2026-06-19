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
import hashlib
import inspect
import json
from collections.abc import Callable
from dataclasses import replace
from typing import Any

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


def _request_fingerprint(ctx: GovernanceContext) -> str:
    """A stable hash of the part of the request policy actually decides on —
    action, subject, payload. Binds an idempotency key to ONE request so a key
    reused for a different action/subject/payload is detected as a conflict.
    ``ts`` and ``extra`` are excluded: a retried request keeps its identity even
    if the clock or out-of-band metadata moved."""
    canonical = json.dumps(
        {"action": ctx.action, "subject": ctx.subject, "payload": ctx.to_dict()["payload"]},
        sort_keys=True,
        default=str,
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
        self._idem_lock = asyncio.Lock()
        # key -> (request fingerprint, did, decision). The fingerprint binds the
        # key to the ONE request it was minted for: an idempotency key identifies a
        # request, it is not a bearer token that replays a prior allow onto any
        # action. A key reused with a different action/subject/payload is a conflict,
        # not a duplicate, and fails closed (below) rather than bypassing policy.
        self._idem_ledger: dict[str, tuple[str, str, Decision]] = {}

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
        async with self._idem_lock:
            if key in self._idem_ledger:
                seen_fp, did, decision = self._idem_ledger[key]
                if seen_fp != fingerprint:
                    # Same key, different request: a conflict, not a duplicate.
                    # Replaying the prior decision here would let an ungoverned
                    # action ride a recycled key past policy. Fail closed: audit the
                    # conflict and raise — the tool never runs, policy is never
                    # bypassed. The conflicting request was never identity-resolved,
                    # so it is NOT attributable to the prior key holder: stamp the
                    # reserved unidentified DID, never the cached (first-caller) DID.
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
                # Genuine duplicate: record the REPLAY (not a second success/denied)
                # so the trail shows it was recognised, then re-apply the original
                # enforcement so the caller sees the same outcome. Flag the returned
                # decision as a replay so a DIRECT govern/govern_sync caller can skip
                # re-running its own side effect (the proxy dedupes effects itself).
                await self._audit.write(
                    AuditEntry.from_decision(
                        ctx, did, decision, outcome="replay", mode=self._mode
                    )
                )
                return self._enforce(replace(decision, replayed=True))
            did, decision = await self._evaluate_and_audit(ctx)
            # Cache only a completed evaluation; a fail-closed system error raises
            # out of _evaluate_and_audit and is left un-cached so a retry re-runs.
            self._idem_ledger[key] = (fingerprint, did, decision)
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

    async def _with_budget(self, coro):
        """Await *coro* under the configured decision budget. With no budget, a
        plain await; with one, ``asyncio.wait_for`` — whose ``TimeoutError`` is an
        ordinary exception caught by the fail-closed boundary above.

        **Known limitation (tracked in TODOS.md)**: ``asyncio.wait_for`` cancels
        the inner coroutine on a timeout breach, but it cannot prevent a
        *well-intentioned-but-wrong* engine from catching ``CancelledError``
        internally and returning a value anyway.  In that CPython edge case
        ``wait_for`` will return that value after the budget has already been
        declared breached — effectively producing a post-breach result.  This
        guard therefore assumes that identity and policy engines are
        *cancellation-safe*: they do not catch ``asyncio.CancelledError`` and
        swallow it.  Fixing this properly requires a more invasive design (shield
        + cancel + re-await with a secondary timeout), which is deferred to a
        future sprint.
        """
        if self._timeout is None:
            return await coro
        return await asyncio.wait_for(coro, self._timeout)

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
        # idempotency_key -> Future[result]. Dedupes the EFFECT: a keyed duplicate
        # returns this cached/in-flight result instead of re-invoking the tool. Only
        # successful effects are cached (failures/denies are popped), so a retry of a
        # transient fault re-runs. Process-local + unbounded in v0.1 (see TODOS.md).
        self._results: dict[str, asyncio.Future[Any]] = {}

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

        inflight = self._results.get(key)
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
        self._results[key] = task
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
            # Only a SUCCESSFUL effect stays cached; a cancel or an exception evicts.
            if task.cancelled() or task.exception() is not None:
                # Guard against a same-key task having already replaced this slot.
                if self._results.get(key) is task:
                    del self._results[key]

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
