"""The orchestration core — one ``govern()`` call, fail-closed.

Order is fixed (A2): identity → policy → audit. Identity first because policy may
key on the subject and every audit entry is stamped with the DID. Audit last
because it records the final decision — EVERY outcome, including fail-closed
denials. Any unexpected exception is wrapped as :class:`GovernanceError`, audited
as a denial, and re-raised — the tool never runs (no ``scheduler.py:29-30``
fall-through).
"""

from __future__ import annotations

import asyncio
import inspect
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


class ZemtikGovern:
    """Wires the three seams and runs them in the sanctioned order."""

    def __init__(
        self,
        identity: IdentityProvider,
        policy: PolicyEngine,
        audit: AuditSink,
    ) -> None:
        self._identity = identity
        self._policy = policy
        self._audit = audit

    async def govern(self, ctx: GovernanceContext) -> Decision:
        # Identity AND policy run inside the fail-closed boundary: a fault in
        # EITHER is a system denial, audited then re-raised. Identity is no
        # exception — an unaudited, unwrapped identity failure would be a hole in
        # the "every outcome audited" contract. If identity is what failed we have
        # no DID, so the audit entry is stamped with the reserved unidentified DID.
        did = _UNIDENTIFIED_DID
        try:
            did = await self._identity.identify(ctx.subject)
            decision = await self._policy.evaluate(ctx)
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
                AuditEntry.from_decision(ctx, did, denial, outcome="error")
            )
            raise GovernanceError("governance engine failed; tool blocked") from exc

        event_id = await self._audit.write(AuditEntry.from_decision(ctx, did, decision))
        decision = replace(decision, audit_event_id=event_id)
        if not decision.allowed:
            raise GovernanceDenied(decision)
        return decision

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

    def _build_ctx(
        self, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> GovernanceContext:
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
        ctx = self._build_ctx(args, kwargs)
        await self._gov.govern(ctx)  # raises on deny -> the tool never runs
        result = self._fn(*args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result
