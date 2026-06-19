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
from dataclasses import replace

from .context import GovernanceContext
from .errors import GovernanceDenied, GovernanceError
from .protocols import (
    AuditEntry,
    AuditSink,
    Decision,
    IdentityProvider,
    PolicyEngine,
)


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
        did = await self._identity.identify(ctx.subject)

        try:
            decision = await self._policy.evaluate(ctx)
        except Exception as exc:
            # Fail-closed: an engine fault is a SYSTEM denial, audited then
            # re-raised. The tool never runs; the original exception is preserved.
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
