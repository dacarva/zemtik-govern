"""The policy core — deny-by-default over a fail-open AGT evaluator.

``AgentOsPolicy`` is the wrapper's :class:`~zemtik_govern.protocols.PolicyEngine`.
Its single job that AGT will not do for you: when no rule matches, AGT returns
``allowed=True`` (``matched_rule is None``). This adapter overrides that to a
deny. The fail-closed rule lives here, next to the AGT call it guards — not
scattered across call sites.
"""

from __future__ import annotations

from typing import Any

from ._agt import AGTBoundary
from .context import GovernanceContext
from .protocols import Decision


class AgentOsPolicy:
    """Deny-by-default policy engine backed by ``agent_os`` through the boundary."""

    def __init__(
        self,
        boundary: AGTBoundary,
        rules: list[dict[str, Any]] | None = None,
        root_dir: str | None = None,
    ) -> None:
        policies = [boundary._policy_document(rules)] if rules else None
        self._evaluator = boundary._policy_evaluator(policies=policies, root_dir=root_dir)

    async def evaluate(self, ctx: GovernanceContext) -> Decision:
        raw = self._evaluator.evaluate(ctx.to_dict())

        # The moat: AGT fails OPEN on no-match. Override to deny-by-default.
        if raw.matched_rule is None:
            return Decision(
                allowed=False,
                action="deny",
                matched_rule=None,
                reason="deny-by-default: no policy rule matched",
                denial_kind="policy",
            )

        return Decision(
            allowed=bool(raw.allowed),
            action=str(raw.action),
            matched_rule=str(raw.matched_rule),
            reason=str(raw.reason),
            denial_kind=None if raw.allowed else "policy",
        )
