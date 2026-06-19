"""Registry — wires the three protocol implementations into one ``ZemtikGovern``.

The single place that knows how a :class:`~zemtik_govern.config.GovernanceConfig`
and an :class:`~zemtik_govern._agt.AGTBoundary` become wired identity / policy /
audit seams. ``build()`` refuses to return a core with a missing seam — the same
fail-at-startup contract that config holds, so there is no way to assemble a
half-wired governor that quietly skips a concern at request time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .core import ZemtikGovern
from .errors import GovernanceNotConfigured
from .protocols import AuditSink, IdentityProvider, PolicyEngine

if TYPE_CHECKING:
    from ._agt import AGTBoundary
    from .config import GovernanceConfig


class GovernanceRegistry:
    """Collects the three seams, then builds the orchestration core."""

    def __init__(self) -> None:
        self._identity: IdentityProvider | None = None
        self._policy: PolicyEngine | None = None
        self._audit: AuditSink | None = None

    def register_identity(self, impl: IdentityProvider) -> GovernanceRegistry:
        self._identity = impl
        return self

    def register_policy(self, impl: PolicyEngine) -> GovernanceRegistry:
        self._policy = impl
        return self

    def register_audit(self, impl: AuditSink) -> GovernanceRegistry:
        self._audit = impl
        return self

    def build(self) -> ZemtikGovern:
        missing = [
            name
            for name, seam in (
                ("identity", self._identity),
                ("policy", self._policy),
                ("audit", self._audit),
            )
            if seam is None
        ]
        if missing:
            raise GovernanceNotConfigured(
                f"registry missing seam(s): {', '.join(missing)}"
            )
        return ZemtikGovern(
            identity=self._identity,  # type: ignore[arg-type]
            policy=self._policy,  # type: ignore[arg-type]
            audit=self._audit,  # type: ignore[arg-type]
        )

    @classmethod
    def from_config(
        cls, config: GovernanceConfig, boundary: AGTBoundary
    ) -> GovernanceRegistry:
        """Wire the v0.1 default seams from a validated config + AGT boundary:
        StaticIdentity, deny-by-default AgentOsPolicy, Merkle-chained AgentMeshAudit.
        """
        # Local imports keep registry importable without dragging the whole AGT
        # surface in until something actually wires from config.
        from .identity import StaticIdentity
        from .policy import AgentOsPolicy

        # Resolve the audit sink FIRST: an unsupported sink is a config error, and
        # config errors should surface before any AGT object is constructed.
        audit = cls._build_audit(config, boundary)

        # Empty rules only reaches here in shadow mode; strict/enforce reject it
        # at config time, so the None (no PolicyDocument) path is not a missed deny.
        rules = list(config.rules) or None
        return (
            cls()
            .register_identity(StaticIdentity(boundary))
            .register_policy(
                AgentOsPolicy(boundary, rules=rules, root_dir=config.policy_dir)
            )
            .register_audit(audit)
        )

    @staticmethod
    def _build_audit(config: GovernanceConfig, boundary: AGTBoundary) -> AuditSink:
        """Honour the validated ``audit_sink`` instead of silently defaulting.

        ``"memory"`` (or unset) selects the in-memory Merkle log. Anything else
        is a file/external sink, which lands in S5 — fail loud now rather than
        discard the configured destination and write the trail somewhere the
        operator did not choose.
        """
        from .audit import AgentMeshAudit

        sink = config.audit_sink
        if sink in (None, "memory"):
            return AgentMeshAudit(boundary)
        raise GovernanceNotConfigured(
            f"audit_sink {sink!r} not supported yet; only 'memory' is wired in v0.1 (file sink: S5)"
        )
