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
        self._mode: str = "enforce"

    def register_mode(self, mode: str) -> GovernanceRegistry:
        """The operational mode (``shadow``/``enforce``/``strict``) the built core
        runs in. Validated at config time; recorded here so ``build()`` carries it
        into the core rather than defaulting silently."""
        self._mode = mode
        return self

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
            mode=self._mode,
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
            .register_mode(config.mode)
            .register_identity(StaticIdentity(boundary))
            .register_policy(
                AgentOsPolicy(boundary, rules=rules, root_dir=config.policy_dir)
            )
            .register_audit(audit)
        )

    # The HMAC signing key for a file audit sink is read from the environment,
    # never the config file — a signing secret does not belong in checked-in YAML.
    _AUDIT_SECRET_ENV = "ZEMTIK_AUDIT_SECRET"

    @staticmethod
    def _build_audit(config: GovernanceConfig, boundary: AGTBoundary) -> AuditSink:
        """Honour the validated ``audit_sink`` instead of silently defaulting.

        ``"memory"`` (or unset) selects the in-memory Merkle log. Any other value
        is treated as a file path and backed by a durable, HMAC-signed
        :class:`FileAuditSink`. The signing key comes from
        ``$ZEMTIK_AUDIT_SECRET``; a file sink without it is a startup error — an
        unsigned tamper-evident log is a contradiction, not a degraded mode.
        """
        import os

        from .audit import AgentMeshAudit

        sink = config.audit_sink
        if sink in (None, "memory"):
            return AgentMeshAudit(boundary)

        secret = os.environ.get(GovernanceRegistry._AUDIT_SECRET_ENV)
        if not secret:
            raise GovernanceNotConfigured(
                f"file audit_sink {sink!r} requires an HMAC secret in "
                f"${GovernanceRegistry._AUDIT_SECRET_ENV}; refusing an unsigned trail"
            )
        file_sink = boundary.file_audit_sink(sink, secret.encode("utf-8"))
        return AgentMeshAudit(boundary, sink=file_sink)
