"""Registry — wires the three protocol implementations into one ``ZemtikGovern``.

The single place that knows how a :class:`~zemtik_govern.config.GovernanceConfig`
and an :class:`~zemtik_govern._agt.AGTBoundary` become wired identity / policy /
audit seams. ``build()`` refuses to return a core with a missing seam — the same
fail-at-startup contract that config holds, so there is no way to assemble a
half-wired governor that quietly skips a concern at request time.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .core import ZemtikGovern
from .errors import GovernanceNotConfigured
from .protocols import AuditSink, IdentityProvider, PolicyEngine

_LOG = logging.getLogger("zemtik_govern")

if TYPE_CHECKING:
    from ._agt import AGTBoundary
    from .config import GovernanceConfig


class GovernanceRegistry:
    """Collects the three seams, then builds the orchestration core."""

    def __init__(self) -> None:
        """Start with all three seams empty. Call ``register_*`` then ``build()``."""
        self._identity: IdentityProvider | None = None
        self._policy: PolicyEngine | None = None
        self._audit: AuditSink | None = None
        self._mode: str = "enforce"
        # Per-call decision budget (seconds) for identity + policy. None until set
        # so the raw builder matches the core default; from_config threads the
        # config's (non-None) decision_budget_seconds so a config-built governor is
        # never silently unbounded (#33).
        self._decision_budget_seconds: float | None = None
        # Bounded idempotency cache controls (#35). None until set so the raw
        # builder defers to the core defaults; from_config threads the validated
        # config values so a config-built governor's caches are bounded.
        self._idem_max_entries: int | None = None
        self._idem_ttl_seconds: float | None = None
        self._idem_ttl_set: bool = False
        # Mandatory injection classifier in non-shadow modes (#36); None until wired.
        self._injection_classifier: Any | None = None
        # Per-guard stance (D10). Default enforce (the secure default); from_config
        # threads the validated config values so a guard runs shadow only when the
        # operator asked for it.
        self._injection_mode: str = "enforce"
        self._budget_mode: str = "enforce"

    def register_guard_modes(
        self, injection_mode: str, budget_mode: str
    ) -> GovernanceRegistry:
        """The per-guard stances (``enforce|shadow``) carried into
        ``ZemtikGovern``. Validated at config time; recorded here so ``build()``
        threads them rather than silently enforcing."""
        self._injection_mode = injection_mode
        self._budget_mode = budget_mode
        return self

    def register_injection_classifier(self, impl: Any) -> GovernanceRegistry:
        """The prompt-injection classifier carried into ``ZemtikGovern(
        injection_classifier=)``. Wrapped around the selected engine so primary and
        fallback are both guarded."""
        self._injection_classifier = impl
        return self

    def register_idempotency_caps(
        self, max_entries: int, ttl_seconds: float | None
    ) -> GovernanceRegistry:
        """The bounded-cache cap and TTL carried into ``ZemtikGovern``. Validated at
        config time; recorded here so ``build()`` threads them rather than silently
        defaulting."""
        self._idem_max_entries = max_entries
        self._idem_ttl_seconds = ttl_seconds
        self._idem_ttl_set = True
        return self

    def register_decision_budget(
        self, seconds: float | None
    ) -> GovernanceRegistry:
        """The per-call decision budget (seconds) carried into ``ZemtikGovern(
        timeout=)``. ``None`` leaves the path unbounded (opt-out). Validated at
        config time; recorded here so ``build()`` threads it rather than silently
        defaulting to no budget."""
        self._decision_budget_seconds = seconds
        return self

    def register_mode(self, mode: str) -> GovernanceRegistry:
        """The operational mode (``shadow``/``enforce``/``strict``) the built core
        runs in. Validated at config time; recorded here so ``build()`` carries it
        into the core rather than defaulting silently."""
        self._mode = mode
        return self

    def register_identity(self, impl: IdentityProvider) -> GovernanceRegistry:
        """Register the :class:`~zemtik_govern.protocols.IdentityProvider` seam."""
        self._identity = impl
        return self

    def register_policy(self, impl: PolicyEngine) -> GovernanceRegistry:
        """Register the :class:`~zemtik_govern.protocols.PolicyEngine` seam."""
        self._policy = impl
        return self

    def register_audit(self, impl: AuditSink) -> GovernanceRegistry:
        """Register the :class:`~zemtik_govern.protocols.AuditSink` seam."""
        self._audit = impl
        return self

    def build(self) -> ZemtikGovern:
        """Return a fully-wired :class:`ZemtikGovern`.

        Raises :class:`GovernanceNotConfigured` if any seam is missing — a
        half-wired core would silently skip a concern at request time.
        """
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
        # Only override the core's cache defaults when from_config supplied them;
        # the raw builder leaves them untouched (matching the core default).
        extra: dict[str, Any] = {}
        if self._idem_max_entries is not None:
            extra["idem_max_entries"] = self._idem_max_entries
        if self._idem_ttl_set:
            extra["idem_ttl_seconds"] = self._idem_ttl_seconds
        if self._injection_classifier is not None:
            extra["injection_classifier"] = self._injection_classifier
        return ZemtikGovern(
            identity=self._identity,  # type: ignore[arg-type]
            policy=self._policy,  # type: ignore[arg-type]
            audit=self._audit,  # type: ignore[arg-type]
            mode=self._mode,
            timeout=self._decision_budget_seconds,
            injection_mode=self._injection_mode,
            budget_mode=self._budget_mode,
            **extra,
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

        # Build the mandatory injection classifier (#36, T3). A non-shadow governor
        # MUST ship explicit rules — refusing sample coverage is the security
        # stance, mirroring the AGT-pins / audit-secret boot-time contract.
        classifier = cls._build_injection_classifier(config, boundary)

        # The confidence floor (D5/Q2) is a reserved paranoid-mode dial: validated
        # but not yet load-bearing (the shipped AGT screen exposes no per-detection
        # confidence). Make the inert-ness visible at BOOT, not only in docs, so an
        # operator who set a non-zero floor expecting fewer denies sees that it has
        # no runtime effect rather than silently getting full enforcement.
        if config.injection_confidence_floor > 0.0:
            _LOG.warning(
                "injection_confidence_floor=%s is set but reserved (not yet "
                "load-bearing); detections are not filtered by confidence",
                config.injection_confidence_floor,
            )

        # Empty rules only reaches here in shadow mode; strict/enforce reject it
        # at config time, so the None (no PolicyDocument) path is not a missed deny.
        rules = list(config.rules) or None
        return (
            cls()
            .register_mode(config.mode)
            .register_guard_modes(config.injection_mode, config.budget_mode)
            .register_decision_budget(config.decision_budget_seconds)
            .register_idempotency_caps(
                config.idempotency_max_entries, config.idempotency_ttl_seconds
            )
            .register_identity(StaticIdentity(boundary))
            .register_policy(
                AgentOsPolicy(boundary, rules=rules, root_dir=config.policy_dir)
            )
            .register_audit(audit)
            .register_injection_classifier(classifier)
        )

    # Modes that must NOT run without an explicit injection rule set.
    _SHADOW_MODE = "shadow"

    @staticmethod
    def _build_injection_classifier(config: GovernanceConfig, boundary: AGTBoundary):
        """Build the AGT-backed injection classifier, fail-closed (#36).

        Non-shadow modes REQUIRE an explicit ``injection_rules_path``; a missing
        path, or a file that does not exist / lacks the required sections, is a
        startup error (``GovernanceNotConfigured``) — never a silent fall-back to
        AGT's sample rules. Shadow mode (observe-only) may omit it; if a path is
        given it is still wired and validated."""
        from .injection import AgtInjectionClassifier

        path = config.injection_rules_path
        if not path:
            if config.mode == GovernanceRegistry._SHADOW_MODE:
                return None
            raise GovernanceNotConfigured(
                f"{config.mode} mode requires an explicit injection_rules_path; "
                "refusing to run on AGT sample injection rules"
            )
        try:
            return AgtInjectionClassifier(boundary, path)
        except (FileNotFoundError, ValueError) as exc:
            raise GovernanceNotConfigured(
                f"injection_rules_path {path!r} could not be loaded: {exc}"
            ) from exc

    # The HMAC signing key for a file audit sink is read from the environment,
    # never the config file — a signing secret does not belong in checked-in YAML.
    # Operators must set this env var when ``audit_sink`` is a file path; the
    # canonical reference for usage and security notes is ``docs/operations.md``.
    # This constant is intentionally private: external code should reference the
    # documented env var name (``"ZEMTIK_AUDIT_SECRET"``), not this symbol.
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
