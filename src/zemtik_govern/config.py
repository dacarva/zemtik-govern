"""Config — parse the wrapper's startup configuration and refuse insecure shapes.

Fail at *startup*, not at request time. A wrapper booted into a shape that can
silently let tools through — a policy-enforcing mode with nothing to enforce, or
any mode with no audit trail — raises
:class:`~zemtik_govern.errors.GovernanceNotConfigured` before it ever sees a
request. The check lives here, next to the parse, so the insecure config never
reaches the orchestrator.

Modes:

- ``strict``  — the secure default. Requires policy rules (inline or a non-empty
  ``policy_dir``) AND an audit sink.
- ``enforce`` — same enforcement surface as strict (reserved for the S4
  kill-switch wiring). Validated identically to strict: the strongest-sounding
  mode must NOT be the least-validated.
- ``shadow``  — observe-only. Relaxed on the policy source (it does not block),
  but STILL requires an audit sink — observing into nowhere is not observing.

Every mode requires an audit sink. Only ``strict`` and ``enforce`` require a
policy source.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .errors import GovernanceNotConfigured

VALID_MODES: tuple[str, ...] = ("strict", "shadow", "enforce")

# Modes that block on policy: they MUST have a usable policy source.
_ENFORCING_MODES: tuple[str, ...] = ("strict", "enforce")

# The default per-call decision budget (seconds). Bounds the identity + policy
# path so a config-built governor is never silently unbounded. Generous enough to
# not trip a healthy engine, tight enough that a hung seam fails closed promptly;
# latency-sensitive deployments lower it, see docs/configuration-reference.md.
_DEFAULT_DECISION_BUDGET_SECONDS: float = 5.0

# Bounded idempotency caches (#35). Both the decision ledger and the proxy's
# effect-dedup slots ride one bounded LRU+TTL cache, so unique-key traffic cannot
# grow them without bound (a DoS surface) and a stale decision expires and
# re-evaluates. Defaults are generous for a single process; tune down on
# memory-constrained or high-cardinality-key deployments.
_DEFAULT_IDEM_MAX_ENTRIES: int = 10_000
_DEFAULT_IDEM_TTL_SECONDS: float = 3600.0


@dataclass(frozen=True)
class GovernanceConfig:
    """Parsed, validated startup configuration.

    ``rules`` are inline AGT rule dicts; ``policy_dir`` points at a directory of
    policy files AGT loads. ``audit_sink`` names where the trail goes
    (``"memory"`` for the in-memory Merkle log, or a file path for S5's file sink).

    Frozen value object with default (value) equality — two configs parsed from
    the same source compare equal. Not used as a dict key, so the dict-bearing
    ``rules`` field never needs hashing.
    """

    mode: str = "strict"
    rules: tuple[dict[str, Any], ...] = ()
    policy_dir: str | None = None
    audit_sink: str | None = None
    # Per-call decision budget (SECONDS) for the identity + policy path, threaded
    # to ``ZemtikGovern(timeout=)``. Unit-suffixed (D5) so the seconds-vs-ms 1000×
    # footgun dies at the name. Defaults to a real bound — a config-built governor
    # must never silently run unbounded (#33). ``None`` is an explicit opt-out for
    # callers that enforce their own upstream deadline.
    decision_budget_seconds: float | None = _DEFAULT_DECISION_BUDGET_SECONDS
    # Bounded idempotency cache controls (#35). ``idempotency_max_entries`` caps
    # the shared LRU; ``idempotency_ttl_seconds`` expires a ledgered decision so a
    # later same-key request re-evaluates rather than replaying a stale verdict.
    idempotency_max_entries: int = _DEFAULT_IDEM_MAX_ENTRIES
    idempotency_ttl_seconds: float | None = _DEFAULT_IDEM_TTL_SECONDS
    # Path to the EXPLICIT prompt-injection rule file (#36). Mandatory in
    # non-shadow modes: the registry refuses to wire a governor without it rather
    # than ship AGT's sample rules. The presence requirement is enforced at wiring
    # time (registry.from_config), where the file is actually loaded and a missing
    # or malformed file becomes a fail-closed GovernanceNotConfigured.
    injection_rules_path: str | None = None

    def __post_init__(self) -> None:
        """Validate the config, raising :class:`GovernanceNotConfigured` on any insecure shape.

        All validation runs at parse time so an insecure config never reaches the
        orchestrator. Normalises ``rules`` to an immutable tuple.
        """
        # Normalise rules to an immutable tuple regardless of how they arrived.
        object.__setattr__(self, "rules", tuple(self.rules))
        if self.mode not in VALID_MODES:
            raise GovernanceNotConfigured(
                f"unknown mode {self.mode!r}; expected one of {VALID_MODES}"
            )
        self._validate_rule_shapes()
        self._validate_decision_budget()
        self._validate_idempotency_caps()
        # Universal: no mode is allowed to run without somewhere to record outcomes.
        if not self.audit_sink:
            raise GovernanceNotConfigured(
                f"{self.mode} mode requires an audit sink; none configured"
            )
        # Enforcing modes additionally need something to enforce.
        if self.mode in _ENFORCING_MODES:
            self._validate_policy_source()

    def _validate_rule_shapes(self) -> None:
        """Ensure every rule is a Mapping; a non-mapping rule is a config error, not runtime."""
        for i, rule in enumerate(self.rules):
            if not isinstance(rule, Mapping):
                raise GovernanceNotConfigured(
                    f"rule {i} must be a mapping, got {type(rule).__name__}"
                )

    def _validate_decision_budget(self) -> None:
        """A budget that is present must be a positive, finite number of seconds.

        ``None`` (explicit opt-out) is allowed; ``0``, negatives, and non-numbers
        are not — a non-positive budget would make every decision time out instantly,
        denying all traffic, which is a misconfiguration, not a security stance.
        ``bool`` is rejected explicitly: it is an ``int`` subclass, and ``True`` as a
        1-second budget is almost certainly a typo, not an intent.
        """
        budget = self.decision_budget_seconds
        if budget is None:
            return
        if isinstance(budget, bool) or not isinstance(budget, (int, float)):
            raise GovernanceNotConfigured(
                f"decision_budget_seconds must be a number of seconds or None, "
                f"got {type(budget).__name__}"
            )
        if budget <= 0:
            raise GovernanceNotConfigured(
                f"decision_budget_seconds must be > 0, got {budget!r}"
            )

    def _validate_idempotency_caps(self) -> None:
        """The cache cap must be a positive int; the TTL, if present, a positive
        finite number of seconds. A zero/negative cap or TTL is a misconfiguration
        (it would evict everything instantly), not a tuning choice. ``None`` TTL is
        an explicit opt-out (no expiry). ``bool`` is rejected (an ``int`` subclass)."""
        cap = self.idempotency_max_entries
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
            raise GovernanceNotConfigured(
                f"idempotency_max_entries must be a positive int, got {cap!r}"
            )
        ttl = self.idempotency_ttl_seconds
        if ttl is None:
            return
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0:
            raise GovernanceNotConfigured(
                f"idempotency_ttl_seconds must be > 0 or None, got {ttl!r}"
            )

    def _validate_policy_source(self) -> None:
        """Raise if an enforcing mode has no usable policy source (no rules AND no policy_dir)."""
        if not self.rules and self.policy_dir is None:
            raise GovernanceNotConfigured(
                f"{self.mode} mode requires policy rules or a policy_dir; got zero rules"
            )
        if self.policy_dir is not None and not self._policy_dir_has_files():
            raise GovernanceNotConfigured(
                f"{self.mode} mode + empty policy dir: {self.policy_dir!r} has no policy files"
            )

    def _policy_dir_has_files(self) -> bool:
        """Return True if ``policy_dir`` exists and contains at least one file."""
        directory = Path(self.policy_dir) if self.policy_dir else None
        if directory is None or not directory.is_dir():
            return False
        return any(child.is_file() for child in directory.iterdir())

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> GovernanceConfig:
        """Build a config from a parsed dict (e.g. from ``yaml.safe_load``).

        Coerces and validates field types before handing to ``__post_init__``,
        so callers get a :class:`GovernanceNotConfigured` with a clear field name
        rather than a raw ``TypeError`` deep in the dataclass.
        """
        if not isinstance(data, Mapping):
            raise GovernanceNotConfigured("config root must be a mapping")
        rules = data.get("rules") or []
        if not isinstance(rules, (list, tuple)):
            raise GovernanceNotConfigured("config 'rules' must be a list")
        policy_dir = data.get("policy_dir")
        if policy_dir is not None and not isinstance(policy_dir, str):
            raise GovernanceNotConfigured("config 'policy_dir' must be a string")
        audit_sink = data.get("audit_sink")
        if audit_sink is not None and not isinstance(audit_sink, str):
            raise GovernanceNotConfigured("config 'audit_sink' must be a string")
        budget = data.get("decision_budget_seconds", _DEFAULT_DECISION_BUDGET_SECONDS)
        if budget is not None and (
            isinstance(budget, bool) or not isinstance(budget, (int, float))
        ):
            raise GovernanceNotConfigured(
                "config 'decision_budget_seconds' must be a number of seconds or null, "
                f"got {type(budget).__name__}"
            )
        cap = data.get("idempotency_max_entries", _DEFAULT_IDEM_MAX_ENTRIES)
        if isinstance(cap, bool) or not isinstance(cap, int):
            raise GovernanceNotConfigured(
                "config 'idempotency_max_entries' must be an int, "
                f"got {type(cap).__name__}"
            )
        ttl = data.get("idempotency_ttl_seconds", _DEFAULT_IDEM_TTL_SECONDS)
        if ttl is not None and (
            isinstance(ttl, bool) or not isinstance(ttl, (int, float))
        ):
            raise GovernanceNotConfigured(
                "config 'idempotency_ttl_seconds' must be a number of seconds or null, "
                f"got {type(ttl).__name__}"
            )
        injection_rules_path = data.get("injection_rules_path")
        if injection_rules_path is not None and not isinstance(injection_rules_path, str):
            raise GovernanceNotConfigured(
                "config 'injection_rules_path' must be a string path or null, "
                f"got {type(injection_rules_path).__name__}"
            )
        return cls(
            mode=str(data.get("mode", "strict")),
            rules=tuple(rules),
            policy_dir=policy_dir,
            audit_sink=audit_sink,
            decision_budget_seconds=budget,
            idempotency_max_entries=cap,
            idempotency_ttl_seconds=ttl,
            injection_rules_path=injection_rules_path,
        )

    @classmethod
    def load(cls, path: str | Path) -> GovernanceConfig:
        """Read and validate a YAML config file. Any read or parse failure is a
        startup error, not a None-returning silent skip."""
        p = Path(path)
        try:
            raw = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise GovernanceNotConfigured(f"cannot read config {str(path)!r}: {exc}") from exc
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise GovernanceNotConfigured(f"invalid YAML in {str(path)!r}: {exc}") from exc
        return cls.from_mapping(data or {})
