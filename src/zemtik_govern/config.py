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
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml

from .errors import GovernanceNotConfigured

VALID_MODES: tuple[str, ...] = ("strict", "shadow", "enforce")

# Modes that block on policy: they MUST have a usable policy source.
_ENFORCING_MODES: tuple[str, ...] = ("strict", "enforce")

# Per-guard stance (D10): a single guard runs ``enforce`` (blocks) or ``shadow``
# (observes a would-deny without enforcing). The observe-then-enforce upgrade
# path, scoped to one guard. Default enforce — the secure default.
VALID_GUARD_MODES: tuple[str, ...] = ("enforce", "shadow")
_DEFAULT_GUARD_MODE: str = "enforce"

# Injection confidence floor (D5/D7, design Q2). A paranoid-mode dial, exposed in
# config but OFF by default (0.0 = every detection counts). Reserved: the shipped
# AGT screen does not yet surface a per-detection confidence to compare against,
# so a non-zero floor is accepted and documented but not yet load-bearing. Kept in
# config now so the name and the off-by-default contract are stable for callers.
_DEFAULT_INJECTION_CONFIDENCE_FLOOR: float = 0.0

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


# Output tool I/O classification (#39). An action maps to ``read`` or ``write``;
# an unmapped action defaults to ``write`` at the seam (fail-closed). Validated
# here so a typo'd classification is a startup error, not a silent miss.
VALID_IO_CLASSES: tuple[str, ...] = ("read", "write")

# Output-rail defaults: a rail observes (``shadow``) or blocks (``enforce``), with
# a confidence ``threshold`` honored per-provider (the regex PII rail is binary;
# scoring providers like Presidio surface real confidences in C1). 0.0 = every
# detection counts.
_DEFAULT_RAIL_THRESHOLD: float = 0.0


@dataclass(frozen=True)
class RailConfig:
    """One output rail's tuning: which rail, its confidence ``threshold``, and its
    ``mode`` (``enforce`` blocks, ``shadow`` observes). Frozen value object; the
    C0 seam ships one rail (``pii``), more arrive with the C1 ensemble."""

    name: str
    threshold: float = _DEFAULT_RAIL_THRESHOLD
    mode: str = _DEFAULT_GUARD_MODE

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise GovernanceNotConfigured(
                f"rail name must be a non-empty string, got {self.name!r}"
            )
        if self.mode not in VALID_GUARD_MODES:
            raise GovernanceNotConfigured(
                f"rail {self.name!r} mode must be one of {VALID_GUARD_MODES}, got {self.mode!r}"
            )
        thr = self.threshold
        if isinstance(thr, bool) or not isinstance(thr, (int, float)):
            raise GovernanceNotConfigured(
                f"rail {self.name!r} threshold must be a number in [0.0, 1.0], "
                f"got {type(thr).__name__}"
            )
        if not (0.0 <= thr <= 1.0):
            raise GovernanceNotConfigured(
                f"rail {self.name!r} threshold must be in [0.0, 1.0], got {thr!r}"
            )
        object.__setattr__(self, "threshold", float(thr))


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
    # Per-guard stance (D10). ``injection_mode`` / ``budget_mode`` = ``enforce`` |
    # ``shadow``. Independent of the global ``mode``: an integrator can run a NEW
    # guard in shadow for one release (observe would-denies), then flip to enforce
    # — boring upgrades. Default enforce; the global ``mode`` still gates overall.
    injection_mode: str = _DEFAULT_GUARD_MODE
    budget_mode: str = _DEFAULT_GUARD_MODE
    # Injection confidence floor (D5/D7, design Q2). Off by default (0.0). Reserved
    # paranoid-mode dial; see the module constant. Documented off-by-default in
    # docs/configuration-reference.md.
    injection_confidence_floor: float = _DEFAULT_INJECTION_CONFIDENCE_FLOOR
    # Output-governance seam (#39, C0). ``output_screening`` enables the
    # post-invocation rail seam in proxy() (off by default — opt-in). ``tool_io_map``
    # classifies each action ``read``|``write`` (unmapped → ``write`` at the seam,
    # fail-closed). ``rails`` is the per-rail threshold/mode table. All three are
    # validated at startup, same discipline as every other field.
    output_screening: bool = False
    tool_io_map: Mapping[str, str] = field(default_factory=dict)
    rails: tuple[RailConfig, ...] = ()

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
        self._validate_guard_modes()
        self._validate_confidence_floor()
        self._validate_output_seam()
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
            raise GovernanceNotConfigured(f"decision_budget_seconds must be > 0, got {budget!r}")

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

    def _validate_guard_modes(self) -> None:
        """Each per-guard mode must be ``enforce`` or ``shadow``. A typo'd stance
        is a startup error, not a silent fall-through to the wrong one — the same
        fail-at-startup contract the global mode holds."""
        for name, value in (
            ("injection_mode", self.injection_mode),
            ("budget_mode", self.budget_mode),
        ):
            if value not in VALID_GUARD_MODES:
                raise GovernanceNotConfigured(
                    f"{name} must be one of {VALID_GUARD_MODES}, got {value!r}"
                )

    def _validate_confidence_floor(self) -> None:
        """The injection confidence floor must be a number in ``[0.0, 1.0]``
        (0.0 = off). ``bool`` is rejected (an ``int`` subclass); out-of-range is a
        misconfiguration, not a tuning choice."""
        floor = self.injection_confidence_floor
        if isinstance(floor, bool) or not isinstance(floor, (int, float)):
            raise GovernanceNotConfigured(
                f"injection_confidence_floor must be a number in [0.0, 1.0], "
                f"got {type(floor).__name__}"
            )
        if not (0.0 <= floor <= 1.0):
            raise GovernanceNotConfigured(
                f"injection_confidence_floor must be in [0.0, 1.0], got {floor!r}"
            )

    def _validate_output_seam(self) -> None:
        """Validate the output-seam fields (#39). ``output_screening`` must be a
        bool; every ``tool_io_map`` value must be ``read``/``write``; ``rails`` must
        be ``RailConfig`` instances (each self-validating). Normalises the io map to
        an immutable view and rails to a tuple. A typo here is a startup error."""
        if not isinstance(self.output_screening, bool):
            raise GovernanceNotConfigured(
                f"output_screening must be a bool, got {type(self.output_screening).__name__}"
            )
        io_map = dict(self.tool_io_map)
        for action, cls in io_map.items():
            if cls not in VALID_IO_CLASSES:
                raise GovernanceNotConfigured(
                    f"tool_io_map[{action!r}] must be one of {VALID_IO_CLASSES}, got {cls!r}"
                )
        object.__setattr__(self, "tool_io_map", MappingProxyType(io_map))
        rails = tuple(self.rails)
        for r in rails:
            if not isinstance(r, RailConfig):
                raise GovernanceNotConfigured(
                    f"rails entries must be RailConfig, got {type(r).__name__}"
                )
        names = [r.name for r in rails]
        if len(names) != len(set(names)):
            raise GovernanceNotConfigured(f"duplicate rail name(s) in {names}")
        object.__setattr__(self, "rails", rails)

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
                f"config 'idempotency_max_entries' must be an int, got {type(cap).__name__}"
            )
        ttl = data.get("idempotency_ttl_seconds", _DEFAULT_IDEM_TTL_SECONDS)
        if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, (int, float))):
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
        # Per-guard modes (D10). Accept a nested block (``injection: {mode: ...}``)
        # OR a flat key (``injection_mode: ...``); the nested form mirrors the
        # design's ``injection.mode`` notation. A non-mapping nested block is a
        # config error, not a silently-ignored stanza.
        injection_block = cls._guard_block(data, "injection")
        budget_block = cls._guard_block(data, "budget")
        injection_mode = str(
            injection_block.get("mode", data.get("injection_mode", _DEFAULT_GUARD_MODE))
        )
        budget_mode = str(budget_block.get("mode", data.get("budget_mode", _DEFAULT_GUARD_MODE)))
        floor = injection_block.get(
            "confidence_floor",
            data.get("injection_confidence_floor", _DEFAULT_INJECTION_CONFIDENCE_FLOOR),
        )
        if isinstance(floor, bool) or not isinstance(floor, (int, float)):
            raise GovernanceNotConfigured(
                "config 'injection_confidence_floor' must be a number in [0.0, 1.0], "
                f"got {type(floor).__name__}"
            )
        output_screening = data.get("output_screening", False)
        if not isinstance(output_screening, bool):
            raise GovernanceNotConfigured(
                f"config 'output_screening' must be a bool, got {type(output_screening).__name__}"
            )
        tool_io_map = cls._parse_tool_io_map(data.get("tool_io_map"))
        rails = cls._parse_rails(data.get("rails"))
        return cls(
            mode=str(data.get("mode", "strict")),
            rules=tuple(rules),
            policy_dir=policy_dir,
            audit_sink=audit_sink,
            decision_budget_seconds=budget,
            idempotency_max_entries=cap,
            idempotency_ttl_seconds=ttl,
            injection_rules_path=injection_rules_path,
            injection_mode=injection_mode,
            budget_mode=budget_mode,
            injection_confidence_floor=float(floor),
            output_screening=output_screening,
            tool_io_map=tool_io_map,
            rails=rails,
        )

    @staticmethod
    def _parse_tool_io_map(raw: Any) -> dict[str, str]:
        """Coerce the ``tool_io_map`` block to a plain ``{action: class}`` dict.
        Value validation (``read``/``write``) is left to ``__post_init__`` so the
        same check covers both the from_mapping and direct-construction paths."""
        if raw is None:
            return {}
        if not isinstance(raw, Mapping):
            raise GovernanceNotConfigured(
                f"config 'tool_io_map' must be a mapping, got {type(raw).__name__}"
            )
        return {str(k): v for k, v in raw.items()}

    @staticmethod
    def _parse_rails(raw: Any) -> tuple[RailConfig, ...]:
        """Parse the ``rails`` block — a ``{name: {threshold, mode}}`` mapping — into
        a tuple of :class:`RailConfig`. Each entry self-validates on construction."""
        if raw is None:
            return ()
        if not isinstance(raw, Mapping):
            raise GovernanceNotConfigured(
                f"config 'rails' must be a mapping of rail name to settings, "
                f"got {type(raw).__name__}"
            )
        out: list[RailConfig] = []
        for name, settings in raw.items():
            if settings is None:
                settings = {}
            if not isinstance(settings, Mapping):
                raise GovernanceNotConfigured(
                    f"config rails[{name!r}] must be a mapping (e.g. "
                    f"{{threshold: 0.5, mode: shadow}}), got {type(settings).__name__}"
                )
            out.append(
                RailConfig(
                    name=str(name),
                    threshold=settings.get("threshold", _DEFAULT_RAIL_THRESHOLD),
                    mode=str(settings.get("mode", _DEFAULT_GUARD_MODE)),
                )
            )
        return tuple(out)

    @staticmethod
    def _guard_block(data: Mapping[str, Any], name: str) -> Mapping[str, Any]:
        """Return the nested per-guard block (e.g. ``injection: {mode: ...}``) or an
        empty mapping when absent. A present-but-non-mapping block is a config
        error — a scalar ``injection:`` would silently drop ``mode``/floor."""
        block = data.get(name)
        if block is None:
            return {}
        if not isinstance(block, Mapping):
            raise GovernanceNotConfigured(
                f"config {name!r} must be a mapping (e.g. {{mode: shadow}}), "
                f"got {type(block).__name__}"
            )
        return block

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
