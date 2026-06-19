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

    def __post_init__(self) -> None:
        # Normalise rules to an immutable tuple regardless of how they arrived.
        object.__setattr__(self, "rules", tuple(self.rules))
        if self.mode not in VALID_MODES:
            raise GovernanceNotConfigured(
                f"unknown mode {self.mode!r}; expected one of {VALID_MODES}"
            )
        self._validate_rule_shapes()
        # Universal: no mode is allowed to run without somewhere to record outcomes.
        if not self.audit_sink:
            raise GovernanceNotConfigured(
                f"{self.mode} mode requires an audit sink; none configured"
            )
        # Enforcing modes additionally need something to enforce.
        if self.mode in _ENFORCING_MODES:
            self._validate_policy_source()

    def _validate_rule_shapes(self) -> None:
        for i, rule in enumerate(self.rules):
            if not isinstance(rule, Mapping):
                raise GovernanceNotConfigured(
                    f"rule {i} must be a mapping, got {type(rule).__name__}"
                )

    def _validate_policy_source(self) -> None:
        if not self.rules and self.policy_dir is None:
            raise GovernanceNotConfigured(
                f"{self.mode} mode requires policy rules or a policy_dir; got zero rules"
            )
        if self.policy_dir is not None and not self._policy_dir_has_files():
            raise GovernanceNotConfigured(
                f"{self.mode} mode + empty policy dir: {self.policy_dir!r} has no policy files"
            )

    def _policy_dir_has_files(self) -> bool:
        directory = Path(self.policy_dir) if self.policy_dir else None
        if directory is None or not directory.is_dir():
            return False
        return any(child.is_file() for child in directory.iterdir())

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> GovernanceConfig:
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
        return cls(
            mode=str(data.get("mode", "strict")),
            rules=tuple(rules),
            policy_dir=policy_dir,
            audit_sink=audit_sink,
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
