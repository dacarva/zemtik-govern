"""#33 — decision_budget_seconds threaded config → registry → core.

`ZemtikGovern(timeout=...)` already bounds the identity+policy decision path, but
`GovernanceConfig`/`GovernanceRegistry` never set it, so every config-built
governor silently ran with `timeout=None` (no budget). These pin the wiring: a
config carries a documented, unit-suffixed `decision_budget_seconds` with a
non-None default, and a config-built governor actually receives it.
"""

import pytest

from zemtik_govern.config import GovernanceConfig
from zemtik_govern.errors import GovernanceNotConfigured


def test_config_has_non_none_decision_budget_by_default():
    cfg = GovernanceConfig(
        mode="strict",
        rules=[{"name": "r", "action": "allow"}],
        audit_sink="memory",
    )
    # the silent None default is gone: a config-built governor gets a real budget
    assert cfg.decision_budget_seconds is not None
    assert cfg.decision_budget_seconds > 0


def test_decision_budget_seconds_is_overridable():
    cfg = GovernanceConfig(
        mode="strict",
        rules=[{"name": "r", "action": "allow"}],
        audit_sink="memory",
        decision_budget_seconds=0.25,
    )
    assert cfg.decision_budget_seconds == 0.25


def test_decision_budget_can_be_disabled_with_none():
    # explicit opt-out for callers who manage their own deadline upstream
    cfg = GovernanceConfig(
        mode="strict",
        rules=[{"name": "r", "action": "allow"}],
        audit_sink="memory",
        decision_budget_seconds=None,
    )
    assert cfg.decision_budget_seconds is None


def test_non_positive_decision_budget_rejected_at_startup():
    with pytest.raises(GovernanceNotConfigured, match="decision_budget_seconds"):
        GovernanceConfig(
            mode="strict",
            rules=[{"name": "r", "action": "allow"}],
            audit_sink="memory",
            decision_budget_seconds=0,
        )


def test_from_mapping_reads_decision_budget_seconds():
    cfg = GovernanceConfig.from_mapping(
        {
            "mode": "strict",
            "rules": [{"name": "r", "action": "allow"}],
            "audit_sink": "memory",
            "decision_budget_seconds": 1.5,
        }
    )
    assert cfg.decision_budget_seconds == 1.5


def test_from_mapping_rejects_non_numeric_decision_budget():
    with pytest.raises(GovernanceNotConfigured, match="decision_budget_seconds"):
        GovernanceConfig.from_mapping(
            {
                "mode": "strict",
                "rules": [{"name": "r", "action": "allow"}],
                "audit_sink": "memory",
                "decision_budget_seconds": "soon",
            }
        )


# --- registry threads the budget into the core (the actual #33 wiring) --------


class _Seam:
    async def identify(self, subject):
        return "did:mesh:" + subject

    async def evaluate(self, ctx):
        from zemtik_govern.protocols import Decision

        return Decision(allowed=True, action="allow", matched_rule="r", reason="ok")

    async def write(self, entry):
        return "evt-1"


def test_registry_threads_decision_budget_into_core():
    from zemtik_govern.registry import GovernanceRegistry

    seam = _Seam()
    gov = (
        GovernanceRegistry()
        .register_identity(seam)
        .register_policy(seam)
        .register_audit(seam)
        .register_decision_budget(0.25)
        .build()
    )
    assert gov._timeout == 0.25


def test_from_config_gives_core_a_non_none_budget():
    """The headline #33 fix: a governor built from config no longer runs with the
    silent ``timeout=None``. Uses the real AGT-backed seams via from_config."""
    from zemtik_govern._agt import AGTBoundary
    from zemtik_govern.registry import GovernanceRegistry

    cfg = GovernanceConfig(
        mode="strict",
        rules=[
            {
                "name": "allow-tool-run",
                "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
                "action": "allow",
            }
        ],
        audit_sink="memory",
        decision_budget_seconds=2.0,
        injection_rules_path="policies/prompt-injection.yaml",
    )
    gov = GovernanceRegistry.from_config(cfg, AGTBoundary()).build()
    assert gov._timeout == 2.0
