"""S2 — GovernanceConfig: parse and refuse insecure shapes at startup.

The acceptance criterion the skeleton was missing: GovernanceNotConfigured must
fire on (a) strict + zero rules, (b) strict + no audit sink, (c) strict + an
empty policy dir. These tests pin all three plus the happy path and YAML load.
"""

from pathlib import Path

import pytest

from zemtik_govern.config import GovernanceConfig
from zemtik_govern.errors import GovernanceNotConfigured


def test_strict_with_inline_rules_and_sink_builds():
    cfg = GovernanceConfig(
        mode="strict",
        rules=[{"name": "r", "action": "allow"}],
        audit_sink="memory",
    )
    assert cfg.mode == "strict"
    assert cfg.audit_sink == "memory"
    # rules normalised to an immutable tuple
    assert isinstance(cfg.rules, tuple)


def test_strict_zero_rules_raises():
    with pytest.raises(GovernanceNotConfigured, match="zero rules"):
        GovernanceConfig(mode="strict", rules=[], audit_sink="memory")


def test_enforce_mode_validates_like_strict():
    # enforce is documented as the same enforcement surface as strict — it must
    # NOT be the least-validated mode. Zero rules in enforce is a hard error.
    with pytest.raises(GovernanceNotConfigured, match="zero rules"):
        GovernanceConfig(mode="enforce", rules=[], audit_sink="memory")


def test_every_mode_requires_an_audit_sink():
    # Observing/enforcing into nowhere is not governance — all modes need a sink.
    for mode in ("strict", "shadow", "enforce"):
        with pytest.raises(GovernanceNotConfigured, match="audit sink"):
            GovernanceConfig(
                mode=mode, rules=[{"name": "r"}], audit_sink=None
            )


def test_malformed_rule_element_raises():
    with pytest.raises(GovernanceNotConfigured, match="must be a mapping"):
        GovernanceConfig(mode="strict", rules=["not-a-dict"], audit_sink="memory")


def test_strict_no_audit_sink_raises():
    with pytest.raises(GovernanceNotConfigured, match="audit sink"):
        GovernanceConfig(mode="strict", rules=[{"name": "r"}], audit_sink=None)


def test_strict_empty_policy_dir_raises(tmp_path: Path):
    empty = tmp_path / "policies"
    empty.mkdir()
    with pytest.raises(GovernanceNotConfigured, match="empty policy dir"):
        GovernanceConfig(mode="strict", policy_dir=str(empty), audit_sink="memory")


def test_strict_non_empty_policy_dir_builds(tmp_path: Path):
    pol = tmp_path / "policies"
    pol.mkdir()
    (pol / "allow.yaml").write_text("name: x\n", encoding="utf-8")
    cfg = GovernanceConfig(mode="strict", policy_dir=str(pol), audit_sink="memory")
    assert cfg.policy_dir == str(pol)


def test_unknown_mode_raises():
    with pytest.raises(GovernanceNotConfigured, match="unknown mode"):
        GovernanceConfig(mode="yolo", audit_sink="memory")


def test_shadow_mode_is_lenient_on_policy_source():
    # shadow relaxes the policy-source requirement (observe-only, never blocks)
    # but still requires an audit sink.
    cfg = GovernanceConfig(mode="shadow", audit_sink="memory")
    assert cfg.mode == "shadow"
    assert cfg.rules == ()


def test_load_reads_the_example_yaml():
    example = Path(__file__).resolve().parents[1] / "zemtik.example.yaml"
    cfg = GovernanceConfig.load(example)
    assert cfg.mode == "strict"
    assert cfg.audit_sink == "memory"
    assert any(r.get("name") == "allow-tool-run" for r in cfg.rules)


def test_load_missing_file_raises():
    with pytest.raises(GovernanceNotConfigured, match="cannot read config"):
        GovernanceConfig.load("/nonexistent/zemtik.yaml")


def test_load_invalid_yaml_raises(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("mode: [unclosed\n", encoding="utf-8")
    with pytest.raises(GovernanceNotConfigured, match="invalid YAML"):
        GovernanceConfig.load(bad)


def test_from_mapping_non_mapping_root_raises():
    with pytest.raises(GovernanceNotConfigured, match="must be a mapping"):
        GovernanceConfig.from_mapping(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_from_mapping_rules_not_a_list_raises():
    with pytest.raises(GovernanceNotConfigured, match="'rules' must be a list"):
        GovernanceConfig.from_mapping({"rules": "oops", "audit_sink": "memory"})


def test_from_mapping_non_string_policy_dir_raises():
    with pytest.raises(GovernanceNotConfigured, match="'policy_dir' must be a string"):
        GovernanceConfig.from_mapping(
            {"policy_dir": ["x"], "audit_sink": "memory", "rules": [{"name": "r"}]}
        )


def test_config_value_equality():
    a = GovernanceConfig(mode="strict", rules=[{"name": "r"}], audit_sink="memory")
    b = GovernanceConfig(mode="strict", rules=[{"name": "r"}], audit_sink="memory")
    assert a == b  # value equality, not identity
