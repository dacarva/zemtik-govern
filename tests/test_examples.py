"""Tests for example scripts and documentation completeness (issue #21)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
DOCS_DIR = Path(__file__).parent.parent / "docs"
ROOT_DIR = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Slice 1: examples/govern.yaml valid + allows exactly one named tool
# ---------------------------------------------------------------------------

def test_govern_yaml_exists():
    assert (EXAMPLES_DIR / "govern.yaml").exists(), "examples/govern.yaml must exist"


def test_govern_yaml_is_valid_yaml():
    parsed = yaml.safe_load((EXAMPLES_DIR / "govern.yaml").read_text())
    assert isinstance(parsed, dict)
    assert "mode" in parsed
    assert "rules" in parsed


def test_govern_yaml_allows_exactly_one_named_tool():
    parsed = yaml.safe_load((EXAMPLES_DIR / "govern.yaml").read_text())
    allow_rules = [r for r in (parsed.get("rules") or []) if r.get("action") == "allow"]
    assert len(allow_rules) == 1, f"Expected 1 allow rule, got {len(allow_rules)}"
    condition = allow_rules[0].get("condition", {})
    assert condition.get("operator") == "eq", "Rule must use exact match, not allow-all"


# ---------------------------------------------------------------------------
# Slice 2-3: langchain_minimal.py exists and runs end-to-end
# ---------------------------------------------------------------------------

def test_langchain_minimal_exists():
    assert (EXAMPLES_DIR / "langchain_minimal.py").exists()


def test_langchain_minimal_runs():
    result = subprocess.run(
        [sys.executable, str(EXAMPLES_DIR / "langchain_minimal.py")],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"langchain_minimal.py failed:\n{result.stderr}"


# ---------------------------------------------------------------------------
# Slice 4-5: langgraph_toolnode.py exists and runs end-to-end
# ---------------------------------------------------------------------------

def test_langgraph_toolnode_exists():
    assert (EXAMPLES_DIR / "langgraph_toolnode.py").exists()


def test_langgraph_toolnode_runs():
    result = subprocess.run(
        [sys.executable, str(EXAMPLES_DIR / "langgraph_toolnode.py")],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"langgraph_toolnode.py failed:\n{result.stderr}"


# ---------------------------------------------------------------------------
# Slice 6: CONTRIBUTING.md exists with pytest + ruff instructions
# ---------------------------------------------------------------------------

def test_contributing_md_exists():
    assert (ROOT_DIR / "CONTRIBUTING.md").exists()


def test_contributing_md_has_pytest_and_ruff():
    content = (ROOT_DIR / "CONTRIBUTING.md").read_text()
    assert "pytest" in content
    assert "ruff" in content


# ---------------------------------------------------------------------------
# Slice 7: .github/ISSUE_TEMPLATE/bug_report.md has required fields
# ---------------------------------------------------------------------------

def test_bug_report_template_exists():
    assert (ROOT_DIR / ".github" / "ISSUE_TEMPLATE" / "bug_report.md").exists()


def test_bug_report_template_has_required_fields():
    content = (ROOT_DIR / ".github" / "ISSUE_TEMPLATE" / "bug_report.md").read_text()
    assert "python" in content.lower()
    assert "langchain" in content.lower()
    assert any(word in content.lower() for word in ["repro", "reproduce", "minimal"])


# ---------------------------------------------------------------------------
# Slice 8: docs/integrations/langchain.md Error Reference table ≥4 rows
# ---------------------------------------------------------------------------

def test_langchain_integration_doc_exists():
    assert (DOCS_DIR / "integrations" / "langchain.md").exists()


def test_langchain_integration_doc_has_error_reference_table():
    content = (DOCS_DIR / "integrations" / "langchain.md").read_text()
    assert "Error Reference" in content or "error reference" in content.lower()
    for error in ["GovernanceDenied", "GovernanceError", "ValueError", "GovernanceNotConfigured"]:
        assert error in content, f"Missing {error} from Error Reference"


# ---------------------------------------------------------------------------
# Slice 9: @governed decorator order warning is highlighted
# ---------------------------------------------------------------------------

def test_governed_decorator_order_warning_is_highlighted():
    content = (DOCS_DIR / "integrations" / "langchain.md").read_text()
    has_warning = (
        "> [!WARNING]" in content
        or "> **Warning" in content
        or "⚠️" in content
        or "**Warning:**" in content
        or "**IMPORTANT:**" in content
    )
    assert has_warning, "Decorator order warning must be highlighted"
    assert "@tool" in content
    assert "@governed" in content
