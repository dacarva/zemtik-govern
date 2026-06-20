"""CI guard: extracts and executes the README quick start snippet (issue #22).

Fails if the README snippet is stale, broken, or missing.
"""
from __future__ import annotations

import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

README = Path(__file__).parent.parent / "README.md"


def _extract_quickstart_snippet() -> str:
    """Extract the code block tagged <!-- quickstart --> from README."""
    text = README.read_text()
    # Find a python block immediately following the <!-- quickstart --> marker
    match = re.search(
        r"<!--\s*quickstart\s*-->\s*```python\n(.*?)```",
        text,
        re.DOTALL,
    )
    if not match:
        raise ValueError(
            "README.md is missing a <!-- quickstart --> tagged python code block. "
            "Tag the quick start snippet with <!-- quickstart --> on the line before ```python."
        )
    return textwrap.dedent(match.group(1))


# ---------------------------------------------------------------------------
# Slice 1: README headline references LangChain/LangGraph
# ---------------------------------------------------------------------------

def test_readme_headline_references_langchain():
    text = README.read_text()
    first_500 = text[:500].lower()
    assert "langchain" in first_500 or "langgraph" in first_500, (
        "README headline must mention LangChain or LangGraph"
    )


# ---------------------------------------------------------------------------
# Slice 2: README has a quickstart-tagged code block
# ---------------------------------------------------------------------------

def test_readme_has_quickstart_snippet():
    snippet = _extract_quickstart_snippet()
    assert snippet.strip(), "Quickstart snippet must not be empty"


# ---------------------------------------------------------------------------
# Slice 3: README snippet runs without error
# ---------------------------------------------------------------------------

def test_readme_quickstart_snippet_runs():
    snippet = _extract_quickstart_snippet()
    result = subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"README quickstart snippet failed:\n"
        f"STDOUT: {result.stdout}\n"
        f"STDERR: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Slice 4: Quick start is ≤ 4 Python lines (excluding blanks/comments)
# ---------------------------------------------------------------------------

def test_readme_quickstart_is_concise():
    snippet = _extract_quickstart_snippet()
    code_lines = [
        ln for ln in snippet.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert len(code_lines) <= 20, (
        f"Quickstart snippet is {len(code_lines)} lines (target ≤ 20 meaningful lines)"
    )


# ---------------------------------------------------------------------------
# Slice 5: ZEMTIK_DEV debug command appears in README
# ---------------------------------------------------------------------------

def test_readme_has_zemtik_dev_debug_command():
    text = README.read_text()
    assert "ZEMTIK_DEV=1" in text, (
        "README must include the ZEMTIK_DEV=1 debug command"
    )


# ---------------------------------------------------------------------------
# Slice 6: Embedded govern.yaml allows exactly one named tool (not allow-all)
# ---------------------------------------------------------------------------

def test_readme_embedded_yaml_allows_one_specific_tool():
    import yaml
    text = README.read_text()
    yaml_blocks = re.findall(r"```yaml\n(.*?)```", text, re.DOTALL)
    # Find the one that looks like a govern.yaml (has mode + rules)
    govern_yaml = None
    for block in yaml_blocks:
        parsed = yaml.safe_load(block)
        if isinstance(parsed, dict) and "mode" in parsed and "rules" in parsed:
            govern_yaml = parsed
            break
    assert govern_yaml is not None, "README must include an embedded govern.yaml with mode + rules"
    allow_rules = [r for r in (govern_yaml.get("rules") or []) if r.get("action") == "allow"]
    assert len(allow_rules) >= 1, "Embedded govern.yaml must have at least one allow rule"
    # Must use exact match — not allow-all
    for rule in allow_rules:
        condition = rule.get("condition", {})
        assert condition.get("operator") == "eq", (
            "Embedded govern.yaml must allow a specific tool (eq), not allow-all"
        )
