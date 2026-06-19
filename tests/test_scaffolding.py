"""Tests for issue #14: project scaffolding — optional deps + directory structure."""

from pathlib import Path

import tomllib

REPO_ROOT = Path(__file__).parent.parent
SRC_ROOT = REPO_ROOT / "src" / "zemtik_govern"
TESTS_ROOT = REPO_ROOT / "tests"


# ---------------------------------------------------------------------------
# Directory structure
# ---------------------------------------------------------------------------


def test_langchain_package_dir_exists():
    d = SRC_ROOT / "langchain"
    assert d.is_dir(), f"Missing directory: {d}"
    assert (d / "__init__.py").is_file(), f"Missing __init__.py in {d}"


def test_cli_package_dir_exists():
    d = SRC_ROOT / "cli"
    assert d.is_dir(), f"Missing directory: {d}"
    assert (d / "__init__.py").is_file(), f"Missing __init__.py in {d}"


def test_mcp_package_dir_exists():
    d = SRC_ROOT / "mcp"
    assert d.is_dir(), f"Missing directory: {d}"
    assert (d / "__init__.py").is_file(), f"Missing __init__.py in {d}"


def test_tests_langchain_dir_exists():
    d = TESTS_ROOT / "langchain"
    assert d.is_dir(), f"Missing directory: {d}"
    assert (d / "__init__.py").is_file(), f"Missing __init__.py in {d}"


# ---------------------------------------------------------------------------
# pyproject.toml optional-dependencies
# ---------------------------------------------------------------------------


def _load_optional_deps() -> dict:
    with open(REPO_ROOT / "pyproject.toml", "rb") as f:
        data = tomllib.load(f)
    return data.get("project", {}).get("optional-dependencies", {})


def test_langchain_optional_group_exists():
    optional = _load_optional_deps()
    assert "langchain" in optional, "Missing [project.optional-dependencies.langchain]"


def test_langchain_group_contains_langchain_core():
    optional = _load_optional_deps()
    deps = optional.get("langchain", [])
    assert any("langchain-core" in d for d in deps), f"langchain-core not in {deps}"


def test_langchain_group_contains_langgraph():
    optional = _load_optional_deps()
    deps = optional.get("langchain", [])
    assert any("langgraph" in d for d in deps), f"langgraph not in {deps}"


def test_mcp_optional_group_exists():
    optional = _load_optional_deps()
    assert "mcp" in optional, "Missing [project.optional-dependencies.mcp]"


def test_mcp_group_contains_mcp_sdk():
    optional = _load_optional_deps()
    deps = optional.get("mcp", [])
    assert any(d.startswith("mcp") for d in deps), f"mcp sdk not in {deps}"
