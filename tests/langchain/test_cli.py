"""Tests for `zemtik init langchain` CLI subcommand.

Acceptance criteria:
- `zemtik init langchain` emits valid YAML with all tools denied (to stdout)
- `zemtik init langchain > govern.yaml` works (YAML to stdout only)
- Import failure exits non-zero, error to stderr, no YAML to stdout
- Dynamic @tool schema emits placeholder with warning to stderr
- No Click/Typer dependency
- All existing tests pass
"""
from __future__ import annotations

import importlib
import types
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

# The module under test — imported lazily so individual tests can mock cleanly.
CLI_MODULE = "zemtik_govern.cli.init_langchain"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_generate(tools_module: str | None = None, output: str | None = None):
    """Import and call generate_govern_yaml directly, returns (exit_code, stdout_str, stderr_str)."""
    from zemtik_govern.cli.init_langchain import generate_govern_yaml

    stdout_buf = StringIO()
    stderr_buf = StringIO()
    exit_code = generate_govern_yaml(
        tools_module=tools_module,
        output=output,
        stdout=stdout_buf,
        stderr=stderr_buf,
    )
    return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()


def _make_fake_tool(name: str, schema_fields: dict | None = None):
    """Create a minimal LangChain-tool-like object."""
    tool = MagicMock()
    tool.name = name
    if schema_fields is None:
        tool.args_schema = None
    else:
        schema = MagicMock()
        schema.model_fields = schema_fields
        tool.args_schema = schema
    return tool


# ---------------------------------------------------------------------------
# 1. No tools-module → minimal valid YAML to stdout
# ---------------------------------------------------------------------------


class TestNoToolsModule:
    def test_exit_code_zero(self):
        code, _out, _err = _run_generate()
        assert code == 0

    def test_yaml_to_stdout(self):
        _code, out, _err = _run_generate()
        assert out.strip(), "Expected YAML on stdout"

    def test_output_is_valid_yaml(self):
        _code, out, _err = _run_generate()
        parsed = yaml.safe_load(out)
        assert isinstance(parsed, dict)

    def test_yaml_has_required_top_level_keys(self):
        _code, out, _err = _run_generate()
        parsed = yaml.safe_load(out)
        assert "mode" in parsed
        assert "audit_sink" in parsed
        assert "rules" in parsed

    def test_mode_is_strict(self):
        _code, out, _err = _run_generate()
        parsed = yaml.safe_load(out)
        assert parsed["mode"] == "strict"

    def test_rules_empty_when_no_tools(self):
        _code, out, _err = _run_generate()
        parsed = yaml.safe_load(out)
        # rules may be empty list or null — both are acceptable
        assert not parsed.get("rules")

    def test_no_stderr_when_no_tools_module(self):
        _code, _out, err = _run_generate()
        assert err.strip() == ""


# ---------------------------------------------------------------------------
# 2. With a valid tools module → commented-out rules in YAML
# ---------------------------------------------------------------------------


class TestWithToolsModule:
    def _fake_module_ctx(self, tools: list):
        """Context manager: patches importlib.import_module to return a fake module."""
        fake_mod = types.ModuleType("fake_tools")
        for t in tools:
            setattr(fake_mod, t.name, t)

        return patch("zemtik_govern.cli.init_langchain.importlib.import_module", return_value=fake_mod)

    def test_exit_code_zero_with_valid_module(self):
        tool = _make_fake_tool("send_email", {"to": MagicMock(), "body": MagicMock()})
        with self._fake_module_ctx([tool]):
            code, _out, _err = _run_generate(tools_module="fake_tools")
        assert code == 0

    def test_yaml_still_to_stdout(self):
        tool = _make_fake_tool("send_email", {"to": MagicMock()})
        with self._fake_module_ctx([tool]):
            _code, out, _err = _run_generate(tools_module="fake_tools")
        assert out.strip()

    def test_generated_yaml_is_valid(self):
        tool = _make_fake_tool("send_email", {"to": MagicMock()})
        with self._fake_module_ctx([tool]):
            _code, out, _err = _run_generate(tools_module="fake_tools")
        parsed = yaml.safe_load(out)
        assert isinstance(parsed, dict)

    def test_tool_names_appear_as_comments(self):
        tool = _make_fake_tool("send_email", {"to": MagicMock()})
        with self._fake_module_ctx([tool]):
            _code, out, _err = _run_generate(tools_module="fake_tools")
        # The rule block must be commented out
        assert "allow-send-email" in out
        # It must appear in a comment context (lines starting with #)
        comment_lines = [ln.lstrip() for ln in out.splitlines() if ln.lstrip().startswith("#")]
        assert any("allow-send-email" in ln for ln in comment_lines)

    def test_rules_section_commented_out_so_yaml_parse_has_no_rules(self):
        """When all rules are commented out, parsed YAML must have empty/null rules."""
        tool = _make_fake_tool("send_email", {"to": MagicMock()})
        with self._fake_module_ctx([tool]):
            _code, out, _err = _run_generate(tools_module="fake_tools")
        parsed = yaml.safe_load(out)
        # Rules must not appear as active entries (all commented out)
        assert not parsed.get("rules")

    def test_multiple_tools_all_appear_as_comments(self):
        t1 = _make_fake_tool("send_email", {"to": MagicMock()})
        t2 = _make_fake_tool("search_web", {"query": MagicMock()})
        with self._fake_module_ctx([t1, t2]):
            _code, out, _err = _run_generate(tools_module="fake_tools")
        assert "allow-send-email" in out
        assert "allow-search-web" in out


# ---------------------------------------------------------------------------
# 3. Dynamic schema → placeholder + warning to stderr
# ---------------------------------------------------------------------------


class TestDynamicSchema:
    def _fake_module_ctx(self, tools: list):
        fake_mod = types.ModuleType("fake_tools")
        for t in tools:
            setattr(fake_mod, t.name, t)
        return patch("zemtik_govern.cli.init_langchain.importlib.import_module", return_value=fake_mod)

    def test_dynamic_tool_emits_warning_to_stderr(self):
        tool = _make_fake_tool("dynamic_tool", schema_fields=None)  # no schema
        with self._fake_module_ctx([tool]):
            _code, _out, err = _run_generate(tools_module="fake_tools")
        assert "dynamic" in err.lower() or "warning" in err.lower() or "dynamic_tool" in err

    def test_dynamic_tool_placeholder_appears_in_stdout(self):
        tool = _make_fake_tool("dynamic_tool", schema_fields=None)
        with self._fake_module_ctx([tool]):
            _code, out, _err = _run_generate(tools_module="fake_tools")
        assert "dynamic_tool" in out

    def test_dynamic_tool_does_not_fail_exit_code(self):
        """Dynamic schema is a warning, not a hard failure."""
        tool = _make_fake_tool("dynamic_tool", schema_fields=None)
        with self._fake_module_ctx([tool]):
            code, _out, _err = _run_generate(tools_module="fake_tools")
        assert code == 0

    def test_dynamic_tool_yaml_still_valid(self):
        tool = _make_fake_tool("dynamic_tool", schema_fields=None)
        with self._fake_module_ctx([tool]):
            _code, out, _err = _run_generate(tools_module="fake_tools")
        parsed = yaml.safe_load(out)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# 4. Import failure → exit(1), error to stderr, NO yaml to stdout
# ---------------------------------------------------------------------------


class TestImportFailure:
    def test_exit_code_nonzero_on_bad_module(self):
        with patch("zemtik_govern.cli.init_langchain.importlib.import_module", side_effect=ImportError("no module")):
            code, _out, _err = _run_generate(tools_module="nonexistent.module")
        assert code != 0

    def test_no_yaml_on_stdout_on_import_failure(self):
        with patch("zemtik_govern.cli.init_langchain.importlib.import_module", side_effect=ImportError("no module")):
            _code, out, _err = _run_generate(tools_module="nonexistent.module")
        # stdout must be empty (no partial YAML)
        assert out.strip() == ""

    def test_error_message_on_stderr_on_import_failure(self):
        with patch("zemtik_govern.cli.init_langchain.importlib.import_module", side_effect=ImportError("no module named 'x'")):
            _code, _out, err = _run_generate(tools_module="nonexistent.module")
        assert err.strip(), "Expected error message on stderr"
        assert "nonexistent.module" in err or "ImportError" in err or "no module" in err.lower()


# ---------------------------------------------------------------------------
# 5. --output flag writes to file, not stdout
# ---------------------------------------------------------------------------


class TestOutputFlag:
    def test_output_flag_writes_file(self, tmp_path: Path):
        out_file = str(tmp_path / "govern.yaml")
        code, stdout_out, _err = _run_generate(output=out_file)
        assert code == 0
        # stdout must be empty when --output is given
        assert stdout_out.strip() == ""
        # file must exist and be valid YAML
        content = Path(out_file).read_text()
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, dict)
        assert "mode" in parsed

    def test_output_flag_with_tools_module(self, tmp_path: Path):
        tool = _make_fake_tool("send_email", {"to": MagicMock()})
        fake_mod = types.ModuleType("fake_tools")
        fake_mod.send_email = tool
        out_file = str(tmp_path / "govern.yaml")
        with patch("zemtik_govern.cli.init_langchain.importlib.import_module", return_value=fake_mod):
            code, stdout_out, _err = _run_generate(tools_module="fake_tools", output=out_file)
        assert code == 0
        assert stdout_out.strip() == ""
        content = Path(out_file).read_text()
        assert "allow-send-email" in content


# ---------------------------------------------------------------------------
# 6. CLI argument parsing via __main__
# ---------------------------------------------------------------------------


class TestArgParsing:
    def test_module_is_importable(self):
        """The CLI module must import without error."""
        mod = importlib.import_module(CLI_MODULE)
        assert mod is not None

    def test_main_callable_exists(self):
        mod = importlib.import_module(CLI_MODULE)
        assert callable(getattr(mod, "main", None))

    def test_cli_main_no_args_exits_zero(self):
        """Calling main with no args (no --tools-module) should exit 0."""
        from zemtik_govern.cli.init_langchain import main

        # Pass an empty argv list — no flags means no tools-module, outputs to real stdout.
        # We just check the exit code; stdout side-effect is acceptable in this test.
        with patch("sys.argv", ["zemtik", "init", "langchain"]):
            code = main(argv=[])
        assert code == 0

    def test_cli_entry_point_module(self):
        """zemtik_govern.cli package must be importable."""
        cli_pkg = importlib.import_module("zemtik_govern.cli")
        assert cli_pkg is not None
