"""Tests for govern_tool() core API and ZEMTIK_DEV observability (issues #15 #17).

TDD — vertical slices, one test → one implementation at a time.
"""

from __future__ import annotations

import asyncio
import logging
import os

import pytest
from langchain_core.tools import tool

from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.identity import AgentRef
from zemtik_govern.protocols import Decision


# ---------------------------------------------------------------------------
# Shared fake governor helpers (pattern from tests/test_core.py)
# ---------------------------------------------------------------------------


class _FakeSeams:
    def __init__(self, *, allowed=True, rule="allow-all", reason="ok"):
        self._decision = Decision(
            allowed=allowed,
            action="test",
            matched_rule=rule if allowed else None,
            reason=reason,
            denial_kind=None if allowed else "policy",
        )
        self.entries = []

    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)

    async def evaluate(self, ctx):
        return self._decision

    async def write(self, entry):
        self.entries.append(entry)
        return "evt-1"


def _make_governor(*, allowed=True, rule="allow-all", reason="ok"):
    s = _FakeSeams(allowed=allowed, rule=rule, reason=reason)
    return ZemtikGovern(identity=s, policy=s, audit=s)


# ---------------------------------------------------------------------------
# A minimal langchain @tool for use in tests
# ---------------------------------------------------------------------------


@tool
def read_file(path: str) -> str:
    """Read a file."""
    return f"contents of {path}"


# ---------------------------------------------------------------------------
# Slice 1 — ValueError when both config= and govern= provided
# ---------------------------------------------------------------------------


def test_govern_tool_raises_when_both_config_and_govern_provided():
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor()
    with pytest.raises(ValueError, match="config"):
        govern_tool(read_file, config={"mode": "enforce"}, govern=gov)


# ---------------------------------------------------------------------------
# Slice 2 — ValueError when neither config= nor govern= provided
# ---------------------------------------------------------------------------


def test_govern_tool_raises_when_neither_config_nor_govern_provided():
    from zemtik_govern.langchain.tools import govern_tool

    with pytest.raises(ValueError, match="required"):
        govern_tool(read_file)


# ---------------------------------------------------------------------------
# Slice 3 — Basic allow: govern= pre-built governor, invoke() returns tool result
# ---------------------------------------------------------------------------


def test_govern_tool_allow_returns_tool_result():
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=True)
    governed = govern_tool(read_file, govern=gov)
    result = governed.invoke({"path": "/etc/hosts"})
    assert result == "contents of /etc/hosts"


# ---------------------------------------------------------------------------
# Slice 4 — Deny + on_denied="raise" → raises GovernanceDenied
# ---------------------------------------------------------------------------


def test_govern_tool_deny_raises_governance_denied():
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=False, rule="deny-all", reason="blocked")
    governed = govern_tool(read_file, govern=gov, on_denied="raise")
    with pytest.raises(GovernanceDenied):
        governed.invoke({"path": "/etc/shadow"})


# ---------------------------------------------------------------------------
# Slice 5 — Deny + on_denied="tool_message" → returns ToolMessage
# ---------------------------------------------------------------------------


def test_govern_tool_deny_tool_message_returns_tool_message(monkeypatch):
    from langchain_core.messages import ToolMessage

    from zemtik_govern.langchain.tools import govern_tool

    monkeypatch.delenv("ZEMTIK_DEV", raising=False)
    gov = _make_governor(allowed=False, rule="deny-all", reason="blocked")
    governed = govern_tool(read_file, govern=gov, on_denied="tool_message")
    result = governed.invoke({"path": "/etc/shadow"})
    assert isinstance(result, ToolMessage)
    assert result.content == "tool call denied"


# ---------------------------------------------------------------------------
# Slice 6 — Subject from RunnableConfig.configurable["agent_id"],
#            fallback metadata["agent_id"], fallback "langchain"
# ---------------------------------------------------------------------------


def test_govern_tool_subject_from_configurable_agent_id():
    """Subject extracted from RunnableConfig.configurable["agent_id"]."""
    from zemtik_govern.langchain.tools import _extract_subject

    config = {"configurable": {"agent_id": "agent-42"}, "metadata": {}}
    assert _extract_subject(config) == "agent-42"


def test_govern_tool_subject_fallback_metadata_agent_id():
    """Subject falls back to metadata["agent_id"] when not in configurable."""
    from zemtik_govern.langchain.tools import _extract_subject

    config = {"configurable": {}, "metadata": {"agent_id": "meta-agent"}}
    assert _extract_subject(config) == "meta-agent"


def test_govern_tool_subject_fallback_langchain():
    """Subject falls back to 'langchain' when not found in config."""
    from zemtik_govern.langchain.tools import _extract_subject

    assert _extract_subject(None) == "langchain"
    assert _extract_subject({"configurable": {}, "metadata": {}}) == "langchain"


# ---------------------------------------------------------------------------
# Slice 7 — ainvoke() governs via await gov.govern(ctx)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_govern_tool_ainvoke_allow_returns_tool_result():
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=True)
    governed = govern_tool(read_file, govern=gov)
    result = await governed.ainvoke({"path": "/tmp/test"})
    assert result == "contents of /tmp/test"


@pytest.mark.asyncio
async def test_govern_tool_ainvoke_deny_raises():
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=False, reason="blocked")
    governed = govern_tool(read_file, govern=gov, on_denied="raise")
    with pytest.raises(GovernanceDenied):
        await governed.ainvoke({"path": "/etc/shadow"})


# ---------------------------------------------------------------------------
# Slice 8 — govern_tools() wraps a list
# ---------------------------------------------------------------------------


@tool
def write_file(path: str) -> str:
    """Write a file."""
    return f"wrote {path}"


def test_govern_tools_wraps_list():
    from zemtik_govern.langchain.tools import _GovernedTool, govern_tools

    gov = _make_governor()
    governed = govern_tools([read_file, write_file], govern=gov)
    assert len(governed) == 2
    assert all(isinstance(t, _GovernedTool) for t in governed)
    assert governed[0].name == "read_file"
    assert governed[1].name == "write_file"


def test_govern_tools_all_allow():
    from zemtik_govern.langchain.tools import govern_tools

    gov = _make_governor(allowed=True)
    governed = govern_tools([read_file, write_file], govern=gov)
    assert governed[0].invoke({"path": "/a"}) == "contents of /a"
    assert governed[1].invoke({"path": "/b"}) == "wrote /b"


# ---------------------------------------------------------------------------
# Slice 9 — @governed decorator on a @tool function
# ---------------------------------------------------------------------------


def test_governed_decorator_wraps_tool():
    from zemtik_govern.langchain.tools import _GovernedTool, govern_tool

    gov = _make_governor(allowed=True)

    @tool
    def list_dir(path: str) -> str:
        """List directory."""
        return f"listing {path}"

    wrapped = govern_tool(list_dir, govern=gov)
    assert isinstance(wrapped, _GovernedTool)
    assert wrapped.invoke({"path": "/home"}) == "listing /home"


def test_governed_decorator_with_config_none_raises_on_wrong_order():
    """governed() must be applied AFTER @tool — wrong order raises GovernanceError."""
    from zemtik_govern.langchain.tools import governed

    with pytest.raises(GovernanceError, match="governed\\(\\) must be applied after @tool"):
        @governed({"mode": "enforce"})
        def plain_fn(path: str) -> str:
            """Not a BaseTool — wrong order."""
            return path


# ---------------------------------------------------------------------------
# Slice 10 — Wrong decorator order → GovernanceError at decoration time
# ---------------------------------------------------------------------------


def test_governed_wrong_order_raises_governance_error():
    """@governed applied before @tool (i.e., to a plain function) raises GovernanceError."""
    from zemtik_govern.langchain.tools import governed

    with pytest.raises(GovernanceError):
        @governed({"mode": "enforce"})
        def not_a_tool(x: str) -> str:
            return x


# ---------------------------------------------------------------------------
# Slice 11 — invoke() inside running loop → GovernanceError pointing to ainvoke()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_govern_tool_invoke_inside_loop_raises():
    """invoke() called from inside an async context raises GovernanceError."""
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=True)
    governed = govern_tool(read_file, govern=gov)
    with pytest.raises(GovernanceError, match="ainvoke\\(\\)"):
        governed.invoke({"path": "/test"})


# ---------------------------------------------------------------------------
# Issue #17 — _is_dev_mode() uses ZEMTIK_DEV env var
# ---------------------------------------------------------------------------


def test_is_dev_mode_false_when_not_set(monkeypatch):
    from zemtik_govern.langchain.tools import _is_dev_mode

    monkeypatch.delenv("ZEMTIK_DEV", raising=False)
    assert _is_dev_mode() is False


def test_is_dev_mode_true_when_set(monkeypatch):
    from zemtik_govern.langchain.tools import _is_dev_mode

    monkeypatch.setenv("ZEMTIK_DEV", "1")
    assert _is_dev_mode() is True


# ---------------------------------------------------------------------------
# Issue #17 — DEBUG log on allow AND deny
# ---------------------------------------------------------------------------


def test_govern_tool_logs_allow_at_debug(caplog):
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=True, rule="allow-tools")
    governed = govern_tool(read_file, govern=gov)
    with caplog.at_level(logging.DEBUG, logger="zemtik_govern"):
        governed.invoke({"path": "/tmp/x"})
    assert any("ALLOW" in r.message and "read_file" in r.message for r in caplog.records)


def test_govern_tool_logs_deny_at_debug(caplog):
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=False, reason="no access")
    governed = govern_tool(read_file, govern=gov, on_denied="tool_message")
    with caplog.at_level(logging.DEBUG, logger="zemtik_govern"):
        governed.invoke({"path": "/etc/shadow"})
    assert any("DENY" in r.message and "read_file" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Issue #17 — on_denied="tool_message" + ZEMTIK_DEV → verbose content
# ---------------------------------------------------------------------------


def test_govern_tool_denied_tool_message_dev_mode_verbose(monkeypatch):
    from langchain_core.messages import ToolMessage

    from zemtik_govern.langchain.tools import govern_tool

    monkeypatch.setenv("ZEMTIK_DEV", "1")
    gov = _make_governor(allowed=False, rule="deny-rule", reason="no permission")
    governed = govern_tool(read_file, govern=gov, on_denied="tool_message")
    result = governed.invoke({"path": "/secret"})
    assert isinstance(result, ToolMessage)
    assert "deny-rule" in result.content or "no permission" in result.content


# ---------------------------------------------------------------------------
# Issue #17 — on_denied="tool_message" → always logs warning regardless of dev mode
# ---------------------------------------------------------------------------


def test_govern_tool_denied_tool_message_logs_warning(caplog, monkeypatch):
    from zemtik_govern.langchain.tools import govern_tool

    monkeypatch.delenv("ZEMTIK_DEV", raising=False)
    gov = _make_governor(allowed=False, reason="blocked")
    governed = govern_tool(read_file, govern=gov, on_denied="tool_message")
    with caplog.at_level(logging.WARNING, logger="zemtik_govern"):
        governed.invoke({"path": "/secret"})
    assert any("ZEMTIK WARNING" in r.message for r in caplog.records)


def test_govern_tool_denied_tool_message_logs_warning_in_dev_mode(caplog, monkeypatch):
    from zemtik_govern.langchain.tools import govern_tool

    monkeypatch.setenv("ZEMTIK_DEV", "1")
    gov = _make_governor(allowed=False, reason="blocked")
    governed = govern_tool(read_file, govern=gov, on_denied="tool_message")
    with caplog.at_level(logging.WARNING, logger="zemtik_govern"):
        governed.invoke({"path": "/secret"})
    assert any("ZEMTIK WARNING" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Fix 1 — run() and arun() raise GovernanceError (governance bypass guard)
# ---------------------------------------------------------------------------


def test_run_raises_governance_error():
    """run() must raise GovernanceError — it bypasses governance."""
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=True)
    governed = govern_tool(read_file, govern=gov)
    with pytest.raises(GovernanceError, match="run\\(\\).*governance"):
        governed.run({"path": "/test"})


@pytest.mark.asyncio
async def test_arun_raises_governance_error():
    """arun() must raise GovernanceError — it bypasses governance."""
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=True)
    governed = govern_tool(read_file, govern=gov)
    with pytest.raises(GovernanceError, match="arun\\(\\).*governance"):
        await governed.arun({"path": "/test"})


# ---------------------------------------------------------------------------
# Fix 3 — args_schema propagated to _GovernedTool
# ---------------------------------------------------------------------------


def test_governed_tool_copies_args_schema():
    """_GovernedTool.args_schema must equal the wrapped tool's args_schema."""
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=True)
    governed = govern_tool(read_file, govern=gov)
    assert governed.args_schema == read_file.args_schema
