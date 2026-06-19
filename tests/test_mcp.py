"""TDD tests for GovernedMCPServer (issue #20).

Written FIRST (red), then the implementation makes them green.

Architecture invariants under test:
  - Every tool call passes through govern() (identity -> policy -> audit).
  - Fail-closed: governance fault blocks the tool; tool never runs.
  - on_denied="raise": raises GovernanceDenied on policy deny.
  - on_denied="error_response": returns error content instead of raising.
  - AGT boundary rule: agent_os/agentmesh imports stay in _agt.py only.
  - Subject resolution: per-request agent_id from X-Agent-ID header or JWT sub.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.mcp import GovernedMCPServer
from zemtik_govern.protocols import Decision

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _allow_decision(action: str = "tool:hello") -> Decision:
    return Decision(allowed=True, action=action, matched_rule="allow-all", reason="ok")


def _deny_decision(action: str = "tool:hello") -> Decision:
    return Decision(
        allowed=False,
        action=action,
        matched_rule=None,
        reason="denied by policy",
        denial_kind="policy",
    )


def _make_govern(decision: Decision) -> MagicMock:
    """Return a ZemtikGovern mock that returns *decision* from govern()."""
    gov = MagicMock()
    gov.govern = AsyncMock(return_value=decision)
    return gov


async def _hello(name: str = "world") -> str:
    """Minimal async tool for testing."""
    return f"hello {name}"


def _sync_hello(name: str = "world") -> str:
    """Minimal sync tool for testing."""
    return f"hello {name}"


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_governed_mcp_server_construction_with_govern():
    """GovernedMCPServer accepts a pre-built ZemtikGovern instance."""
    gov = _make_govern(_allow_decision())
    server = GovernedMCPServer(tools=[_hello], govern=gov)
    assert server is not None


def test_governed_mcp_server_construction_requires_tools_list():
    """Tools must be a list of callables."""
    gov = _make_govern(_allow_decision())
    with pytest.raises((TypeError, ValueError)):
        GovernedMCPServer(tools="not_a_list", govern=gov)  # type: ignore[arg-type]


def test_governed_mcp_server_default_on_denied_is_raise():
    """Default on_denied mode is 'raise'."""
    gov = _make_govern(_allow_decision())
    server = GovernedMCPServer(tools=[_hello], govern=gov)
    assert server.on_denied == "raise"


def test_governed_mcp_server_accepts_error_response_mode():
    """on_denied='error_response' is accepted."""
    gov = _make_govern(_allow_decision())
    server = GovernedMCPServer(tools=[_hello], govern=gov, on_denied="error_response")
    assert server.on_denied == "error_response"


def test_governed_mcp_server_rejects_invalid_on_denied():
    """Invalid on_denied values are rejected at construction."""
    gov = _make_govern(_allow_decision())
    with pytest.raises((TypeError, ValueError)):
        GovernedMCPServer(tools=[_hello], govern=gov, on_denied="invalid")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Tool invocation — allow path
# ---------------------------------------------------------------------------


async def test_governed_tool_runs_on_allow():
    """Tool executes and returns result when govern() allows."""
    gov = _make_govern(_allow_decision("tool:hello"))
    server = GovernedMCPServer(tools=[_hello], govern=gov)
    result = await server._invoke_tool("hello", {"name": "alice"}, subject="agent:test")
    assert result == "hello alice"
    gov.govern.assert_awaited_once()


async def test_governed_tool_runs_sync_callable_on_allow():
    """Sync tools are also supported (awaited transparently)."""
    gov = _make_govern(_allow_decision("tool:sync_hello"))
    server = GovernedMCPServer(tools=[_sync_hello], govern=gov)
    result = await server._invoke_tool("sync_hello", {"name": "bob"}, subject="agent:test")
    assert result == "hello bob"


async def test_govern_called_before_tool():
    """govern() is called before the tool; if govern raises, tool never runs."""
    call_log: list[str] = []

    async def spy_tool(x: int = 0) -> int:
        call_log.append("tool")
        return x

    gov = MagicMock()

    async def deny_then_allow(ctx: GovernanceContext) -> Decision:
        call_log.append("govern")
        return _allow_decision("tool:spy_tool")

    gov.govern = deny_then_allow
    server = GovernedMCPServer(tools=[spy_tool], govern=gov)
    await server._invoke_tool("spy_tool", {"x": 1}, subject="agent:test")
    assert call_log == ["govern", "tool"], "govern must run before tool"


# ---------------------------------------------------------------------------
# Tool invocation — deny path
# ---------------------------------------------------------------------------


async def test_on_denied_raise_raises_governance_denied():
    """With on_denied='raise', a deny raises GovernanceDenied."""
    gov = _make_govern(_deny_decision("tool:hello"))
    gov.govern.side_effect = GovernanceDenied(_deny_decision("tool:hello"))
    server = GovernedMCPServer(tools=[_hello], govern=gov, on_denied="raise")
    with pytest.raises(GovernanceDenied):
        await server._invoke_tool("hello", {}, subject="agent:test")


async def test_on_denied_error_response_returns_error_content():
    """With on_denied='error_response', a deny returns error content dict."""
    decision = _deny_decision("tool:hello")
    gov = _make_govern(decision)
    gov.govern.side_effect = GovernanceDenied(decision)
    server = GovernedMCPServer(tools=[_hello], govern=gov, on_denied="error_response")
    result = await server._invoke_tool("hello", {}, subject="agent:test")
    # Must be a dict with an error indicator
    assert isinstance(result, dict)
    assert result.get("error") is True or "denied" in str(result).lower()


async def test_tool_never_runs_on_deny():
    """The wrapped tool function is NEVER called when governance denies."""
    ran = []

    async def guarded(x: int = 0) -> int:
        ran.append(x)
        return x

    gov = MagicMock()
    gov.govern = AsyncMock(side_effect=GovernanceDenied(_deny_decision("tool:guarded")))
    server = GovernedMCPServer(tools=[guarded], govern=gov, on_denied="error_response")
    await server._invoke_tool("guarded", {"x": 42}, subject="agent:test")
    assert ran == [], "tool must not run when governance denies"


# ---------------------------------------------------------------------------
# Fail-closed — system fault
# ---------------------------------------------------------------------------


async def test_governance_system_fault_blocks_tool():
    """A GovernanceError (system fault) blocks the tool — fail-closed."""
    ran = []

    async def guarded(x: int = 0) -> int:
        ran.append(x)
        return x

    gov = MagicMock()
    gov.govern = AsyncMock(side_effect=GovernanceError("engine fault"))
    server = GovernedMCPServer(tools=[guarded], govern=gov, on_denied="raise")
    with pytest.raises(GovernanceError):
        await server._invoke_tool("guarded", {"x": 1}, subject="agent:test")
    assert ran == [], "tool must not run on governance system fault"


async def test_governance_system_fault_with_error_response_mode():
    """GovernanceError with on_denied='error_response' returns error content."""
    gov = MagicMock()
    gov.govern = AsyncMock(side_effect=GovernanceError("engine fault"))
    server = GovernedMCPServer(tools=[_hello], govern=gov, on_denied="error_response")
    result = await server._invoke_tool("hello", {}, subject="agent:test")
    assert isinstance(result, dict)
    assert result.get("error") is True


# ---------------------------------------------------------------------------
# Subject resolution
# ---------------------------------------------------------------------------


async def test_subject_from_explicit_kwarg():
    """Subject passes through from the explicit subject kwarg."""
    gov = _make_govern(_allow_decision("tool:hello"))
    server = GovernedMCPServer(tools=[_hello], govern=gov)
    await server._invoke_tool("hello", {}, subject="agent:explicit")
    ctx: GovernanceContext = gov.govern.call_args[0][0]
    assert ctx.subject == "agent:explicit"


async def test_govern_context_action_is_tool_name():
    """GovernanceContext.action is prefixed 'tool:<name>'."""
    gov = _make_govern(_allow_decision("tool:hello"))
    server = GovernedMCPServer(tools=[_hello], govern=gov)
    await server._invoke_tool("hello", {"name": "z"}, subject="agent:x")
    ctx: GovernanceContext = gov.govern.call_args[0][0]
    assert ctx.action == "tool:hello"


async def test_govern_context_payload_contains_args():
    """GovernanceContext.payload contains the tool arguments."""
    gov = _make_govern(_allow_decision("tool:hello"))
    server = GovernedMCPServer(tools=[_hello], govern=gov)
    await server._invoke_tool("hello", {"name": "carol"}, subject="agent:x")
    ctx: GovernanceContext = gov.govern.call_args[0][0]
    assert ctx.payload.get("name") == "carol"


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------


async def test_invoke_unknown_tool_raises():
    """Invoking a tool not registered raises an appropriate error."""
    gov = _make_govern(_allow_decision("tool:nonexistent"))
    server = GovernedMCPServer(tools=[_hello], govern=gov)
    with pytest.raises((KeyError, ValueError, AttributeError)):
        await server._invoke_tool("nonexistent", {}, subject="agent:x")


# ---------------------------------------------------------------------------
# serve() API surface
# ---------------------------------------------------------------------------


def test_server_has_serve_method():
    """GovernedMCPServer exposes a serve() coroutine method."""
    gov = _make_govern(_allow_decision())
    server = GovernedMCPServer(tools=[_hello], govern=gov)
    assert asyncio.iscoroutinefunction(server.serve)


# ---------------------------------------------------------------------------
# AGT boundary rule (import-level)
# ---------------------------------------------------------------------------


def test_mcp_server_module_does_not_import_agent_os():
    """server.py must not import agent_os directly (AGT boundary rule)."""
    import ast
    import pathlib

    server_path = (
        pathlib.Path(__file__).parent.parent
        / "src"
        / "zemtik_govern"
        / "mcp"
        / "server.py"
    )
    source = server_path.read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                names = [node.module or ""]
            for name in names:
                assert not name.startswith("agent_os"), (
                    f"AGT boundary violation: server.py imports {name!r}. "
                    "Only _agt.py may import agent_os."
                )
                assert not name.startswith("agentmesh"), (
                    f"AGT boundary violation: server.py imports {name!r}. "
                    "Only _agt.py may import agentmesh."
                )


def test_mcp_init_does_not_import_agent_os():
    """mcp/__init__.py must not import agent_os or agentmesh."""
    import ast
    import pathlib

    init_path = (
        pathlib.Path(__file__).parent.parent
        / "src"
        / "zemtik_govern"
        / "mcp"
        / "__init__.py"
    )
    source = init_path.read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                names = [node.module or ""]
            for name in names:
                assert not name.startswith("agent_os"), (
                    f"AGT boundary violation: mcp/__init__.py imports {name!r}"
                )
                assert not name.startswith("agentmesh"), (
                    f"AGT boundary violation: mcp/__init__.py imports {name!r}"
                )


# ---------------------------------------------------------------------------
# Export surface
# ---------------------------------------------------------------------------


def test_governed_mcp_server_exported_from_mcp_package():
    """GovernedMCPServer is importable from zemtik_govern.mcp."""
    from zemtik_govern.mcp import GovernedMCPServer as _GMS  # noqa: F401

    assert _GMS is GovernedMCPServer
