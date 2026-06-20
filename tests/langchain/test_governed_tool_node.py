"""TDD — GovernedToolNode vertical slices (issue #16)."""
from __future__ import annotations

import threading

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool

from zemtik_govern.core import ZemtikGovern
from zemtik_govern.identity import AgentRef
from zemtik_govern.protocols import Decision

# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------


@tool
def read_file(path: str) -> str:
    """Read a file."""
    return f"content of {path}"


@tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
    return f"sent to {to}"


class _FakeSeams:
    def __init__(self, *, allowed=True, rule="allow-all", reason="ok"):
        self._decision = Decision(
            allowed=allowed,
            action="test",
            matched_rule=rule if allowed else None,
            reason=reason,
            denial_kind=None if allowed else "policy",
        )

    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)

    async def evaluate(self, ctx):
        return self._decision

    async def write(self, entry):
        return "evt-1"


def _make_governor(*, allowed=True):
    s = _FakeSeams(allowed=allowed)
    return ZemtikGovern(identity=s, policy=s, audit=s)


def _state(tool_name, args, tool_call_id="tc-1"):
    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": tool_name,
                        "args": args,
                        "id": tool_call_id,
                        "type": "tool_call",
                    }
                ],
            )
        ]
    }


# ---------------------------------------------------------------------------
# Slice 1 — tracer bullet: GovernedToolNode is NOT a ToolNode subclass
# ---------------------------------------------------------------------------


def test_governed_tool_node_is_not_tool_node_subclass():
    from zemtik_govern.langchain import GovernedToolNode

    gov = _make_governor()
    node = GovernedToolNode([read_file], govern=gov)

    try:
        from langgraph.prebuilt import ToolNode as LGToolNode
        assert not isinstance(node, LGToolNode)
    except ImportError:
        pass  # no langgraph installed — pass vacuously

    # Fundamental check: it's our class, not a ToolNode
    assert type(node).__name__ == "GovernedToolNode"


# ---------------------------------------------------------------------------
# Slice 2 — ValueError when both config= and govern= provided
# ---------------------------------------------------------------------------


def test_raises_when_both_config_and_govern():
    from zemtik_govern.langchain import GovernedToolNode

    gov = _make_governor()
    with pytest.raises(ValueError, match="config=.*govern=|govern=.*config="):
        GovernedToolNode([read_file], config={"mode": "strict"}, govern=gov)


# ---------------------------------------------------------------------------
# Slice 3 — ValueError when neither config= nor govern= provided
# ---------------------------------------------------------------------------


def test_raises_when_neither_config_nor_govern():
    from zemtik_govern.langchain import GovernedToolNode

    with pytest.raises(ValueError):
        GovernedToolNode([read_file])


# ---------------------------------------------------------------------------
# Slice 4 — allow path: __call__ returns {messages: [ToolMessage with result]}
# ---------------------------------------------------------------------------


def test_call_allow_returns_tool_message():
    from zemtik_govern.langchain import GovernedToolNode

    gov = _make_governor(allowed=True)
    node = GovernedToolNode([read_file], govern=gov)

    state = _state("read_file", {"path": "/tmp/foo"}, tool_call_id="tc-allow")
    result = node(state)

    assert "messages" in result
    msgs = result["messages"]
    assert len(msgs) == 1
    tm = msgs[0]
    assert isinstance(tm, ToolMessage)
    assert tm.tool_call_id == "tc-allow"
    assert "content of /tmp/foo" in tm.content


# ---------------------------------------------------------------------------
# Slice 5 — KEY GATE: deny preserves tool_call_id
# ---------------------------------------------------------------------------


def test_deny_returns_tool_message_with_correct_tool_call_id():
    from zemtik_govern.langchain import GovernedToolNode

    gov = _make_governor(allowed=False)
    node = GovernedToolNode([read_file], govern=gov)

    state = _state("read_file", {"path": "/etc/passwd"}, tool_call_id="tc-denied")
    result = node(state)

    assert "messages" in result
    msgs = result["messages"]
    assert len(msgs) == 1
    tm = msgs[0]
    assert isinstance(tm, ToolMessage)
    assert tm.tool_call_id == "tc-denied"
    assert tm.content == "tool call denied"


# ---------------------------------------------------------------------------
# Slice 6 — multiple tool_calls: deny one, allow another
# ---------------------------------------------------------------------------


def test_multiple_tool_calls_deny_one_allow_another():
    from zemtik_govern.langchain import GovernedToolNode

    class _SelectiveSeams:
        """Allow read_file, deny send_email."""
        async def identify(self, subject):
            return AgentRef(did="did:mesh:" + subject)

        async def evaluate(self, ctx):
            if ctx.action == "read_file":
                return Decision(
                    allowed=True, action=ctx.action,
                    matched_rule="allow-all", reason="ok",
                )
            return Decision(
                allowed=False, action=ctx.action,
                matched_rule=None, reason="denied",
                denial_kind="policy",
            )

        async def write(self, entry):
            return "evt-x"

    s = _SelectiveSeams()
    gov = ZemtikGovern(identity=s, policy=s, audit=s)
    node = GovernedToolNode([read_file, send_email], govern=gov)

    state = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "read_file", "args": {"path": "/tmp/a"}, "id": "tc-r", "type": "tool_call"},
                    {"name": "send_email", "args": {"to": "x@x.com", "body": "hi"}, "id": "tc-e", "type": "tool_call"},
                ],
            )
        ]
    }

    result = node(state)
    msgs = result["messages"]
    assert len(msgs) == 2

    by_id = {m.tool_call_id: m for m in msgs}
    assert "content of /tmp/a" in by_id["tc-r"].content
    assert by_id["tc-e"].content == "tool call denied"
    assert by_id["tc-e"].tool_call_id == "tc-e"


# ---------------------------------------------------------------------------
# Slice 7 — govern_tool_node() shorthand returns GovernedToolNode
# ---------------------------------------------------------------------------


def test_govern_tool_node_shorthand():
    from zemtik_govern.langchain import GovernedToolNode, govern_tool_node

    gov = _make_governor()
    node = govern_tool_node([read_file], govern=gov)
    assert isinstance(node, GovernedToolNode)


# ---------------------------------------------------------------------------
# Slice 8 — concurrent calls before lazy init completes → no deadlock
# ---------------------------------------------------------------------------


def test_concurrent_calls_no_deadlock():
    """Threading.Lock must serialize lazy init without deadlock."""
    from zemtik_govern.langchain import GovernedToolNode

    gov = _make_governor(allowed=True)
    node = GovernedToolNode([read_file], govern=gov)

    results = []
    errors = []

    def worker():
        try:
            state = _state("read_file", {"path": "/tmp/t"}, tool_call_id="tc-concurrent")
            r = node(state)
            results.append(r)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    alive = [t for t in threads if t.is_alive()]
    assert not alive, f"{len(alive)} threads still alive after 5s — possible deadlock"
    assert not errors, f"Errors in threads: {errors}"
    assert len(results) == 10


# ---------------------------------------------------------------------------
# Fix 2 — denial ToolMessage tool_call_id matches the tool_call's id
# ---------------------------------------------------------------------------


def test_deny_tool_message_tool_call_id_from_governed_tool():
    """_GovernedTool with on_denied=tool_message must use the input's id field."""
    from zemtik_govern.langchain.tools import govern_tool

    gov = _make_governor(allowed=False)
    governed = govern_tool(read_file, govern=gov, on_denied="tool_message")
    # Simulate a ToolCall dict with an explicit id
    result = governed.invoke({"path": "/etc/shadow", "id": "tc-fix2"})
    from langchain_core.messages import ToolMessage
    assert isinstance(result, ToolMessage)
    assert result.tool_call_id == "tc-fix2"


# ---------------------------------------------------------------------------
# Fix 4 — GovernedToolNode guards against invalid state
# ---------------------------------------------------------------------------


def test_call_empty_messages_returns_empty():
    """Empty messages list must return empty results without error."""
    from zemtik_govern.langchain import GovernedToolNode

    gov = _make_governor(allowed=True)
    node = GovernedToolNode([read_file], govern=gov)

    result = node({"messages": []})
    assert result == {"messages": []}


def test_call_missing_messages_key_returns_empty():
    """Missing messages key must return empty results without error."""
    from zemtik_govern.langchain import GovernedToolNode

    gov = _make_governor(allowed=True)
    node = GovernedToolNode([read_file], govern=gov)

    result = node({})
    assert result == {"messages": []}


def test_call_last_message_no_tool_calls_returns_empty():
    """Last message with no tool_calls attribute must return empty results."""
    from langchain_core.messages import HumanMessage

    from zemtik_govern.langchain import GovernedToolNode

    gov = _make_governor(allowed=True)
    node = GovernedToolNode([read_file], govern=gov)

    # HumanMessage has no tool_calls attribute
    result = node({"messages": [HumanMessage(content="hello")]})
    assert result == {"messages": []}
