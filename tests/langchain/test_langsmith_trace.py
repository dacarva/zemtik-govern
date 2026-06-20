"""Tests for LangSmith trace — governance metadata via langchain-core callbacks (issue #18)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool

from zemtik_govern.core import ZemtikGovern
from zemtik_govern.identity import AgentRef
from zemtik_govern.langchain.tools import govern_tool
from zemtik_govern.protocols import Decision


class _FakeSeams:
    def __init__(self, *, allowed=True, rule="allow-all", reason="ok"):
        self._decision = Decision(
            allowed=allowed, action="test",
            matched_rule=rule if allowed else None,
            reason=reason,
            denial_kind=None if allowed else "policy",
        )

    async def identify(self, subject): return AgentRef(did="did:mesh:" + subject)
    async def evaluate(self, ctx): return self._decision
    async def write(self, entry): return "evt-1"


def _make_governor(*, allowed=True, rule="allow-all", reason="ok"):
    s = _FakeSeams(allowed=allowed, rule=rule, reason=reason)
    return ZemtikGovern(identity=s, policy=s, audit=s)


@tool
def _echo(msg: str) -> str:
    """Echo the message."""
    return msg


def _make_tool(gov, **kwargs):
    return govern_tool(_echo, govern=gov, **kwargs)


# ---------------------------------------------------------------------------
# Slice 1: no error when config=None (callback skipped)
# ---------------------------------------------------------------------------

def test_no_error_when_config_none():
    gt = _make_tool(_make_governor())
    result = gt.invoke({"msg": "hi"})
    assert result == "hi"


# ---------------------------------------------------------------------------
# Slice 2: no error when RunnableConfig has no callbacks key
# ---------------------------------------------------------------------------

def test_no_error_when_runnable_config_has_no_callbacks():
    gt = _make_tool(_make_governor())
    config = RunnableConfig()
    result = gt.invoke({"msg": "hello"}, config)
    assert result == "hello"


# ---------------------------------------------------------------------------
# Slice 3: on_chain_start called with correct metadata when callbacks present
# ---------------------------------------------------------------------------

def test_on_chain_start_called_with_governance_metadata():
    gt = _make_tool(_make_governor(rule="allow-all"))
    mock_cb = MagicMock()
    with patch("zemtik_govern.langchain.tools.get_callback_manager_for_config", return_value=mock_cb) as _p:
        config = RunnableConfig()
        gt.invoke({"msg": "test"}, config)
    mock_cb.on_chain_start.assert_called_once()
    call_kwargs = mock_cb.on_chain_start.call_args
    metadata = call_kwargs[0][1]  # second positional arg is the metadata dict
    assert "governance.decision" in metadata
    assert "governance.rule" in metadata
    assert "governance.subject" in metadata


# ---------------------------------------------------------------------------
# Slice 4: governance.decision = "allowed" on allow
# ---------------------------------------------------------------------------

def test_governance_decision_is_allowed():
    gt = _make_tool(_make_governor(allowed=True))
    mock_cb = MagicMock()
    with patch("zemtik_govern.langchain.tools.get_callback_manager_for_config", return_value=mock_cb) as _p:
        gt.invoke({"msg": "test"}, RunnableConfig())
    metadata = mock_cb.on_chain_start.call_args[0][1]
    assert metadata["governance.decision"] == "allowed"


# ---------------------------------------------------------------------------
# Slice 5: governance.rule matches matched_rule
# ---------------------------------------------------------------------------

def test_governance_rule_matches_matched_rule():
    gt = _make_tool(_make_governor(rule="my-custom-rule"))
    mock_cb = MagicMock()
    with patch("zemtik_govern.langchain.tools.get_callback_manager_for_config", return_value=mock_cb) as _p:
        gt.invoke({"msg": "test"}, RunnableConfig())
    metadata = mock_cb.on_chain_start.call_args[0][1]
    assert metadata["governance.rule"] == "my-custom-rule"


# ---------------------------------------------------------------------------
# Slice 6: governance.subject matches extracted subject
# ---------------------------------------------------------------------------

def test_governance_subject_matches_extracted_subject():
    gt = _make_tool(_make_governor())
    mock_cb = MagicMock()
    config = RunnableConfig(configurable={"agent_id": "agent-xyz"})
    with patch("zemtik_govern.langchain.tools.get_callback_manager_for_config", return_value=mock_cb) as _p:
        gt.invoke({"msg": "test"}, config)
    metadata = mock_cb.on_chain_start.call_args[0][1]
    assert metadata["governance.subject"] == "agent-xyz"


# ---------------------------------------------------------------------------
# Slice 7: on_chain_end called after on_chain_start
# ---------------------------------------------------------------------------

def test_on_chain_end_called_after_on_chain_start():
    gt = _make_tool(_make_governor())
    call_order = []
    mock_run_manager = MagicMock()
    mock_run_manager.on_chain_end.side_effect = lambda *a, **k: call_order.append("end")
    mock_cb = MagicMock()
    mock_cb.on_chain_start.side_effect = lambda *a, **k: (call_order.append("start"), mock_run_manager)[1]
    with patch("zemtik_govern.langchain.tools.get_callback_manager_for_config", return_value=mock_cb) as _p:
        gt.invoke({"msg": "test"}, RunnableConfig())
    assert call_order == ["start", "end"]


# ---------------------------------------------------------------------------
# Slice 8: no callback emission when tool is denied
# ---------------------------------------------------------------------------

def test_no_callback_on_denial():
    gt = _make_tool(_make_governor(allowed=False), on_denied="tool_message")
    mock_cb = MagicMock()
    with patch("zemtik_govern.langchain.tools.get_callback_manager_for_config", return_value=mock_cb) as _p:
        gt.invoke({"msg": "test", "id": "tc-1"}, RunnableConfig())
    mock_cb.on_chain_start.assert_not_called()
    mock_cb.on_chain_end.assert_not_called()


# ---------------------------------------------------------------------------
# Slice 9: ainvoke (async) also emits callbacks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ainvoke_emits_callbacks():
    gt = _make_tool(_make_governor(rule="async-rule"))
    mock_cb = MagicMock()
    with patch("zemtik_govern.langchain.tools.get_callback_manager_for_config", return_value=mock_cb) as _p:
        await gt.ainvoke({"msg": "test"}, RunnableConfig())
    mock_cb.on_chain_start.assert_called_once()
    metadata = mock_cb.on_chain_start.call_args[0][1]
    assert metadata["governance.rule"] == "async-rule"
