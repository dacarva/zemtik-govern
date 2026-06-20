"""GovernedToolNode — drop-in LangGraph ToolNode with governance (issue #16).

Composition wrapper (NOT a ToolNode subclass). Intercepts tool_calls from the
last message in state, runs each through a governed tool, and returns
ToolMessage results. GovernanceDenied produces a denial ToolMessage that
preserves the original tool_call_id.
"""
from __future__ import annotations

from typing import Any

from langchain_core.messages import ToolMessage

from zemtik_govern.errors import GovernanceDenied

from .tools import govern_tool


class GovernedToolNode:
    """Composition wrapper that adds governance to a set of LangChain tools.

    Parameters
    ----------
    tools:
        List of LangChain BaseTool instances to govern.
    config:
        GovernanceConfig dict/object — used for lazy ZemtikGovern init.
    govern:
        Pre-built ZemtikGovern instance — bypasses lazy init.
    messages_key:
        Key in state dict that holds the messages list. Default "messages".

    Exactly one of ``config`` or ``govern`` must be provided.
    """

    def __init__(
        self,
        tools: list,
        *,
        config=None,
        govern=None,
        messages_key: str = "messages",
    ) -> None:
        if config is not None and govern is not None:
            raise ValueError(
                "Provide either config= or govern=, not both."
            )
        if config is None and govern is None:
            raise ValueError(
                "One of config= or govern= is required."
            )

        self._messages_key = messages_key

        # Build governed tools keyed by name
        # Each _GovernedTool handles its own lazy ZemtikGovern init (thread-safe).
        self._governed_tools: dict[str, Any] = {
            t.name: govern_tool(t, govern=govern, config=config, on_denied="raise")
            for t in tools
        }

    def __call__(self, state: dict, config=None) -> dict:
        """Execute governed tool calls from the last message in state.

        For each tool_call in state[messages_key][-1].tool_calls:
        - Invoke the governed tool (allow path) → ToolMessage with result
        - GovernanceDenied (deny path) → ToolMessage(content="tool call denied",
          tool_call_id=tool_call["id"])

        Returns {messages_key: [list of ToolMessages]}.
        """
        messages = state.get(self._messages_key, [])
        if not messages:
            return {self._messages_key: []}

        last_message = messages[-1]
        tool_calls = getattr(last_message, "tool_calls", None) or []

        results: list[ToolMessage] = []
        for tool_call in tool_calls:
            name = tool_call["name"]
            args = tool_call["args"]
            tool_call_id = tool_call["id"]

            governed = self._governed_tools.get(name)
            if governed is None:
                results.append(
                    ToolMessage(
                        content=f"unknown tool: {name}",
                        tool_call_id=tool_call_id,
                    )
                )
                continue

            try:
                result = governed.invoke(args, config)
                if isinstance(result, ToolMessage):
                    # Governed tool returned a ToolMessage directly (on_denied=tool_message path)
                    results.append(result)
                else:
                    results.append(
                        ToolMessage(
                            content=str(result),
                            tool_call_id=tool_call_id,
                        )
                    )
            except GovernanceDenied:
                results.append(
                    ToolMessage(
                        content="tool call denied",
                        tool_call_id=tool_call_id,
                    )
                )

        return {self._messages_key: results}


def govern_tool_node(
    tools: list,
    *,
    config=None,
    govern=None,
    messages_key: str = "messages",
) -> GovernedToolNode:
    """Shorthand constructor for GovernedToolNode."""
    return GovernedToolNode(tools, config=config, govern=govern, messages_key=messages_key)
