"""LangGraph GovernedToolNode — drop-in ToolNode replacement with governance.

Debug: ZEMTIK_DEV=1 python examples/langgraph_toolnode.py
"""
import os

os.environ.setdefault("ZEMTIK_DEV", "1")

from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from zemtik_govern.core import ZemtikGovern
from zemtik_govern.identity import AgentRef
from zemtik_govern.langchain import GovernedToolNode
from zemtik_govern.protocols import Decision


class _DemoPolicy:
    async def identify(self, subject):
        return AgentRef(did=f"did:demo:{subject}")

    async def evaluate(self, ctx):
        return Decision(
            allowed=True,
            action=ctx.action,
            matched_rule="allow-search-web",
            reason="demo allow",
        )

    async def write(self, entry):
        return "evt-demo"


gov = ZemtikGovern(identity=_DemoPolicy(), policy=_DemoPolicy(), audit=_DemoPolicy())


@tool
def search_web(query: str) -> str:
    """Search the web for information."""
    return f"Results for: {query}"


# Drop-in replacement for LangGraph ToolNode
node = GovernedToolNode([search_web], govern=gov)

state = {
    "messages": [
        AIMessage(
            content="",
            tool_calls=[
                {"name": "search_web", "args": {"query": "zemtik governance"}, "id": "tc-1"},
            ],
        )
    ]
}

result = node(state)
for msg in result.get("messages", []):
    print(f"Tool result: {msg.content}")
