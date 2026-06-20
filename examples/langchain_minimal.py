"""Minimal LangChain governance example.

Copy-paste demo: govern a single tool in under 10 lines.
Debug: ZEMTIK_DEV=1 python examples/langchain_minimal.py
"""
import os
os.environ.setdefault("ZEMTIK_DEV", "1")

from langchain_core.tools import tool

from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied
from zemtik_govern.identity import AgentRef
from zemtik_govern.langchain import govern_tool
from zemtik_govern.protocols import Decision


class _DemoPolicy:
    async def identify(self, subject):
        return AgentRef(did=f"did:demo:{subject}")

    async def evaluate(self, ctx):
        return Decision(
            allowed=True,
            action=ctx.action,
            matched_rule="allow-add-numbers",
            reason="demo allow",
        )

    async def write(self, entry):
        return "evt-demo"


gov = ZemtikGovern(identity=_DemoPolicy(), policy=_DemoPolicy(), audit=_DemoPolicy())


@tool
def add_numbers(a: int, b: int) -> int:
    """Add two numbers together."""
    return a + b


governed_add = govern_tool(add_numbers, govern=gov)

try:
    result = governed_add.invoke({"a": 3, "b": 4})
    print(f"3 + 4 = {result}")
except GovernanceDenied as exc:
    print(f"Denied: {exc}")
