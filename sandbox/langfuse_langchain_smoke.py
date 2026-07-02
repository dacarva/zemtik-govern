#!/usr/bin/env python3
"""Slice 2b real-backend smoke test: proves `langfuse_callback()` (issue #59)
emits a real LLM generation observation AND a governed tool call's governance
spans under the SAME trace, on a live Langfuse backend — self-hosted or
cloud. See `sandbox/langfuse_boundary_smoke.py` (Slice 1) and
`sandbox/langfuse_slice2_smoke.py` (Slice 2) for the narrower predecessors.

Uses a fake/stub LangChain chat model (no OpenAI key required) so this script
only needs the `[langchain,langfuse]` extras and Langfuse credentials — the
point is proving the trace-sharing wiring, not a real model call.

Run against a self-hosted instance (e.g. via the official Langfuse docker
compose: https://langfuse.com/self-hosting/docker-compose):

    LANGFUSE_PUBLIC_KEY=pk-lf-... \\
    LANGFUSE_SECRET_KEY=sk-lf-... \\
    LANGFUSE_HOST=http://localhost:3000 \\
    python sandbox/langfuse_langchain_smoke.py

Or copy `.env` (see `.env.example`) and set the three LANGFUSE_* vars there —
this script loads `.env` the same way the other smoke scripts do.
Requires the extras: `uv pip install -e ".[dev,langchain,langfuse]"`.
"""

from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))

REPO_ROOT = pathlib.Path(__file__).parent.parent

_SENTINEL = "SENTINEL-RAW-SLICE2B-SMOKE"

_ALLOW_TOOL_RUN = {
    "name": "allow-echo",
    "condition": {"field": "action", "operator": "eq", "value": "echo"},
    "action": "allow",
}


def load_dotenv(path: pathlib.Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main() -> int:
    load_dotenv(REPO_ROOT / ".env")
    os.environ.setdefault("LANGFUSE_HOST", "http://localhost:3000")

    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    host = os.environ["LANGFUSE_HOST"]

    if not public_key or not secret_key:
        print(
            "Missing LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY.\n"
            "Set them in .env or the environment — see .env.example and\n"
            "docs/observability.md.",
            file=sys.stderr,
        )
        return 2

    try:
        from zemtik_govern.observability._langfuse import LangfuseBoundary
        from zemtik_govern.observability.tracer import LangfuseTracer
    except ImportError as exc:
        print(
            f"langfuse is not installed: {exc}\n"
            'Install the extra: uv pip install -e ".[dev,langfuse]"',
            file=sys.stderr,
        )
        return 2

    try:
        from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
        from langchain_core.messages import AIMessage, HumanMessage
        from langchain_core.runnables import RunnableLambda
        from langchain_core.tools import tool
    except ImportError as exc:
        print(
            f"langchain is not installed: {exc}\n"
            'Install the extra: uv pip install -e ".[dev,langchain]"',
            file=sys.stderr,
        )
        return 2

    from zemtik_govern._agt import AGTBoundary
    from zemtik_govern.audit import AgentMeshAudit
    from zemtik_govern.core import ZemtikGovern
    from zemtik_govern.identity import StaticIdentity
    from zemtik_govern.langchain import govern_tool, langfuse_callback
    from zemtik_govern.policy import AgentOsPolicy

    print(f"Constructing LangfuseBoundary + LangfuseTracer against {host!r} ...")
    lf_boundary = LangfuseBoundary(public_key=public_key, secret_key=secret_key, host=host)
    tracer = LangfuseTracer(lf_boundary)
    handler = langfuse_callback(lf_boundary)

    agt_boundary = AGTBoundary()
    gov = ZemtikGovern(
        identity=StaticIdentity(agt_boundary),
        policy=AgentOsPolicy(agt_boundary, rules=[_ALLOW_TOOL_RUN]),
        audit=AgentMeshAudit(agt_boundary),
        mode="strict",
        tracer=tracer,
    )

    @tool
    def echo(msg: str) -> str:
        """Echo the message."""
        return msg

    governed_echo = govern_tool(echo, govern=gov)

    model = FakeMessagesListChatModel(
        name="zemtik-slice2b-smoke-model",
        responses=[
            AIMessage(
                content="ack",
                usage_metadata={"input_tokens": 4, "output_tokens": 1, "total_tokens": 5},
            )
        ],
    )

    print("\nRunning a fake model call + a governed tool call under one agent-run trace ...")

    def _agent_run(_input, config=None):
        model.invoke([HumanMessage(content=_SENTINEL)], config=config)
        governed_echo.invoke({"msg": _SENTINEL}, config=config)
        return "done"

    RunnableLambda(_agent_run).invoke({}, config={"callbacks": [handler]})

    print("\nFlushing to the backend ...")
    lf_boundary.client.flush()
    print(
        "\nDone. Check the Langfuse UI: one trace should contain BOTH a\n"
        "'zemtik-slice2b-smoke-model' generation observation (with token usage)\n"
        "AND a 'govern' span with identity/policy children — same trace id.\n"
        f"None of them should contain the substring {_SENTINEL!r} anywhere in the\n"
        "governance spans (the generation's own input/output legitimately echoes\n"
        "it — only the core Tracer seam's no-echo guarantee is under test here)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
