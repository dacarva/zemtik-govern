"""Slice 2b — Langfuse LangChain callback helper (issue #59): the LLM
generation and the core Tracer's governance spans share one root trace.

`importorskip`-guarded for `langfuse` + `langchain` (the extras this helper
needs — see `zemtik_govern/langchain/observability.py`'s docstring for why
the full `langchain` package, not just `langchain-core`, is required). The
langfuse-free/langchain-free CI job never collects this file.
"""

from __future__ import annotations

import pytest

pytest.importorskip("langfuse")
pytest.importorskip("langchain")

from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import tool
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from zemtik_govern.core import ZemtikGovern
from zemtik_govern.identity import AgentRef
from zemtik_govern.langchain.observability import _InertCallbackHandler, langfuse_callback
from zemtik_govern.langchain.tools import govern_tool
from zemtik_govern.observability._langfuse import LangfuseBoundary
from zemtik_govern.observability.tracer import LangfuseTracer
from zemtik_govern.protocols import Decision


class _Seams:
    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)

    async def evaluate(self, ctx):
        return Decision(allowed=True, action="allow", matched_rule="r", reason="ok")

    async def write(self, entry):
        return "evt-1"


@tool
def _echo(msg: str) -> str:
    """Echo the message."""
    return msg


def _boundary_with_exporter(public_key: str) -> tuple[LangfuseBoundary, InMemorySpanExporter]:
    """A real boundary whose isolated TracerProvider also feeds an in-memory
    exporter, so tests can inspect emitted spans without a live Langfuse
    server. Each test uses a unique public_key (the SDK keys its client
    registry by it) to avoid cross-test state leakage."""
    boundary = LangfuseBoundary(public_key=public_key, secret_key="sk", host="http://localhost:3000")
    exporter = InMemorySpanExporter()
    boundary._tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    return boundary, exporter


def _fake_model() -> FakeMessagesListChatModel:
    return FakeMessagesListChatModel(
        name="fake-model-x",
        responses=[
            AIMessage(
                content="hi there",
                usage_metadata={"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
            )
        ],
    )


def test_langfuse_callback_wires_a_real_callback_handler():
    boundary, _ = _boundary_with_exporter("pk-cb-wire-test")
    handler = langfuse_callback(boundary)
    assert isinstance(handler, BaseCallbackHandler)
    assert not isinstance(handler, _InertCallbackHandler)


def test_running_a_fake_model_through_the_callback_emits_one_generation_span_with_model_and_tokens():
    boundary, exporter = _boundary_with_exporter("pk-cb-generation-test")
    handler = langfuse_callback(boundary)
    model = _fake_model()

    model.invoke([HumanMessage(content="hello")], config={"callbacks": [handler]})

    generation_spans = [
        s for s in exporter.get_finished_spans()
        if s.attributes.get("langfuse.observation.type") == "generation"
    ]
    assert len(generation_spans) == 1
    gen = generation_spans[0]
    assert gen.name == "fake-model-x"
    assert gen.attributes["langfuse.observation.usage_details"] == (
        '{"input": 3, "output": 2, "total": 5}'
    )


def test_governed_tool_call_nests_under_the_same_root_trace_as_the_generation():
    boundary, exporter = _boundary_with_exporter("pk-cb-nesting-test")
    handler = langfuse_callback(boundary)
    tracer = LangfuseTracer(boundary)
    seams = _Seams()
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    governed_echo = govern_tool(_echo, govern=gov)
    model = _fake_model()

    def _agent_run(_input, config=None):
        model.invoke([HumanMessage(content="hello")], config=config)
        governed_echo.invoke({"msg": "hi"}, config=config)
        return "done"

    RunnableLambda(_agent_run).invoke({}, config={"callbacks": [handler]})

    spans = exporter.get_finished_spans()
    trace_ids = {s.context.trace_id for s in spans}
    assert len(trace_ids) == 1, f"expected one shared trace, got {len(trace_ids)}: {spans}"
    span_names = {s.name for s in spans}
    assert {"fake-model-x", "govern", "identity", "policy"} <= span_names


def test_fail_open_a_broken_boundary_leaves_the_tool_call_unaffected():
    """A boundary whose langchain_callback_handler() blows up degrades to an
    inert no-op callback — the governed tool call's decision and result are
    unaffected."""

    class _ExplodingBoundary:
        def langchain_callback_handler(self):
            raise RuntimeError("boom: callback init failed")

    handler = langfuse_callback(_ExplodingBoundary())
    assert isinstance(handler, _InertCallbackHandler)

    seams = _Seams()
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams)
    governed_echo = govern_tool(_echo, govern=gov)
    result = governed_echo.invoke({"msg": "hi"}, config={"callbacks": [handler]})
    assert result == "hi"
