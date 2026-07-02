"""Langfuse LangChain callback helper — Slice 2b (issue #59).

Wires Langfuse's native LangChain ``CallbackHandler`` so an LLM generation
(model, tokens, cost) is captured under the same root trace as the core
``Tracer`` seam's governance spans (identity/policy/audit/injection/output).
The core library stays LLM-agnostic — this helper lives under the optional
``langchain`` extra and is opt-in.

Never imports ``langfuse`` directly. Only ``observability/_langfuse.py`` may
(see its docstring and
``tests/observability/test_langfuse_boundary.py::test_no_direct_langfuse_imports_outside_the_boundary``).
This module calls ``LangfuseBoundary.langchain_callback_handler()``, duck-typed,
the same discipline ``LangfuseTracer`` already follows.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.callbacks.base import BaseCallbackHandler

_LOG = logging.getLogger("zemtik_govern.observability")


class _InertCallbackHandler(BaseCallbackHandler):
    """A conforming no-op LangChain callback — every hook is inherited as a
    no-op from ``BaseCallbackHandler``. Used as the fail-open fallback when
    the real Langfuse callback can't be built."""


def langfuse_callback(boundary: Any) -> BaseCallbackHandler:
    """Build a Langfuse LangChain callback handler bound to ``boundary``.

    On any failure — the SDK/``langchain`` extras missing, a misconfigured
    client, an SDK error — this degrades to an inert no-op callback rather
    than raising. A broken observability integration must never change a
    governed tool call's decision or result.
    """
    try:
        return boundary.langchain_callback_handler()
    except Exception:
        _LOG.debug(
            "Langfuse LangChain callback unavailable; LLM generation will "
            "not be traced for this run",
            exc_info=True,
        )
        return _InertCallbackHandler()
