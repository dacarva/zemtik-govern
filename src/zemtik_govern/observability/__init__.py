"""Optional Langfuse observability — OFF by default, isolated behind one boundary.

Public surface for the observability seam. Importing this package pulls in NO
third-party dependency: the default :class:`NoOpTracer`, :class:`LangfuseTracer`
(a duck-typed façade — it never imports ``langfuse`` itself), and the Protocols
are all pure-stdlib. Only ``zemtik_govern.observability._langfuse`` ever imports
``langfuse``, and only when a ``LangfuseBoundary`` is actually constructed
(config/registry wiring that reaches it lands in a later slice).
"""

from __future__ import annotations

from .protocols import Span, Tracer
from .tracer import LangfuseTracer, NoOpTracer

__all__ = ["Span", "Tracer", "NoOpTracer", "LangfuseTracer"]
