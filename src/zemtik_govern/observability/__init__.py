"""Optional Langfuse observability — OFF by default, isolated behind one boundary.

Public surface for the observability seam. Importing this package pulls in NO
third-party dependency: the default :class:`NoOpTracer` and the Protocols are
pure-stdlib. Only ``build_tracer`` (added in a later slice) ever reaches the
Langfuse boundary, and only when observability is explicitly enabled.
"""

from __future__ import annotations

from .protocols import Span, Tracer
from .tracer import NoOpTracer

__all__ = ["Span", "Tracer", "NoOpTracer"]
