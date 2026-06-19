"""Audit package — the Merkle-chained adapter and the redacted fallback channel.

Public surface is unchanged from the v0.1 single-module form: ``from
zemtik_govern.audit import AgentMeshAudit`` still works.
"""

from .fallback import DEFAULT_FALLBACK_PATH, emit_fallback, redacted_record
from .log import AgentMeshAudit

__all__ = [
    "AgentMeshAudit",
    "DEFAULT_FALLBACK_PATH",
    "emit_fallback",
    "redacted_record",
]
