"""Audit — a thin adapter over agentmesh's Merkle-chained ``AuditLog``.

The tamper-evidence (Merkle chain + HMAC + ``verify_integrity`` + ``get_proof``)
is an agentmesh primitive; we delegate to it rather than hand-rolling. This
adapter only adapts the wrapper's entry dict to ``AuditLog.log`` and re-exposes
verification so callers can prove the trail without reaching past the boundary.
"""

from __future__ import annotations

from ._agt import AGTBoundary
from .protocols import AuditEntry


class AgentMeshAudit:
    """The wrapper's :class:`~zemtik_govern.protocols.AuditSink`."""

    def __init__(self, boundary: AGTBoundary, sink=None) -> None:
        self._log = boundary.audit_log(sink)

    async def write(self, entry: AuditEntry) -> str:
        # this adapter is the one place that knows agentmesh's kwarg names
        written = self._log.log(
            event_type=entry.event_type,
            agent_did=entry.agent_did,
            action=entry.action,
            outcome=entry.outcome,
            policy_decision=entry.policy_decision,
        )
        return written.entry_id

    def verify_integrity(self):
        """Delegates to agentmesh — ``(ok: bool, err: str | None)``."""
        return self._log.verify_integrity()

    def get_proof(self, entry_id: str):
        """Delegates to agentmesh — a Merkle proof for a written entry."""
        return self._log.get_proof(entry_id)
