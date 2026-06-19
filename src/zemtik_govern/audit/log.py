"""Audit adapter — a thin layer over agentmesh's Merkle-chained ``AuditLog``.

The tamper-evidence (Merkle chain + HMAC + ``verify_integrity`` + ``get_proof``)
is an agentmesh primitive; we delegate to it rather than hand-rolling. This
adapter only adapts the wrapper's :class:`~zemtik_govern.protocols.AuditEntry` to
``AuditLog.log`` and re-exposes verification so callers can prove the trail
without reaching past the boundary.

One thing it MUST do: thaw the frozen ``GovernanceContext`` payload back to plain
``dict``/``list`` before handing it to agentmesh. agentmesh hashes each entry with
``json.dumps``, which rejects the ``MappingProxyType`` the context is deep-frozen
into — so an unthawed payload would crash the write (or, worse, silently degrade
to ``str``). The bytes policy saw stay the bytes audit records.

On a primary-sink failure the write is routed through the redacted emergency
fallback (:mod:`zemtik_govern.audit.fallback`) and then re-raised as a
:class:`~zemtik_govern.errors.GovernanceError`: the denial invariant holds
unconditionally — the guarded tool never runs even when audit cannot.
"""

from __future__ import annotations

from .._agt import AGTBoundary
from ..context import _thaw
from ..errors import GovernanceError
from ..protocols import AuditEntry
from .fallback import emit_fallback


class AgentMeshAudit:
    """The wrapper's :class:`~zemtik_govern.protocols.AuditSink`."""

    def __init__(self, boundary: AGTBoundary, sink=None, *, fallback_path=None) -> None:
        self._log = boundary.audit_log(sink)
        self._fallback_path = fallback_path

    async def write(self, entry: AuditEntry) -> str:
        """Write an audit entry to the Merkle-chained log and return its entry ID.

        Thaws the frozen payload before passing to agentmesh (which hashes with
        ``json.dumps`` and cannot handle ``MappingProxyType``). On primary-sink
        failure: routes to the redacted fallback channel then raises
        :class:`GovernanceError` — the tool is blocked even when audit cannot.
        """
        try:
            # this adapter is the one place that knows agentmesh's kwarg names
            written = self._log.log(
                event_type=entry.event_type,
                agent_did=entry.agent_did,
                action=entry.action,
                outcome=entry.outcome,
                policy_decision=entry.policy_decision,
                # thaw: frozen MappingProxyType -> plain dict for json-based hashing
                data=self._build_data(entry),
            )
        except Exception as exc:
            # Primary sink failed. Record a redacted, metadata-only fallback so the
            # outcome is not lost, then fail closed — the tool must not run.
            emit_fallback(entry, exc, path=self._fallback_path)
            raise GovernanceError("audit sink failed; tool blocked") from exc
        return written.entry_id

    def _build_data(self, entry: AuditEntry) -> dict:
        """Plain-dict payload for agentmesh, with the mode folded in so the
        shadow/enforce distinction is observable on the recorded entry."""
        data = {"payload": _thaw(entry.payload)}
        if entry.mode is not None:
            data["mode"] = entry.mode
        return data

    def verify_integrity(self):
        """Delegates to agentmesh — ``(ok: bool, err: str | None)``."""
        return self._log.verify_integrity()

    def get_proof(self, entry_id: str):
        """Delegates to agentmesh — a Merkle proof for a written entry.

        **Precondition**: the log must contain at least **two** entries before a
        sibling path can be constructed.  Calling this on a log with fewer than
        two entries will raise an error from agentmesh (the exact type depends on
        the agentmesh version; treat any exception from this call as a
        precondition violation).  Ensure entries have been written before
        requesting a proof (e.g. at least two successful ``govern()`` calls).
        """
        return self._log.get_proof(entry_id)
