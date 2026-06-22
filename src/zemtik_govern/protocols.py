"""The public contract — the seams the core orchestrates, and the Decision it
hands back.

Async-first (A3): the voice workload is latency-sensitive and streaming, so the
public Protocols are ``async def`` from day one — retrofitting async into a frozen
sync Protocol would rework the whole core. Sync callers go through
``ZemtikGovern.govern_sync``.

Three seams, in the order the core runs them (A2): identity → policy → audit.
Each is a :class:`typing.Protocol`, so any object with the right shape satisfies
it — StaticIdentity today, Ed25519 later, with no base class to inherit.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .context import GovernanceContext
from .identity.protocols import AgentRef


@dataclass(frozen=True)
class Decision:
    """The wrapper's own verdict — NOT the raw AGT ``PolicyDecision``.

    Enriched (E8) so a decision is explainable and correlatable without
    re-deriving it: ``denial_kind`` separates a policy deny from a system
    (fail-closed) deny; ``correlation_id`` threads one request across policy and
    audit; ``audit_event_id`` back-links to the written entry.

    ``replayed`` is True when this decision was served from the idempotency ledger
    rather than freshly evaluated. A *direct* ``govern``/``govern_sync`` caller that
    performs its own side effect MUST gate on it (``if d.allowed and not
    d.replayed: do_write()``) — otherwise a retried fintech write executes twice.
    Callers that go through :meth:`ZemtikGovern.proxy` get effect-idempotency for
    free and need not check this.
    """

    allowed: bool
    action: str
    matched_rule: str | None
    reason: str
    denial_kind: str | None = None  # "policy" | "system" | None when allowed
    # Reserved enrichment fields — always ``None`` in v0.1.  Do NOT write code
    # that reads live data from these fields; they are declared here to reserve
    # the names for a future sprint that threads correlation and policy metadata
    # through the core.  See TODOS.md ("Populate Decision enrichment fields").
    correlation_id: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    audit_event_id: str | None = None
    replayed: bool = False  # True when served from the idempotency ledger

    @property
    def audit_id(self) -> str | None:
        """The id of the audit row this decision was stamped with — the public,
        guard-agnostic name for ``audit_event_id`` (D9). The SAME id rides a
        raised exception's ``.audit_id``, so an allowed result and a blocked one
        correlate to the trail the same way. ``None`` until the audit write
        returns (i.e. on a decision not yet through the audit seam)."""
        return self.audit_event_id


@dataclass(frozen=True)
class AuditEntry:
    """The audit record — a typed value shared by the core (writer) and the audit
    sink (reader), so the schema of the most security-critical record is the type,
    not an agreement between two functions. ``from_decision`` owns the
    decision→audit-vocabulary mapping (candidate 3), keeping that language out of
    the orchestrator.
    """

    event_type: str
    agent_did: str
    action: str
    outcome: str
    policy_decision: str | None = None
    mode: str | None = None
    # Carried from the governed context so the audit sink can record the request
    # data (the adapter thaws it first) and the fallback can hash it. Frozen on
    # the context; never mutated here.
    payload: Mapping[str, Any] = field(default_factory=dict)
    idempotency_key: str | None = None
    ts: str | None = None

    @classmethod
    def from_decision(
        cls,
        ctx: GovernanceContext,
        agent_did: str,
        decision: Decision,
        outcome: str | None = None,
        mode: str | None = None,
    ) -> AuditEntry:
        """Map a governance decision into the audit vocabulary.

        Owns the decision→audit-entry translation so the orchestrator stays pure
        orchestration. ``outcome`` defaults to ``"success"``/``"denied"`` for
        ordinary allow/deny results; callers pass an explicit value for special
        cases (``"error"``, ``"replay"``).
        """
        if outcome is None:
            outcome = "success" if decision.allowed else "denied"
        return cls(
            event_type="tool_invoked" if decision.allowed else "tool_blocked",
            agent_did=agent_did,
            action=ctx.action,
            outcome=outcome,
            policy_decision=decision.reason,
            mode=mode,
            payload=ctx.payload,
            idempotency_key=ctx.idempotency_key,
            ts=ctx.ts,
        )


@runtime_checkable
class IdentityProvider(Protocol):
    """Resolves a subject to a stable :class:`AgentRef`. Runs FIRST: policy may key
    on the subject and every audit entry is stamped with the resolved DID."""

    async def identify(self, subject: str) -> AgentRef: ...


@runtime_checkable
class PolicyEngine(Protocol):
    """Decides a context. MUST impose deny-by-default — raw AGT fails open, so an
    implementation that passes the unmatched case through is a moat breach."""

    async def evaluate(self, ctx: GovernanceContext) -> Decision: ...


@runtime_checkable
class AuditSink(Protocol):
    """Records EVERY outcome and returns the written entry's id. Runs LAST so it
    can stamp the final decision."""

    async def write(self, entry: AuditEntry) -> str: ...
