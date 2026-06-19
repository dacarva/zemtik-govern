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

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .context import GovernanceContext


@dataclass(frozen=True)
class Decision:
    """The wrapper's own verdict — NOT the raw AGT ``PolicyDecision``.

    Enriched (E8) so a decision is explainable and correlatable without
    re-deriving it: ``denial_kind`` separates a policy deny from a system
    (fail-closed) deny; ``correlation_id`` threads one request across policy and
    audit; ``audit_event_id`` back-links to the written entry.
    """

    allowed: bool
    action: str
    matched_rule: str | None
    reason: str
    denial_kind: str | None = None  # "policy" | "system" | None when allowed
    correlation_id: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    audit_event_id: str | None = None


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

    @classmethod
    def from_decision(
        cls,
        ctx: GovernanceContext,
        agent_did: str,
        decision: Decision,
        outcome: str | None = None,
    ) -> AuditEntry:
        if outcome is None:
            outcome = "success" if decision.allowed else "denied"
        return cls(
            event_type="tool_invoked" if decision.allowed else "tool_blocked",
            agent_did=agent_did,
            action=ctx.action,
            outcome=outcome,
            policy_decision=decision.reason,
        )


@runtime_checkable
class IdentityProvider(Protocol):
    """Resolves a subject to a stable DID. Runs FIRST: policy may key on the
    subject and every audit entry is stamped with the DID."""

    async def identify(self, subject: str) -> str: ...


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
