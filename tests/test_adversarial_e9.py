"""E9 — adversarial matrix, sprint hardening (issue #25).

Extends the S7 matrix in ``tests/test_adversarial.py`` with the four E9
attack classes the issue names explicitly:

1. TOCTOU on ``GovernanceContext`` immutability under *concurrent* access.
2. Policy-bypass attempts: injected subject, malformed action, payload mutation
   by a hostile engine mid-evaluation.
3. Audit chain integrity after crash-recovery *plus* tamper detection.
4. Idempotency-key collision under concurrency (same key, different request).

These exercise the real seams (real AGT for the policy moat) rather than the
happy path. Fakes are kept local so the module does not couple to the S7 suite.
"""

import asyncio

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceError
from zemtik_govern.identity import AgentRef
from zemtik_govern.protocols import Decision


class _Identity:
    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)


class _RecordingAudit:
    def __init__(self):
        self.entries = []

    async def write(self, entry):
        self.entries.append(entry)
        return f"evt-{len(self.entries)}"


# --- 1. TOCTOU: immutability holds under concurrent mutate + read -------------


@pytest.mark.asyncio
async def test_frozen_context_survives_concurrent_mutation_attempts():
    """Many tasks racing to mutate the SAME frozen payload while others read it:
    every write raises ``TypeError`` and no mutation ever escapes, so the bytes a
    concurrent reader (policy) sees are the bytes audit will record. Guards the
    deep-freeze (MappingProxyType/tuple) against a TOCTOU window under load."""
    payload = {"limits": {"daily": [1, 2, {"max": 100}]}, "tags": (1, 2, 3)}
    ctx = GovernanceContext(action="wire.transfer", subject="agent-1", payload=payload)

    async def mutate():
        # Each attempt must fail closed (TypeError) at every depth.
        with pytest.raises(TypeError):
            ctx.payload["limits"] = "tamper"  # type: ignore[index]
        with pytest.raises(TypeError):
            ctx.payload["limits"]["daily"][2]["max"] = 0  # type: ignore[index]
        await asyncio.sleep(0)

    async def read():
        # A concurrent reader always observes the original, untampered value.
        for _ in range(50):
            assert ctx.payload["limits"]["daily"][2]["max"] == 100
            assert isinstance(ctx.payload["limits"]["daily"], tuple)
            await asyncio.sleep(0)

    await asyncio.gather(*(mutate() for _ in range(20)), *(read() for _ in range(20)))

    # The frozen original is pristine; a thawed copy is isolated from it.
    assert ctx.payload["limits"]["daily"][2]["max"] == 100
    plain = ctx.to_dict()
    plain["payload"]["limits"]["daily"][2]["max"] = 0
    assert ctx.payload["limits"]["daily"][2]["max"] == 100


# --- 2. Policy-bypass attempts ------------------------------------------------

# A deny-by-default policy that explicitly allows ONE read action. Everything
# else (writes, malformed actions) must hit AgentOsPolicy's no-match → deny moat.
_ALLOW_READ = {
    "name": "allow-read-balance",
    "condition": {"field": "action", "operator": "eq", "value": "read_balance"},
    "action": "allow",
}


def _real_policy():
    """The real ``AgentOsPolicy`` over the pinned AGT evaluator — the deny-by-
    default moat under test, not a fake."""
    from zemtik_govern._agt import AGTBoundary
    from zemtik_govern.policy import AgentOsPolicy

    return AgentOsPolicy(AGTBoundary(), rules=[_ALLOW_READ])


@pytest.mark.asyncio
async def test_injected_subject_is_stamped_with_resolved_did_not_smuggled_past_policy():
    """An attacker-controlled ``subject`` cannot ride past the moat: a privileged
    write under a hostile subject is still denied deny-by-default, and the audit
    entry is stamped with the identity-RESOLVED DID, never the raw subject —
    subject is an input to identity, not a bearer of authority."""
    from zemtik_govern.errors import GovernanceDenied

    audit = _RecordingAudit()
    gov = ZemtikGovern(identity=_Identity(), policy=_real_policy(), audit=audit)

    with pytest.raises(GovernanceDenied):
        await gov.govern(
            GovernanceContext(
                action="wire.transfer",
                subject="'; DROP POLICY; --",
                payload={"amount": 10_000},
            )
        )

    entry = audit.entries[-1]
    assert entry.outcome == "denied"
    # The DID is derived by identity from the subject; the raw injected string is
    # not what authorizes the call.
    assert entry.agent_did == "did:mesh:'; DROP POLICY; --"


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_action", ["", "   ", "read_balance ", "READ_BALANCE", "🤖"])
async def test_malformed_action_hits_deny_by_default(bad_action):
    """A malformed/garbage action never matches a rule, so the moat denies it —
    an empty, whitespace-padded, wrong-case, or non-ASCII action can never be
    mistaken for the allowed ``read_balance`` and silently permitted."""
    from zemtik_govern.errors import GovernanceDenied

    audit = _RecordingAudit()
    gov = ZemtikGovern(identity=_Identity(), policy=_real_policy(), audit=audit)

    with pytest.raises(GovernanceDenied):
        await gov.govern(GovernanceContext(action=bad_action, subject="agent-1"))
    assert audit.entries[-1].outcome == "denied"


@pytest.mark.asyncio
async def test_hostile_engine_cannot_mutate_payload_mid_evaluation():
    """A buggy/hostile policy engine that tries to mutate the context during
    ``evaluate()`` is blocked by the deep-freeze (``TypeError``), which the
    fail-closed boundary converts to an audited ``GovernanceError`` — the tool
    never runs and the payload bytes are unchanged (TOCTOU closed end-to-end)."""

    class _MutatingPolicy:
        async def evaluate(self, ctx):
            ctx.payload["amount"] = 0  # frozen → TypeError
            return Decision(allowed=True, action="allow", matched_rule="r", reason="ok")

    audit = _RecordingAudit()
    gov = ZemtikGovern(identity=_Identity(), policy=_MutatingPolicy(), audit=audit)
    ctx = GovernanceContext(
        action="wire.transfer", subject="agent-1", payload={"amount": 10_000}
    )

    with pytest.raises(GovernanceError):
        await gov.govern(ctx)

    assert audit.entries[-1].outcome == "error"
    assert ctx.payload["amount"] == 10_000  # untouched


# --- 3. Audit chain integrity: tamper detected after crash-recovery -----------

_ALLOW_TOOL_RUN = {
    "name": "allow-tool-run",
    "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
    "action": "allow",
}


@pytest.mark.asyncio
async def test_recovered_trail_detects_a_tampered_entry(tmp_path, monkeypatch):
    """The crash-recovery story has teeth: after a fresh sink re-opens the
    persisted trail, flipping a single byte in a recorded entry makes
    ``verify_integrity()`` fail with a reason — the Merkle/HMAC chain is
    tamper-EVIDENT, not merely re-readable across a crash."""
    from zemtik_govern._agt import AGTBoundary
    from zemtik_govern.config import GovernanceConfig
    from zemtik_govern.registry import GovernanceRegistry

    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "tamper-secret")
    audit_file = tmp_path / "audit.jsonl"
    cfg = GovernanceConfig(
        mode="strict", rules=[_ALLOW_TOOL_RUN], audit_sink=str(audit_file),
        injection_rules_path="policies/prompt-injection.yaml",
    )

    gov = GovernanceRegistry.from_config(cfg, AGTBoundary()).build()
    for _ in range(3):
        await gov.govern(GovernanceContext(action="tool.run", subject="agent-1"))

    # Sanity: the pristine, recovered trail verifies.
    recovered = AGTBoundary().file_audit_sink(str(audit_file), b"tamper-secret")
    ok, _ = recovered.verify_integrity()
    assert ok

    # Tamper: flip a digit inside the first persisted entry, then re-verify cold.
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("agent-1", "agent-2", 1)
    audit_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tampered = AGTBoundary().file_audit_sink(str(audit_file), b"tamper-secret")
    ok, err = tampered.verify_integrity()
    assert not ok
    assert err  # a non-empty reason is surfaced, not a bare False


# --- 4. Idempotency key collision under concurrency ---------------------------


class _CountingPolicy:
    """Counts real evaluations so a bypassed/conflicting request is provably
    never handed to policy."""

    def __init__(self, decision):
        self.calls = 0
        self._decision = decision

    async def evaluate(self, ctx):
        self.calls += 1
        await asyncio.sleep(0)  # force interleaving under gather
        return self._decision


@pytest.mark.asyncio
async def test_concurrent_key_collision_lets_exactly_one_through_and_no_ledger_poison():
    """Two requests racing under the SAME key but DIFFERENT fingerprints: exactly
    one is evaluated, the colliding one fails closed as a conflict (audited
    ``error``, policy never asked), and the ledger is not poisoned — a later
    legitimate retry of the winning request still replays from cache."""
    allow = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
    policy = _CountingPolicy(allow)
    audit = _RecordingAudit()
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=audit)

    ctx_b = GovernanceContext(
        action="wire.transfer", subject="agent-1", idempotency_key="K",
        payload={"amount": 1},
    )
    ctx_c = GovernanceContext(
        action="wire.transfer", subject="evil", idempotency_key="K",
        payload={"amount": 1_000_000_000},
    )

    results = await asyncio.gather(
        gov.govern(ctx_b), gov.govern(ctx_c), return_exceptions=True
    )

    decisions = [r for r in results if isinstance(r, Decision)]
    errors = [r for r in results if isinstance(r, GovernanceError)]
    assert len(decisions) == 1 and len(errors) == 1  # exactly one through
    assert policy.calls == 1  # the conflict never reached policy
    assert audit.entries[-1].outcome == "error"  # conflict was audited

    # The winner is whichever ctx got evaluated; retrying it must REPLAY, proving
    # the conflict did not corrupt the ledger entry.
    winner = ctx_b if isinstance(results[0], Decision) else ctx_c
    replay = await gov.govern(winner)
    assert replay.replayed is True
    assert policy.calls == 1  # still no re-evaluation
