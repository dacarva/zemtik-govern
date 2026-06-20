"""S7 — the adversarial matrix.

Five scenarios that try to break the wrapper's core invariants: payload
immutability under deep nesting, deterministic handling of duplicate idempotency
keys under concurrency, fail-closed denial when policy or identity hangs, and a
tamper-evident audit chain that still verifies after a simulated crash-recovery.

These exercise the real seams (real AGT where it matters), not the happy path.
"""

import asyncio

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.identity import AgentRef
from zemtik_govern.protocols import Decision

# --- 1. Malformed / deeply-nested payload: no mutation escape ----------------


def test_deeply_nested_payload_is_recursively_immutable():
    """A hostile, deeply-nested payload is deep-frozen at every level — there is no
    inner dict/list an attacker (or a buggy policy) can mutate after the context is
    built, so the bytes policy evaluates are the bytes audit records."""
    payload = {
        "outer": {
            "list": [{"deep": {"deeper": ["x", {"deepest": 1}]}}],
            "set_like": (1, 2, 3),
        }
    }
    ctx = GovernanceContext(action="wire.transfer", subject="agent-1", payload=payload)

    # top level is read-only
    with pytest.raises(TypeError):
        ctx.payload["outer"] = "tamper"  # type: ignore[index]
    # nested mapping is read-only
    with pytest.raises(TypeError):
        ctx.payload["outer"]["list"] = []  # type: ignore[index]
    # the deepest mapping, reached through a frozen list, is read-only too
    deepest = ctx.payload["outer"]["list"][0]["deep"]["deeper"][1]
    with pytest.raises(TypeError):
        deepest["deepest"] = 999  # type: ignore[index]
    # sequences became tuples (no append/extend reachable)
    assert isinstance(ctx.payload["outer"]["list"], tuple)

    # to_dict round-trips to plain, mutable, JSON-serializable Python without
    # leaking the frozen views back to the caller
    plain = ctx.to_dict()
    plain["payload"]["outer"]["list"].append("safe-copy")  # mutating the copy is fine
    assert "safe-copy" not in str(ctx.payload)  # the frozen original is untouched


# --- 2. Duplicate idempotency_key under concurrency: deterministic replay -----


class _CountingPolicy:
    """Records how many times the engine actually evaluated — proves a duplicate
    is not silently re-evaluated as a fresh request."""

    def __init__(self, decision):
        self.calls = 0
        self._decision = decision

    async def evaluate(self, ctx):
        self.calls += 1
        # yield control so two concurrent governs genuinely interleave
        await asyncio.sleep(0)
        return self._decision


class _RecordingAudit:
    def __init__(self):
        self.entries = []

    async def write(self, entry):
        self.entries.append(entry)
        return f"evt-{len(self.entries)}"


class _Identity:
    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)


@pytest.mark.asyncio
async def test_duplicate_idempotency_key_is_replayed_not_re_evaluated():
    """Two concurrent calls carrying the SAME idempotency_key resolve
    deterministically: the engine evaluates exactly once, the duplicate is recorded
    as a ``replay`` (not a new ``success``), and both callers see the same
    decision — a replayed wire transfer is never silently accepted as new."""
    allow = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
    policy = _CountingPolicy(allow)
    audit = _RecordingAudit()
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=audit)

    ctx = GovernanceContext(
        action="wire.transfer", subject="agent-1", idempotency_key="txn-42"
    )
    first, second = await asyncio.gather(gov.govern(ctx), gov.govern(ctx))

    # the engine ran ONCE despite two submissions
    assert policy.calls == 1
    # both callers got the same (deterministic) decision, sharing one audit id
    assert first.allowed is second.allowed is True
    assert first.audit_event_id == second.audit_event_id
    # both outcomes were recorded; exactly one is the replay, never a second success
    outcomes = sorted(e.outcome for e in audit.entries)
    assert outcomes == ["replay", "success"]


# --- 2b. Idempotency key reuse on a DIFFERENT request: never replay a stale allow -


@pytest.mark.asyncio
async def test_reused_idempotency_key_on_a_different_request_is_not_replayed():
    """An idempotency key identifies one request, not a bearer token for *any*
    request. Reusing a key from a prior allowed ``tool.run`` to push a fresh
    ``wire.transfer`` must NOT replay the cached allow — that would let an
    ungoverned action ride a stolen/recycled key straight past policy. The
    mismatch fails closed: policy is never bypassed, the conflict is audited."""
    from zemtik_govern.errors import GovernanceError

    allow = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
    policy = _CountingPolicy(allow)
    audit = _RecordingAudit()
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=audit)

    # first request under key K is evaluated and allowed
    await gov.govern(
        GovernanceContext(action="tool.run", subject="agent-1", idempotency_key="K")
    )
    assert policy.calls == 1

    # a DIFFERENT request reusing K must not inherit the prior allow
    with pytest.raises(GovernanceError):
        await gov.govern(
            GovernanceContext(
                action="wire.transfer",
                subject="evil",
                idempotency_key="K",
                payload={"amount": 1_000_000_000},
            )
        )

    # policy was never asked to bless the mismatched request, and the conflict
    # was recorded — no silent ungoverned pass-through
    assert policy.calls == 1
    assert audit.entries[-1].outcome == "error"


# --- 2c. Replayed DENY stays denied without re-evaluating ---------------------


@pytest.mark.asyncio
async def test_duplicate_idempotency_key_replays_a_deny_without_re_evaluating():
    """A replayed DENIED request must stay denied: the engine evaluates once, the
    duplicate re-raises GovernanceDenied from the cached decision (outcome
    ``replay``, never a second ``denied``). A blocked wire transfer cannot be
    laundered into an allow by retrying it under the same key."""
    from zemtik_govern.errors import GovernanceDenied

    deny = Decision(
        allowed=False, action="deny", matched_rule="r", reason="no", denial_kind="policy"
    )
    policy = _CountingPolicy(deny)
    audit = _RecordingAudit()
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=audit)
    ctx = GovernanceContext(
        action="wire.transfer", subject="agent-1", idempotency_key="txn-deny"
    )

    for _ in range(2):
        with pytest.raises(GovernanceDenied):
            await gov.govern(ctx)

    assert policy.calls == 1  # the deny was cached, not re-evaluated
    assert sorted(e.outcome for e in audit.entries) == ["denied", "replay"]


# --- 2d. A fail-closed system error is NOT cached: a retry re-runs ------------


@pytest.mark.asyncio
async def test_fail_closed_system_error_is_not_cached_so_a_retry_re_runs():
    """A transient engine fault raises GovernanceError and is left un-cached, so a
    retry under the same key re-evaluates rather than replaying the failure — a
    poisoned ledger would turn one transient fault into a permanent deny."""
    from zemtik_govern.errors import GovernanceError

    class _FlakyPolicy:
        def __init__(self):
            self.calls = 0

        async def evaluate(self, ctx):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("transient")
            return Decision(allowed=True, action="allow", matched_rule="r", reason="ok")

    policy = _FlakyPolicy()
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=_RecordingAudit())
    ctx = GovernanceContext(action="tool.run", subject="agent-1", idempotency_key="k")

    with pytest.raises(GovernanceError):
        await gov.govern(ctx)
    decision = await gov.govern(ctx)

    assert decision.allowed is True  # the retry succeeded
    assert policy.calls == 2  # the error was not cached


# --- 2e. Fingerprint excludes ts: a retry with a moved clock still replays ----


@pytest.mark.asyncio
async def test_retry_with_moved_clock_still_replays_not_conflicts():
    """The fingerprint binds action/subject/payload but NOT ``ts``: a genuine retry
    whose only difference is a later timestamp must replay, not be misread as a
    conflict and failed closed. Guards against a regression that starts hashing
    ``ts`` and turns every legitimate retry into a GovernanceError."""
    allow = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
    policy = _CountingPolicy(allow)
    audit = _RecordingAudit()
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=audit)
    payload = {"amount": 100}

    await gov.govern(
        GovernanceContext(
            action="wire.transfer", subject="agent-1", payload=payload,
            idempotency_key="k", ts="2026-01-01T00:00:00Z",
        )
    )
    await gov.govern(
        GovernanceContext(
            action="wire.transfer", subject="agent-1", payload=payload,
            idempotency_key="k", ts="2026-06-19T12:00:00Z",
        )
    )

    assert policy.calls == 1  # the moved clock did not trigger a false conflict
    assert sorted(e.outcome for e in audit.entries) == ["replay", "success"]


# --- 2f. Replay is signalled to a DIRECT caller so it won't double-execute -----


@pytest.mark.asyncio
async def test_replayed_decision_is_flagged_for_direct_callers():
    """A direct govern() caller (no proxy) double-executes its side effect unless it
    can tell a replay from a fresh allow. The first decision is not flagged; the
    duplicate's returned decision carries ``replayed=True`` so the caller can skip
    re-running the write. The ledgered (cached) decision stays unflagged."""
    allow = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
    policy = _CountingPolicy(allow)
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=_RecordingAudit())
    ctx = GovernanceContext(
        action="wire.transfer", subject="agent-1", idempotency_key="txn-flag"
    )

    first = await gov.govern(ctx)
    second = await gov.govern(ctx)

    assert first.replayed is False  # fresh evaluation: the caller SHOULD act
    assert second.replayed is True  # replay: the caller should NOT re-execute
    assert policy.calls == 1


# --- 2g. An un-fingerprintable payload fails closed (audited), never raw -------


@pytest.mark.asyncio
async def test_unfingerprintable_keyed_payload_fails_closed_and_audits():
    """The keyed path fingerprints the request before matching the ledger. A payload
    that cannot be canonically serialised (here, a nested non-string mapping key)
    must fail closed — an audited GovernanceError — not raise a raw exception that
    skips the audit trail and the fail-closed boundary."""
    from zemtik_govern.errors import GovernanceError

    policy = _CountingPolicy(
        Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
    )
    audit = _RecordingAudit()
    gov = ZemtikGovern(identity=_Identity(), policy=policy, audit=audit)

    # a tuple dict-key is hashable (so the context builds) but not JSON-serialisable
    ctx = GovernanceContext(
        action="wire.transfer",
        subject="agent-1",
        idempotency_key="bad",
        payload={"nested": {(1, 2): "boom"}},
    )

    with pytest.raises(GovernanceError):
        await gov.govern(ctx)

    assert policy.calls == 0  # policy never reached
    assert audit.entries[-1].outcome == "error"  # the failure was audited


# --- 3. Policy evaluate() timeout: fail-closed deny + audit, tool not called --


class _SlowPolicy:
    async def evaluate(self, ctx):
        await asyncio.sleep(10)  # never returns within the decision budget
        return Decision(allowed=True, action="allow", matched_rule="r", reason="ok")


@pytest.mark.asyncio
async def test_policy_timeout_fails_closed_and_audits_without_running_the_tool():
    """A policy engine that hangs past the decision budget is a system fault: the
    governor denies fail-closed, records the timeout, and the wrapped tool never
    runs — a slow policy can never become an implicit allow."""
    from zemtik_govern.errors import GovernanceError

    audit = _RecordingAudit()
    gov = ZemtikGovern(
        identity=_Identity(), policy=_SlowPolicy(), audit=audit, timeout=0.01
    )

    ran = []
    tool = gov.proxy(lambda: ran.append("ran"), action="tool.run", subject="agent-1")
    with pytest.raises(GovernanceError):
        await tool()

    assert ran == []  # fail-closed: the tool never ran
    assert audit.entries[-1].outcome == "error"  # the timeout was recorded


# --- 4. Identity resolution timeout: fail-closed deny ------------------------


class _SlowIdentity:
    async def identify(self, subject):
        await asyncio.sleep(10)  # identity backend hangs
        return AgentRef(did="did:mesh:" + subject)


@pytest.mark.asyncio
async def test_identity_timeout_fails_closed_before_policy_runs():
    """A hanging identity backend is inside the fail-closed boundary too: the
    governor denies, policy never runs, and the audit entry carries the reserved
    unidentified DID (no identity was resolved to attribute it to)."""
    from zemtik_govern.errors import GovernanceError

    policy = _CountingPolicy(
        Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
    )
    audit = _RecordingAudit()
    gov = ZemtikGovern(
        identity=_SlowIdentity(), policy=policy, audit=audit, timeout=0.01
    )

    with pytest.raises(GovernanceError):
        await gov.govern(
            GovernanceContext(action="tool.run", subject="agent-1")
        )

    assert policy.calls == 0  # policy never reached
    assert audit.entries[-1].outcome == "error"
    assert audit.entries[-1].agent_did == "did:mesh:unidentified"


# --- 5. Audit verify_integrity() after crash-recovery ------------------------

_ALLOW_TOOL_RUN = {
    "name": "allow-tool-run",
    "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
    "action": "allow",
}


@pytest.mark.asyncio
async def test_merkle_chain_verifies_after_crash_recovery_from_file_sink(
    tmp_path, monkeypatch
):
    """Outcomes written to a durable HMAC-signed file sink survive process loss:
    after the original governor is dropped, a FRESH sink opened over the same file
    re-verifies the Merkle chain from disk — tamper-evidence is a property of the
    persisted trail, not of the live process."""
    from zemtik_govern._agt import AGTBoundary
    from zemtik_govern.config import GovernanceConfig
    from zemtik_govern.errors import GovernanceDenied
    from zemtik_govern.registry import GovernanceRegistry

    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "crash-secret")
    audit_file = tmp_path / "audit.jsonl"
    cfg = GovernanceConfig(
        mode="strict", rules=[_ALLOW_TOOL_RUN], audit_sink=str(audit_file),
        injection_rules_path="policies/prompt-injection.yaml",
    )

    # original process: record an allow and a deny, then "crash" (drop everything)
    boundary = AGTBoundary()
    gov = GovernanceRegistry.from_config(cfg, boundary).build()
    await gov.govern(GovernanceContext(action="tool.run", subject="agent-1"))
    with pytest.raises(GovernanceDenied):
        await gov.govern(GovernanceContext(action="wire.transfer", subject="agent-1"))
    del gov, boundary  # simulate crash: nothing in-memory survives

    # recovery process: a brand-new boundary + sink over the persisted file
    recovered = AGTBoundary().file_audit_sink(str(audit_file), b"crash-secret")
    ok, err = recovered.verify_integrity()
    assert ok, err
