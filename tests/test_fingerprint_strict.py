"""#32 — the strict request-fingerprint encoder.

The idempotency fingerprint binds one key to one request. The v0.1 encoder used
``json.dumps(..., default=str)``, which LOSSILY coerces any non-JSON-native value
to its ``str()``. Two genuinely different requests whose payloads stringify alike
collapsed to the same SHA-256 and the second was falsely served the first's cached
decision — a replay that bypassed policy.

These pin the strict encoder: non-JSON-native payloads (custom objects, non-string
keys, NaN/Inf) are rejected at the fingerprint seam, inside the fail-closed
boundary, so a collision can never become a false replay.
"""

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceError
from zemtik_govern.identity import AgentRef
from zemtik_govern.protocols import Decision


class _CountingPolicy:
    def __init__(self, decision):
        self.calls = 0
        self._decision = decision

    async def evaluate(self, ctx):
        self.calls += 1
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


def _gov(policy, audit):
    return ZemtikGovern(identity=_Identity(), policy=policy, audit=audit)


_ALLOW = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")


@pytest.mark.asyncio
async def test_stringify_collision_no_longer_false_replays():
    """A different request whose non-native payload the lossy encoder would have
    collapsed onto a prior request's fingerprint must NOT inherit its cached allow.
    Strict rejection at the seam makes the collision a fail-closed audited error,
    never a replay of someone else's decision."""

    class Stamp:
        """A non-JSON-native value whose ``str()`` mimics a benign native string."""

        def __str__(self):  # pragma: no cover - exercised only by the lossy encoder
            return "100"

    policy = _CountingPolicy(_ALLOW)
    audit = _RecordingAudit()
    gov = _gov(policy, audit)

    # First request under key K: a native payload, evaluated and allowed + cached.
    await gov.govern(
        GovernanceContext(
            action="wire.transfer",
            subject="agent-1",
            idempotency_key="K",
            payload={"amt": "100"},
        )
    )
    assert policy.calls == 1

    # A DIFFERENT request reusing K, identical in every field EXCEPT the payload,
    # whose non-native value stringifies to the same "100". The old default=str
    # encoder produced a byte-identical fingerprint and REPLAYED the cached allow.
    # Strict rejects the non-native value: fail closed, never a silent replay.
    with pytest.raises(GovernanceError):
        await gov.govern(
            GovernanceContext(
                action="wire.transfer",
                subject="agent-1",
                idempotency_key="K",
                payload={"amt": Stamp()},
            )
        )

    assert policy.calls == 1  # the mismatched request was never served the cache
    assert audit.entries[-1].outcome == "error"  # blocked outcome was audited


@pytest.mark.asyncio
async def test_nan_payload_rejected_fail_closed():
    """``allow_nan=False``: a NaN float can't be canonically fingerprinted, so the
    keyed request fails closed (audited error) rather than hashing a non-standard
    ``NaN`` token that no strict JSON reader would accept on replay."""
    policy = _CountingPolicy(_ALLOW)
    audit = _RecordingAudit()
    gov = _gov(policy, audit)

    with pytest.raises(GovernanceError):
        await gov.govern(
            GovernanceContext(
                action="m.run",
                subject="agent-1",
                idempotency_key="K",
                payload={"x": float("nan")},
            )
        )
    assert policy.calls == 0
    assert audit.entries[-1].outcome == "error"


@pytest.mark.asyncio
async def test_infinity_payload_rejected_fail_closed():
    """Inf is rejected for the same reason as NaN — no non-finite float reaches a
    fingerprint."""
    policy = _CountingPolicy(_ALLOW)
    audit = _RecordingAudit()
    gov = _gov(policy, audit)

    with pytest.raises(GovernanceError):
        await gov.govern(
            GovernanceContext(
                action="m.run",
                subject="agent-1",
                idempotency_key="K",
                payload={"x": float("inf")},
            )
        )
    assert policy.calls == 0
    assert audit.entries[-1].outcome == "error"


@pytest.mark.asyncio
async def test_non_string_mapping_key_rejected_fail_closed():
    """``json.dumps`` silently coerces ``int``/``bool`` keys to strings, collapsing
    ``{1: …}`` and ``{"1": …}`` onto one fingerprint. The strict walk rejects any
    non-string key so the two stay distinct requests, not a false replay."""
    policy = _CountingPolicy(_ALLOW)
    audit = _RecordingAudit()
    gov = _gov(policy, audit)

    with pytest.raises(GovernanceError):
        await gov.govern(
            GovernanceContext(
                action="m.run",
                subject="agent-1",
                idempotency_key="K",
                payload={"nested": {1: "a"}},
            )
        )
    assert policy.calls == 0
    assert audit.entries[-1].outcome == "error"


@pytest.mark.asyncio
async def test_native_payload_still_fingerprints_and_replays():
    """The strict encoder must not over-reject: an ordinary nested-native payload
    (strings, ints, floats, bools, None, lists, dicts) still fingerprints, so a
    genuine duplicate under the same key replays exactly once."""
    policy = _CountingPolicy(_ALLOW)
    audit = _RecordingAudit()
    gov = _gov(policy, audit)

    def _ctx():
        return GovernanceContext(
            action="m.run",
            subject="agent-1",
            idempotency_key="K",
            payload={"a": [1, 2.5, True, None], "b": {"c": "ok"}},
        )

    first = await gov.govern(_ctx())
    second = await gov.govern(_ctx())
    assert first.replayed is False
    assert second.replayed is True
    assert policy.calls == 1  # evaluated once; the duplicate replayed
