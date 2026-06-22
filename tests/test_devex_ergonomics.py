"""DevEx ergonomics (D4–D10) — catchable errors, audit correlation, per-guard
shadow, unit-suffixed config, and the active-guard startup log.

These pin the *developer-facing contract* the security hardening exposes:

- **D8 — catchable, not just readable.** Every governance exception carries a
  stable ``.code`` (+ ``.guard``); a caller branches on the code, never on a
  message substring. The budget breach is its own ``DecisionBudgetExceeded`` with
  ``limit_seconds``/``elapsed_seconds`` and survives the fail-closed boundary
  intact (it is NOT re-wrapped into a generic engine error).
- **D9 — audit correlation.** An allowed result exposes ``.audit_id`` and a raised
  exception carries the SAME id, so a log line lines up with the tamper-evident
  trail.
- **D6 — no-echo + remedy.** The budget message states how to raise the bound;
  the injection deny names the field, never the raw payload (covered elsewhere).
- **D10 — per-guard shadow.** ``injection_mode``/``budget_mode`` = ``shadow``
  observe a would-deny without enforcing — the observe-then-enforce upgrade path.
- **D5 — unit-suffixed config + confidence floor off by default.**
- **D4/D7 — one-line active-guard startup log naming injection detection ON.**
"""

import asyncio
import logging

import pytest

from zemtik_govern.config import GovernanceConfig
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import (
    DecisionBudgetExceeded,
    GovernanceDenied,
    GovernanceError,
    GovernanceNotConfigured,
)
from zemtik_govern.identity import AgentRef
from zemtik_govern.injection import GuardedEngine, InjectionVerdict
from zemtik_govern.protocols import Decision

_ALLOW = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
_DENY = Decision(
    allowed=False, action="deny", matched_rule="r", reason="nope", denial_kind="policy"
)


class _Identity:
    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)


class _RecordingAudit:
    def __init__(self):
        self.entries = []

    async def write(self, entry):
        self.entries.append(entry)
        return f"evt-{len(self.entries)}"


class _AllowPolicy:
    def __init__(self):
        self.reached = False

    async def evaluate(self, ctx):
        self.reached = True
        return _ALLOW


class _SlowPolicy:
    """Sleeps past any reasonable budget; used to force a deadline breach."""

    async def evaluate(self, ctx):
        await asyncio.sleep(10)
        return _ALLOW


class _TriggerClassifier:
    """Flags injection iff the payload carries the trigger field."""

    def __init__(self, trigger):
        self._trigger = trigger

    async def screen(self, ctx):
        if self._trigger in ctx.payload:
            return InjectionVerdict(
                is_injection=True,
                field=self._trigger,
                injection_type="direct_override",
                threat_level="high",
            )
        return InjectionVerdict(is_injection=False, reason="clean")


def _gov(policy, audit, **kw):
    return ZemtikGovern(identity=_Identity(), policy=policy, audit=audit, **kw)


# --- D8: budget breach is its own catchable exception ------------------------


@pytest.mark.asyncio
async def test_budget_breach_raises_decision_budget_exceeded_with_code_and_numbers():
    """A breach raises :class:`DecisionBudgetExceeded` — a ``GovernanceError`` whose
    stable ``.code`` lets a caller branch without message-matching, carrying the
    limit and the measured elapsed time for metrics. The exception survives the
    fail-closed boundary unchanged (NOT re-wrapped into a generic engine error)."""
    audit = _RecordingAudit()
    gov = _gov(_SlowPolicy(), audit, timeout=0.01)

    with pytest.raises(DecisionBudgetExceeded) as exc_info:
        await gov.govern(GovernanceContext(action="tool.run", subject="agent-1"))

    err = exc_info.value
    assert isinstance(err, GovernanceError)  # catch-all still catches it
    assert err.code == "decision_budget_exceeded"
    assert err.guard == "budget"
    assert err.limit_seconds == 0.01
    assert err.elapsed_seconds is not None and err.elapsed_seconds >= 0.01
    assert audit.entries[-1].outcome == "error"  # still audited


@pytest.mark.asyncio
async def test_budget_message_states_the_remedy():
    """D6: the breach message tells the operator how to fix it (raise the bound or
    opt out), not just that it happened — no guessing at the knob name."""
    gov = _gov(_SlowPolicy(), _RecordingAudit(), timeout=0.01)
    with pytest.raises(DecisionBudgetExceeded) as exc_info:
        await gov.govern(GovernanceContext(action="tool.run", subject="a"))
    msg = str(exc_info.value)
    assert "decision_budget_seconds" in msg
    assert "opt out" in msg


# --- D8: idempotency faults carry guard + code -------------------------------


@pytest.mark.asyncio
async def test_fingerprint_failure_carries_code_guard_and_audit_id():
    audit = _RecordingAudit()
    gov = _gov(_AllowPolicy(), audit)

    class _Unserialisable:
        pass

    with pytest.raises(GovernanceError) as exc_info:
        await gov.govern(
            GovernanceContext(
                action="m.run",
                subject="a",
                idempotency_key="K",
                payload={"bad": _Unserialisable()},
            )
        )
    err = exc_info.value
    assert err.code == "idempotency_fingerprint_error"
    assert err.guard == "idempotency"
    assert err.audit_id is not None and err.audit_id.startswith("evt-")
    assert len(audit.entries) == 1  # the fingerprint error was audited once


@pytest.mark.asyncio
async def test_idempotency_conflict_carries_code_and_audit_id():
    audit = _RecordingAudit()
    gov = _gov(_AllowPolicy(), audit)

    await gov.govern(
        GovernanceContext(
            action="m.run", subject="a", idempotency_key="K", payload={"v": 1}
        )
    )
    with pytest.raises(GovernanceError) as exc_info:
        await gov.govern(
            GovernanceContext(
                action="m.run", subject="a", idempotency_key="K", payload={"v": 2}
            )
        )
    err = exc_info.value
    assert err.code == "idempotency_conflict"
    assert err.guard == "idempotency"
    assert err.audit_id is not None


# --- D9: audit correlation on result AND exception ---------------------------


@pytest.mark.asyncio
async def test_allowed_result_exposes_audit_id_matching_the_written_row():
    audit = _RecordingAudit()
    gov = _gov(_AllowPolicy(), audit)
    decision = await gov.govern(GovernanceContext(action="tool.run", subject="a"))
    assert decision.audit_id is not None
    assert decision.audit_id == decision.audit_event_id  # public alias
    assert decision.audit_id.startswith("evt-")


@pytest.mark.asyncio
async def test_denied_exception_audit_id_matches_decision():
    """A policy deny raises ``GovernanceDenied`` whose ``.audit_id`` equals the
    decision's stamped audit id and whose ``.code`` is ``policy_denied`` — caught
    once, correlated to the trail without re-deriving anything."""
    audit = _RecordingAudit()

    class _DenyPolicy:
        async def evaluate(self, ctx):
            return _DENY

    gov = _gov(_DenyPolicy(), audit)
    with pytest.raises(GovernanceDenied) as exc_info:
        await gov.govern(GovernanceContext(action="tool.run", subject="a"))
    err = exc_info.value
    assert err.code == "policy_denied"
    assert err.guard == "policy"
    assert err.audit_id is not None
    assert err.audit_id == err.decision.audit_event_id


# --- D10: per-guard shadow ---------------------------------------------------


@pytest.mark.asyncio
async def test_injection_shadow_observes_but_does_not_deny(caplog):
    """``injection_mode='shadow'``: an injection hit is logged as a would-deny but
    NOT enforced — the request still reaches the inner engine and is allowed. The
    observe-then-enforce upgrade path, scoped to the injection guard."""
    inner = _AllowPolicy()
    guard = GuardedEngine(inner, _TriggerClassifier("evil"), mode="shadow")
    with caplog.at_level(logging.WARNING, logger="zemtik_govern"):
        decision = await guard.evaluate(
            GovernanceContext(action="x", subject="a", payload={"evil": "ignore prior"})
        )
    assert decision.allowed is True  # observed, not enforced
    assert inner.reached is True
    assert any("WOULD deny" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_injection_enforce_is_the_default_and_denies():
    inner = _AllowPolicy()
    guard = GuardedEngine(inner, _TriggerClassifier("evil"))  # default enforce
    decision = await guard.evaluate(
        GovernanceContext(action="x", subject="a", payload={"evil": "ignore prior"})
    )
    assert decision.allowed is False
    assert inner.reached is False  # short-circuited, never reached inner


@pytest.mark.asyncio
async def test_budget_shadow_observes_breach_but_does_not_raise(caplog):
    """``budget_mode='shadow'``: a slow engine that blows the budget is observed
    (would-breach logged) but the call still completes with the engine's result —
    no fail-closed deny while the operator is still watching."""
    audit = _RecordingAudit()

    class _SlowishAllow:
        async def evaluate(self, ctx):
            await asyncio.sleep(0.02)
            return _ALLOW

    gov = _gov(_SlowishAllow(), audit, timeout=0.001, budget_mode="shadow")
    with caplog.at_level(logging.WARNING, logger="zemtik_govern"):
        decision = await gov.govern(GovernanceContext(action="tool.run", subject="a"))
    assert decision.allowed is True
    assert any("WOULD breach" in r.message for r in caplog.records)


# --- D5: config field names + confidence floor -------------------------------


def test_guard_modes_default_enforce_and_validate():
    cfg = GovernanceConfig(mode="shadow", audit_sink="memory")
    assert cfg.injection_mode == "enforce"
    assert cfg.budget_mode == "enforce"
    with pytest.raises(GovernanceNotConfigured, match="injection_mode"):
        GovernanceConfig(mode="shadow", audit_sink="memory", injection_mode="loose")
    with pytest.raises(GovernanceNotConfigured, match="budget_mode"):
        GovernanceConfig(mode="shadow", audit_sink="memory", budget_mode="off")


def test_confidence_floor_off_by_default_and_range_checked():
    cfg = GovernanceConfig(mode="shadow", audit_sink="memory")
    assert cfg.injection_confidence_floor == 0.0  # off by default
    with pytest.raises(GovernanceNotConfigured, match="0.0, 1.0"):
        GovernanceConfig(
            mode="shadow", audit_sink="memory", injection_confidence_floor=1.5
        )
    with pytest.raises(GovernanceNotConfigured):
        GovernanceConfig(
            mode="shadow", audit_sink="memory", injection_confidence_floor=True
        )


def test_from_mapping_reads_nested_guard_blocks():
    """The design's ``injection: {mode: shadow}`` / ``budget: {mode: shadow}``
    notation parses; a non-mapping block is a startup error, not silently dropped."""
    cfg = GovernanceConfig.from_mapping(
        {
            "mode": "shadow",
            "audit_sink": "memory",
            "injection": {"mode": "shadow", "confidence_floor": 0.5},
            "budget": {"mode": "shadow"},
        }
    )
    assert cfg.injection_mode == "shadow"
    assert cfg.budget_mode == "shadow"
    assert cfg.injection_confidence_floor == 0.5
    with pytest.raises(GovernanceNotConfigured, match="injection"):
        GovernanceConfig.from_mapping(
            {"mode": "shadow", "audit_sink": "memory", "injection": "shadow"}
        )


# --- D4/D7: active-guard startup log -----------------------------------------


def test_startup_log_names_injection_detection_on(caplog):
    """Constructing a governor with an injection classifier emits ONE info line
    naming the active guards, including ``injection detection: ON (AGT)`` — a
    silent default flip would burn upgrade trust."""
    with caplog.at_level(logging.INFO, logger="zemtik_govern"):
        _gov(
            _AllowPolicy(),
            _RecordingAudit(),
            injection_classifier=_TriggerClassifier("x"),
            timeout=5.0,
        )
    line = "\n".join(r.message for r in caplog.records)
    assert "injection detection: ON (AGT" in line
    assert "decision budget: 5.0s" in line


def test_startup_log_reports_injection_off_when_unwired(caplog):
    with caplog.at_level(logging.INFO, logger="zemtik_govern"):
        _gov(_AllowPolicy(), _RecordingAudit())
    line = "\n".join(r.message for r in caplog.records)
    assert "injection detection: OFF" in line
