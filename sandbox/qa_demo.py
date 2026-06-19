#!/usr/bin/env python3
"""Manual QA sandbox: exercises zemtik-govern's three-seam pipeline.

Run with:
    ZEMTIK_AUDIT_SECRET=qa-test-secret python sandbox/qa_demo.py

Scenarios (S1-S10) map to the security guarantees documented in
docs/architecture.md. Each must print PASS for the QA run to be green.
"""
from __future__ import annotations

import asyncio
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.audit import AgentMeshAudit
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.identity import StaticIdentity
from zemtik_govern.policy import AgentOsPolicy
from zemtik_govern.protocols import Decision

PASS = "  ✅ PASS"
FAIL = "  ❌ FAIL"
_ALLOW_TOOL_RUN = {
    "name": "allow-tool-run",
    "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
    "action": "allow",
}


def check(label: str, condition: bool, detail: str = "") -> None:
    status = PASS if condition else FAIL
    suffix = f"\n         detail: {detail}" if detail else ""
    print(f"{status}  {label}{suffix}")
    if not condition:
        raise AssertionError(f"QA FAILED: {label}")


def _boundary() -> AGTBoundary:
    return AGTBoundary()


def _strict_gov(boundary: AGTBoundary, rules: list | None) -> tuple[ZemtikGovern, AgentMeshAudit]:
    audit = AgentMeshAudit(boundary)
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=AgentOsPolicy(boundary, rules=rules),
        audit=audit,
        mode="strict",
    )
    return gov, audit


# ---------------------------------------------------------------------------
# S1 — Deny-by-default: no rule → tool blocked
# ---------------------------------------------------------------------------
async def s1_deny_by_default() -> None:
    print("\n[S1] Deny-by-default (no matching rule)")
    boundary = _boundary()
    gov, _ = _strict_gov(boundary, rules=None)

    denied_raised = False
    denial_kind = None
    try:
        await gov.govern(GovernanceContext(action="tool.run", subject="qa-agent"))
    except GovernanceDenied as exc:
        denied_raised = True
        denial_kind = exc.decision.denial_kind

    check("GovernanceDenied raised when no rules match", denied_raised)
    check("denial_kind is 'policy' (not a system error)", denial_kind == "policy",
          f"got {denial_kind!r}")


# ---------------------------------------------------------------------------
# S2 — Allow path: matching rule → decision.allowed = True
# ---------------------------------------------------------------------------
async def s2_allow_path() -> None:
    print("\n[S2] Allow path (rule matches)")
    boundary = _boundary()
    gov, audit = _strict_gov(boundary, rules=[_ALLOW_TOOL_RUN])

    decision = await gov.govern(GovernanceContext(action="tool.run", subject="qa-agent"))

    check("decision.allowed is True", decision.allowed is True)
    check("audit_event_id is set on the returned decision", decision.audit_event_id is not None)

    ok, err = audit.verify_integrity()
    check("Merkle chain verifies after one allow", ok, err)


# ---------------------------------------------------------------------------
# S3 — Fail-closed on identity fault
# ---------------------------------------------------------------------------
async def s3_fail_closed_identity() -> None:
    print("\n[S3] Fail-closed: identity provider raises")

    class _BrokenIdentity:
        async def identify(self, subject: str):  # noqa: ANN201
            raise RuntimeError("identity backend down")

    boundary = _boundary()
    audit = AgentMeshAudit(boundary)
    gov = ZemtikGovern(
        identity=_BrokenIdentity(),
        policy=AgentOsPolicy(boundary, rules=[_ALLOW_TOOL_RUN]),
        audit=audit,
        mode="strict",
    )

    error_raised = False
    is_governance_error = False
    try:
        await gov.govern(GovernanceContext(action="tool.run", subject="qa-agent"))
    except GovernanceError as exc:
        error_raised = True
        is_governance_error = not isinstance(exc, GovernanceDenied)
        _ = exc  # suppress unused
    except RuntimeError:
        pass  # wrong — raw exception escaped the boundary

    check("GovernanceError raised (fail-closed)", error_raised)
    check("Raw RuntimeError is wrapped (not escaped)", is_governance_error)


# ---------------------------------------------------------------------------
# S4 — Fail-closed on policy fault
# ---------------------------------------------------------------------------
async def s4_fail_closed_policy() -> None:
    print("\n[S4] Fail-closed: policy engine raises")

    class _BrokenPolicy:
        async def evaluate(self, ctx: GovernanceContext) -> Decision:
            raise RuntimeError("policy evaluator crashed")

    boundary = _boundary()
    audit = AgentMeshAudit(boundary)
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=_BrokenPolicy(),
        audit=audit,
        mode="strict",
    )

    error_raised = False
    try:
        await gov.govern(GovernanceContext(action="tool.run", subject="qa-agent"))
    except GovernanceError:
        error_raised = True
    except RuntimeError:
        pass  # wrong — raw exception escaped

    check("GovernanceError raised when policy crashes", error_raised)


# ---------------------------------------------------------------------------
# S5 — Shadow mode: deny observed but not enforced
# ---------------------------------------------------------------------------
async def s5_shadow_mode() -> None:
    print("\n[S5] Shadow mode: deny is observed, not raised")
    boundary = _boundary()
    audit = AgentMeshAudit(boundary)
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=AgentOsPolicy(boundary, rules=None),  # deny everything
        audit=audit,
        mode="shadow",
    )

    exception_raised = False
    decision = None
    try:
        decision = await gov.govern(
            GovernanceContext(action="wire.transfer", subject="qa-agent")
        )
    except GovernanceDenied:
        exception_raised = True

    check("No exception raised in shadow mode", not exception_raised)
    check("Decision still reflects deny", decision is not None and not decision.allowed)

    ok, _ = audit.verify_integrity()
    check("Deny was audited (chain verifies)", ok)


# ---------------------------------------------------------------------------
# S6 — Idempotency replay: same key + same payload → replayed = True
# ---------------------------------------------------------------------------
async def s6_idempotency_replay() -> None:
    print("\n[S6] Idempotency: duplicate key → replay, not re-evaluation")
    boundary = _boundary()
    gov, _ = _strict_gov(boundary, rules=[_ALLOW_TOOL_RUN])

    eval_count = 0
    original_evaluate = AgentOsPolicy.evaluate

    async def _counting_evaluate(self, ctx):  # noqa: ANN001, ANN201
        nonlocal eval_count
        eval_count += 1
        return await original_evaluate(self, ctx)

    ctx_a = GovernanceContext(action="tool.run", subject="qa-agent", idempotency_key="k-s6")
    ctx_b = GovernanceContext(action="tool.run", subject="qa-agent", idempotency_key="k-s6")

    AgentOsPolicy.evaluate = _counting_evaluate  # type: ignore[method-assign]
    try:
        d1 = await gov.govern(ctx_a)
        d2 = await gov.govern(ctx_b)
    finally:
        AgentOsPolicy.evaluate = original_evaluate  # type: ignore[method-assign]

    check("First decision: replayed = False", d1.replayed is False)
    check("Second decision: replayed = True", d2.replayed is True)
    check("Policy evaluated exactly once (not twice)", eval_count == 1,
          f"evaluate() called {eval_count} times")


# ---------------------------------------------------------------------------
# S7 — Idempotency conflict: same key, different payload → GovernanceError
# ---------------------------------------------------------------------------
async def s7_idempotency_conflict() -> None:
    print("\n[S7] Idempotency conflict: same key, different payload → hard stop")
    boundary = _boundary()
    gov, _ = _strict_gov(boundary, rules=[_ALLOW_TOOL_RUN])

    ctx_first = GovernanceContext(
        action="tool.run", subject="qa-agent",
        payload={"amount": 100}, idempotency_key="k-s7",
    )
    ctx_conflict = GovernanceContext(
        action="tool.run", subject="qa-agent",
        payload={"amount": 999}, idempotency_key="k-s7",
    )

    await gov.govern(ctx_first)

    conflict_raised = False
    try:
        await gov.govern(ctx_conflict)
    except GovernanceError:
        conflict_raised = True

    check("GovernanceError raised on same key + different payload", conflict_raised)


# ---------------------------------------------------------------------------
# S8 — Proxy effect-idempotency: tool body runs once for keyed duplicate
# ---------------------------------------------------------------------------
async def s8_proxy_effect_idempotency() -> None:
    print("\n[S8] Proxy: effect-idempotency (tool body runs once)")
    boundary = _boundary()
    gov, _ = _strict_gov(boundary, rules=[_ALLOW_TOOL_RUN])

    call_count = 0

    async def _tool(amount: int) -> str:
        nonlocal call_count
        call_count += 1
        return f"processed-{amount}"

    def _ctx_factory(amount: int) -> GovernanceContext:
        return GovernanceContext(
            action="tool.run",
            subject="qa-agent",
            payload={"amount": amount},
            idempotency_key="proxy-s8",
        )

    tool = gov.proxy(_tool, action="tool.run", subject="qa-agent", context_factory=_ctx_factory)

    result_a = await tool(42)
    result_b = await tool(42)

    check("Tool body ran exactly once", call_count == 1, f"called {call_count} times")
    check("Both calls returned the same result", result_a == result_b,
          f"a={result_a!r} b={result_b!r}")


# ---------------------------------------------------------------------------
# S9 — Context immutability: mutation rejected after construction (TOCTOU)
# ---------------------------------------------------------------------------
async def s9_context_immutability() -> None:
    print("\n[S9] Context immutability: payload cannot be mutated post-construction")
    ctx = GovernanceContext(action="tool.run", subject="qa-agent", payload={"user": "alice"})

    mutation_blocked = False
    try:
        ctx.payload["user"] = "mallory"  # type: ignore[index]
    except TypeError:
        mutation_blocked = True

    check("Mutation of ctx.payload raises TypeError", mutation_blocked)
    check("Original value unchanged", ctx.payload.get("user") == "alice")  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# S10 — Durable file audit + Merkle verification across process boundary
# ---------------------------------------------------------------------------
async def s10_durable_audit_and_merkle() -> None:
    print("\n[S10] Durable file audit: HMAC-signed trail + Merkle verification")
    import tempfile

    secret = os.environ.get("ZEMTIK_AUDIT_SECRET", "qa-test-secret")
    fd, _tmp = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    audit_path = pathlib.Path(_tmp)

    boundary = _boundary()
    file_sink = boundary.file_audit_sink(str(audit_path), secret.encode())
    audit = AgentMeshAudit(boundary, sink=file_sink)
    gov = ZemtikGovern(
        identity=StaticIdentity(boundary),
        policy=AgentOsPolicy(boundary, rules=[_ALLOW_TOOL_RUN]),
        audit=audit,
        mode="strict",
    )

    # allow
    await gov.govern(GovernanceContext(action="tool.run", subject="qa-agent"))
    # deny (no matching rule for wire.transfer)
    try:
        await gov.govern(GovernanceContext(action="wire.transfer", subject="qa-agent"))
    except GovernanceDenied:
        pass

    lines = [ln for ln in audit_path.read_text().splitlines() if ln.strip()]
    check("Two audit entries written to disk", len(lines) == 2, f"got {len(lines)} lines")

    # Simulate process crash: open a fresh sink on the same file
    fresh_sink = boundary.file_audit_sink(str(audit_path), secret.encode())
    fresh_audit = AgentMeshAudit(boundary, sink=fresh_sink)
    ok, err = fresh_audit.verify_integrity()
    check("Fresh sink verifies Merkle chain from disk", ok, err)

    audit_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
async def main() -> None:
    print("=" * 60)
    print("zemtik-govern Manual QA — Three-Seam Pipeline")
    print("=" * 60)

    scenarios = [
        s1_deny_by_default,
        s2_allow_path,
        s3_fail_closed_identity,
        s4_fail_closed_policy,
        s5_shadow_mode,
        s6_idempotency_replay,
        s7_idempotency_conflict,
        s8_proxy_effect_idempotency,
        s9_context_immutability,
        s10_durable_audit_and_merkle,
    ]

    passed = 0
    failed = 0
    for scenario in scenarios:
        try:
            await scenario()
            passed += 1
        except AssertionError as exc:
            print(f"  {exc}")
            failed += 1
        except Exception as exc:
            print(f"  ❌ UNEXPECTED EXCEPTION  {exc!r}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
