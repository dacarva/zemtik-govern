"""Staged dogfood cutover — moving a live fintech agent onto the substrate.

A fintech company runs a customer-support agent with a handful of governed call
sites: a few reads (safe) and a few privileged money-path writes. This demo
cuts that agent over from a hand-wired path to ``zemtik-govern`` in the two
phases a careful rollout actually uses:

    Phase A — SHADOW   run the governor alongside the live path; record what it
                       WOULD decide, enforce nothing. Diff shadow vs. live to
                       surface false-denies on the money path BEFORE enforcing.

    Phase B — ENFORCE  flip the per-env kill-switch to enforcing. The privileged
                       writes are now blocked. The kill-switch reverts to the
                       agent's PRIOR governed path in one toggle — never to
                       allow-all; engaging with no governed fallback fails closed.

Every call site assembles its governance context through ONE factory
(``make_context``) — a single unified contract, no per-site dict assembly. Both
phases write a durable, HMAC-signed, Merkle-chained audit trail that is read
back and integrity-checked at the end.

Run (no API key needed — the agent is scripted, the governance is real AGT):

    ZEMTIK_AUDIT_SECRET=dogfood-secret python sandbox/dogfood_cutover.py

The agent here is a generic fintech stand-in for any money-path workload.
"""

from __future__ import annotations

import os
from collections import namedtuple
from pathlib import Path

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.audit import AgentMeshAudit
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import Killswitch, ZemtikGovern
from zemtik_govern.errors import GovernanceDenied, GovernanceError
from zemtik_govern.identity import StaticIdentity
from zemtik_govern.policy import AgentOsPolicy

# The agent's identity at every call site — the unified contract keys policy and
# stamps audit on this one subject.
SUBJECT = "fintech-agent"

# One governed action per call site. ``kind`` is documentation only — policy
# decides via the rules below, never via this flag (a write is denied because no
# rule matches it, not because we labelled it "write").
CallSite = namedtuple("CallSite", ["action", "payload", "kind"])

# Seven govern() call sites: four reads (explicitly allowed) and three
# privileged money-path writes (no rule → deny-by-default).
CALL_SITES: list[CallSite] = [
    CallSite("read_account", {"account_id": "acc-001"}, "read"),
    CallSite("read_transactions", {"account_id": "acc-001", "limit": 20}, "read"),
    CallSite("get_feature_flags", {"env": "prod"}, "read"),
    CallSite("get_exchange_rate", {"pair": "USD/EUR"}, "read"),
    CallSite("transfer_funds", {"from_id": "acc-003", "to_id": "acc-002", "amount": 1000}, "write"),
    CallSite("close_account", {"account_id": "acc-002"}, "write"),
    CallSite("issue_refund", {"account_id": "acc-001", "amount": 250}, "write"),
]

# Deny-by-default policy: name the safe reads, say nothing about the writes. The
# AgentOsPolicy moat turns "no rule matched" into a deny, so the three writes are
# blocked without ever being enumerated.
POLICY_RULES: list[dict] = [
    {
        "name": f"allow-{site.action}",
        "condition": {"field": "action", "operator": "eq", "value": site.action},
        "action": "allow",
    }
    for site in CALL_SITES
    if site.kind == "read"
]


# The agent's PRIOR governed path: a more permissive policy that still named
# every action it allowed (including the money-path writes). The kill-switch
# reverts to THIS — a governed policy, never allow-all. It remains deny-by-default
# for anything it does not name.
PRIOR_GOVERNED_RULES: list[dict] = [
    {
        "name": f"prior-allow-{site.action}",
        "condition": {"field": "action", "operator": "eq", "value": site.action},
        "action": "allow",
    }
    for site in CALL_SITES
]


def build_fallback_policy() -> AgentOsPolicy:
    """The prior governed path the kill-switch reverts to — deny-by-default, but
    permissive enough to have allowed the money-path writes before the cutover."""
    return AgentOsPolicy(AGTBoundary(), rules=PRIOR_GOVERNED_RULES)


def make_context(action: str, **payload) -> GovernanceContext:
    """The ONE place a governance context is assembled. Every call site routes
    through here, so the request contract cannot drift site to site."""
    return GovernanceContext(action=action, subject=SUBJECT, payload=payload)


AUDIT_SECRET_ENV = "ZEMTIK_AUDIT_SECRET"

# One per-call-site outcome. ``allowed`` is the policy verdict (identical in
# shadow and enforce — that is the zero-false-denies proof); ``ran`` is whether
# the tool actually executed (shadow runs denied writes, enforce blocks them).
SiteResult = namedtuple("SiteResult", ["action", "allowed", "ran"])


def _build_audit(boundary: AGTBoundary, audit_path: str | Path) -> AgentMeshAudit:
    """A durable, HMAC-signed, Merkle-chained file sink. The signing secret comes
    from the environment, never a checked-in file — same contract the registry
    enforces."""
    secret = os.environ.get(AUDIT_SECRET_ENV)
    if not secret:
        raise GovernanceError(
            f"file audit sink requires an HMAC secret in ${AUDIT_SECRET_ENV}"
        )
    file_sink = boundary.file_audit_sink(str(audit_path), secret.encode("utf-8"))
    return AgentMeshAudit(boundary, sink=file_sink)


def build_governor(
    audit_path: str | Path,
    mode: str,
    *,
    fallback: AgentOsPolicy | None = None,
    killswitch: Killswitch | None = None,
    rules: list[dict] | None = None,
) -> tuple[ZemtikGovern, AGTBoundary, AgentMeshAudit]:
    """Wire the three real seams (StaticIdentity → AgentOsPolicy → AgentMeshAudit)
    into a governor for one cutover phase. Built directly (not via the registry)
    so the optional kill-switch fallback can be supplied for Phase B."""
    boundary = AGTBoundary()
    identity = StaticIdentity(boundary)
    policy = AgentOsPolicy(boundary, rules=rules if rules is not None else POLICY_RULES)
    audit = _build_audit(boundary, audit_path)
    gov = ZemtikGovern(
        identity=identity,
        policy=policy,
        audit=audit,
        mode=mode,
        fallback=fallback,
        killswitch=killswitch,
    )
    return gov, boundary, audit


async def run_phase(gov: ZemtikGovern, mode: str) -> list[SiteResult]:
    """Drive every call site through ``govern()`` once and record the outcome.

    A denial that is enforced (enforce mode) raises and the tool does not run; a
    denial that is only observed (shadow mode) returns a not-allowed decision and
    the tool still runs. Either way the policy verdict is captured for the diff.
    """
    results: list[SiteResult] = []
    for site in CALL_SITES:
        ctx = make_context(site.action, **site.payload)
        blocked = False
        try:
            decision = await gov.govern(ctx)
            allowed = decision.allowed
        except GovernanceDenied as exc:
            allowed = exc.decision.allowed  # False
            blocked = True
        results.append(SiteResult(site.action, allowed=allowed, ran=not blocked))
    return results


# --------------------------------------------------------------------------- #
# Runnable demo — both phases, the kill-switch revert, integrity, a report     #
# --------------------------------------------------------------------------- #
REPO_ROOT = Path(__file__).resolve().parent.parent
SHADOW_TRAIL = REPO_ROOT / "sandbox" / "dogfood_shadow.audit.jsonl"
ENFORCE_TRAIL = REPO_ROOT / "sandbox" / "dogfood_enforce.audit.jsonl"
# The kill-switch probe writes its own entries (denied write, reverted allow,
# no-fallback system error) to a SEPARATE trail so the enforce trail stays a
# faithful record of just the enforce phase for any file-based AuditReader.
KILLSWITCH_TRAIL = REPO_ROOT / "sandbox" / "dogfood_killswitch.audit.jsonl"
REPORT_MD = REPO_ROOT / "sandbox" / "dogfood_cutover_report.md"


async def _killswitch_revert_probe(audit_path: Path) -> dict:
    """Prove the kill-switch reverts a denied write to the prior governed path
    and that, with no fallback, engaging fails closed (never allow-all)."""
    ks = Killswitch()
    gov, _, _ = build_governor(
        audit_path, mode="enforce", fallback=build_fallback_policy(), killswitch=ks
    )
    write = make_context(
        "transfer_funds", from_id="acc-003", to_id="acc-002", amount=1000
    )

    new_policy_blocks = False
    try:
        await gov.govern(write)
    except GovernanceDenied:
        new_policy_blocks = True

    ks.engage()
    reverted_allows = (await gov.govern(write)).allowed

    # A separate governor with the switch engaged but NO fallback must fail closed.
    no_fallback = Killswitch(engaged=True)
    gov2, _, _ = build_governor(
        audit_path, mode="enforce", fallback=None, killswitch=no_fallback
    )
    fails_closed = False
    try:
        await gov2.govern(make_context("read_account", account_id="acc-001"))
    except GovernanceError:
        fails_closed = True

    return {
        "new_policy_blocks_write": new_policy_blocks,
        "reverted_to_prior_path_allows": reverted_allows,
        "no_fallback_fails_closed": fails_closed,
    }


def _render_report(shadow, enforce, ks_probe, shadow_ok, enforce_ok) -> tuple[str, bool]:
    """Render the markdown report and return ``(text, passed)``."""
    lines: list[str] = []
    w = lines.append
    verdicts_match = {(r.action, r.allowed) for r in shadow} == {
        (r.action, r.allowed) for r in enforce
    }
    writes_blocked = all(not r.ran for r in enforce if _kind(r.action) == "write")
    # Parity alone is not the proof: a deny-all policy would match shadow to
    # enforce AND block every write. Assert the reads actually run under enforce
    # so "zero false-denies" means the safe path stayed open, not that nothing ran.
    reads_allowed = all(
        r.allowed and r.ran for r in enforce if _kind(r.action) == "read"
    )
    passed = (
        verdicts_match
        and writes_blocked
        and reads_allowed
        and shadow_ok
        and enforce_ok
        and ks_probe["new_policy_blocks_write"]
        and ks_probe["reverted_to_prior_path_allows"]
        and ks_probe["no_fallback_fails_closed"]
    )

    w("# Dogfood Cutover Report — fintech agent onto the substrate\n")
    w("> A simulated fintech agent with 7 govern() call sites, cut over in two "
      "phases. All decisions below come from the real pinned AGT policy moat.\n")
    w(f"## Verdict: {'PASS ✅' if passed else 'FAIL ❌'}\n")

    w("## Phase A (shadow) vs Phase B (enforce)\n")
    w("| call site | kind | verdict | shadow ran? | enforce ran? |")
    w("|-----------|------|---------|-------------|--------------|")
    se = {r.action: r for r in enforce}
    for r in shadow:
        e = se[r.action]
        w(f"| `{r.action}` | {_kind(r.action)} | "
          f"{'allow' if r.allowed else 'DENY'} | "
          f"{'yes' if r.ran else 'no'} | {'yes' if e.ran else 'no'} |")
    w("")
    w(f"- Verdicts identical across phases (zero false-denies): **{verdicts_match}**")
    w(f"- Safe reads stay open under enforce (not a deny-all): **{reads_allowed}**")
    w(f"- Privileged writes blocked under enforce: **{writes_blocked}**\n")

    w("## Kill-switch revert\n")
    w(f"- New policy blocks the money-path write: **{ks_probe['new_policy_blocks_write']}**")
    w(f"- Engaged → reverts to prior governed path (write allowed again): "
      f"**{ks_probe['reverted_to_prior_path_allows']}**")
    w(f"- Engaged with NO fallback → fails closed (never allow-all): "
      f"**{ks_probe['no_fallback_fails_closed']}**\n")

    w("## Audit integrity\n")
    w(f"- Shadow trail verifies: **{shadow_ok}**")
    w(f"- Enforce trail verifies: **{enforce_ok}**\n")
    return "\n".join(lines) + "\n", passed


def _kind(action: str) -> str:
    for site in CALL_SITES:
        if site.action == action:
            return site.kind
    return "unknown"


async def main() -> int:
    os.environ.setdefault(AUDIT_SECRET_ENV, "dogfood-local-demo-secret")
    for trail in (SHADOW_TRAIL, ENFORCE_TRAIL, KILLSWITCH_TRAIL):
        if trail.exists():
            trail.unlink()

    shadow_gov, _, shadow_audit = build_governor(SHADOW_TRAIL, mode="shadow")
    enforce_gov, _, enforce_audit = build_governor(ENFORCE_TRAIL, mode="enforce")

    shadow = await run_phase(shadow_gov, mode="shadow")
    enforce = await run_phase(enforce_gov, mode="enforce")
    ks_probe = await _killswitch_revert_probe(KILLSWITCH_TRAIL)

    shadow_ok, _ = shadow_audit.verify_integrity()
    enforce_ok, _ = enforce_audit.verify_integrity()

    report, passed = _render_report(shadow, enforce, ks_probe, shadow_ok, enforce_ok)
    REPORT_MD.write_text(report, encoding="utf-8")
    print(report)
    print(f"Report: {REPORT_MD.relative_to(REPO_ROOT)}")
    return 0 if passed else 1


if __name__ == "__main__":
    import asyncio

    raise SystemExit(asyncio.run(main()))
