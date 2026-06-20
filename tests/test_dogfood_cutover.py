"""E2E for the staged dogfood cutover demo (issue #8).

Drives ``sandbox/dogfood_cutover.py`` — a simulated multi-callsite fintech agent
moved onto the substrate in two phases (shadow → enforce) with a kill-switch
revert path. Asserts every acceptance criterion in-repo, no network needed:

- all call sites route through ONE unified context factory (no per-site dicts);
- shadow mode observes the same denials enforce mode blocks (zero false-denies);
- enforce mode blocks the privileged writes;
- the kill-switch reverts to a prior governed fallback (never allow-all);
- both durable audit trails pass ``verify_integrity()``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SANDBOX_DIR = Path(__file__).parent.parent / "sandbox"
if str(SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(SANDBOX_DIR))

import dogfood_cutover as dc  # noqa: E402

from zemtik_govern.context import GovernanceContext  # noqa: E402
from zemtik_govern.errors import GovernanceError  # noqa: E402

# --- Slice 1: a single unified context contract across every call site --------


def test_seven_call_sites_all_route_through_one_context_factory():
    """The cutover's call sites assemble their governance context in exactly one
    place — ``make_context`` — so there is no per-site dict assembly that could
    drift. Seven sites, every one a real ``GovernanceContext``."""
    assert len(dc.CALL_SITES) == 7

    for site in dc.CALL_SITES:
        ctx = dc.make_context(site.action, **site.payload)
        assert isinstance(ctx, GovernanceContext)
        assert ctx.action == site.action
        assert ctx.subject == dc.SUBJECT
        # the factory is the only assembler: payload round-trips verbatim
        assert ctx.to_dict()["payload"] == site.payload


# --- Slice 2: Phase A shadow — denials observed, never enforced ---------------


@pytest.mark.asyncio
async def test_shadow_phase_observes_write_denials_without_blocking(tmp_path, monkeypatch):
    """Shadow mode is the safe first step of a cutover: it records what it WOULD
    deny but enforces nothing, so the live money path keeps running while the
    operator inspects the would-be denials. Reads are allowed; the privileged
    writes are recorded as denied yet still execute (observe-only)."""
    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "dogfood-test-secret")
    gov, _, _ = dc.build_governor(tmp_path / "shadow.jsonl", mode="shadow")

    results = await dc.run_phase(gov, mode="shadow")
    by_action = {r.action: r for r in results}

    for site in dc.CALL_SITES:
        r = by_action[site.action]
        if site.kind == "read":
            assert r.allowed and r.ran
        else:  # write
            assert not r.allowed  # policy WOULD deny
            assert r.ran          # but shadow does not enforce — tool still ran


# --- Slice 3: Phase B enforce blocks writes; verdicts match shadow ------------


@pytest.mark.asyncio
async def test_enforce_blocks_writes_with_identical_verdicts_to_shadow(tmp_path, monkeypatch):
    """The cutover's payoff: enforce mode blocks the three privileged writes
    (tool never runs) while still allowing the reads. And the policy verdicts are
    IDENTICAL to shadow's — same allows, same denies — so flipping to enforce
    introduces zero false-denies on the money path; only enforcement changes."""
    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "dogfood-test-secret")

    shadow_gov, _, _ = dc.build_governor(tmp_path / "shadow.jsonl", mode="shadow")
    enforce_gov, _, _ = dc.build_governor(tmp_path / "enforce.jsonl", mode="enforce")

    shadow = await dc.run_phase(shadow_gov, mode="shadow")
    enforce = await dc.run_phase(enforce_gov, mode="enforce")

    # enforcement: writes blocked, reads run
    for site, r in zip(dc.CALL_SITES, enforce, strict=True):
        assert r.action == site.action
        if site.kind == "read":
            assert r.allowed and r.ran
        else:
            assert not r.allowed and not r.ran  # blocked: the tool never ran

    # zero false-denies: the verdict set is identical between phases
    assert {(r.action, r.allowed) for r in shadow} == {
        (r.action, r.allowed) for r in enforce
    }


# --- Slice 4: kill-switch reverts to a prior governed path, never allow-all ----


@pytest.mark.asyncio
async def test_killswitch_reverts_to_prior_governed_fallback(tmp_path, monkeypatch):
    """The kill-switch is the one-toggle escape hatch: engaged, it routes
    evaluation back to the agent's PRIOR governed path (which allowed the
    money-path writes) so the tool runs again under the old policy. Disengaged,
    the new deny-by-default policy is back in force."""
    from zemtik_govern.errors import GovernanceDenied

    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "dogfood-test-secret")
    ks = dc.Killswitch()
    fallback = dc.build_fallback_policy()
    gov, _, _ = dc.build_governor(
        tmp_path / "ks.jsonl", mode="enforce", fallback=fallback, killswitch=ks
    )
    write = dc.make_context("transfer_funds", from_id="acc-003", to_id="acc-002", amount=1000)

    # new policy in force: the write is denied
    with pytest.raises(GovernanceDenied):
        await gov.govern(write)

    # revert: the prior governed path allowed this write, so it is allowed again
    ks.engage()
    decision = await gov.govern(write)
    assert decision.allowed is True

    # back to the new policy
    ks.disengage()
    with pytest.raises(GovernanceDenied):
        await gov.govern(write)


@pytest.mark.asyncio
async def test_killswitch_fallback_is_governed_not_allow_all(tmp_path, monkeypatch):
    """Reverting is NOT a bypass: the prior governed path is itself deny-by-
    default, so an action it never blessed stays denied even with the switch
    engaged. The kill-switch trades one governed policy for another, never for
    allow-all."""
    from zemtik_govern.errors import GovernanceDenied

    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "dogfood-test-secret")
    ks = dc.Killswitch(engaged=True)
    gov, _, _ = dc.build_governor(
        tmp_path / "ks2.jsonl", mode="enforce", fallback=dc.build_fallback_policy(), killswitch=ks
    )

    # an action neither policy names is still denied under the engaged fallback
    with pytest.raises(GovernanceDenied):
        await gov.govern(dc.make_context("delete_all_accounts"))


@pytest.mark.asyncio
async def test_killswitch_with_no_fallback_fails_closed(tmp_path, monkeypatch):
    """Engaging the switch with NO governed fallback wired must fail closed — a
    system error, not a silent allow-all. This is the in-repo analogue of
    removing a fail-OPEN ``NullGovernanceProvider``: absence of a governed path
    blocks, it does not pass through."""
    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "dogfood-test-secret")
    ks = dc.Killswitch(engaged=True)
    gov, _, _ = dc.build_governor(
        tmp_path / "ks3.jsonl", mode="enforce", fallback=None, killswitch=ks
    )

    with pytest.raises(GovernanceError):
        await gov.govern(dc.make_context("read_account", account_id="acc-001"))


# --- Slice 5: both durable trails are tamper-evident and verify ---------------


@pytest.mark.asyncio
async def test_both_phase_audit_trails_verify_integrity(tmp_path, monkeypatch):
    """Every governed call in both phases lands in a durable, HMAC-signed,
    Merkle-chained trail — and both trails re-verify, so the record of the
    cutover is itself tamper-evident, not just the live decisions."""
    monkeypatch.setenv("ZEMTIK_AUDIT_SECRET", "dogfood-test-secret")

    shadow_gov, _, shadow_audit = dc.build_governor(tmp_path / "shadow.jsonl", mode="shadow")
    enforce_gov, _, enforce_audit = dc.build_governor(tmp_path / "enforce.jsonl", mode="enforce")

    await dc.run_phase(shadow_gov, mode="shadow")
    await dc.run_phase(enforce_gov, mode="enforce")

    for audit in (shadow_audit, enforce_audit):
        ok, err = audit.verify_integrity()
        assert ok, err
