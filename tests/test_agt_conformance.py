"""S1 spike, as an executable conformance gate (E4).

These are the "pinning-bet early warning" tests from the design doc: if a future
AGT bump changes a signature or a default the wrapper relies on, CI fails here
*before* the change reaches the governance core. Each test pins one fact the
compat map in spike/verify_agt_signatures.py asserts in prose.
"""

from zemtik_govern._agt import AGTBoundary


def test_agt_policy_is_allow_by_default_NOT_deny():
    """The moat-critical finding: raw AGT policy fails OPEN.

    The design doc claimed agent_os PolicyEvaluator was "deny-by-default (keep)".
    It is not. An evaluator with no matching rule returns allowed=True. The
    wrapper must therefore impose deny-by-default itself (S3); this test exists
    so that assumption can never silently rot.
    """
    boundary = AGTBoundary()
    decision = boundary._policy_evaluator().evaluate({"action": "anything", "subject": "x"})
    assert decision.allowed is True, (
        "AGT policy default changed — re-evaluate the wrapper's deny-by-default layer"
    )


def test_policy_decision_carries_expected_fields():
    """Compat map: the Decision fields the wrapper maps onto its own contract."""
    boundary = AGTBoundary()
    decision = boundary._policy_evaluator().evaluate({"action": "a", "subject": "s"})
    for field in ("allowed", "matched_rule", "action", "reason"):
        assert hasattr(decision, field), f"AGT PolicyDecision lost field {field!r}"


def test_audit_log_stamps_agent_did_and_chains():
    """Compat map: identity→audit. The did string mints, then stamps an entry,
    and the Merkle chain verifies across two entries."""
    boundary = AGTBoundary()
    did = boundary.mint_did("agent-conformance")
    log = boundary.audit_log()
    e1 = log.log(event_type="tool_invoked", agent_did=did, action="a1")
    e2 = log.log(event_type="tool_blocked", agent_did=did, action="a2", outcome="denied")
    assert e1.agent_did == did
    assert e2.agent_did == did
    ok, err = log.verify_integrity()
    assert ok, err
    # tamper-evidence proof is retrievable for a written entry
    assert log.get_proof(e1.entry_id) is not None
