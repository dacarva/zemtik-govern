"""S1 — single AGT boundary (E4).

These tests exercise the wrapper's only sanctioned door to Microsoft AGT.
Everything here is behavior visible through the public boundary surface, not
the internals of how agent_os / agentmesh are wired.
"""

import pytest

from zemtik_govern._agt import AGT_PINS, AGTBoundary, AGTVersionError


def test_boundary_constructs_when_pins_match():
    """In a correctly-provisioned env the boundary builds without error."""
    boundary = AGTBoundary()
    assert boundary.pins == AGT_PINS


def test_boundary_rejects_version_drift():
    """A wrong pinned version is a hard failure at construction, not a warning."""
    with pytest.raises(AGTVersionError):
        AGTBoundary(pins={"agent-os-kernel": "9.9.9"})


def test_boundary_rejects_missing_distribution():
    """An absent AGT distribution fails closed rather than degrading."""
    with pytest.raises(AGTVersionError):
        AGTBoundary(pins={"not-a-real-agt-package": "1.0.0"})


# --- concern surface: policy / audit / identity reachable only via the boundary ---


def test_raw_policy_evaluator_is_not_on_the_public_surface():
    """Candidate 1: the fail-OPEN evaluator must not be publicly reachable. The
    only public door to a policy decision is AgentOsPolicy (deny-by-default); the
    raw evaluator lives behind the boundary, named privately so only the policy
    core and the conformance tests (which document AGT) touch it."""
    boundary = AGTBoundary()
    assert not hasattr(boundary, "policy_evaluator")
    assert not hasattr(boundary, "policy_document")
    # the private door still exists for the one sanctioned internal caller
    assert hasattr(boundary, "_policy_evaluator")


def test_boundary_exposes_audit_log_that_verifies():
    """Audit concern: log an entry, integrity check passes."""
    boundary = AGTBoundary()
    log = boundary.audit_log()
    log.log(event_type="tool_invoked", agent_did="did:mesh:agent-1", action="tool.run")
    ok, err = log.verify_integrity()
    assert ok, err


def test_boundary_mints_did_string():
    """Identity concern: mint the did:mesh string that audit.log stamps."""
    boundary = AGTBoundary()
    did = boundary.mint_did("loopay-agent-1")
    assert did == "did:mesh:loopay-agent-1"
