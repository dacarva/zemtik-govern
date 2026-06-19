"""Conformance tests: MCPGateway deny-by-default contract.

``agent_os.mcp_gateway.MCPGateway`` is available as a mock in dev AGT.  These
tests document the contract that any MCPGateway implementation must satisfy and
pin the behaviour of the current mock so regressions are caught in CI.

Design contract:

    MCPGateway MUST deny when an unknown tool is called with an explicit
    allow-list.  With an empty ``allowed_tools`` the mock fails OPEN (allows
    all), which is the same security hazard as the raw ``PolicyEvaluator``.

    The ``GovernedMCPServer`` does NOT rely on MCPGateway for its deny-by-
    default guarantee.  It routes every call through ``govern()`` which uses
    ``AgentOsPolicy``, which forces ``matched_rule is None`` -> deny.  This
    conformance suite documents MCPGateway's behaviour and guards against future
    drift — it is NOT the primary enforcement path.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Availability guard
# ---------------------------------------------------------------------------

try:
    from agent_os.mcp_gateway import GovernancePolicy as _GovernancePolicy
    from agent_os.mcp_gateway import MCPGateway as _MCPGateway

    _HAS_MCP_GATEWAY = True
except (ImportError, AttributeError):
    _HAS_MCP_GATEWAY = False

_skip_no_gateway = pytest.mark.skipif(
    not _HAS_MCP_GATEWAY,
    reason="agent_os.mcp_gateway not available; "
    "these tests run only when MCPGateway is importable",
)


# ---------------------------------------------------------------------------
# Contract documentation (always collected, never skipped)
# ---------------------------------------------------------------------------


def test_mcp_gateway_deny_by_default_contract_is_documented():
    """Documents the required contract regardless of gateway availability.

    The GovernedMCPServer deny-by-default moat:

    - Raw AGT ``PolicyEvaluator`` allows when no rule matches (see
      test_agt_conformance.py::test_agt_policy_is_allow_by_default_NOT_deny).
    - ``MCPGateway.intercept_tool_call`` with an empty ``allowed_tools`` list
      ALSO fails open -- same hazard, different surface.
    - ``GovernedMCPServer`` does NOT rely on MCPGateway for deny-by-default.
      It routes every call through ``govern()`` -> ``AgentOsPolicy``, which
      forces deny when ``matched_rule is None``.  This is the moat.
    - A call that bypasses ``govern()`` breaks the invariant -- there is no
      ungoverned path to a tool in GovernedMCPServer.

    If ``MCPGateway`` ever changes its default from fail-open to fail-closed,
    that is a welcome improvement but does NOT remove the requirement for
    ``GovernedMCPServer`` to still apply its own deny layer.
    """
    assert True, "contract documented -- see docstring"


# ---------------------------------------------------------------------------
# Gateway-specific conformance (skipped when gateway is absent)
# ---------------------------------------------------------------------------


@_skip_no_gateway
def test_mcp_gateway_fails_open_with_no_allowed_tools():
    """MCPGateway with empty allowed_tools allows any tool -- fails OPEN.

    This documents the hazard: an MCPGateway constructed with default policy
    (empty allowed_tools) allows any tool call.  GovernedMCPServer must NOT
    rely on MCPGateway as its only enforcement layer.
    """
    policy = _GovernancePolicy()  # empty allowed_tools -> fail-open
    gateway = _MCPGateway(policy)
    allowed, reason = gateway.intercept_tool_call("agent:test", "unknown_tool", {})
    # Documents the FAIL-OPEN behaviour (not what we want as a moat):
    assert allowed is True, (
        "MCPGateway default changed -- review GovernedMCPServer's deny layer"
    )


@_skip_no_gateway
def test_mcp_gateway_denies_tool_not_on_explicit_allow_list():
    """MCPGateway denies when a tool is not on an explicit allow-list.

    This is the correct configuration: only explicitly allowed tools pass.
    ``GovernedMCPServer`` enforces deny-by-default at the governance level
    so this gateway-level deny is defence-in-depth, not the primary gate.
    """
    policy = _GovernancePolicy(allowed_tools=["permitted_tool"])
    gateway = _MCPGateway(policy)
    allowed, reason = gateway.intercept_tool_call("agent:test", "unknown_tool", {})
    assert allowed is False, (
        "MCPGateway should deny tools not on the allow list"
    )
    assert reason  # non-empty reason string


@_skip_no_gateway
def test_mcp_gateway_allows_explicitly_listed_tool():
    """MCPGateway allows a tool that is on the explicit allow-list."""
    policy = _GovernancePolicy(allowed_tools=["permitted_tool"])
    gateway = _MCPGateway(policy)
    allowed, _reason = gateway.intercept_tool_call("agent:test", "permitted_tool", {})
    assert allowed is True


@_skip_no_gateway
def test_mcp_gateway_intercept_returns_tuple():
    """MCPGateway.intercept_tool_call returns (bool, str) -- the compat contract."""
    policy = _GovernancePolicy()
    gateway = _MCPGateway(policy)
    result = gateway.intercept_tool_call("agent:test", "any_tool", {})
    assert isinstance(result, tuple)
    assert len(result) == 2
    allowed, reason = result
    assert isinstance(allowed, bool)
    assert isinstance(reason, str)
