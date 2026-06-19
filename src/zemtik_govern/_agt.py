"""The single sanctioned boundary to Microsoft AGT.

No other module in zemtik-govern may import ``agent_os`` or ``agentmesh``
directly. Everything the wrapper needs from AGT flows through :class:`AGTBoundary`,
which asserts the pinned *distribution* versions at construction time.

Why distribution metadata and not ``module.__version__``:
the installed wheels report ``agent_os.__version__ == "3.2.2"`` and
``agentmesh.__version__ == "3.6.0"`` while the pinned distributions are both
``3.7.0``. The module attributes lag the packaging version, so trusting them
would silently accept a wrong build. ``importlib.metadata.version`` reads the
authoritative distribution version that pip/uv resolved.
"""

from __future__ import annotations

import importlib.metadata as _metadata

# Pinned AGT distributions. The wrapper is built and tested against exactly
# these; any drift is a hard failure, not a warning.
AGT_PINS: dict[str, str] = {
    "agent-os-kernel": "3.7.0",
    "agentmesh-platform": "3.7.0",
}


class AGTVersionError(RuntimeError):
    """Raised when an installed AGT distribution does not match its pin."""


def assert_pins(pins: dict[str, str] = AGT_PINS) -> dict[str, str]:
    """Verify every pinned distribution is installed at the exact version.

    Returns the resolved versions on success; raises :class:`AGTVersionError`
    on the first mismatch or missing distribution.
    """
    resolved: dict[str, str] = {}
    for dist, expected in pins.items():
        try:
            found = _metadata.version(dist)
        except _metadata.PackageNotFoundError as exc:
            raise AGTVersionError(f"AGT distribution {dist!r} is not installed") from exc
        if found != expected:
            raise AGTVersionError(
                f"AGT distribution {dist!r} pinned at {expected} but {found} is installed"
            )
        resolved[dist] = found
    return resolved


class AGTBoundary:
    """The one object that owns AGT. Asserts pins when built."""

    def __init__(self, pins: dict[str, str] = AGT_PINS) -> None:
        self.pins = dict(pins)
        self._resolved = assert_pins(self.pins)

        # The only place agent_os / agentmesh are imported. Deferred to here so
        # importing this module costs nothing until a boundary is actually built
        # (and so pin assertion runs before any AGT code is touched).
        from agent_os.policies import PolicyDocument as _PolicyDocument
        from agent_os.policies import PolicyEvaluator as _PolicyEvaluator
        from agentmesh.governance.audit import AuditLog as _AuditLog
        from agentmesh.identity import AgentDID as _AgentDID

        self._PolicyEvaluator = _PolicyEvaluator
        self._PolicyDocument = _PolicyDocument
        self._AuditLog = _AuditLog
        self._AgentDID = _AgentDID

    # --- policy concern (agent_os) ---
    # Both helpers are PRIVATE: the raw evaluator fails OPEN (allowed=True on
    # no-match), so the only sanctioned public door to a policy decision is
    # AgentOsPolicy, which imposes deny-by-default. The conformance tests reach
    # the private member on purpose — documenting AGT's fail-open default is the
    # one place that should.
    def _policy_document(self, rules, name: str = "zemtik-govern"):
        """Build an AGT ``PolicyDocument`` from rule dicts, behind the boundary."""
        return self._PolicyDocument(name=name, rules=list(rules))

    def _policy_evaluator(self, policies=None, root_dir=None):
        """The raw, fail-OPEN AGT evaluator. Private — only AgentOsPolicy and the
        conformance tests may name it."""
        return self._PolicyEvaluator(policies=policies, root_dir=root_dir)

    # --- audit concern (agentmesh) ---
    def audit_log(self, sink=None):
        """A tamper-evident AGT audit log (Merkle-chained)."""
        return self._AuditLog(sink=sink)

    # --- identity concern (agentmesh) ---
    def mint_did(self, unique_id: str) -> str:
        """Mint the ``did:mesh:<unique_id>`` string that audit entries stamp.

        v0.1 ships a static identity; this is the compat point where a real
        DID provider would plug in. The string form is what
        ``AuditLog.log(agent_did=...)`` consumes, closing the identity→audit map.
        """
        return str(self._AgentDID(unique_id=unique_id))
