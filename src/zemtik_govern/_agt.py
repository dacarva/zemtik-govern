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


# --- agent_os -> agentmesh -> wrapper compat map ----------------------------
# The single documented source of how AGT's policy verdict maps onto the
# wrapper's own Decision, and how identity threads into audit. The spike
# (spike/verify_agt_signatures.py) prints this; tests/test_agt_conformance.py
# pins each fact in CI. Recorded here, in the boundary, because this is the one
# module allowed to know AGT's surface.
#
#   agent_os.PolicyDecision.allowed       -> Decision.allowed   (BUT see note)
#   agent_os.PolicyDecision.matched_rule  -> Decision.matched_rule
#   agent_os.PolicyDecision.action        -> Decision.action
#   agent_os.PolicyDecision.reason        -> Decision.reason  / AuditLog.log(policy_decision=)
#   agentmesh AgentDID(unique_id)         -> did:mesh:<id>     -> AuditLog.log(agent_did=)
#
# NOTE (the moat): AGT fails OPEN — matched_rule is None => allowed=True. The
# wrapper overrides that no-match case to a deny in AgentOsPolicy. So
# PolicyDecision.allowed maps to Decision.allowed ONLY when a rule matched.
AGT_COMPAT_MAP: dict[str, str] = {
    "PolicyDecision.allowed": "Decision.allowed (only when matched_rule is not None)",
    "PolicyDecision.matched_rule": "Decision.matched_rule",
    "PolicyDecision.action": "Decision.action",
    "PolicyDecision.reason": "Decision.reason / AuditLog.log(policy_decision=)",
    "AgentDID(unique_id)": "did:mesh:<id> / AuditLog.log(agent_did=)",
}


class AGTVersionError(RuntimeError):
    """Raised when an installed AGT distribution does not match its pin."""


def assert_pins(pins: dict[str, str] = AGT_PINS) -> dict[str, str]:
    """Verify every pinned distribution is installed at the exact version.

    Returns the resolved versions on success; raises :class:`AGTVersionError`
    on the first mismatch or missing distribution.

    UX note: the function raises on the *first* mismatch rather than collecting
    all mismatches.  This is intentional: in a correctly-pinned environment the
    common case is zero failures; a fast-fail on the first bad distribution is
    safe (no ungoverned tool will run regardless of which pin failed) and keeps
    the code simple.  An operator who needs to audit all installed versions can
    run ``importlib.metadata.version`` on each distribution directly.  This is a
    UX trade-off, not a security gap — any single mismatch is a hard abort.
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
        from agent_os.prompt_injection import PromptInjectionConfig as _InjectionConfig
        from agent_os.prompt_injection import PromptInjectionDetector as _Detector
        from agent_os.prompt_injection import (
            load_prompt_injection_config as _load_injection_config,
        )
        from agentmesh.governance import FileAuditSink as _FileAuditSink
        from agentmesh.governance.audit import AuditLog as _AuditLog
        from agentmesh.identity import AgentDID as _AgentDID

        self._PolicyEvaluator = _PolicyEvaluator
        self._PolicyDocument = _PolicyDocument
        self._Detector = _Detector
        self._InjectionConfig = _InjectionConfig
        self._load_injection_config = _load_injection_config
        self._AuditLog = _AuditLog
        self._FileAuditSink = _FileAuditSink
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

    def file_audit_sink(self, path, secret_key: bytes):
        """A durable, HMAC-signed, hash-chained file sink (agentmesh primitive).

        The ``secret_key`` is required: a file audit trail without a signing key is
        not tamper-evident. The caller (registry) sources it and fails closed if
        absent."""
        return self._FileAuditSink(path, secret_key)

    # --- prompt-injection concern (agent_os) ---
    def prompt_injection_detector(self, rules_path: str | None = None):
        """Build an AGT ``PromptInjectionDetector`` with an EXPLICIT rule config.

        With ``rules_path=None`` (the default), the detector is built from AGT's
        own vetted ``PromptInjectionConfig()`` defaults, passed explicitly. This
        is NOT the bare ``PromptInjectionDetector()`` sample-rule path: passing an
        explicit config suppresses AGT's sample-rule ``UserWarning``, and the rules
        track the pinned wheel automatically (no in-repo copy to maintain). Pass a
        ``rules_path`` to load a custom file instead (to pin a version or diverge);
        a missing or malformed file raises ``FileNotFoundError`` / ``ValueError``,
        which the caller (registry) turns into a fail-closed
        ``GovernanceNotConfigured`` at startup. Detection is pure, so one detector
        is built once and reused (see the spike findings)."""
        config = (
            self._InjectionConfig()
            if rules_path is None
            else self._load_injection_config(rules_path)
        )
        return self._Detector(injection_config=config)

    def screen_text(
        self, detector, text: str, source: str
    ) -> tuple[bool, str | None, str | None]:
        """Run one ``detect`` and return ONLY the no-echo-safe verdict facts:
        ``(is_injection, injection_type, threat_level)`` as plain strings. The
        detector's internal ``audit_log`` (an unbounded ``list``) is cleared after
        every call so a long-lived reused detector cannot leak memory — we keep our
        own audit seam. D6: ``matched_patterns`` / ``explanation`` (which can echo
        the attacker payload) are deliberately NOT returned."""
        result = detector.detect(text, source=source)
        # Keep the detector's internal audit trail flat: it appends one record per
        # detect (``audit_log`` is a read-only copy property; the real store is the
        # private ``_audit_log`` deque). We have our own audit seam and never read
        # it, so clear it after every call rather than let it ride to its cap.
        try:
            detector._audit_log.clear()
        except AttributeError:
            pass
        injection_type = (
            result.injection_type.value
            if result.injection_type is not None
            else None
        )
        threat_level = (
            result.threat_level.value if result.threat_level is not None else None
        )
        return bool(result.is_injection), injection_type, threat_level

    # --- identity concern (agentmesh) ---
    def mint_did(self, unique_id: str) -> str:
        """Mint the ``did:mesh:<unique_id>`` string that audit entries stamp.

        v0.1 ships a static identity; this is the compat point where a real
        DID provider would plug in. The string form is what
        ``AuditLog.log(agent_did=...)`` consumes, closing the identity→audit map.
        """
        return str(self._AgentDID(unique_id=unique_id))
