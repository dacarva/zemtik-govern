"""No-echo span-attribute assembly (Slice 2) — the masking discipline the core
guard (``core.py::_traced``/``_span_set``) delegates to.

Pure functions only: no ``langfuse`` import, no import from ``core.py`` (avoids
a cycle) — only the public ``Decision``/``GovernanceContext`` types. Every
function returns ONLY masked, safe facts: action, mode, ``allowed``,
``denial_kind``, the matched rule's *name* (or an opaque id), the audit event
id, an injection annotation derived from the policy deny's reason string, and
the output rail's *name*. Never ``ctx.payload``, matched patterns, or raw
output — the same "name the field, never the value" discipline the injection
and output seams already use (see ``injection.py``, ``output.py``).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ..context import GovernanceContext
from ..protocols import Decision

# Mirrors the exact reason shape GuardedEngine.evaluate builds on an
# enforce-mode injection hit (injection.py) — already D6-safe (field NAME +
# AGT's type/threat classification labels, never payload content), so
# re-parsing it for span attrs adds no new leak. Shadow-mode injection hits
# never produce this Decision shape at all (see injection.py's shadow branch),
# so they are simply left un-annotated here — documented in observability.md.
#
# injection.py builds the field name via Python's `!r` (repr), whose quoting
# is value-dependent: a field name containing an apostrophe (and no double
# quote) flips repr to double quotes. The backreference below matches either
# delimiter, as long as both ends agree, so that case still parses instead of
# silently dropping the injection annotation.
_INJECTION_REASON_RE = re.compile(
    r"^prompt injection detected in field (?P<quote>['\"])(?P<field>.*)(?P=quote) "
    r"\(type=(?P<type>[^,]+), threat=(?P<threat>[^)]+)\)$"
)


def safe_trace_attrs_root(ctx: GovernanceContext, *, mode: str) -> dict[str, Any]:
    """Attributes for the root ``"govern"`` span: which action, under which mode."""
    return {"action": ctx.action, "mode": mode}


def _opaque_rule_id(rule_name: str) -> str:
    """A deterministic, non-reversible stand-in for a rule name (Slice 5 formalizes
    the operator-facing ``emit_rule_names=False`` knob this backs)."""
    return "rule:" + hashlib.sha256(rule_name.encode()).hexdigest()[:12]


def _injection_annotation(decision: Decision) -> dict[str, Any]:
    """Derive an injection fact from GuardedEngine's policy-deny reason string
    (no new hook on GuardedEngine — see injection.py). An unparsed or foreign
    reason string (any ordinary policy deny) is simply left un-annotated."""
    if decision.denial_kind != "policy" or not decision.reason:
        return {}
    match = _INJECTION_REASON_RE.match(decision.reason)
    if not match:
        return {}
    return {
        "injection": True,
        "injection.type": match.group("type"),
        "injection.threat": match.group("threat"),
        "injection.field": match.group("field"),
    }


def safe_trace_attrs_decision(
    decision: Decision, *, emit_rule_names: bool = True
) -> dict[str, Any]:
    """Attributes for the ``"policy"`` span and the root's post-evaluation
    annotation: the verdict, never the request that produced it."""
    attrs: dict[str, Any] = {
        "action": decision.action,
        "allowed": decision.allowed,
        "denial_kind": decision.denial_kind,
    }
    if decision.matched_rule is not None:
        attrs["rule"] = (
            decision.matched_rule if emit_rule_names else _opaque_rule_id(decision.matched_rule)
        )
    if decision.audit_event_id is not None:
        attrs["audit_event_id"] = decision.audit_event_id
    attrs.update(_injection_annotation(decision))
    return attrs


def safe_trace_attrs_output(
    *, event: str, rail: str | None, severity: str | None = None
) -> dict[str, Any]:
    """Attributes for the ``"output"`` span: the rail's *name* and outcome,
    never the screened value."""
    attrs: dict[str, Any] = {"event": event, "rail": rail or "none"}
    if severity is not None:
        attrs["severity"] = severity
    return attrs
