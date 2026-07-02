"""Slice 2 — core façade instrumentation, Red→Green steps 1–8.

The ``ZemtikGovern`` core emits masked spans through the ``Tracer`` seam at a
handful of points: a root ``"govern"`` span, nested ``"identity"``/``"policy"``
children, and (proxy-only) an ``"output"`` child. Every attribute is assembled
through ``observability/masking.py`` — no raw payload/output ever reaches a
span. This file drives the happy-path shape (1-5) and the no-echo masking
invariant (6-8); fail-open + budget-isolation + replay/conflict live in
``test_core_tracing_failopen.py``.
"""

from __future__ import annotations

import json

import pytest

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.identity import AgentRef
from zemtik_govern.injection import GuardedEngine
from zemtik_govern.output import RegexPIIClassifier
from zemtik_govern.protocols import Decision

from ._fakes import RecordingTracer

_ALLOW = Decision(allowed=True, action="allow", matched_rule="r", reason="ok")
_DENY = Decision(
    allowed=False,
    action="deny",
    matched_rule=None,
    reason="deny-by-default",
    denial_kind="policy",
)


class _Seams:
    """Satisfies identity/policy/audit; records audit entries with a literal,
    independently-derivable event-id sentinel (``evt-1``, ``evt-2``, ...) —
    never recomputed by the test, just counted."""

    def __init__(self, *, decision: Decision):
        self._decision = decision
        self.entries: list = []

    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)

    async def evaluate(self, ctx):
        return self._decision

    async def write(self, entry):
        self.entries.append(entry)
        return f"evt-{len(self.entries)}"


class _FakeInjectionClassifier:
    """Deterministic injection trigger for test 8 (mirrors
    tests/test_injection_guard.py::_FakeClassifier)."""

    def __init__(self, *, trigger_field: str):
        self._trigger = trigger_field

    async def screen(self, ctx):
        from zemtik_govern.injection import InjectionVerdict

        if self._trigger in ctx.payload:
            return InjectionVerdict(
                is_injection=True,
                field=self._trigger,
                injection_type="direct_override",
                threat_level="high",
            )
        return InjectionVerdict(is_injection=False, reason="clean")


def _ctx(payload=None):
    return GovernanceContext(action="tool.run", subject="agent-1", payload=payload or {})


def _no_raw_substring(root, needle: str) -> bool:
    """No attribute anywhere in the recorded span tree contains ``needle`` —
    a substring no-echo check, mirroring test_injection_guard.py's
    ``"SUPERSECRET" not in decision.reason`` pattern, applied to a whole tree."""
    blob = json.dumps({"attrs": root.attrs, "children": [_tree(c) for c in root.children]})
    return needle not in blob


def _tree(span):
    return {"name": span.name, "attrs": span.attrs, "children": [_tree(c) for c in span.children]}


@pytest.mark.asyncio
async def test_govern_call_opens_one_root_span_named_govern():
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    await gov.govern(_ctx())
    assert len(tracer.roots) == 1
    assert tracer.roots[0].name == "govern"


@pytest.mark.asyncio
async def test_root_span_first_child_is_identity():
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    await gov.govern(_ctx())
    assert tracer.roots[0].children[0].name == "identity"


@pytest.mark.asyncio
async def test_root_span_second_child_is_policy_with_allowed_attr():
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    await gov.govern(_ctx())
    policy_span = tracer.roots[0].children[1]
    assert policy_span.name == "policy"
    assert policy_span.attrs["allowed"] is True


@pytest.mark.asyncio
async def test_policy_span_carries_denial_kind_on_deny():
    tracer = RecordingTracer()
    seams = _Seams(decision=_DENY)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer, mode="shadow")
    await gov.govern(_ctx())
    policy_span = tracer.roots[0].children[1]
    assert policy_span.attrs["denial_kind"] == "policy"


@pytest.mark.asyncio
async def test_policy_span_annotated_with_the_real_audit_event_id():
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    await gov.govern(_ctx())
    policy_span = tracer.roots[0].children[1]
    assert policy_span.name == "policy"
    assert policy_span.attrs["audit_event_id"] == "evt-1"


@pytest.mark.asyncio
async def test_proxy_call_emits_an_output_span_with_rail_name_only():
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(
        identity=seams,
        policy=seams,
        audit=seams,
        tracer=tracer,
        output_classifiers=[RegexPIIClassifier()],
        tool_io_map={"tool.run": "write"},
    )
    proxy = gov.proxy(lambda: "a clean, non-PII return value", action="tool.run", subject="agent-1")
    await proxy()
    output_span = tracer.roots[0].children[-1]
    assert output_span.name == "output"
    assert output_span.attrs == {"event": "allowed", "rail": "none"}


@pytest.mark.asyncio
async def test_masking_no_raw_payload_substring_on_allow():
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer)
    await gov.govern(_ctx(payload={"ssn": "SENTINEL-RAW-99999"}))
    assert _no_raw_substring(tracer.roots[0], "SENTINEL-RAW-99999")


@pytest.mark.asyncio
async def test_masking_no_raw_payload_substring_on_deny():
    tracer = RecordingTracer()
    seams = _Seams(decision=_DENY)
    gov = ZemtikGovern(identity=seams, policy=seams, audit=seams, tracer=tracer, mode="shadow")
    await gov.govern(_ctx(payload={"ssn": "SENTINEL-RAW-99999"}))
    assert _no_raw_substring(tracer.roots[0], "SENTINEL-RAW-99999")


@pytest.mark.asyncio
async def test_masking_no_raw_payload_substring_on_injection_hit_and_injection_annotated():
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)  # inner engine would allow; injection short-circuits it
    classifier = _FakeInjectionClassifier(trigger_field="evil")
    gov = ZemtikGovern(
        identity=seams,
        policy=GuardedEngine(seams, classifier),
        audit=seams,
        tracer=tracer,
        mode="shadow",
    )
    await gov.govern(_ctx(payload={"evil": "SENTINEL-RAW-99999"}))
    root = tracer.roots[0]
    assert _no_raw_substring(root, "SENTINEL-RAW-99999")
    policy_span = root.children[1]
    assert policy_span.attrs["injection"] is True
    assert policy_span.attrs["injection.type"] == "direct_override"
    assert policy_span.attrs["injection.threat"] == "high"


@pytest.mark.asyncio
async def test_injection_annotation_survives_a_field_name_containing_an_apostrophe():
    """injection.py builds the deny reason via `{field!r}`, and Python's repr
    switches to double quotes when the field name itself contains an apostrophe
    (and no double quote) — the injection-annotation regex must match either
    delimiter, or the annotation silently disappears for exactly these field
    names."""
    tracer = RecordingTracer()
    seams = _Seams(decision=_ALLOW)
    classifier = _FakeInjectionClassifier(trigger_field="user's_note")
    gov = ZemtikGovern(
        identity=seams,
        policy=GuardedEngine(seams, classifier),
        audit=seams,
        tracer=tracer,
        mode="shadow",
    )
    await gov.govern(_ctx(payload={"user's_note": "irrelevant"}))
    policy_span = tracer.roots[0].children[1]
    assert policy_span.attrs["injection"] is True
    assert policy_span.attrs["injection.field"] == "user's_note"
