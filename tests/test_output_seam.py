"""Issue #39 — the output-governance seam: read-deny path through proxy().

After a governed tool runs, its return value is screened by the configured
output rails INSIDE proxy()'s effect path. A read-classified tool whose output
trips a rail has its output withheld and OutputGovernanceDenied raised — the
caller never sees the offending value. This is the spine the other output-rail
slices (write-deny + RedactedOutput, unwrap, shadow) build on.
"""

import asyncio
import logging
import time

import pytest

from zemtik_govern.config import GovernanceConfig, RailConfig
from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceNotConfigured, OutputGovernanceDenied
from zemtik_govern.identity import AgentRef
from zemtik_govern.output import (
    OutputExtractionError,
    RegexPIIClassifier,
    extract_text,
    resolve_io,
)
from zemtik_govern.protocols import Decision


class _Seams:
    """Allow-all seams with a capturing audit trail (records every entry)."""

    def __init__(self, *, decision=None):
        self._decision = decision or Decision(
            allowed=True, action="allow", matched_rule="r", reason="ok"
        )
        self.entries = []

    async def identify(self, subject):
        return AgentRef(did="did:mesh:" + subject)

    async def evaluate(self, ctx):
        return self._decision

    async def write(self, entry):
        self.entries.append(entry)
        return f"evt-{len(self.entries)}"


def _gov(*, seams=None, **kw):
    seams = seams or _Seams()
    return ZemtikGovern(identity=seams, policy=seams, audit=seams, **kw)


@pytest.mark.asyncio
async def test_read_tool_returning_pii_raises_output_denied():
    seen = []

    def tool():
        return "reach me at alice@example.com please"

    gov = _gov(
        output_classifiers=[RegexPIIClassifier()],
        tool_io_map={"db.read": "read"},
    )
    proxy = gov.proxy(tool, action="db.read", subject="agent-1")
    with pytest.raises(OutputGovernanceDenied):
        seen.append(await proxy())

    assert seen == []  # the caller never received the offending value


@pytest.mark.asyncio
async def test_denied_output_error_correlates_to_audit_entry():
    seams = _Seams()
    gov = _gov(
        seams=seams,
        output_classifiers=[RegexPIIClassifier()],
        tool_io_map={"db.read": "read"},
    )
    proxy = gov.proxy(lambda: "leak: bob@corp.example", action="db.read", subject="agent-1")
    with pytest.raises(OutputGovernanceDenied) as excinfo:
        await proxy()

    err = excinfo.value
    assert err.code == "output_denied"
    assert err.rail == "pii"
    out = seams.entries[-1]
    assert out.event_type == "output_denied_raised"
    assert err.audit_id == f"evt-{len(seams.entries)}"  # id of THAT output row
    # No-echo: the offending value is never in the message or the audit row.
    assert "bob@corp.example" not in str(err)
    assert "bob@corp.example" not in (out.policy_decision or "")


@pytest.mark.asyncio
async def test_allowed_read_output_passes_through_and_emits_output_allowed():
    seams = _Seams()
    gov = _gov(
        seams=seams,
        output_classifiers=[RegexPIIClassifier()],
        tool_io_map={"db.read": "read"},
    )
    proxy = gov.proxy(lambda: "nothing sensitive in here", action="db.read", subject="agent-1")
    result = await proxy()
    assert result == "nothing sensitive in here"
    assert seams.entries[-1].event_type == "output_allowed"


def test_tool_io_map_defaults_unmapped_action_to_write():
    m = {"db.read": "read"}
    assert resolve_io(m, "db.read") == "read"
    assert resolve_io(m, "send.email") == "write"  # unmapped -> fail-closed write
    assert resolve_io(None, "anything") == "write"  # no map at all -> write
    assert resolve_io({}, "anything") == "write"


@pytest.mark.asyncio
async def test_write_classified_pii_output_fails_closed_in_this_slice():
    """Write tool returning PII → returns RedactedOutput (never raises); raw value
    never leaks to caller; HIGH-severity output_denied_redacted audit row emitted,
    correlated by audit_id. (#40)"""
    seams = _Seams()
    gov = _gov(seams=seams, output_classifiers=[RegexPIIClassifier()])  # no io map => write
    proxy = gov.proxy(lambda: "card holder carol@example.org", action="send.email", subject="a")
    result = await proxy()

    from zemtik_govern.output import RedactedOutput
    assert isinstance(result, RedactedOutput)
    # raw PII never reaches the caller
    assert "carol@example.org" not in str(result)
    # HIGH-severity audit row emitted
    out = seams.entries[-1]
    assert out.event_type == "output_denied_redacted"
    assert out.outcome == "output_denied"
    assert getattr(out, "severity", None) == "HIGH"
    # correlated by audit_id
    assert result.audit_id == f"evt-{len(seams.entries)}"


@pytest.mark.asyncio
async def test_unscreenable_return_type_is_denied_fail_closed():
    """Deny-by-default conformance (ADR 001 pattern): a return type outside
    str/bytes/JSON-native cannot be projected to text, so it is denied — never
    passed through unscanned."""

    class Opaque:  # not str/bytes/JSON-native
        pass

    gov = _gov(output_classifiers=[RegexPIIClassifier()], tool_io_map={"db.read": "read"})
    proxy = gov.proxy(lambda: Opaque(), action="db.read", subject="a")
    with pytest.raises(OutputGovernanceDenied):
        await proxy()


@pytest.mark.asyncio
async def test_generator_return_is_denied():
    """A generator/streaming return bypasses whole-value screening (chunked
    screening is a follow-up), so v1 denies it rather than leave a fail-open hole."""

    def streaming_tool():
        def gen():
            yield "tok"

        return gen()

    gov = _gov(output_classifiers=[RegexPIIClassifier()], tool_io_map={"db.read": "read"})
    proxy = gov.proxy(streaming_tool, action="db.read", subject="a")
    with pytest.raises(OutputGovernanceDenied):
        await proxy()


@pytest.mark.asyncio
async def test_redos_adversarial_256kb_output_screens_in_linear_time():
    """The PII patterns are anchored/linear-time (no nested quantifiers), so a
    crafted 256KB output cannot trigger catastrophic backtracking. Screen a
    pathological at-cap input and assert it completes well under a wall bound."""
    # An adversarial run of local-part chars with no valid TLD — maximises the
    # work a backtracking engine would do, stays at the screenable cap.
    adversarial = ("a" * 1000 + "@") * 250 + "a" * 100  # ~250KB, under cap, no TLD

    gov = _gov(output_classifiers=[RegexPIIClassifier()], tool_io_map={"db.read": "read"})
    proxy = gov.proxy(lambda: adversarial, action="db.read", subject="a")

    start = time.perf_counter()
    result = await proxy()  # no real PII match -> passes through
    elapsed = time.perf_counter() - start

    assert result == adversarial
    assert elapsed < 0.5  # linear scan; a ReDoS would blow well past this


@pytest.mark.asyncio
async def test_direct_govern_is_input_only_and_unscreened():
    """Premise 2: a DIRECT govern() caller gets input-only governance and NO output
    rail. Wiring output classifiers must not change govern()'s behavior — only
    proxy() screens output."""
    seams = _Seams()
    gov = _gov(
        seams=seams,
        output_classifiers=[RegexPIIClassifier()],
        tool_io_map={"db.read": "read"},
    )
    ctx = GovernanceContext(action="db.read", subject="a", payload={"q": "x"})
    decision = await gov.govern(ctx)

    assert decision.allowed
    # No output_* event is emitted on the direct path — output is never screened.
    assert all(not e.event_type.startswith("output_") for e in seams.entries)


# --- Config: output-seam enable flag, tool_io_map, per-rail threshold/mode ------


def _base_cfg(**extra):
    """A minimal valid strict config (one rule + memory sink) plus *extra*."""
    data = {
        "mode": "strict",
        "audit_sink": "memory",
        "rules": [
            {
                "name": "r",
                "condition": {"field": "action", "operator": "eq", "value": "db.read"},
                "action": "allow",
            }
        ],
    }
    data.update(extra)
    return GovernanceConfig.from_mapping(data)


def test_output_seam_config_defaults_are_off_and_empty():
    cfg = _base_cfg()
    assert cfg.output_screening is False
    assert cfg.tool_io_map == {}
    assert cfg.rails == ()


def test_output_seam_config_parses_enable_io_map_and_rails():
    cfg = _base_cfg(
        output_screening=True,
        tool_io_map={"db.read": "read", "send.email": "write"},
        rails={"pii": {"threshold": 0.5, "mode": "shadow"}},
    )
    assert cfg.output_screening is True
    assert cfg.tool_io_map == {"db.read": "read", "send.email": "write"}
    assert cfg.rails == (RailConfig(name="pii", threshold=0.5, mode="shadow"),)


def test_rail_config_defaults_threshold_and_enforce_mode():
    cfg = _base_cfg(output_screening=True, rails={"pii": {}})
    assert cfg.rails == (RailConfig(name="pii", threshold=0.0, mode="enforce"),)


def test_invalid_io_classification_is_rejected_at_startup():
    with pytest.raises(GovernanceNotConfigured, match="tool_io_map"):
        _base_cfg(tool_io_map={"db.read": "sideways"})


def test_invalid_rail_mode_is_rejected_at_startup():
    with pytest.raises(GovernanceNotConfigured, match="mode"):
        _base_cfg(rails={"pii": {"mode": "loud"}})


def test_out_of_range_rail_threshold_is_rejected_at_startup():
    with pytest.raises(GovernanceNotConfigured, match="threshold"):
        _base_cfg(rails={"pii": {"threshold": 1.5}})


# --- Registry wiring: from_config builds the seam end to end --------------------


@pytest.mark.asyncio
async def test_from_config_proxy_screens_read_output_end_to_end():
    """The full stack: a config with output_screening + a pii rail + an io map
    builds a governor whose proxy() screens a read tool's output and denies PII."""
    from zemtik_govern._agt import AGTBoundary
    from zemtik_govern.registry import GovernanceRegistry

    config = GovernanceConfig.from_mapping(
        {
            "mode": "strict",
            "audit_sink": "memory",
            "rules": [
                {
                    "name": "allow-db-read",
                    "condition": {"field": "action", "operator": "eq", "value": "db.read"},
                    "action": "allow",
                }
            ],
            "output_screening": True,
            "tool_io_map": {"db.read": "read"},
            "rails": {"pii": {"threshold": 0.0, "mode": "enforce"}},
        }
    )
    gov = GovernanceRegistry.from_config(config, AGTBoundary()).build()
    proxy = gov.proxy(lambda: "user dave@example.net", action="db.read", subject="agent-1")
    with pytest.raises(OutputGovernanceDenied):
        await proxy()


def test_from_config_unknown_rail_is_rejected_at_startup():
    """A configured rail C0 doesn't know how to build is a startup error, not a
    silently-skipped rail (fail-closed wiring)."""
    from zemtik_govern._agt import AGTBoundary
    from zemtik_govern.registry import GovernanceRegistry

    config = _base_cfg(output_screening=True, rails={"jailbreak": {"mode": "enforce"}})
    with pytest.raises(GovernanceNotConfigured, match="jailbreak"):
        GovernanceRegistry.from_config(config, AGTBoundary()).build()


# --- Effect-cache placement: screen runs INSIDE the effect, once ---------------


def _keyed_factory(key, action="db.read"):
    def factory(*args, **kwargs):
        return GovernanceContext(action=action, subject="agent-1", idempotency_key=key, payload={})

    return factory


@pytest.mark.asyncio
async def test_keyed_replay_returns_cached_screened_value_and_screens_once():
    """The output screen runs inside proxy()'s effect path, so a keyed replay
    returns the already-screened cached value WITHOUT re-running the tool or
    re-screening — exactly one output_allowed event for two calls."""
    seams = _Seams()
    runs = []

    def tool():
        runs.append(True)
        return "clean result"

    gov = _gov(
        seams=seams,
        output_classifiers=[RegexPIIClassifier()],
        tool_io_map={"db.read": "read"},
    )
    proxy = gov.proxy(
        tool, action="db.read", subject="agent-1", context_factory=_keyed_factory("k1")
    )
    first = await proxy()
    second = await proxy()

    assert first == second == "clean result"
    assert runs == [True]  # tool ran once
    output_events = [e for e in seams.entries if e.event_type == "output_allowed"]
    assert len(output_events) == 1  # screened once, not on replay


# --- Rail coverage + extraction hardening (post-review hardening) --------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "leak",
    [
        "ssn on file 123-45-6789 thanks",
        "card 4111 1111 1111 1111 charged",
        "call me at (415) 555-0132 today",
        "email me bob@corp.example please",
    ],
)
async def test_pii_rail_denies_non_email_pii(leak):
    """The rail is named `pii`, not `email`: SSNs, payment-card shapes, and phone
    numbers must deny too, not just email."""
    gov = _gov(output_classifiers=[RegexPIIClassifier()], tool_io_map={"db.read": "read"})
    proxy = gov.proxy(lambda: leak, action="db.read", subject="a")
    with pytest.raises(OutputGovernanceDenied):
        await proxy()


def test_extract_text_denies_wide_json_before_projecting():
    """A wide (not deep) JSON return must be denied by the size estimate BEFORE
    json.dumps materialises a multi-MB string — the projection must never be the
    DoS lever. The estimate fires without building the string."""
    huge = list(range(2_000_000))  # would project to ~15MB
    with pytest.raises(OutputExtractionError, match="maximum screenable size"):
        extract_text(huge)


@pytest.mark.asyncio
async def test_nfkc_normalisation_catches_fullwidth_email():
    """A compatibility variant (fullwidth ＠ U+FF20) must fold to canonical form
    before screening, so Unicode-obfuscated PII does not slip past ASCII patterns."""
    gov = _gov(output_classifiers=[RegexPIIClassifier()], tool_io_map={"db.read": "read"})
    proxy = gov.proxy(lambda: "reach me at alice＠example.com", action="db.read", subject="a")
    with pytest.raises(OutputGovernanceDenied):
        await proxy()


@pytest.mark.asyncio
async def test_async_generator_return_is_denied():
    """An async-generator return is not awaitable and bypasses whole-value
    screening; it must fail closed like a sync generator."""

    def tool():
        async def agen():
            yield "tok"

        return agen()

    gov = _gov(output_classifiers=[RegexPIIClassifier()], tool_io_map={"db.read": "read"})
    proxy = gov.proxy(tool, action="db.read", subject="a")
    with pytest.raises(OutputGovernanceDenied):
        await proxy()


# --- DID attribution + shadow observe-only (post-review hardening) -------------


@pytest.mark.asyncio
async def test_output_audit_row_attributed_to_resolved_did():
    """Output audit rows carry the SAME identity-resolved DID as the input row,
    not the reserved unidentified DID — output allows/denies are attributable."""
    seams = _Seams()
    gov = _gov(
        seams=seams,
        output_classifiers=[RegexPIIClassifier()],
        tool_io_map={"db.read": "read"},
    )
    proxy = gov.proxy(lambda: "clean text", action="db.read", subject="agent-1")
    await proxy()
    out = seams.entries[-1]
    assert out.event_type == "output_allowed"
    assert out.agent_did == "did:mesh:agent-1"


@pytest.mark.asyncio
async def test_global_shadow_observes_output_deny_without_raising():
    """Under global mode=shadow the output seam observes a would-deny and returns
    the value (mirrors the input-side _enforce contract) — a whole-governor shadow
    rollout never hard-blocks on output rails."""
    seams = _Seams()
    gov = _gov(
        seams=seams,
        mode="shadow",
        output_classifiers=[RegexPIIClassifier()],
        tool_io_map={"db.read": "read"},
    )
    proxy = gov.proxy(lambda: "pii alice@example.com", action="db.read", subject="a")
    result = await proxy()  # observed, not raised
    assert result == "pii alice@example.com"
    assert seams.entries[-1].event_type == "output_would_deny"


@pytest.mark.asyncio
async def test_per_rail_shadow_observes_without_raising():
    """A single rail set to mode=shadow is observe-only even when the governor is
    enforcing — the observe-then-enforce upgrade path scoped to one rail."""
    seams = _Seams()
    gov = _gov(
        seams=seams,
        output_classifiers=[RegexPIIClassifier(mode="shadow")],
        tool_io_map={"db.read": "read"},
    )
    proxy = gov.proxy(lambda: "pii bob@corp.example", action="db.read", subject="a")
    result = await proxy()
    assert result == "pii bob@corp.example"
    assert seams.entries[-1].event_type == "output_would_deny"


# --- #40: RedactedOutput sentinel + HIGH-severity audit for write tools ---------


@pytest.mark.asyncio
async def test_redacted_output_frozen_and_isinstance_checkable():
    """RedactedOutput is frozen (immutable) and isinstance-checkable."""
    from zemtik_govern.output import RedactedOutput
    r = RedactedOutput(audit_id="evt-1")
    assert isinstance(r, RedactedOutput)
    with pytest.raises((AttributeError, TypeError)):
        r.audit_id = "mutated"


@pytest.mark.asyncio
async def test_redacted_output_spare_methods_do_not_raise():
    """str/repr/format/json.dumps(default=str) all return the redaction marker."""
    import json
    from zemtik_govern.output import RedactedOutput
    r = RedactedOutput(audit_id="evt-42")
    marker = "<output redacted: audit_id=evt-42>"
    assert str(r) == marker
    assert repr(r) == marker
    assert format(r) == marker
    assert json.dumps(r, default=str) == json.dumps(marker)


@pytest.mark.asyncio
async def test_redacted_output_poison_methods_raise_typed_error():
    """getattr/getitem/iter/unpack on RedactedOutput raise RedactedOutputAccessError."""
    from zemtik_govern.errors import RedactedOutputAccessError
    from zemtik_govern.output import RedactedOutput
    r = RedactedOutput(audit_id="evt-7")
    with pytest.raises(RedactedOutputAccessError) as exc:
        _ = r.some_attribute
    assert exc.value.audit_id == "evt-7"

    with pytest.raises(RedactedOutputAccessError):
        _ = r["key"]

    with pytest.raises(RedactedOutputAccessError):
        for _ in r:
            pass


@pytest.mark.asyncio
async def test_redacted_output_equality_based_on_type_only():
    """Two RedactedOutputs with differing audit_ids compare equal."""
    from zemtik_govern.output import RedactedOutput
    r1 = RedactedOutput(audit_id="evt-1")
    r2 = RedactedOutput(audit_id="evt-2")
    assert r1 == r2
    assert hash(r1) == hash(r2)


@pytest.mark.asyncio
async def test_keyed_replay_returns_redacted_value_without_rerunning():
    """Keyed replay on a write tool that returned RedactedOutput: returns the
    cached RedactedOutput without re-running the tool or re-screening."""
    from zemtik_govern.output import RedactedOutput
    seams = _Seams()
    runs = []

    def tool():
        runs.append(True)
        return "card holder carol@example.org"

    gov = _gov(
        seams=seams,
        output_classifiers=[RegexPIIClassifier()],
    )  # no io map => write
    proxy = gov.proxy(
        tool, action="send.email", subject="agent-1", context_factory=_keyed_factory("k2", action="send.email")
    )
    first = await proxy()
    second = await proxy()

    assert isinstance(first, RedactedOutput)
    assert first == second  # same type-equality
    assert runs == [True]  # tool ran once
    # Only one output_denied_redacted event (not re-screened on replay)
    redacted_events = [e for e in seams.entries if e.event_type == "output_denied_redacted"]
    assert len(redacted_events) == 1


@pytest.mark.asyncio
async def test_rail_fault_on_write_tool_returns_redacted_output():
    """If classifier.screen() raises on a WRITE tool, return RedactedOutput +
    HIGH audit with reason rail_fault. Do NOT raise."""
    from zemtik_govern.output import RedactedOutput

    class FaultingClassifier:
        name = "faulty"
        mode = "enforce"

        async def screen(self, text, ctx):
            raise RuntimeError("rail exploded")

    seams = _Seams()
    gov = _gov(seams=seams, output_classifiers=[FaultingClassifier()])
    # no io map => write
    proxy = gov.proxy(lambda: "some output", action="send.email", subject="a")
    result = await proxy()

    assert isinstance(result, RedactedOutput)
    out = seams.entries[-1]
    assert out.event_type == "output_denied_redacted"
    assert getattr(out, "severity", None) == "HIGH"
    assert "rail_fault" in (out.policy_decision or "")


@pytest.mark.asyncio
async def test_rail_fault_on_read_tool_raises_fail_closed():
    """If classifier.screen() raises on a READ tool, keep failing closed by raising."""
    from zemtik_govern.errors import OutputGovernanceDenied

    class FaultingClassifier:
        name = "faulty"
        mode = "enforce"

        async def screen(self, text, ctx):
            raise RuntimeError("rail exploded")

    gov = _gov(output_classifiers=[FaultingClassifier()], tool_io_map={"db.read": "read"})
    proxy = gov.proxy(lambda: "some output", action="db.read", subject="a")
    with pytest.raises(OutputGovernanceDenied) as exc:
        await proxy()
    assert exc.value.rail == "rail_fault"


# --- Issue #42: Output-seam discoverability: startup banner + warn-once ----------


def test_output_seam_enabled_logs_screening_on_at_construction(caplog):
    """Building a governor with output_classifiers wired logs 'output screening: ON'
    containing the rail name(s) and mode so an operator sees the active rails at
    startup (D4/D7 discoverability pattern)."""
    with caplog.at_level(logging.INFO, logger="zemtik_govern"):
        gov = _gov(
            output_classifiers=[RegexPIIClassifier()],
            tool_io_map={"db.read": "read"},
        )
    assert "output screening: ON" in caplog.text
    assert "pii" in caplog.text  # rail name surfaced


def test_output_seam_banner_surfaces_io_map_and_fail_closed_default(caplog):
    """The construction banner announces both:
    1. The classified tool_io_map so operators know which actions are explicitly
       declared (e.g. io_map={db.read: read}).
    2. That every unmapped action defaults to 'write' (fail-closed) — so the
       operator sees the security posture, not just the happy-path listing."""
    with caplog.at_level(logging.INFO, logger="zemtik_govern"):
        gov = _gov(
            output_classifiers=[RegexPIIClassifier()],
            tool_io_map={"db.read": "read"},
        )
    assert "io_map=" in caplog.text
    assert "unmapped" in caplog.text.lower() or "default" in caplog.text.lower()


@pytest.mark.asyncio
async def test_unmapped_action_warns_once_then_silent(caplog):
    """First call to an unmapped action emits exactly ONE WARNING naming the action
    and the fail-closed default; a second call to the SAME action emits NO further
    warning. A DIFFERENT unmapped action warns on its own first call."""
    gov = _gov(
        output_classifiers=[RegexPIIClassifier()],
        tool_io_map={"db.read": "read"},
    )
    proxy_email = gov.proxy(lambda: "clean output", action="send.email", subject="a")
    proxy_sms = gov.proxy(lambda: "clean output", action="send.sms", subject="a")

    with caplog.at_level(logging.WARNING, logger="zemtik_govern"):
        await proxy_email()  # first call -> warns about send.email
        await proxy_email()  # second call -> NO further warn for send.email
        await proxy_sms()    # first call for different action -> warns about send.sms

    email_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING
        and "send.email" in r.message
        and "unmapped" in r.message.lower()
    ]
    sms_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING
        and "send.sms" in r.message
        and "unmapped" in r.message.lower()
    ]
    assert len(email_warnings) == 1, f"expected 1 send.email warning, got {len(email_warnings)}"
    assert len(sms_warnings) == 1, f"expected 1 send.sms warning, got {len(sms_warnings)}"


@pytest.mark.asyncio
async def test_output_seam_disabled_no_banner_and_no_warn(caplog):
    """When output_classifiers is empty (seam disabled):
    - No 'output screening' line at construction.
    - No unmapped-action warning at call time even for unmapped actions."""
    with caplog.at_level(logging.INFO, logger="zemtik_govern"):
        gov = _gov()  # no output_classifiers

    assert "output screening" not in caplog.text

    proxy = gov.proxy(lambda: "clean output", action="send.email", subject="a")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="zemtik_govern"):
        await proxy()

    assert "unmapped" not in caplog.text.lower()
