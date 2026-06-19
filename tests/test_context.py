"""S2 — the immutable governance context (E1).

The context is frozen and deep-frozen so the bytes the policy evaluated are
provably the bytes the audit log records — closing the decision→audit TOCTOU.
"""

import dataclasses

import pytest

from zemtik_govern.context import GovernanceContext


def test_context_top_level_is_frozen():
    """Rebinding a field on the context raises — it is a value, not a record."""
    ctx = GovernanceContext(action="tool.run", subject="agent-1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.action = "other"


def test_context_deep_freezes_nested_payload():
    """A nested dict inside payload cannot be mutated after construction —
    no caller can swap the bytes between the policy decision and the audit write."""
    ctx = GovernanceContext(
        action="transfer", subject="agent-1", payload={"amount": {"value": 100}}
    )
    with pytest.raises(TypeError):
        ctx.payload["amount"]["value"] = 999


def test_context_freezes_lists_into_tuples():
    """Sequences in payload become tuples — no in-place append/replace."""
    ctx = GovernanceContext(
        action="batch", subject="agent-1", payload={"items": [1, 2, 3]}
    )
    assert ctx.payload["items"] == (1, 2, 3)
    with pytest.raises(AttributeError):
        ctx.payload["items"].append(4)


def test_to_dict_is_plain_mutable_json_serializable():
    """AGT's evaluate() and agentmesh serialization need plain Python — to_dict
    thaws the frozen views back to dict/list, with action/subject at top level."""
    import json

    ctx = GovernanceContext(
        action="transfer",
        subject="agent-1",
        payload={"amount": {"value": 100}, "items": [1, 2]},
        idempotency_key="k1",
    )
    d = ctx.to_dict()
    assert d["action"] == "transfer"
    assert d["subject"] == "agent-1"
    assert d["idempotency_key"] == "k1"
    assert isinstance(d["payload"], dict)
    assert d["payload"]["items"] == [1, 2]  # tuple thawed back to list
    # mutating the thawed copy must not touch the frozen original
    d["payload"]["amount"]["value"] = 0
    assert ctx.payload["amount"]["value"] == 100
    json.dumps(d)  # must be JSON-serializable
