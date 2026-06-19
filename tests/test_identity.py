"""S6 — identity: the v0.1 ``StaticIdentity`` stub resolves a subject to a stable
``AgentRef`` (``did:mesh:<subject>``), replacing a faked random per-call identity
(``secrets.token_hex(32)``). The :class:`IdentityProvider` Protocol is the only
public seam; ``StaticIdentity`` is an impl detail.
"""

import pytest

from zemtik_govern._agt import AGTBoundary
from zemtik_govern.identity import AgentRef, StaticIdentity
from zemtik_govern.protocols import IdentityProvider


@pytest.mark.asyncio
async def test_static_identity_resolves_subject_to_a_stable_agent_ref():
    """identify() returns an AgentRef carrying the minted did:mesh DID — a stable,
    deterministic identity, never a random token_hex."""
    boundary = AGTBoundary()
    identity = StaticIdentity(boundary)

    ref = await identity.identify("agent-1")

    assert isinstance(ref, AgentRef)
    assert ref.did == "did:mesh:agent-1"
    # deterministic: the same subject resolves to the same DID every time
    again = await identity.identify("agent-1")
    assert again.did == ref.did


def test_static_identity_satisfies_the_identity_provider_seam():
    """StaticIdentity is reached only through the IdentityProvider Protocol — it is
    an impl detail, structurally interchangeable with a future Ed25519 provider."""
    assert isinstance(StaticIdentity(AGTBoundary()), IdentityProvider)
