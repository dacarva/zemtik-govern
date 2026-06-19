"""The identity seam's value type.

:class:`AgentRef` is the resolved identity an :class:`IdentityProvider` hands back
— a typed value, not a bare string, so the identity that policy keys on and audit
stamps is one explainable object that a richer provider (Ed25519, ``did:web``,
IATP) can extend without changing the seam.

The :class:`~zemtik_govern.protocols.IdentityProvider` Protocol itself lives in the
top-level :mod:`zemtik_govern.protocols` alongside the policy and audit seams (the
three are one public contract); it returns this :class:`AgentRef`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentRef:
    """A resolved agent identity. ``did`` is the stable ``did:mesh:<subject>``
    string that audit entries stamp; v0.1 carries only the DID, but the value
    object is the seam where issuer / key / claims attach in v0.2."""

    did: str
