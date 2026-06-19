"""Identity — the v0.1 ``StaticIdentity`` stub.

Resolves a subject to a stable :class:`AgentRef` carrying the
``did:mesh:<subject>`` string that audit entries stamp, minted through the AGT
boundary. v0.1 ships static identity (no Ed25519/``did:web`` yet); a real provider
plugs in behind the same :class:`~zemtik_govern.protocols.IdentityProvider` seam,
returning the same :class:`AgentRef` value, with no change to the core.

This replaces a faked random per-call identity (``secrets.token_hex(32)``): the
resolved DID is deterministic in the subject, so audit attribution is stable.
"""

from __future__ import annotations

from .._agt import AGTBoundary
from .protocols import AgentRef


class StaticIdentity:
    """Maps a subject straight to its minted DID. Cannot fail in v0.1.

    Constructed with the :class:`AGTBoundary` so ``did:mesh`` minting stays behind
    the single sanctioned AGT door — ``StaticIdentity`` never imports AGT itself.
    """

    def __init__(self, boundary: AGTBoundary) -> None:
        self._boundary = boundary

    async def identify(self, subject: str) -> AgentRef:
        return AgentRef(did=self._boundary.mint_did(subject))
