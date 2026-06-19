"""Identity — the v0.1 ``StaticIdentity`` stub.

Resolves a subject to the ``did:mesh:<subject>`` string that audit entries stamp,
via the AGT boundary. v0.1 ships static identity (no Ed25519/``did:web`` yet); a
real provider plugs in behind the same :class:`~zemtik_govern.protocols.IdentityProvider`
seam with no change to the core.
"""

from __future__ import annotations

from ._agt import AGTBoundary


class StaticIdentity:
    """Maps a subject straight to its minted DID. Cannot fail in v0.1."""

    def __init__(self, boundary: AGTBoundary) -> None:
        self._boundary = boundary

    async def identify(self, subject: str) -> str:
        return self._boundary.mint_did(subject)
