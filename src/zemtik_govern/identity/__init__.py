"""Identity seam — the v0.1 ``StaticIdentity`` stub and its ``AgentRef`` value.

The public seam is :class:`~zemtik_govern.protocols.IdentityProvider` (defined with
the policy and audit seams in :mod:`zemtik_govern.protocols`); ``StaticIdentity`` is
one implementation of it, ``AgentRef`` the value it returns.
"""

from __future__ import annotations

from .protocols import AgentRef
from .static_identity import StaticIdentity

__all__ = ["AgentRef", "StaticIdentity"]
