"""zemtik-govern — security-first modular wrapper around Microsoft AGT.

Public surface (v0.1): wire the three seams and run one ``govern()`` call.

    from zemtik_govern import (
        AGTBoundary, ZemtikGovern, GovernanceContext,
        StaticIdentity, AgentOsPolicy, AgentMeshAudit,
    )
"""

__version__ = "0.1.0.dev0"

from ._agt import AGTBoundary, AGTVersionError
from .audit import AgentMeshAudit
from .config import GovernanceConfig
from .context import GovernanceContext
from .core import Killswitch, ZemtikGovern
from .errors import GovernanceDenied, GovernanceError, GovernanceNotConfigured
from .identity import AgentRef, StaticIdentity
from .policy import AgentOsPolicy
from .protocols import (
    AuditEntry,
    AuditSink,
    Decision,
    IdentityProvider,
    PolicyEngine,
)
from .registry import GovernanceRegistry

__all__ = [
    "__version__",
    "AGTBoundary",
    "AGTVersionError",
    "AgentMeshAudit",
    "AgentRef",
    "AgentOsPolicy",
    "AuditEntry",
    "AuditSink",
    "Decision",
    "GovernanceConfig",
    "GovernanceContext",
    "GovernanceDenied",
    "GovernanceError",
    "GovernanceNotConfigured",
    "GovernanceRegistry",
    "IdentityProvider",
    "Killswitch",
    "PolicyEngine",
    "StaticIdentity",
    "ZemtikGovern",
]
