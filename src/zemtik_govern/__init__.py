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
from .context import GovernanceContext
from .core import ZemtikGovern
from .errors import GovernanceDenied, GovernanceError, GovernanceNotConfigured
from .identity import StaticIdentity
from .policy import AgentOsPolicy
from .protocols import (
    AuditEntry,
    AuditSink,
    Decision,
    IdentityProvider,
    PolicyEngine,
)

__all__ = [
    "__version__",
    "AGTBoundary",
    "AGTVersionError",
    "AgentMeshAudit",
    "AgentOsPolicy",
    "AuditEntry",
    "AuditSink",
    "Decision",
    "GovernanceContext",
    "GovernanceDenied",
    "GovernanceError",
    "GovernanceNotConfigured",
    "IdentityProvider",
    "PolicyEngine",
    "StaticIdentity",
    "ZemtikGovern",
]
