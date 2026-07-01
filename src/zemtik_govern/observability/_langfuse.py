"""The single sanctioned boundary to the Langfuse SDK.

No other module in ``zemtik_govern`` may import ``langfuse`` directly. Mirrors
``_agt.py``'s shape deliberately: a lazy import (importing this module costs
nothing until a boundary is actually built), a version-compatibility
assertion at construction, and an isolated ``TracerProvider`` so wiring
telemetry never mutates process-global OpenTelemetry state.

Major-version (not exact-pin) compatibility: the ``[langfuse]`` extra is
range-pinned (``langfuse>=4.12,<5``) rather than exact-pinned like the
load-bearing AGT distributions, so this boundary asserts ``major == 4``
instead of reusing ``_agt.py``'s exact-match ``assert_pins``.
"""

from __future__ import annotations

import importlib.metadata as _metadata
from typing import TYPE_CHECKING, Any

from ..errors import GovernanceNotConfigured

if TYPE_CHECKING:
    from langfuse import Langfuse
    from langfuse.types import MaskFunction

LANGFUSE_EXTRA = "langfuse"
SUPPORTED_MAJOR = 4


class LangfuseVersionError(RuntimeError):
    """Raised when the installed ``langfuse`` distribution is not
    major-version compatible with this boundary."""


def _installed_version(dist: str = "langfuse") -> str:
    """Read the authoritative installed distribution version.

    A thin, monkeypatchable seam (mirrors ``_agt.py``'s reliance on
    ``importlib.metadata``) so tests can simulate "SDK absent" or "wrong
    major version" without actually uninstalling/reinstalling the package.
    """
    return _metadata.version(dist)


def _default_mask(*, data: Any, **_kwargs: Any) -> Any:
    """Identity by default; Slice 2 wires the real no-echo masking discipline
    through this hook. A boundary caller may override it (e.g. for tests)."""
    return data


class LangfuseBoundary:
    """The one object that owns the Langfuse SDK.

    Asserts major-version compatibility, then constructs a ``Langfuse``
    client bound to an isolated ``TracerProvider`` it owns — never the
    process-global OTel provider — so enabling telemetry cannot disturb
    other OpenTelemetry-instrumented libraries sharing the process.
    """

    def __init__(
        self,
        *,
        public_key: str | None = None,
        secret_key: str | None = None,
        host: str | None = None,
        mask: MaskFunction | None = None,
    ) -> None:
        try:
            installed = _installed_version()
        except _metadata.PackageNotFoundError as exc:
            raise GovernanceNotConfigured(
                "Langfuse observability is enabled but the 'langfuse' package "
                "is not installed. Install it with: "
                f"pip install 'zemtik-govern[{LANGFUSE_EXTRA}]'"
            ) from exc

        major = int(installed.split(".")[0])
        if major != SUPPORTED_MAJOR:
            raise LangfuseVersionError(
                f"langfuse {installed} is installed but zemtik-govern requires "
                f"major version {SUPPORTED_MAJOR}.x"
            )

        # Deferred to here so importing this module (and failing the checks
        # above) never touches the SDK or OpenTelemetry.
        from langfuse import Langfuse
        from opentelemetry.sdk.trace import TracerProvider

        self.version = installed
        self._tracer_provider = TracerProvider()
        self.client: Langfuse = Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=host,
            tracer_provider=self._tracer_provider,
            mask=mask or _default_mask,
        )
