"""MCP adapter — GovernedMCPServer.

Every MCP tool call passes through ``govern()`` before the tool runs.
Fail-closed: any governance fault blocks the tool and is propagated.

AGT boundary rule: this module MUST NOT import ``agent_os`` or ``agentmesh``.
Those imports stay in ``_agt.py`` only.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from pathlib import Path

# TYPE_CHECKING guard so ZemtikGovern / GovernanceConfig don't create a
# circular import at runtime (they depend on protocols, not on mcp).
from typing import TYPE_CHECKING, Any, Literal

from ..context import GovernanceContext
from ..errors import GovernanceDenied, GovernanceError

if TYPE_CHECKING:
    from ..config import GovernanceConfig
    from ..core import ZemtikGovern


class GovernedMCPServer:
    """An MCP server where every tool call is governed before execution.

    Every registered tool is wrapped so that ``govern()`` runs (identity →
    policy → audit) before the tool function is invoked.  A deny raises
    :class:`~zemtik_govern.errors.GovernanceDenied` (``on_denied="raise"``)
    or returns an error content dict (``on_denied="error_response"``).

    Subject resolution priority (per-request):
      1. Explicit ``subject`` kwarg to :meth:`_invoke_tool`.
      2. HTTP header ``X-Agent-ID`` (when integrated with an HTTP transport).
      3. JWT ``sub`` claim (future sprint).
      4. Fallback: ``"agent:anonymous"``.

    AGT boundary rule: this class MUST NOT import ``agent_os`` or
    ``agentmesh``.  Those imports belong exclusively in ``_agt.py``.
    """

    _VALID_ON_DENIED = frozenset({"raise", "error_response"})

    def __init__(
        self,
        tools: list[Callable[..., Any]],
        *,
        config: str | Path | GovernanceConfig | None = None,
        govern: ZemtikGovern | None = None,
        on_denied: Literal["raise", "error_response"] = "raise",
    ) -> None:
        """
        Args:
            tools: List of callables to register as governed MCP tools.
            config: Optional governance config (path or object).  Ignored when
                *govern* is supplied; reserved for future auto-wiring.
            govern: A pre-built :class:`~zemtik_govern.core.ZemtikGovern`
                instance.  Callers in production wire the three seams outside
                this class; tests inject a mock.
            on_denied: ``"raise"`` (default) propagates
                :class:`~zemtik_govern.errors.GovernanceDenied`; ``"error_response"``
                catches it and returns an error content dict instead so the MCP
                caller sees a structured error rather than an exception.
        """
        if not isinstance(tools, list):
            raise TypeError(f"tools must be a list of callables, got {type(tools).__name__}")
        if on_denied not in self._VALID_ON_DENIED:
            raise ValueError(
                f"on_denied must be one of {sorted(self._VALID_ON_DENIED)}, got {on_denied!r}"
            )

        self._tools: dict[str, Callable[..., Any]] = {fn.__name__.lstrip("_"): fn for fn in tools}
        self._govern = govern
        self._config = config
        self.on_denied: Literal["raise", "error_response"] = on_denied

    # ------------------------------------------------------------------
    # Core governed invocation
    # ------------------------------------------------------------------

    async def _invoke_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        subject: str = "agent:anonymous",
    ) -> Any:
        """Govern then invoke *tool_name* with *arguments*.

        Raises :class:`GovernanceDenied` / :class:`GovernanceError` when
        ``on_denied="raise"``; returns an error dict when
        ``on_denied="error_response"``.

        This is the primary extension point for testing and for future HTTP
        transport wrappers that extract the subject from a request header.
        """
        if tool_name not in self._tools:
            raise KeyError(f"tool {tool_name!r} is not registered")

        ctx = GovernanceContext(
            action=f"tool:{tool_name}",
            subject=subject,
            payload=dict(arguments),
        )

        try:
            await self._govern.govern(ctx)  # type: ignore[union-attr]
        except (GovernanceDenied, GovernanceError) as exc:
            if self.on_denied == "error_response":
                return {
                    "error": True,
                    "message": str(exc),
                    "denied": isinstance(exc, GovernanceDenied),
                }
            raise

        fn = self._tools[tool_name]
        result = fn(**arguments)
        if inspect.isawaitable(result):
            result = await result
        return result

    # ------------------------------------------------------------------
    # serve() — wraps FastMCP for HTTP transport
    # ------------------------------------------------------------------

    async def serve(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        """Start the governed MCP server over SSE transport.

        Registers each tool with a ``FastMCP`` instance as a governed wrapper,
        then starts the SSE server on *host*:*port*.

        The SSE transport is used because it supports HTTP headers (needed for
        ``X-Agent-ID`` subject resolution).  Stdio callers should call
        ``_invoke_tool`` directly or use a different transport.
        """
        try:
            from mcp.server import FastMCP
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "zemtik-govern[mcp] extra is required: "
                "pip install 'zemtik-govern[mcp]'"
            ) from exc

        fmcp = FastMCP(name="zemtik-governed", host=host, port=port)

        def _make_governed(name: str, doc: str | None) -> Any:
            """Capture loop variable via default arg to avoid B023."""
            async def _governed(**kwargs: Any) -> Any:
                return await self._invoke_tool(name, kwargs)
            _governed.__name__ = name
            _governed.__doc__ = doc or f"Governed tool: {name}"
            return _governed

        for tool_name, fn in self._tools.items():
            fmcp.add_tool(_make_governed(tool_name, fn.__doc__))

        await fmcp.run_sse_async()
