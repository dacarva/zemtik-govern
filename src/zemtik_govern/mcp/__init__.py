"""zemtik-govern MCP adapter.

Optional extra: install with ``pip install 'zemtik-govern[mcp]'``.

Exports:
    GovernedMCPServer: Wraps MCP tools behind the three-seam governance pipeline.
"""

from .server import GovernedMCPServer

__all__ = ["GovernedMCPServer"]
