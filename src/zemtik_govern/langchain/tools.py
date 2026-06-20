"""LangChain integration — govern_tool(), govern_tools(), @governed decorator.

Issues #15 (core API) and #17 (ZEMTIK_DEV observability).
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Any

from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import get_callback_manager_for_config
from langchain_core.tools import BaseTool

from zemtik_govern.context import GovernanceContext
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.errors import GovernanceDenied, GovernanceError

logger = logging.getLogger("zemtik_govern")


def _is_dev_mode() -> bool:
    """True when ZEMTIK_DEV env var is set (any non-empty value)."""
    return bool(os.getenv("ZEMTIK_DEV"))


def govern_tool(
    tool,
    *,
    config=None,
    govern=None,
    action=None,
    on_denied="raise",
) -> _GovernedTool:
    """Wrap a LangChain tool with zemtik governance.

    Exactly one of ``config`` or ``govern`` must be provided.
    """
    if config is not None and govern is not None:
        raise ValueError(
            "Provide either config= or govern=, not both. "
            "Use govern= with a pre-built ZemtikGovern instance, "
            "or config= to build one lazily."
        )
    if config is None and govern is None:
        raise ValueError(
            "One of config= or govern= is required. "
            "Pass a GovernanceConfig dict/object as config=, "
            "or a pre-built ZemtikGovern instance as govern=."
        )
    _VALID_ON_DENIED = {"raise", "tool_message"}
    if on_denied not in _VALID_ON_DENIED:
        raise ValueError(
            f"on_denied must be one of {sorted(_VALID_ON_DENIED)!r}, got {on_denied!r}"
        )
    return _GovernedTool(tool, config=config, govern=govern, action=action, on_denied=on_denied)


def govern_tools(tools, *, config=None, govern=None, on_denied="raise") -> list[_GovernedTool]:
    """Wrap a list of LangChain tools with zemtik governance."""
    return [govern_tool(t, config=config, govern=govern, on_denied=on_denied) for t in tools]


def governed(config, *, action=None, on_denied="raise"):
    """Decorator that wraps a @tool-decorated function with zemtik governance.

    Must be applied AFTER @tool (i.e. outermost decorator):

        @governed(config)
        @tool
        def my_tool(...): ...
    """
    def decorator(tool_fn):
        if not isinstance(tool_fn, BaseTool):
            raise GovernanceError(
                "governed() must be applied after @tool, not before. "
                "Correct order:\n"
                "    @governed(config)\n"
                "    @tool\n"
                "    def my_tool(...): ..."
            )
        return govern_tool(tool_fn, config=config, action=action, on_denied=on_denied)
    return decorator


def _extract_subject(config: RunnableConfig | None) -> str:
    """Extract agent_id from RunnableConfig, falling back to 'langchain'."""
    if config is None:
        return "langchain"
    configurable = config.get("configurable", {}) or {}
    if "agent_id" in configurable:
        return configurable["agent_id"]
    metadata = config.get("metadata", {}) or {}
    if "agent_id" in metadata:
        return metadata["agent_id"]
    return "langchain"


class _GovernedTool(BaseTool):
    """A LangChain BaseTool that runs zemtik governance before every invocation."""

    # Pydantic fields for _GovernedTool
    _wrapped: Any = None
    _govern: Any = None
    _config_dict: Any = None
    _action_override: str | None = None
    _on_denied: str = "raise"
    _gov_lock: Any = None

    def __init__(
        self,
        wrapped_tool: BaseTool,
        *,
        config=None,
        govern=None,
        action=None,
        on_denied="raise",
    ):
        # Copy name, description, and args_schema from the wrapped tool
        super().__init__(
            name=wrapped_tool.name,
            description=wrapped_tool.description or "",
            args_schema=getattr(wrapped_tool, "args_schema", None),
        )
        object.__setattr__(self, "_wrapped", wrapped_tool)
        object.__setattr__(self, "_govern", govern)
        object.__setattr__(self, "_config_dict", config)
        object.__setattr__(self, "_action_override", action)
        object.__setattr__(self, "_on_denied", on_denied)
        object.__setattr__(self, "_gov_lock", threading.Lock())

    def _get_governor(self) -> ZemtikGovern:
        gov = object.__getattribute__(self, "_govern")
        if gov is not None:
            return gov
        # Lazy init from config
        lock = object.__getattribute__(self, "_gov_lock")
        with lock:
            gov = object.__getattribute__(self, "_govern")
            if gov is not None:
                return gov
            from zemtik_govern._agt import AGTBoundary
            from zemtik_govern.config import GovernanceConfig
            from zemtik_govern.registry import GovernanceRegistry

            config_dict = object.__getattribute__(self, "_config_dict")
            if isinstance(config_dict, dict):
                cfg = GovernanceConfig(**config_dict)
            else:
                cfg = config_dict
            new_gov = GovernanceRegistry.from_config(cfg, AGTBoundary()).build()
            object.__setattr__(self, "_govern", new_gov)
            return new_gov

    def _run(self, *args, **kwargs):
        """Sync run — delegates to wrapped tool after governance (sync path)."""
        # _run is called by BaseTool.invoke internally after governance via invoke()
        wrapped = object.__getattribute__(self, "_wrapped")
        return wrapped._run(*args, **kwargs)

    def run(self, *args, **kwargs):
        """Blocked — run() bypasses governance; use invoke() instead."""
        raise GovernanceError(
            "run() bypasses governance; use invoke() instead"
        )

    async def arun(self, *args, **kwargs):
        """Blocked — arun() bypasses governance; use ainvoke() instead."""
        raise GovernanceError(
            "arun() bypasses governance; use ainvoke() instead"
        )

    def _invoke_governed_sync(self, input, config):
        """Run governance synchronously. Returns (GovernanceDenied|None, Decision|None)."""
        gov = self._get_governor()
        subject = _extract_subject(config)
        action_override = object.__getattribute__(self, "_action_override")
        wrapped = object.__getattribute__(self, "_wrapped")
        action = action_override or wrapped.name
        payload = input if isinstance(input, dict) else {"input": input}
        ctx = GovernanceContext(action=action, subject=subject, payload=payload)

        start = time.monotonic()
        try:
            decision = gov.govern_sync(ctx)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            rule = decision.matched_rule or "unknown"
            logger.debug(
                "[ZEMTIK] ALLOW %s | subject=%s | rule=%s | %dms",
                wrapped.name, subject, rule, elapsed_ms,
            )
            return None, decision
        except GovernanceDenied as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            rule = getattr(exc.decision, "matched_rule", None) or "unknown"
            logger.debug(
                "[ZEMTIK] DENY %s | subject=%s | rule=%s | %dms",
                wrapped.name, subject, rule, elapsed_ms,
            )
            return exc, exc.decision

    async def _invoke_governed_async(self, input, config):
        """Run governance asynchronously. Returns (GovernanceDenied|None, Decision|None)."""
        gov = self._get_governor()
        subject = _extract_subject(config)
        action_override = object.__getattribute__(self, "_action_override")
        wrapped = object.__getattribute__(self, "_wrapped")
        action = action_override or wrapped.name
        payload = input if isinstance(input, dict) else {"input": input}
        ctx = GovernanceContext(action=action, subject=subject, payload=payload)

        start = time.monotonic()
        try:
            decision = await gov.govern(ctx)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            rule = decision.matched_rule or "unknown"
            logger.debug(
                "[ZEMTIK] ALLOW %s | subject=%s | rule=%s | %dms",
                wrapped.name, subject, rule, elapsed_ms,
            )
            return None, decision
        except GovernanceDenied as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            rule = getattr(exc.decision, "matched_rule", None) or "unknown"
            logger.debug(
                "[ZEMTIK] DENY %s | subject=%s | rule=%s | %dms",
                wrapped.name, subject, rule, elapsed_ms,
            )
            return exc, exc.decision

    def _emit_callbacks(self, config: RunnableConfig | None, decision, subject: str) -> None:
        """Emit governance metadata into LangChain callbacks (opt-in, null-safe)."""
        if config is None:
            return
        cb = get_callback_manager_for_config(config)
        if cb is None:
            return
        metadata = {
            "governance.decision": "allowed" if decision.allowed else "denied",
            "governance.rule": decision.matched_rule or "none",
            "governance.subject": subject,
        }
        run_manager = cb.on_chain_start({"name": "zemtik_govern"}, metadata)
        if run_manager is not None:
            run_manager.on_chain_end({"governance.decision": metadata["governance.decision"]})

    def invoke(self, input, config: RunnableConfig | None = None, **kwargs):
        """Govern then invoke (sync). Raises GovernanceError if called inside event loop."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass  # No running loop — safe to proceed
        else:
            raise GovernanceError(
                "invoke() called inside a running event loop; use ainvoke() instead"
            )

        wrapped = object.__getattribute__(self, "_wrapped")
        denial, decision = self._invoke_governed_sync(input, config)
        if denial is not None:
            tool_call_id = input.get("id", "unknown") if isinstance(input, dict) else "unknown"
            return self._handle_denied(denial, wrapped.name, config, tool_call_id=tool_call_id)
        self._emit_callbacks(config, decision, _extract_subject(config))
        return wrapped.invoke(input, config, **kwargs)

    async def ainvoke(self, input, config: RunnableConfig | None = None, **kwargs):
        """Govern then invoke (async)."""
        wrapped = object.__getattribute__(self, "_wrapped")
        denial, decision = await self._invoke_governed_async(input, config)
        if denial is not None:
            tool_call_id = input.get("id", "unknown") if isinstance(input, dict) else "unknown"
            return self._handle_denied(denial, wrapped.name, config, tool_call_id=tool_call_id)
        self._emit_callbacks(config, decision, _extract_subject(config))
        return await wrapped.ainvoke(input, config, **kwargs)

    def _handle_denied(
        self,
        exc: GovernanceDenied,
        tool_name: str,
        config: RunnableConfig | None,
        tool_call_id: str = "unknown",
    ):
        on_denied = object.__getattribute__(self, "_on_denied")

        logger.warning(
            "[ZEMTIK WARNING] %s denied (tool_call_id=%s)",
            tool_name,
            tool_call_id,
        )

        if on_denied == "raise":
            raise exc

        if on_denied == "tool_message":
            decision = exc.decision
            rule_name = decision.matched_rule or "unknown"
            reason = decision.reason or "denied"
            if _is_dev_mode():
                content = f"denied by {rule_name}: {reason}"
            else:
                content = "tool call denied"
            return ToolMessage(content=content, tool_call_id=tool_call_id)

        raise exc
