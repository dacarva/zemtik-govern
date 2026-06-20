# LangChain Integration Guide

Zemtik Govern wraps any LangChain `BaseTool` or LangGraph `ToolNode` with a three-seam governance pipeline: **identity → policy → audit**. Every tool call must pass all three seams or it is denied.

## Quick Start

```python
from langchain_core.tools import tool
from zemtik_govern.langchain import govern_tool
from zemtik_govern.errors import GovernanceDenied

@tool
def add_numbers(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b

governed_add = govern_tool(add_numbers, govern=gov)

try:
    result = governed_add.invoke({"a": 3, "b": 4})
except GovernanceDenied as exc:
    print(f"Denied: {exc}")
```

Run the working example:

```bash
ZEMTIK_DEV=1 python examples/langchain_minimal.py
```

## API Reference

### `govern_tool(tool, *, govern=, on_denied="raise")`

Wraps a single `BaseTool`. Returns a `_GovernedTool` that enforces governance on every `invoke()`/`ainvoke()` call.

- `govern`: a pre-built `ZemtikGovern` instance.
- `config`: a `GovernanceConfig` dict/object — builds `ZemtikGovern` lazily (thread-safe).
- `on_denied`: `"raise"` (default) raises `GovernanceDenied`; `"tool_message"` returns a `ToolMessage` with denial content.

### `govern_tools(tools, *, govern=, on_denied="raise")`

Wraps a list of tools. Returns `list[_GovernedTool]`.

### `@governed(config, *, on_denied="raise")`

Decorator form — applies governance to a `@tool`-decorated function.

> [!WARNING]
> **Decorator order matters.** `@tool` must be the inner decorator; `@governed` must be the outer decorator. Applying `@governed` before `@tool` raises `GovernanceError` at import time.
>
> **Correct:**
> ```python
> @governed(config)  # outer
> @tool              # inner
> def my_tool(...): ...
> ```
>
> **Wrong (raises `GovernanceError`):**
> ```python
> @tool
> @governed(config)
> def my_tool(...): ...
> ```

`@governed` only accepts `config=` — not `govern=`. To use a pre-built `ZemtikGovern` instance, use `govern_tool(fn, govern=gov)` directly.

### `GovernedToolNode(tools, *, govern=, on_denied="raise")`

Drop-in replacement for LangGraph `ToolNode`. Intercepts tool calls from graph state, enforces governance on each one.

```python
from zemtik_govern.langchain import GovernedToolNode

node = GovernedToolNode([search_web, send_email], govern=gov)
# Use node in your LangGraph graph exactly like ToolNode
```

### `govern_tool_node(tools, *, govern=)`

Two-line shorthand alias for `GovernedToolNode(tools, govern=govern)`.

## Subject Resolution

The subject (agent identity) is extracted from `RunnableConfig`:

1. `config["configurable"]["agent_id"]`
2. `config["metadata"]["agent_id"]`
3. Falls back to `"langchain"`

To identify callers: `config = RunnableConfig(configurable={"agent_id": "my-agent"})`

## Idempotency

`govern_tool()` does not thread an `idempotency_key` through its governance calls. Callers needing idempotency guarantees (fintech writes, exactly-once side effects) must call `gov.govern()` directly and check `decision.replayed`:

```python
decision = await gov.govern(ctx)
if decision.allowed and not decision.replayed:
    await do_write()
```

## LangSmith Tracing

Governance metadata is emitted as LangChain callback events when a `RunnableConfig` with callbacks is provided. This is **opt-in** — zemtik does not auto-detect an active LangSmith run context.

Keys emitted on `on_chain_start`:
- `governance.decision` — `"allowed"` or `"denied"`
- `governance.rule` — the matched rule name, or `"none"`
- `governance.subject` — the resolved subject identity

To wire callbacks:

```python
from langsmith import Client
from langchain_core.callbacks import LangChainTracer
from langchain_core.runnables import RunnableConfig

config = RunnableConfig(callbacks=[LangChainTracer(client=Client())])
result = governed_tool.invoke({"msg": "hello"}, config)
```

Without a `RunnableConfig` (or with one that has no callbacks), no callbacks are emitted and no error is raised.

## ZEMTIK_DEV Mode

Set `ZEMTIK_DEV=1` to enable detailed governance logs:

```
[ZEMTIK] ALLOW add_numbers | subject=langchain | rule=allow-add-numbers | 3ms
```

On denial with `ZEMTIK_DEV=1`, `ToolMessage` content includes the rule name and reason. In production (no `ZEMTIK_DEV`), denial content is always `"tool call denied"`.

## Error Reference

| Problem | When | Fix |
|---------|------|-----|
| `GovernanceDenied` | Policy denied the action | Check `exc.decision.reason`; update your `govern.yaml` rules or pass the correct subject |
| `GovernanceError: invoke() called inside a running event loop` | Calling `.invoke()` from async context (e.g., Jupyter) | Use `await governed_tool.ainvoke(...)` instead |
| `ValueError: One of config= or govern= is required` | Missing governance config on `govern_tool()` | Pass either `govern=gov` or `config={"mode": "strict", ...}` |
| `GovernanceNotConfigured` | `strict` mode with no rules or no audit sink at startup | Add at least one rule to `govern.yaml` and set `audit_sink` |

## Configuration Reference

See `examples/govern.yaml` for a minimal working config:

```yaml
mode: strict
audit_sink: memory
rules:
  - name: allow-add-numbers
    condition:
      field: action
      operator: eq
      value: add_numbers
    action: allow
```

See `zemtik.example.yaml` for the full annotated configuration reference.
