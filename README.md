# zemtik-govern — LangChain/LangGraph Governance

Govern every LangChain tool call with a three-seam pipeline: **identity → policy → audit**. Fail-closed by design.

## Section 1: LangChain Quick Start

```bash
pip install zemtik-govern[langchain]
```

`govern.yaml` — allow exactly one tool by name:

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

<!-- quickstart -->
```python
from zemtik_govern.core import ZemtikGovern
from zemtik_govern.identity import AgentRef
from zemtik_govern.langchain import govern_tool
from zemtik_govern.protocols import Decision
from langchain_core.tools import tool

class _Policy:
    async def identify(self, s): return AgentRef(did=f"did:x:{s}")
    async def evaluate(self, c): return Decision(allowed=True, action=c.action, matched_rule="allow-add-numbers", reason="ok")
    async def write(self, e): return "e"
gov = ZemtikGovern(identity=_Policy(), policy=_Policy(), audit=_Policy())

@tool
def add_numbers(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b

result = govern_tool(add_numbers, govern=gov).invoke({"a": 3, "b": 4})
print(result)  # 7
```

Debug with full governance logs:

```bash
ZEMTIK_DEV=1 python examples/langchain_minimal.py
```

For a drop-in LangGraph `ToolNode` replacement, see [`examples/langgraph_toolnode.py`](examples/langgraph_toolnode.py).

Full integration guide: [`docs/integrations/langchain.md`](docs/integrations/langchain.md)

## Section 2: AGT-native API

zemtik-govern is a security-first Python wrapper around Microsoft AGT (`agent-os-kernel` + `agentmesh-platform`). Every tool invocation passes identity → policy → audit in fixed order — any fault is a system denial; the guarded tool never runs on a governance error.

```bash
pip install zemtik-govern
```

Wire and call:

```python
from zemtik_govern import AGTBoundary, GovernanceConfig, GovernanceContext, GovernanceRegistry

config = GovernanceConfig.load("zemtik.yaml")
gov = GovernanceRegistry.from_config(config, AGTBoundary()).build()

ctx = GovernanceContext(action="tool.run", subject="agent-1", payload={"q": "hello"})
decision = await gov.govern(ctx)   # raises GovernanceDenied if blocked
```

Or wrap a callable so it is governed on every call:

```python
governed_fn = gov.proxy(my_tool, action="tool.run", subject="agent-1")
result = await governed_fn(q="hello")
```

See [`zemtik.example.yaml`](zemtik.example.yaml) for the full annotated configuration reference.

## Documentation

- [LangChain Integration Guide](docs/integrations/langchain.md) — govern_tool, GovernedToolNode, LangSmith, error reference
- [Architecture](docs/architecture.md) — three-seam design, idempotency, fail-closed guarantee, deny-by-default moat
- [Integration Guide](docs/integration-guide.md) — quickstart, usage patterns, custom seams, error reference
- [Configuration Reference](docs/configuration-reference.md) — YAML fields, mode matrix, env vars, startup validation
- [Operations Guide](docs/operations.md) — deployment checklist, durable audit, kill-switch, shadow rollout, monitoring
- [API Reference](docs/api-reference.md) — full public API (classes, protocols, exceptions)
- [Sandbox & Demos](docs/sandbox.md) — runnable demos: three-seam scenarios, audit forensics, a real `gpt-5.4-nano` agent governed end to end

## Sandbox & Demos

Runnable demos live in [`sandbox/`](sandbox/) and exercise the real pipeline against the live AGT stack:

```bash
source .venv/bin/activate

# Three-seam scenarios S1–S10 (allow, deny, fail-closed, idempotency)
ZEMTIK_AUDIT_SECRET=qa-test-secret python sandbox/qa_demo.py

# Audit trail: verify Merkle/HMAC, extract proofs, detect tampering
ZEMTIK_AUDIT_SECRET=audit-secret python sandbox/auditor.py

# A real gpt-5.4-nano agent governed end to end (needs [langchain,openai] + an OpenAI key)
uv pip install -e ".[dev,langchain,openai]"
cp .env.example .env   # then set OPENAI_API_KEY in .env (gitignored)
python sandbox/e2e_openai_governed.py
```

See [docs/sandbox.md](docs/sandbox.md) for what each demo proves and its outputs.

## Development

```bash
source .venv/bin/activate
pytest
ruff check src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full dev setup and three-seam contract.

Status: pre-v0.1. Apache-2.0.
