# zemtik-govern — Governance for LangChain, LangGraph, and Microsoft AGT

Govern every tool call through a fixed pipeline — **identity → policy → audit** — with a prompt-injection screen folded into the policy seam. Fail-closed by design: any fault during governance blocks the tool and is audited, never silently allowed.

`zemtik-govern` is a security-first Python wrapper around Microsoft AGT (`agent-os-kernel` + `agentmesh-platform`). It is the moat between an autonomous agent and the privileged tools it can call.

## What it guarantees

- **Deny-by-default.** AGT's native evaluator allows when no rule matches; `zemtik-govern` overrides that — no matching rule is a deny. A tool is reachable only if a rule names it.
- **Fail-closed.** Any exception in identity or policy is caught, audited as a system denial, and re-raised. The wrapped tool never runs on a governance fault.
- **Prompt-injection guard.** A poisoned tool argument (`ignore all previous instructions…`, role-play hijacks, delimiter smuggling) is denied before the tool runs, even when policy would allow the call. The deny names the offending field; the raw payload is never echoed into logs.
- **Decision budget.** A hung identity or policy seam is bounded by a per-call deadline. A breach is a fail-closed system denial (`DecisionBudgetExceeded`), not a leaked allow.
- **Tamper-evident audit.** Every outcome — allow, deny, or system error — is recorded on a Merkle-chained, HMAC-signed trail that verifies independently and survives a process crash. A durable file trail requires an HMAC secret in `$ZEMTIK_AUDIT_SECRET`; the in-memory trail does not.
- **Idempotency.** A duplicate `idempotency_key` replays the cached decision; a key reused with a different payload is an audited conflict, never a false replay. Backing caches are bounded (LRU + TTL) against unbounded growth.
- **Safe rollout.** `shadow` mode observes would-denies without enforcing; a per-guard `shadow` stance lets a new guard run observe-only for one release before it enforces. A kill-switch reverts to a prior *governed* fallback — never to allow-all.

The API is async throughout (every seam, `govern`, and `proxy`) and requires Python 3.11+.

Two ways in: use the **LangChain Quick Start** if your tools are LangChain/LangGraph; use the **AGT-native API** to govern any async callable directly.

## LangChain Quick Start

```bash
pip install 'zemtik-govern[langchain]'   # quote the extras for zsh
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

The snippet below wires a **stub** policy that allows every call — it demonstrates *wiring only*, not enforcement. For real deny-by-default policy and the injection guard, build the governor from config (`GovernanceRegistry.from_config`, see the AGT-native API below) and load `govern.yaml`.

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

## AGT-native API

Every tool invocation passes identity → policy → audit in fixed order — any fault is a system denial; the guarded tool never runs on a governance error.

```bash
pip install zemtik-govern
```

Copy [`zemtik.example.yaml`](zemtik.example.yaml) to `zemtik.yaml` and edit it, then wire and call. A request is three inputs: `action` (the tool being called, what policy matches on), `subject` (the caller, resolved to a DID by identity), and `payload` (the arguments, screened by the injection guard).

```python
import asyncio
from zemtik_govern import AGTBoundary, GovernanceConfig, GovernanceContext, GovernanceRegistry

async def main():
    config = GovernanceConfig.load("zemtik.yaml")
    gov = GovernanceRegistry.from_config(config, AGTBoundary()).build()

    ctx = GovernanceContext(action="tool.run", subject="agent-1", payload={"q": "hello"})
    decision = await gov.govern(ctx)   # raises GovernanceDenied if blocked

asyncio.run(main())
```

Or wrap a callable so it is governed on every call (inside an async context):

```python
governed_fn = gov.proxy(my_tool, action="tool.run", subject="agent-1")
result = await governed_fn(q="hello")
```

In `strict`/`enforce` mode the injection guard is always on. By default it uses AGT's own vetted detection rules (no config needed); set `injection_rules_path` only to pin a version or diverge — [`policies/prompt-injection.yaml`](policies/prompt-injection.yaml) is a ready-to-edit snapshot of those defaults. A file `audit_sink` requires an HMAC secret in `$ZEMTIK_AUDIT_SECRET`. See [`zemtik.example.yaml`](zemtik.example.yaml) for the full annotated configuration. To watch the injection guard deny a poisoned argument, run scenario S11 in `sandbox/qa_demo.py` (and S14 for the per-guard shadow stance; see [Sandbox & Demos](#sandbox--demos)).

## Security model

### Operational modes

| Mode | Denials enforced | Policy required | Audit required |
|------|------------------|-----------------|----------------|
| `strict` | Yes | Yes | Yes |
| `enforce` | Yes | Yes | Yes |
| `shadow` | No (observe only) | No | Yes |

A new guard can also run observe-only independent of the mode via a per-guard `injection: {mode: shadow}` or `budget: {mode: shadow}` stance — useful to watch would-denies for one release before enforcing.

### Exceptions

Every failure is a typed, catchable exception carrying a stable `.code` and `.guard`, and an `.audit_id` that correlates back to its audit entry. The two enforcement exceptions raise only in enforcing modes — under `shadow` (or a per-guard `shadow` stance) the would-deny is observed and audited but never raised, so the tool runs:

| Exception | Meaning |
|-----------|---------|
| `GovernanceDenied` | Policy (or the injection guard) denied. Raised in `strict`/`enforce`; in `shadow` it is audited, not raised. Carries the `Decision`. |
| `DecisionBudgetExceeded` | A seam outran the decision budget; fail-closed. Raised when `budget` enforces; under `budget: {mode: shadow}` the breach is logged, not raised. Carries `.limit_seconds` / `.elapsed_seconds`. |
| `GovernanceError` | A system fault in a seam; the tool was blocked. |
| `GovernanceNotConfigured` | Insecure startup config; raised at boot, not request time. |

## Documentation

- [LangChain Integration Guide](docs/integrations/langchain.md) — govern_tool, GovernedToolNode, LangSmith, error reference
- [Architecture](docs/architecture.md) — three-seam design, idempotency, fail-closed guarantee, deny-by-default moat
- [Integration Guide](docs/integration-guide.md) — quickstart, usage patterns, custom seams, error reference
- [Configuration Reference](docs/configuration-reference.md) — YAML fields, mode matrix, env vars, startup validation
- [Operations Guide](docs/operations.md) — deployment checklist, durable audit, kill-switch, shadow rollout, monitoring
- [API Reference](docs/api-reference.md) — full public API (classes, protocols, exceptions)
- [Sandbox & Demos](docs/sandbox.md) — runnable demos: three-seam scenarios, the injection battery, audit forensics, staged shadow → enforce cutover, a real `gpt-5.4-nano` agent governed end to end

## Sandbox & Demos

Runnable demos live in [`sandbox/`](sandbox/) and exercise the real pipeline against the live AGT stack:

```bash
source .venv/bin/activate

# Three-seam scenarios S1–S15: allow, deny, fail-closed, idempotency, the
# injection guard, the decision budget, error codes/audit_id, per-guard shadow
ZEMTIK_AUDIT_SECRET=qa-test-secret python sandbox/qa_demo.py

# Audit trail: verify Merkle/HMAC, extract proofs, detect tampering
ZEMTIK_AUDIT_SECRET=audit-secret python sandbox/auditor.py

# Staged dogfood cutover: shadow -> enforce, kill-switch revert, audit integrity (no API key)
ZEMTIK_AUDIT_SECRET=dogfood-secret python sandbox/dogfood_cutover.py

# A real gpt-5.4-nano agent governed end to end, plus a 15-prompt injection
# battery and deterministic module probes (needs [langchain,openai] + an OpenAI key)
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

Status: pre-1.0, tracking the 0.3.x release line — see [CHANGELOG.md](CHANGELOG.md). The published package metadata reads `0.1.0.dev0` until the first PyPI cut. License: Apache-2.0.
