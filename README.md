# zemtik-govern

Security-first, modular Python wrapper around Microsoft AGT (`agent-os-kernel` +
`agentmesh-platform`). One fail-closed `govern()` call in front of every tool:
identity → policy → audit.

zemtik-govern enforces a **deny-by-default moat** over AGT's fail-open evaluator:
every tool invocation is resolved to a verified identity, evaluated against a
policy, and recorded in a tamper-evident Merkle-chained audit trail — in that
fixed order, every time. Any fault in any seam is a system denial; the guarded
tool never runs on a governance error.

Status: pre-v0.1. Apache-2.0.

## Quick Start

```bash
uv venv .venv --python 3.11 && source .venv/bin/activate
uv pip install -e ".[dev]"
```

Write a `zemtik.yaml` config (see [`zemtik.example.yaml`](zemtik.example.yaml)):

```yaml
mode: strict
audit_sink: memory
rules:
  - name: allow-tool-run
    condition: {field: action, operator: eq, value: tool.run}
    action: allow
```

Wire and call:

```python
from zemtik_govern import AGTBoundary, GovernanceConfig, GovernanceContext, GovernanceRegistry

config = GovernanceConfig.load("zemtik.yaml")
gov = GovernanceRegistry.from_config(config, AGTBoundary()).build()

ctx = GovernanceContext(action="tool.run", subject="agent-1", payload={"q": "hello"})
decision = await gov.govern(ctx)   # raises GovernanceDenied if blocked
```

Or wrap a callable so it's governed on every call:

```python
governed_fn = gov.proxy(my_tool, action="tool.run", subject="agent-1")
result = await governed_fn(q="hello")
```

## Documentation

- [Architecture](docs/architecture.md) — three-seam design, idempotency, fail-closed guarantee, deny-by-default moat
- [Integration Guide](docs/integration-guide.md) — quickstart, usage patterns, custom seams, error reference
- [Configuration Reference](docs/configuration-reference.md) — YAML fields, mode matrix, env vars, startup validation
- [Operations Guide](docs/operations.md) — deployment checklist, durable audit, kill-switch, shadow rollout, monitoring
- [API Reference](docs/api-reference.md) — full public API (classes, protocols, exceptions)

## Development

```bash
# Activate venv (required before any Python command)
source .venv/bin/activate

# Run all tests
pytest

# Run a single test
pytest tests/test_core.py::test_govern_order -v

# Lint
ruff check src/

# AGT surface verification (human-readable)
python spike/verify_agt_signatures.py
```

## Layout

- `src/zemtik_govern/_agt.py` — the **single** sanctioned AGT import boundary.
  Pins are asserted at construction; no other module touches `agent_os` /
  `agentmesh` directly.
- `src/zemtik_govern/core.py` — `ZemtikGovern` orchestrator, idempotency ledger,
  `_GovernedProxy`.
- `src/zemtik_govern/policy.py` — `AgentOsPolicy`: deny-by-default moat.
- `tests/` — 16 test modules including adversarial and pressure tests.
- `spike/` — executable verification of the AGT surface.
- `docs/` — architecture, API reference, integration guide, config reference,
  operations guide.
- `docs/adr/` — architecture decision records.
