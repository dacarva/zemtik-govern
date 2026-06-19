# zemtik-govern

Security-first, modular Python wrapper around Microsoft AGT (`agent-os-kernel` +
`agentmesh-platform`). One fail-closed `govern()` call in front of every tool:
identity → policy → audit.

zemtik-govern enforces a **deny-by-default moat** over AGT's fail-open evaluator:
every tool invocation is resolved to a verified identity, evaluated against a
policy, and recorded in a tamper-evident Merkle-chained audit trail — in that
fixed order, every time. Any fault in any seam is a system denial; the guarded
tool never runs on a governance error.

Status: pre-v0.1, M0–M3 in progress. Apache-2.0.

## Documentation

- [Architecture](docs/architecture.md) — three-seam design, idempotency, fail-closed guarantee, deny-by-default moat
- [Integration Guide](docs/integration-guide.md) — quickstart, usage patterns, custom seams, error reference
- [Configuration Reference](docs/configuration-reference.md) — YAML fields, mode matrix, env vars, startup validation
- [Operations Guide](docs/operations.md) — deployment checklist, durable audit, kill-switch, shadow rollout, monitoring
- [API Reference](docs/api-reference.md) — full public API (classes, protocols, exceptions)

## Layout

- `src/zemtik_govern/_agt.py` — the **single** sanctioned import boundary to AGT.
  Pins are asserted at construction; no other module imports `agent_os` /
  `agentmesh` directly.
- `spike/` — executable verification of the AGT surface and the
  `agent_os` → `agentmesh` compat map.

## Development

```bash
uv venv .venv --python 3.11 && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest
```
