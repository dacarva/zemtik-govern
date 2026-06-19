# zemtik-govern

Security-first, modular Python wrapper around Microsoft AGT (`agent-os-kernel` +
`agentmesh-platform`). One fail-closed `govern()` call in front of every tool:
identity → policy → audit.

Status: pre-v0.1, M0–M3 in progress. Apache-2.0.

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
