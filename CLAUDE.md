# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`zemtik-govern` is a security-first Python governance wrapper around Microsoft AGT (`agent-os-kernel` + `agentmesh-platform`). Every tool invocation must pass three seams in order — **identity → policy → audit** — or it is denied. Fail-closed by design: any fault during governance blocks the tool and is audited.

See **AGENTS.md** for the complete sprint workflow, planning phases, gstack harness, skill dependencies, and MCP tool guidance.

## Dev Commands

```bash
# Setup (first time)
uv venv .venv --python 3.11 && source .venv/bin/activate
uv pip install -e ".[dev]"

# Always activate before any Python/pytest/uv command
source .venv/bin/activate

# Run all tests
pytest

# Run a single test
pytest tests/test_core.py::test_govern_order -v

# Run a test module
pytest tests/test_adversarial.py -v

# Run the end-to-end sandbox suite (real seams, real file audit; slower I/O)
pytest tests/e2e -v

# Lint (gates CI)
ruff check src/

# Format
ruff format src/
```

## Architecture

### The Three-Seam Pipeline

`ZemtikGovern.govern(ctx)` runs three seams in a **fixed order** — this order is a correctness invariant, not a convention:

1. **Identity** (`IdentityProvider.identify(subject) → AgentRef`) — resolves subject to a DID. Must run first because policy may key on subject, and audit stamps the DID.
2. **Policy** (`PolicyEngine.evaluate(ctx) → Decision`) — evaluates the frozen context. Must run after identity so the DID is known.
3. **Audit** (`AuditSink.write(entry) → str`) — records every outcome (allow, deny, or system error). Must run last to stamp the policy verdict.

All three are duck-typed **Protocols** (no base classes). The v0.1 implementations are `StaticIdentity`, `AgentOsPolicy`, and `AgentMeshAudit`.

### Fail-Closed Guarantee

Any exception raised during identity or policy is caught, audited as a `system` denial, then re-raised as `GovernanceError`. The wrapped tool **never runs** on a fault. This means:

- `GovernanceDenied` → policy denied; tool was blocked; carries the `Decision`.
- `GovernanceError` → system fault; tool was blocked; something broke in a seam.
- `GovernanceNotConfigured` → startup config was insecure; raised at boot, not request time.

### The Deny-by-Default Moat

AGT's native `PolicyEvaluator` **allows** when no rule matches (`matched_rule is None` → `allowed=True`). `AgentOsPolicy` (`policy.py`) overrides this: when `matched_rule is None`, it forces a deny. This is the critical security moat. See `docs/adr/001-agt-pins.md` for the conformance test that guards it.

### AGT Boundary Rule

**Only `_agt.py` imports `agent_os` or `agentmesh`.** No other module in `src/` touches AGT directly. `AGTBoundary` asserts pinned versions via `importlib.metadata` at construction (not `module.__version__`, which can lag). Any version mismatch raises `AGTVersionError` at startup.

### Immutable Context

`GovernanceContext` is deep-frozen at construction: dicts become `MappingProxyType`, lists become tuples, recursively. This closes a TOCTOU window: the bytes policy evaluates are provably the bytes audit records. `to_dict()` thaws it for AGT calls.

### Idempotency

`govern()` fingerprints each request: `SHA256(action + subject + sorted_json(payload))`. An `idempotency_key` binds one key to one fingerprint:

- **Same key, same fingerprint** → replay: returns cached `Decision`, skips re-evaluation, audits as replay.
- **Same key, different fingerprint** → conflict: audited as `error`, raises, tool never runs.

Direct callers must check `Decision.replayed` and gate their own side effects on `not decision.replayed`. The `proxy()` wrapper handles effect-idempotency automatically.

### Operational Modes

| Mode | Denials enforced | Policy required | Audit required |
|------|-----------------|-----------------|----------------|
| `strict` | Yes | Yes | Yes |
| `enforce` | Yes | Yes | Yes |
| `shadow` | No (observe only) | No | Yes |

Shadow mode surfaces false-denies without enforcement. The kill-switch reverts to a prior governed fallback policy — never to allow-all.

## Docs

After the documentation sprint, see:

- `docs/architecture.md` — three-seam design, fail-closed invariants, idempotency
- `docs/api-reference.md` — all public classes and method signatures
- `docs/integration-guide.md` — step-by-step wiring with code examples
- `docs/configuration-reference.md` — all config fields, modes, env vars
- `docs/operations.md` — durable audit, kill-switch, Merkle verification

## Workflow Reference

**Source of truth**: See AGENTS.md for complete workflow, roles, and implementation guide.

**Skill dependencies**: skills-lock.json declares required skills (gstack, tdd, to-issues, improve-codebase-architecture). Agents auto-fetch from github.

**Enforcement hooks** (add to .claude/settings.json):

```json
{
  "hooks": {
    "after-skill": [
      {
        "skills": ["/plan-ceo-review", "/plan-eng-review", "/plan-design-review", "/plan-devex-review"],
        "action": "notify",
        "message": "✅ Planning complete. Next: run `/to-issues` to convert design doc to vertical-slice GitHub issues"
      }
    ],
    "before-skill": [
      {
        "skills": ["/ship"],
        "requires-completed": ["tdd-implementation", "improve-codebase-architecture"],
        "action": "block",
        "message": "Pre-ship checklist:\n1. Run `/tdd` for each issue (red-green-refactor)\n2. Run `/improve-codebase-architecture` for deepening opportunities\n3. Run `/review` and `/qa`"
      }
    ],
    "on-branch-create": [
      {
        "action": "notify",
        "message": "📝 Starting implementation: use `/tdd` skill for test-driven development (red → green → refactor)"
      }
    ]
  }
}
```
