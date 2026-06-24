# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | ✅ Yes     |
| < 0.4   | ❌ No      |

## Reporting a Vulnerability

**Please do not open public GitHub issues for vulnerabilities.**

Preferred channel: **GitHub private security advisories**
[Report via GitHub](https://github.com/dacarva/zemtik-govern/security/advisories/new)

Alternatively, email **david@zemtik.com** with subject line `[zemtik-govern] Security Report`.

### Response timelines

| Event | Target |
|-------|--------|
| Acknowledge receipt | 72 hours |
| Triage and severity assessment | 7 days |
| Patch or mitigation plan | Depends on severity; critical issues prioritized |

We will coordinate a disclosure date with you before publishing any fix.

## Scope

This project's threat model centres on:

- **Governance bypass** — inputs that cause a governed tool to run without passing the identity → policy → audit pipeline.
- **Fail-open conditions** — faults during identity or policy that result in an `allow` rather than a `system` denial.
- **Audit tampering** — weaknesses in the Merkle-chained, HMAC-signed audit trail that allow entries to be altered or dropped without detection.
- **Prompt-injection guard evasion** — crafted payloads that pass the injection screen and reach a governed tool.
- **Idempotency conflicts** — same `idempotency_key` with different payload bypassing conflict detection.
- **AGT boundary violations** — code paths that import `agent_os` or `agentmesh` outside of `_agt.py`.

Out of scope: vulnerabilities in `agent-os-kernel`, `agentmesh-platform`, or other upstream AGT dependencies (report those upstream).

## Security Best Practices for Users

- Set `ZEMTIK_AUDIT_SECRET` to enable the HMAC-signed, Merkle-chained audit trail. Without it the in-memory sink provides no tamper-evidence and no persistence across process restarts — unsuitable for production governance.
- Run in `strict` or `enforce` mode in production. `shadow` mode does not enforce denials.
- Keep AGT dependencies pinned to the exact versions declared in `pyproject.toml`; `AGTBoundary.assert_pins()` enforces this at startup.
- Never echo raw governance payloads into logs — the prompt-injection guard intentionally withholds offending fields from audit output.
