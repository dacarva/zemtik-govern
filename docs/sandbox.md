# Sandbox & Demos

The `sandbox/` directory holds runnable demos that exercise the real governance
pipeline against the live pinned AGT stack — no fakes. Use them to see the
three seams (identity → policy → audit) in action, prove the deny-by-default
moat, and verify the tamper-evident audit trail end to end.

All demos require the dev install and an activated venv:

```bash
uv venv .venv --python 3.11 && source .venv/bin/activate
uv pip install -e ".[dev]"
```

| Demo | What it proves | Extra deps |
|------|----------------|------------|
| `qa_demo.py` | Three-seam scenarios S1–S15 (allow, deny, fail-closed, idempotency, injection guard, decision budget, error codes/audit_id, per-guard shadow) | none |
| `auditor.py` | Durable audit trail: verify Merkle/HMAC, extract inclusion proofs, detect tampering | none |
| `dogfood_cutover.py` | Staged cutover of a fintech agent: shadow → enforce, kill-switch revert, audit integrity | none |
| `e2e_openai_governed.py` | A real `gpt-5.4-nano` agent governed through `GovernedToolNode` against a mock bank DB | `[langchain]`, `[openai]`, OpenAI key |

## qa_demo.py — three-seam scenarios

Walks scenarios S1–S15 mapping to the guarantees in
[`docs/architecture.md`](architecture.md): S1–S10 cover the three-seam core;
S11–S15 cover the v0.3.0.0 hardening (injection guard, decision budget, error
codes/audit_id, per-guard shadow). Each prints PASS for a green run.

```bash
ZEMTIK_AUDIT_SECRET=qa-test-secret python sandbox/qa_demo.py
```

## auditor.py — audit trail forensics

Generates a realistic multi-agent workload (allow, deny, system fault, replay),
prints a human-readable event log, verifies the Merkle chain, extracts an
inclusion proof, then mutates one byte to show the chain breaks.

```bash
ZEMTIK_AUDIT_SECRET=audit-secret python sandbox/auditor.py
```

## dogfood_cutover.py — staged shadow → enforce cutover

A simulated fintech agent with seven `govern()` call sites (four reads, three
privileged money-path writes) cut over onto the substrate the way a careful
rollout actually does it. Every call site assembles its context through one
factory (`make_context`) — a single unified contract, no per-site dict assembly.
No API key needed: the agent is scripted, the governance is real AGT.

```bash
ZEMTIK_AUDIT_SECRET=dogfood-secret python sandbox/dogfood_cutover.py
```

- **Phase A (shadow)** records what it *would* deny but enforces nothing, so the
  live path keeps running while you inspect the would-be denials. The reads are
  allowed; the writes are recorded as denied yet still execute.
- **Phase B (enforce)** blocks the three writes. The policy verdicts are
  identical to shadow's — flipping to enforce introduces zero false-denies; only
  enforcement changes.
- **Kill-switch revert** routes evaluation back to the agent's prior governed
  path in one toggle (never allow-all); engaging with no governed fallback fails
  closed.
- Both phases write durable, HMAC-signed, Merkle-chained trails
  (`sandbox/dogfood_*.audit.jsonl`, gitignored) that are integrity-checked at the
  end. The run emits `sandbox/dogfood_cutover_report.md` and exits `0` only on a
  full PASS.

## e2e_openai_governed.py — real OpenAI agent

A live `gpt-5.4-nano` agent is told to read account balances (ALLOWED) and then
move money and delete an account (DENIED by deny-by-default). Every tool call
runs through the governance pipeline and is audited. The script then reads the
durable trail back with `AuditReader`, verifies Merkle/HMAC integrity, proves
the denied writes never touched the in-memory SQLite DB, and emits a governance
report (markdown + machine-readable JSON).

```bash
# 1. Install the optional extras for the LangChain + OpenAI path.
uv pip install -e ".[dev,langchain,openai]"

# 2. Provide a real OpenAI key (and an optional audit signing secret).
cp .env.example .env          # .env is gitignored — never commit it
#   then edit .env: set OPENAI_API_KEY=sk-...

# 3. Run it.
python sandbox/e2e_openai_governed.py
```

The policy lives in [`sandbox/e2e_govern.yaml`](../sandbox/e2e_govern.yaml):
reads (`get_balance`, `list_accounts`) are allowed; writes (`transfer_funds`,
`close_account`) have no rule, so the deny-by-default moat blocks them.

Outputs (gitignored):

- `sandbox/e2e_governance_report.md` — human-readable governance report
- `sandbox/e2e_governance_report.json` — machine-readable, same data verbatim
- `sandbox/e2e.audit.jsonl` — the durable, signed audit trail

Exit code is `0` only when the run PASSES: reads allowed, writes denied, audit
trail verifies, and the DB is provably unchanged.

### Secrets

`OPENAI_API_KEY` is read from `.env` only, which is gitignored (`.env*` is
ignored, `!.env.example` is the one exception). Never paste a key into a
committed file. `ZEMTIK_AUDIT_SECRET` is the HMAC signing key for the audit
trail; it defaults to a local demo value if unset. The `AuditReader` must use
the same secret to verify.
