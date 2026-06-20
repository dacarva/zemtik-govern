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
| `qa_demo.py` | Three-seam pipeline scenarios S1–S10 (allow, deny, fail-closed, idempotency) | none |
| `auditor.py` | Durable audit trail: verify Merkle/HMAC, extract inclusion proofs, detect tampering | none |
| `e2e_openai_governed.py` | A real `gpt-5.4-nano` agent governed through `GovernedToolNode` against a mock bank DB | `[langchain]`, `[openai]`, OpenAI key |

## qa_demo.py — three-seam scenarios

Walks scenarios S1–S10 mapping to the guarantees in
[`docs/architecture.md`](architecture.md). Each prints PASS for a green run.

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
