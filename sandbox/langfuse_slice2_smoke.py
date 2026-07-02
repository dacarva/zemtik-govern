#!/usr/bin/env python3
"""Slice 2 real-backend smoke test: proves the core façade instrumentation
(`ZemtikGovern._traced`/`_span_set`) emits a real, nested, masked trace to a
live Langfuse backend — self-hosted or cloud — through an actual `govern()`
call, not just the raw boundary (see `sandbox/langfuse_boundary_smoke.py` for
the narrower Slice-1 check).

Runs three real governed calls through a real `AgentOsPolicy`/`StaticIdentity`/
`AgentMeshAudit` pipeline with a real `LangfuseTracer`:

  1. allow  -> root "govern" span with identity + policy children, allowed=True
  2. deny   -> root "govern" span, policy child has denial_kind="policy"
  3. replay -> same idempotency_key + payload as (1); root span is annotated
               replayed=true with no identity/policy children

Each call's payload includes a sentinel raw value that must NOT show up in any
span attribute (no-echo masking, invariant 4) — check the Langfuse UI traces
after running this to confirm.

Run against a self-hosted instance (e.g. via the official Langfuse docker
compose: https://langfuse.com/self-hosting/docker-compose):

    LANGFUSE_PUBLIC_KEY=pk-lf-... \\
    LANGFUSE_SECRET_KEY=sk-lf-... \\
    LANGFUSE_HOST=http://localhost:3000 \\
    python sandbox/langfuse_slice2_smoke.py

Or copy `.env` (see `.env.example`) and set the three LANGFUSE_* vars there —
this script loads `.env` the same way `langfuse_boundary_smoke.py` does.
Requires the `[langfuse]` extra: `uv pip install -e ".[dev,langfuse]"`.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))

REPO_ROOT = pathlib.Path(__file__).parent.parent

_SENTINEL = "SENTINEL-RAW-SLICE2-SMOKE"

_ALLOW_TOOL_RUN = {
    "name": "allow-tool-run",
    "condition": {"field": "action", "operator": "eq", "value": "tool.run"},
    "action": "allow",
}


def load_dotenv(path: pathlib.Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


async def main() -> int:
    load_dotenv(REPO_ROOT / ".env")
    os.environ.setdefault("LANGFUSE_HOST", "http://localhost:3000")

    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    host = os.environ["LANGFUSE_HOST"]

    if not public_key or not secret_key:
        print(
            "Missing LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY.\n"
            "Set them in .env or the environment — see .env.example and\n"
            "docs/observability.md.",
            file=sys.stderr,
        )
        return 2

    try:
        from zemtik_govern.observability._langfuse import LangfuseBoundary
        from zemtik_govern.observability.tracer import LangfuseTracer
    except ImportError as exc:
        print(
            f"langfuse is not installed: {exc}\n"
            'Install the extra: uv pip install -e ".[dev,langfuse]"',
            file=sys.stderr,
        )
        return 2

    from zemtik_govern._agt import AGTBoundary
    from zemtik_govern.audit import AgentMeshAudit
    from zemtik_govern.context import GovernanceContext
    from zemtik_govern.core import ZemtikGovern
    from zemtik_govern.errors import GovernanceDenied
    from zemtik_govern.identity import StaticIdentity
    from zemtik_govern.policy import AgentOsPolicy

    print(f"Constructing LangfuseBoundary + LangfuseTracer against {host!r} ...")
    lf_boundary = LangfuseBoundary(public_key=public_key, secret_key=secret_key, host=host)
    tracer = LangfuseTracer(lf_boundary)

    agt_boundary = AGTBoundary()
    gov = ZemtikGovern(
        identity=StaticIdentity(agt_boundary),
        policy=AgentOsPolicy(agt_boundary, rules=[_ALLOW_TOOL_RUN]),
        audit=AgentMeshAudit(agt_boundary),
        mode="strict",
        tracer=tracer,
    )

    print("\n[1/3] allow — govern(tool.run) with a real matching rule ...")
    allow_decision = await gov.govern(
        GovernanceContext(
            action="tool.run",
            subject="slice2-smoke-agent",
            payload={"note": _SENTINEL},
            idempotency_key="slice2-smoke-allow",
        )
    )
    print(f"  allowed={allow_decision.allowed} audit_event_id={allow_decision.audit_event_id}")

    print("\n[2/3] deny — govern(tool.delete) with no matching rule (deny-by-default) ...")
    try:
        await gov.govern(
            GovernanceContext(
                action="tool.delete",
                subject="slice2-smoke-agent",
                payload={"note": _SENTINEL},
            )
        )
        print("  UNEXPECTED: deny path did not raise GovernanceDenied", file=sys.stderr)
        return 1
    except GovernanceDenied as exc:
        print(f"  denied as expected, denial_kind={exc.decision.denial_kind!r}")

    print("\n[3/3] replay — same idempotency_key + payload as [1] ...")
    replay_decision = await gov.govern(
        GovernanceContext(
            action="tool.run",
            subject="slice2-smoke-agent",
            payload={"note": _SENTINEL},
            idempotency_key="slice2-smoke-allow",
        )
    )
    print(f"  replayed={replay_decision.replayed}")

    print("\nFlushing to the backend ...")
    lf_boundary.client.flush()
    print(
        "\nDone. Check the Langfuse UI for 3 root 'govern' traces:\n"
        "  - allow: identity + policy children, policy.attrs allowed=True\n"
        "  - deny: identity + policy children, policy.attrs denial_kind='policy'\n"
        "  - replay: no identity/policy children, root attrs replayed=True\n"
        f"None of them should contain the substring {_SENTINEL!r} anywhere."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
