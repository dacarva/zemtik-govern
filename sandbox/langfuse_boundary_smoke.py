#!/usr/bin/env python3
"""Langfuse boundary smoke test: proves `LangfuseBoundary` (Slice 1) talks to a
REAL Langfuse backend — self-hosted or cloud — not just the local SDK.

This is deliberately NOT a governance demo. Slice 1 only builds the boundary;
nothing in `ZemtikGovern.govern()` calls it yet (core façade instrumentation is
Slice 2, config/registry wiring is Slice 3). So there is no governed call to
trace here — this script opens a manual observation directly against
`boundary.client` to confirm:

  1. the credentials are valid (`auth_check()`),
  2. a trace actually reaches the backend (flushed, not just batched locally),
  3. the isolated TracerProvider doesn't collide with anything else in-process,
  4. the registered `mask` hook is reachable from a real emitted span.

Once Slice 2/2b land, `sandbox/e2e_openai_governed.py` gets an opt-in Langfuse
mode that traces the real governed agent run end to end (Slice 8) — this
script is the narrower, Slice-1-scoped predecessor.

Run against a self-hosted instance (default — see docs/observability.md):

    LANGFUSE_PUBLIC_KEY=pk-lf-... \\
    LANGFUSE_SECRET_KEY=sk-lf-... \\
    LANGFUSE_HOST=http://localhost:3000 \\
    python sandbox/langfuse_boundary_smoke.py

Or copy `.env` (see `.env.example`) and set the three LANGFUSE_* vars there.
Requires the `[langfuse]` extra: `uv pip install -e ".[dev,langfuse]"`.
"""

from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))

REPO_ROOT = pathlib.Path(__file__).parent.parent


def load_dotenv(path: pathlib.Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main() -> int:
    load_dotenv(REPO_ROOT / ".env")
    os.environ.setdefault("LANGFUSE_HOST", "http://localhost:3000")

    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    host = os.environ["LANGFUSE_HOST"]

    if not public_key or not secret_key:
        print(
            "Missing LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY.\n"
            "Set them in .env or the environment — see .env.example and\n"
            "docs/observability.md ('The Langfuse boundary'). This script needs\n"
            "real project keys; it does not run against a fake client.",
            file=sys.stderr,
        )
        return 2

    try:
        from zemtik_govern.observability._langfuse import LangfuseBoundary
    except ImportError as exc:
        print(
            f"langfuse is not installed: {exc}\n"
            'Install the extra: uv pip install -e ".[dev,langfuse]"',
            file=sys.stderr,
        )
        return 2

    print(f"Constructing LangfuseBoundary against {host!r} ...")

    def _mask(*, data, **_kwargs):
        # A trivial, visible redaction so the smoke test can prove the hook is
        # actually invoked by the SDK on a real emitted span, not just present.
        return "<masked-by-smoke-test>" if data == "raw-smoke-test-secret" else data

    boundary = LangfuseBoundary(public_key=public_key, secret_key=secret_key, host=host, mask=_mask)
    print(f"  langfuse SDK version: {boundary.version}")

    print("Checking credentials against the live backend (auth_check) ...")
    try:
        auth_ok = boundary.client.auth_check()
    except Exception as exc:  # auth_check raises on network failure, not just auth failure
        print(
            f"Could not reach {host!r}: {exc}\n"
            "Is a self-hosted Langfuse instance running there, and is "
            "LANGFUSE_HOST reachable from this machine?",
            file=sys.stderr,
        )
        return 1
    if not auth_ok:
        print("Auth check failed — verify LANGFUSE_PUBLIC_KEY/SECRET_KEY/HOST.", file=sys.stderr)
        return 1
    print("  auth OK")

    print("Opening a manual trace + nested span (no governance involved) ...")
    with boundary.client.start_as_current_observation(
        name="zemtik-govern-slice1-smoke", as_type="span"
    ) as root:
        root.update(input={"note": "raw-smoke-test-secret"})
        with root.start_as_current_observation(name="nested-child", as_type="span") as child:
            child.update(metadata={"proves": "boundary-can-nest-spans"})
        trace_id = boundary.client.get_current_trace_id()
        trace_url = boundary.client.get_trace_url()

    print("Flushing to the backend ...")
    boundary.client.flush()
    print(f"\nDone. trace_id={trace_id}")
    if trace_url:
        print(f"View it at: {trace_url}")
    print(
        "\nCheck the trace in the Langfuse UI: the root span's `input` should show\n"
        "'<masked-by-smoke-test>', NOT 'raw-smoke-test-secret' — that confirms the\n"
        "mask hook actually ran on a real, backend-delivered span."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
