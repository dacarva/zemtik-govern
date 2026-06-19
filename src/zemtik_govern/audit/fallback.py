"""Emergency fallback audit channel.

If the primary tamper-evident sink cannot write, the outcome must still leave a
trace — but never at the cost of leaking the request. This channel emits a
*redacted, metadata-only* record: the raw payload is replaced by its SHA-256
digest, so the trail proves *that* a request happened and lets an operator
correlate it, without persisting the (possibly sensitive) payload to a
second-class file.

The record goes to two places: a fixed-path file created ``0600`` (owner-only)
and a structured line on stderr for log scrapers. Writing the fallback never
raises into the caller — the caller's job is to fail closed regardless.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..context import _thaw
from ..protocols import AuditEntry

# The fixed destination for redacted fallback records. Overridable per-deployment
# (and in tests) but defaulted so the channel always has somewhere to go.
DEFAULT_FALLBACK_PATH = Path(
    os.environ.get("ZEMTIK_AUDIT_FALLBACK", "zemtik-govern-audit-fallback.jsonl")
)

# Only these fields are ever written. The raw payload is NOT among them.
_REDACTED_FIELDS = (
    "action",
    "agent_did",
    "decision",
    "idempotency_key",
    "ts",
    "err",
    "payload_sha256",
)


def _payload_sha256(payload: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the thawed payload. Deterministic
    (sorted keys) so the same request hashes the same."""
    canonical = json.dumps(_thaw(payload), sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def redacted_record(entry: AuditEntry, err: BaseException) -> dict[str, Any]:
    """Build the metadata-only record. The raw payload is reduced to its digest;
    no payload field survives."""
    record = {
        "action": entry.action,
        "agent_did": entry.agent_did,
        "decision": entry.outcome,
        "idempotency_key": entry.idempotency_key,
        "ts": entry.ts,
        "err": f"{type(err).__name__}: {err}",
        "payload_sha256": _payload_sha256(entry.payload),
    }
    # Defensive: only the allow-listed fields, never anything else.
    return {k: record[k] for k in _REDACTED_FIELDS}


def emit_fallback(
    entry: AuditEntry, err: BaseException, path: Path | str | None = None
) -> dict[str, Any]:
    """Write the redacted record to the fixed-path file (mode 0600) and stderr.

    Never raises into the caller: the primary-sink failure is already being
    handled fail-closed, and a secondary I/O error must not mask that.
    """
    record = redacted_record(entry, err)
    line = json.dumps(record, sort_keys=True)
    # stderr first — it cannot fail the way the filesystem can.
    print(f"zemtik-govern audit-fallback {line}", file=sys.stderr)
    target = Path(path) if path is not None else DEFAULT_FALLBACK_PATH
    try:
        # Open owner-only (0600). os.open honours the mode on creation; chmod the
        # existing file too, so a pre-existing looser file is tightened.
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.chmod(target, 0o600)
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        # The file channel is best-effort; the stderr line already carried it.
        pass
    return record
