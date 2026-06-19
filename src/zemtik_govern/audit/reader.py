"""AuditReader — reads a durable audit trail for auditor workflows.

Public surface:
  AuditRecord  — typed value for one audit entry
  AuditReader  — reads a .jsonl trail, verifies the chain, returns proofs
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .._agt import AGTBoundary


@dataclass(frozen=True)
class AuditRecord:
    """One entry from the durable audit trail, as a typed value."""

    entry_id: str
    agent_did: str
    action: str
    outcome: str
    event_type: str
    policy_decision: str | None
    timestamp: str
    payload: dict[str, Any]


def _to_record(raw: dict[str, Any]) -> AuditRecord:
    return AuditRecord(
        entry_id=raw.get("entry_id", ""),
        agent_did=raw.get("agent_did", ""),
        action=raw.get("action", ""),
        outcome=raw.get("outcome", ""),
        event_type=raw.get("event_type", ""),
        policy_decision=raw.get("policy_decision"),
        timestamp=str(raw.get("timestamp", "")),
        payload=raw.get("data", {}).get("payload", {}),
    )


class AuditReader:
    """Reads a durable .jsonl audit file written by AgentMeshAudit.

    Provides three capabilities:
      records() — all entries as typed AuditRecord values
      verify()  — Merkle chain + HMAC integrity check
      proof()   — Merkle inclusion proof for a specific entry
    """

    def __init__(
        self,
        path: str | Path,
        boundary: AGTBoundary,
        secret: bytes | str,
    ) -> None:
        self._path = Path(path)
        self._boundary = boundary
        self._secret = secret.encode() if isinstance(secret, str) else secret

    def _sink(self):
        return self._boundary.file_audit_sink(str(self._path), self._secret)

    def _raw_entries(self) -> list[dict]:
        return [
            json.loads(line)
            for line in self._path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def records(self) -> list[AuditRecord]:
        """Return all entries in the trail as typed AuditRecord values."""
        return [_to_record(raw) for raw in self._raw_entries()]

    def verify(self) -> tuple[bool, str | None]:
        """Verify Merkle chain + HMAC integrity of the trail.

        Returns ``(True, None)`` when the chain is intact, or
        ``(False, reason)`` when any entry has been modified, deleted,
        reordered, or when the HMAC secret is wrong.
        """
        try:
            ok, err = self._sink().verify_integrity()
            return ok, err
        except Exception as exc:
            return False, str(exc)

    def proof(self, entry_id: str) -> dict:
        """Return a chain inclusion proof for *entry_id*.

        The returned dict contains:
          ``entry``        — the raw entry dict from the file
          ``merkle_proof`` — list of ``(entry_hash, entry_id)`` from genesis
                            up to and including the target entry
          ``merkle_root``  — entry_hash of the last entry in the trail
          ``verified``     — True when every ``previous_hash`` link in the
                            chain from genesis to this entry is intact

        An auditor can independently verify: for each consecutive pair in
        ``merkle_proof``, the second entry's ``previous_hash`` must equal
        the first entry's hash. A mismatch means the chain was altered.
        """
        entries = self._raw_entries()
        target = next((e for e in entries if e["entry_id"] == entry_id), None)
        if target is None:
            return {"entry": None, "merkle_proof": [], "merkle_root": None, "verified": False}

        def _hash(e: dict) -> str:
            return e.get("entry_hash") or e.get("content_hash") or ""

        idx = entries.index(target)
        chain = entries[: idx + 1]

        # Verify each previous_hash link from genesis to target
        chain_ok = True
        for i in range(1, len(chain)):
            if chain[i].get("previous_hash") != _hash(chain[i - 1]):
                chain_ok = False
                break

        merkle_proof = [(_hash(e), e["entry_id"]) for e in chain]
        merkle_root = _hash(entries[-1])

        return {
            "entry": target,
            "merkle_proof": merkle_proof,
            "merkle_root": merkle_root,
            "verified": chain_ok,
        }
