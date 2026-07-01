"""Slice 1 — the Langfuse boundary: exact/major-version gate, lazy import,
isolated OTel state, and the ``[langfuse]`` extra error path.

Mirrors ``tests/test_agt_boundary.py``: behavior through the public boundary
surface only. Import-heavy assertions are guarded with ``importorskip`` so the
langfuse-free job still runs the SDK-absent error path (it monkeypatches the
version lookup rather than needing the package uninstalled).
"""

from __future__ import annotations

import ast
import importlib.metadata as metadata
from pathlib import Path

import pytest

from zemtik_govern.errors import GovernanceNotConfigured
from zemtik_govern.observability._langfuse import (
    LangfuseBoundary,
    LangfuseVersionError,
    _installed_version,
)

_SRC = Path(__file__).parent.parent.parent / "src" / "zemtik_govern"


def test_build_tracer_names_the_extra_when_sdk_is_absent(monkeypatch):
    """Simulate the SDK missing (no [langfuse] extra installed): a clear,
    fail-at-boot GovernanceNotConfigured naming the extra to install."""

    def _raise(dist: str = "langfuse") -> str:
        raise metadata.PackageNotFoundError(dist)

    monkeypatch.setattr("zemtik_govern.observability._langfuse._installed_version", _raise)
    with pytest.raises(GovernanceNotConfigured, match=r"\[langfuse\]"):
        LangfuseBoundary()


def test_boundary_rejects_incompatible_major_version(monkeypatch):
    """A future/past major bump (e.g. langfuse 5.x) is a hard failure, not a
    silent best-effort import — mirrors AGTVersionError's intent."""
    monkeypatch.setattr(
        "zemtik_govern.observability._langfuse._installed_version",
        lambda dist="langfuse": "5.0.0",
    )
    with pytest.raises(LangfuseVersionError):
        LangfuseBoundary()


def test_installed_version_reads_real_distribution_metadata():
    """Sanity: the real lookup reads authoritative distribution metadata, same
    discipline as AGTBoundary's importlib.metadata.version reliance."""
    pytest.importorskip("langfuse")
    assert _installed_version() == metadata.version("langfuse")


def test_boundary_constructs_without_registering_a_global_tracer_provider():
    """Constructing the boundary must not mutate global OpenTelemetry state —
    the isolated TracerProvider is passed explicitly to the Langfuse client."""
    pytest.importorskip("langfuse")
    from opentelemetry import trace as otel_trace

    before = otel_trace.get_tracer_provider()
    # Unique key: the Langfuse SDK keys a resource-manager singleton by
    # public_key, so a fresh key per test avoids cross-test state leakage.
    LangfuseBoundary(public_key="pk-provider-test", secret_key="sk", host="http://localhost:3000")
    after = otel_trace.get_tracer_provider()
    assert after is before


def test_boundary_mask_hook_scrubs_a_known_raw_value():
    """Behavioral conformance: the registered ``mask`` hook actually redacts a
    known raw value — not just that the hook exists."""
    pytest.importorskip("langfuse")

    def _mask(*, data, **_kwargs):
        return "REDACTED" if data == "raw-ssn-123-45-6789" else data

    boundary = LangfuseBoundary(
        public_key="pk-mask-test",
        secret_key="sk",
        host="http://localhost:3000",
        mask=_mask,
    )
    masked = boundary.client._mask(data="raw-ssn-123-45-6789")
    assert masked == "REDACTED"
    assert "123-45-6789" not in str(masked)


def test_no_direct_langfuse_imports_outside_the_boundary():
    """Boundary rule (mirrors tests/test_agt_boundary.py's AGT scan): only
    ``_langfuse.py`` may import ``langfuse`` anywhere in ``src/``."""
    violations: list[tuple[Path, str]] = []
    for py_file in _SRC.rglob("*.py"):
        if py_file.name == "_langfuse.py":
            continue
        tree = ast.parse(py_file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "langfuse":
                        violations.append((py_file, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] == "langfuse":
                    violations.append((py_file, node.module))
    assert not violations, f"Direct langfuse imports found outside _langfuse.py: {violations}"
