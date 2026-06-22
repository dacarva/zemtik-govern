"""Prompt-injection defense — mandatory, fail-closed, folded into the policy seam.

AGT owns the detection (``PromptInjectionDetector``); this module owns the
governance contract around it (#36):

- **One pluggable seam.** :class:`InjectionClassifier` is the Protocol (P5); the
  shipped concrete implementation is :class:`AgtInjectionClassifier`, AGT-backed
  through :class:`~zemtik_govern._agt.AGTBoundary`.
- **Guards the SELECTED engine.** :class:`GuardedEngine` wraps whatever
  ``ZemtikGovern._select_engine()`` returns — primary AND killswitch fallback — so
  the injection check is not bypassed during the very emergency it most needs to
  cover (T1). It still presents as a :class:`PolicyEngine`, so it folds into the
  policy seam (premise P2): an injection hit is a *policy* deny.
- **Strict, mostly off-loop projection.** The payload is projected to text with a
  STRICT ``json.dumps`` (no ``default=str``), so an attacker-controlled
  ``__str__`` is never invoked (T5). Oversized payloads are denied without
  scanning; large ones are scanned on a dedicated bounded thread pool (a scan
  storm cannot starve the shared default executor, A3); small ones are scanned
  inline to skip the thread-hop on latency-sensitive voice payloads.
- **D6 no-echo.** A deny names the offending FIELD, the injection type, and the
  threat level — never the raw payload, matched patterns, or decoded bytes.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ._agt import AGTBoundary
from .context import GovernanceContext
from .protocols import Decision, PolicyEngine

# Default size gates (characters of projected JSON). Small payloads scan inline;
# larger ones offload to the bounded pool; anything past the hard cap is denied
# unscanned (an unbounded scan is itself a DoS surface).
_DEFAULT_INLINE_THRESHOLD = 4096
_DEFAULT_MAX_PROJECTED_CHARS = 262_144  # 256 KiB of projected text
_DEFAULT_MAX_WORKERS = 4

# Hard cap on payload nesting depth for the size estimate. A pathologically deep
# field would otherwise raise ``RecursionError`` in the recursive walk before the
# size gate ever fires. Denying it explicitly (raise → fail-closed system deny)
# keeps a deep payload from being an uncaught stack trace on the policy seam.
_MAX_PAYLOAD_DEPTH = 64


@dataclass(frozen=True)
class InjectionVerdict:
    """The no-echo-safe outcome of screening one request. ``field`` names the
    offending payload field; ``injection_type``/``threat_level`` are AGT's
    classification. NEVER carries the raw payload (D6)."""

    is_injection: bool
    field: str | None = None
    injection_type: str | None = None
    threat_level: str | None = None
    reason: str | None = None  # safe summary; set for oversized/none cases


@runtime_checkable
class InjectionClassifier(Protocol):
    """Screens a frozen context for prompt injection. Async because the concrete
    implementation may offload the scan to a thread pool."""

    async def screen(self, ctx: GovernanceContext) -> InjectionVerdict: ...


def _project(value: Any) -> str:
    """Strict JSON projection: NO ``default=`` (an un-serialisable leaf raises
    ``TypeError`` instead of invoking its ``__str__``) and ``allow_nan=False``.
    A projection failure propagates and fails closed upstream (system deny)."""
    return json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":"))


def _estimate_size(value: Any, _depth: int = 0) -> int:
    """A cheap upper-ish bound on projected size that NEVER calls ``__str__`` on an
    unknown object (so the size gate cannot trigger attacker code). Used only to
    route inline-vs-offload-vs-deny; the authoritative bytes come from
    :func:`_project`. Depth is bounded (``_MAX_PAYLOAD_DEPTH``) so a deeply nested
    field is an explicit deny (raise → fail-closed), not a ``RecursionError``."""
    if _depth > _MAX_PAYLOAD_DEPTH:
        raise ValueError(f"payload nesting exceeds maximum depth {_MAX_PAYLOAD_DEPTH}")
    if isinstance(value, str):
        return len(value) + 2
    if isinstance(value, bool) or value is None:
        return 5
    if isinstance(value, (int, float)):
        return 24
    if isinstance(value, Mapping):
        return 2 + sum(
            len(str(k)) + 4 + _estimate_size(v, _depth + 1) for k, v in value.items()
        )
    if isinstance(value, (list, tuple)):
        return 2 + sum(_estimate_size(v, _depth + 1) + 1 for v in value)
    return 64  # unknown/non-native leaf: a placeholder; _project will reject it


class AgtInjectionClassifier:
    """The one shipped :class:`InjectionClassifier`: AGT's detector behind the
    boundary, with strict projection and a dedicated bounded thread pool."""

    def __init__(
        self,
        boundary: AGTBoundary,
        rules_path: str | None = None,
        *,
        inline_threshold: int = _DEFAULT_INLINE_THRESHOLD,
        max_projected_chars: int = _DEFAULT_MAX_PROJECTED_CHARS,
        max_workers: int = _DEFAULT_MAX_WORKERS,
        executor: ThreadPoolExecutor | None = None,
    ) -> None:
        self._boundary = boundary
        # Build the detector ONCE (detection is pure; reuse is correct and cheaper
        # than recompiling patterns per call). ``rules_path=None`` uses AGT's own
        # vetted defaults (no in-repo file to maintain); a path loads a custom rule
        # file, and a missing/bad file raises here — surfaced as
        # GovernanceNotConfigured by the caller.
        self._detector = boundary.prompt_injection_detector(rules_path)
        self._inline_threshold = inline_threshold
        self._max_projected_chars = max_projected_chars
        # A DEDICATED bounded pool: a slow-scan storm exhausts THIS pool, never the
        # shared default executor that unrelated awaits depend on (A3 / Codex #4).
        self._executor = executor or ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="zemtik-injection"
        )

    async def screen(self, ctx: GovernanceContext) -> InjectionVerdict:
        """Screen each top-level payload field; return on the first injection hit.

        Per-field so the deny can NAME the offending field (D6). Nested structure is
        caught because the field's value is projected whole and the patterns match
        the projected JSON text. The payload is THAWED first (the frozen context
        holds ``MappingProxyType``/tuples that ``json.dumps`` cannot serialise)."""
        payload = ctx.to_dict()["payload"]
        for field_name, value in payload.items():
            verdict = await self._screen_field(str(field_name), value)
            if verdict.is_injection:
                return verdict
        return InjectionVerdict(is_injection=False, reason="clean")

    async def _screen_field(self, field_name: str, value: Any) -> InjectionVerdict:
        estimate = _estimate_size(value)
        if estimate > self._max_projected_chars:
            # Oversized: deny WITHOUT scanning. An unbounded scan is a DoS lever;
            # refuse rather than burn the pool on an attacker-sized blob.
            return InjectionVerdict(
                is_injection=True,
                field=field_name,
                injection_type="oversized",
                threat_level="high",
                reason="payload field exceeds the maximum screenable size",
            )
        if estimate <= self._inline_threshold:
            # Small (e.g. a voice turn): project + scan inline, skip the thread-hop.
            text = _project(value)
            is_inj, itype, threat = self._boundary.screen_text(
                self._detector, text, source=field_name
            )
        else:
            # Large: project AND scan INSIDE the dedicated pool (T5 — projection is
            # off-loop too, so a big json.dumps never blocks the event loop).
            loop = asyncio.get_running_loop()
            is_inj, itype, threat = await loop.run_in_executor(
                self._executor, self._project_and_scan, value, field_name
            )
        if is_inj:
            return InjectionVerdict(
                is_injection=True,
                field=field_name,
                injection_type=itype,
                threat_level=threat,
            )
        return InjectionVerdict(is_injection=False, field=field_name, reason="clean")

    def _project_and_scan(
        self, value: Any, field_name: str
    ) -> tuple[bool, str | None, str | None]:
        """Off-loop worker: strict projection THEN detection, both in the pool."""
        text = _project(value)
        return self._boundary.screen_text(self._detector, text, source=field_name)


_INJECTION_ENFORCE = "enforce"
_INJECTION_SHADOW = "shadow"

# Module logger for the shadow-mode would-deny observation (D10). Named for the
# package so it shares the operator's existing zemtik-govern log handler.
_LOG = logging.getLogger("zemtik_govern")


class GuardedEngine:
    """Wraps a :class:`PolicyEngine` so every evaluation is injection-screened
    first. An injection hit short-circuits to a POLICY deny (it never reaches the
    inner engine); a clean payload delegates to the inner engine unchanged.

    Because the wrap happens around the engine ``_select_engine()`` returns, BOTH
    the primary policy and the killswitch fallback are guarded — the screen cannot
    be bypassed by engaging the killswitch (T1).

    Per-guard shadow (D10): in ``mode == "shadow"`` an injection hit is OBSERVED
    (the would-deny is logged) but NOT enforced — the payload still delegates to
    the inner engine. This is the observe-then-enforce upgrade path scoped to the
    injection guard alone; the would-deny still names the field only (D6), never
    the raw payload, even in the log."""

    def __init__(
        self,
        inner: PolicyEngine,
        classifier: InjectionClassifier,
        *,
        mode: str = _INJECTION_ENFORCE,
    ) -> None:
        self._inner = inner
        self._classifier = classifier
        self._mode = mode

    async def evaluate(self, ctx: GovernanceContext) -> Decision:
        verdict = await self._classifier.screen(ctx)
        if verdict.is_injection:
            # D6 no-echo: name the field + type + threat only; NEVER the payload.
            reason = (
                f"prompt injection detected in field {verdict.field!r} "
                f"(type={verdict.injection_type}, threat={verdict.threat_level})"
            )
            if self._mode == _INJECTION_SHADOW:
                # Observe-only: record the would-deny (no payload echo) and let the
                # request through to the inner engine. The operator watches these
                # for a release, then flips injection.mode to enforce.
                _LOG.warning("injection WOULD deny (shadow): %s", reason)
                return await self._inner.evaluate(ctx)
            return Decision(
                allowed=False,
                action="deny",
                matched_rule=None,
                reason=reason,
                denial_kind="policy",
            )
        return await self._inner.evaluate(ctx)
