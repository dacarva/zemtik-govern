"""Output governance — the post-invocation rail seam, fail-closed (issue #39, C0).

zemtik governs the *request* (identity → policy → audit) and then the tool runs.
This module governs what comes **back**: after a governed tool returns, its value
is projected to text and screened by the configured output rails INSIDE
``proxy()``'s effect path. A read-classified tool whose output trips a rail has
its value withheld and :class:`OutputGovernanceDenied` raised.

C0 is deliberately concrete: ONE regex PII rail implementing
:class:`OutputClassifier` directly — NO provider abstraction, NO ``Rail`` protocol,
NO ensemble combiner (all deferred to C1, see the design doc). The seam is the
spine; the abstraction is generalized only once a second provider is real.

No-echo (D6): a verdict names the firing rail and a safe summary, NEVER the raw
matched text. Linear-time, anchored patterns only (no nested quantifiers) so a
crafted 256KB output cannot trigger catastrophic backtracking (ReDoS).
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .context import GovernanceContext

# Reuse the input-side projection bounds: a tool return larger than this (projected
# chars) or deeper than this nesting is denied unscanned — an unbounded scan is a
# DoS lever, and the fail-closed direction is to refuse, not to pass it through.
_DEFAULT_MAX_PROJECTED_CHARS = 262_144  # 256 KiB of projected text
_MAX_OUTPUT_DEPTH = 64

# Tool I/O classification. An action absent from the map defaults to ``write``
# (most restrictive — fail-closed): an unclassified tool is treated as
# already-effected, forcing the operator to classify it deliberately.
IO_READ = "read"
IO_WRITE = "write"
_DEFAULT_IO = IO_WRITE


def resolve_io(tool_io_map: Mapping[str, str] | None, action: str) -> str:
    """Classify *action* as ``read`` or ``write``. Unmapped → ``write`` (fail-closed)."""
    if not tool_io_map:
        return _DEFAULT_IO
    return tool_io_map.get(action, _DEFAULT_IO)


class OutputExtractionError(Exception):
    """The tool return could not be safely projected to text for screening. Caught
    at the seam and turned into a fail-closed output deny — an unscreenable value
    is never passed through. Names the offending return type (no value echo)."""


def extract_text(result: Any) -> str:
    """Project a tool return value to the text the rails screen, fail-closed.

    The C0 text-extraction contract (a documented product boundary):
    - ``str`` is screened directly; ``bytes`` is strict-UTF-8 decoded.
    - A JSON-native value (dict/list/number/bool/None of JSON-native leaves) is
      projected with a strict ``json.dumps`` (no ``default=`` — an attacker
      ``__str__`` is never invoked), bounded by depth.
    - Anything else (a custom object, a generator/iterator, a non-UTF-8 bytes) is
      a fail-closed deny: raise :class:`OutputExtractionError` naming the type.

    The per-action ``to_text()`` extractor hook for richer returns is deferred to
    C1 (TODOS.md); until then an unmapped return type denies rather than guesses.
    """
    if isinstance(result, str):
        text = result
    elif isinstance(result, bytes):
        try:
            text = result.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OutputExtractionError(
                "tool returned non-UTF-8 bytes; cannot screen output "
                "(see the per-action to_text hook, deferred to C1)"
            ) from exc
    elif _is_json_native(result):
        # Estimate the projected size BEFORE json.dumps. A wide (not deep) tree —
        # e.g. list(range(2_000_000)) — passes the depth-only _is_json_native and
        # would materialise a multi-MB string, OOM-ing the governor, before any
        # post-hoc len() guard could fire. The estimate walks cheaply (no string
        # built) and denies oversized input up front, so the projection itself is
        # never the DoS lever. Mirrors injection.py's pre-projection size gate.
        if _estimate_size(result) > _DEFAULT_MAX_PROJECTED_CHARS:
            raise OutputExtractionError(
                "tool output exceeds the maximum screenable size "
                f"({_DEFAULT_MAX_PROJECTED_CHARS} chars)"
            )
        text = json.dumps(result, sort_keys=True, allow_nan=False, separators=(",", ":"))
    else:
        raise OutputExtractionError(
            f"tool returned a {type(result).__name__}, which the output seam "
            "cannot project to text; classify it via the per-action to_text hook "
            "(deferred to C1) or return str/bytes/JSON-native"
        )
    # NFKC-normalise the SCREENED text (not the returned value) so a compatibility
    # variant — fullwidth ＠ (U+FF20), ligatures, width-variants — folds to its
    # canonical form before the rails scan. Closes a fail-open gap where Unicode
    # compatibility forms slipped past the ASCII patterns. Confusable homoglyphs
    # across scripts (Cyrillic а vs Latin a) are NOT caught by NFKC — that is an
    # inherent regex-detection limit, addressed by the Presidio provider in C1.
    text = unicodedata.normalize("NFKC", text)
    if len(text) > _DEFAULT_MAX_PROJECTED_CHARS:
        raise OutputExtractionError(
            "tool output exceeds the maximum screenable size "
            f"({_DEFAULT_MAX_PROJECTED_CHARS} chars)"
        )
    return text


def _estimate_size(value: Any, _depth: int = 0) -> int:
    """A cheap upper-ish bound on projected JSON size that builds NO string and
    never calls ``__str__`` on an unknown object. Used only to deny oversized
    returns before :func:`json.dumps` materialises them. Depth-bounded so a deep
    tree is a fail-closed deny (raise) rather than a ``RecursionError``."""
    if _depth > _MAX_OUTPUT_DEPTH:
        raise OutputExtractionError(
            f"tool output nesting exceeds maximum depth {_MAX_OUTPUT_DEPTH}"
        )
    if isinstance(value, str):
        return len(value) + 2
    if isinstance(value, bool) or value is None:
        return 5
    if isinstance(value, (int, float)):
        return 24
    if isinstance(value, Mapping):
        return 2 + sum(len(str(k)) + 4 + _estimate_size(v, _depth + 1) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return 2 + sum(_estimate_size(v, _depth + 1) + 1 for v in value)
    return 64  # unknown leaf; _is_json_native already gated these out


def _is_json_native(value: Any, _depth: int = 0) -> bool:
    """True if *value* is a JSON-native tree within the depth bound. A non-native
    leaf or an over-deep tree returns False, routing the value to a fail-closed
    deny rather than a lossy stringify."""
    if _depth > _MAX_OUTPUT_DEPTH:
        return False
    if isinstance(value, str) or isinstance(value, bool) or value is None:
        return True
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, Mapping):
        return all(isinstance(k, str) and _is_json_native(v, _depth + 1) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return all(_is_json_native(v, _depth + 1) for v in value)
    return False


@dataclass(frozen=True)
class OutputVerdict:
    """The no-echo-safe outcome of screening one tool return. ``rail`` names the
    firing rail; ``reason`` is a safe summary. NEVER carries the matched text (D6)."""

    is_match: bool
    rail: str | None = None
    reason: str | None = None


@runtime_checkable
class OutputClassifier(Protocol):
    """Screens a tool's projected output text for a class of leak. Async because a
    concrete implementation may offload to a thread pool (C1)."""

    name: str

    async def screen(self, text: str, ctx: GovernanceContext) -> OutputVerdict: ...


# PII patterns: anchored shapes with BOUNDED quantifiers only — no nested
# quantifiers and no unbounded ``+`` runs that an adversarial input could force
# into quadratic backtracking. Bounding every repeat to a constant (the real RFC
# field limits) caps the work per anchor position, so screening a crafted 256KB
# output stays linear in the input length (ReDoS-safe). Each is a single scan.
_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        # local@domain.tld, every segment length-capped to its RFC bound.
        "email",
        re.compile(
            r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,255}(?:\.[A-Za-z0-9\-]{1,63}){0,8}"
            r"\.[A-Za-z]{2,24}"
        ),
    ),
    (
        # US SSN: NNN-NN-NNNN, digit-bounded so it does not match inside a longer run.
        "ssn",
        re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    ),
    (
        # Payment-card-shaped: 13–19 digits, optional space/dash grouping. A broad
        # shape (no Luhn check) — the rail errs toward denial (fail-closed); Presidio
        # adds Luhn-validated precision in C1. Bounded repetition keeps it linear.
        "card",
        re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?<=\d)"),
    ),
    (
        # North-American phone: optional +1, common separators, fixed digit groups.
        "phone",
        re.compile(r"(?<!\d)(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}(?!\d)"),
    ),
)


class RegexPIIClassifier:
    """The C0 default PII rail: a concrete :class:`OutputClassifier`, no provider
    indirection. Scans projected output text for common PII shapes with
    linear-time anchored regexes.

    ``threshold`` is honored per-provider (design Q2): a regex hit is a binary
    match (confidence ``1.0``), so any ``threshold <= 1.0`` lets it fire and a
    ``threshold > 1.0`` is unsatisfiable — the field is wired for the C1 ensemble
    where scoring providers (e.g. Presidio) surface real confidences.

    ``mode`` (``enforce`` | ``shadow``) is the per-rail stance the output seam
    reads: a ``shadow`` rail's match is observed (``output_would_deny``) but not
    enforced, so an operator can watch a new rail for a release before flipping it
    to ``enforce``. The seam reads it via the ``mode`` attribute.
    """

    name = "pii"

    def __init__(self, *, threshold: float = 0.0, mode: str = "enforce") -> None:
        self._threshold = threshold
        #: Per-rail stance read by the output seam (``enforce`` | ``shadow``).
        self.mode = mode

    async def screen(self, text: str, ctx: GovernanceContext) -> OutputVerdict:
        for kind, pattern in _PII_PATTERNS:
            if pattern.search(text) is not None:
                # No-echo: name the rail + the PII kind, never the matched value.
                return OutputVerdict(
                    is_match=True,
                    rail=self.name,
                    reason=f"output contains {kind}-shaped PII",
                )
        return OutputVerdict(is_match=False, rail=self.name, reason="clean")


@dataclass(frozen=True)
class RedactedOutput:
    """Returned by ``proxy()`` when a WRITE-classified tool's output trips an
    output rail in ENFORCE mode. The side effect already executed; this is
    post-hoc scrubbing, not prevention.

    **The sentinel contract — two halves:**

    SPARE (never raises):
        ``str()``, ``repr()``, ``format()`` return the redaction marker
        ``"<output redacted: audit_id=…>"`` so structured logging (e.g. JSON
        serialisers that call ``default=str``) never crashes when they
        encounter the sentinel.

    POISON (always raises :class:`~zemtik_govern.errors.RedactedOutputAccessError`):
        Attribute access (other than ``audit_id``), item access (``[]``), and
        iteration (``for``/``unpack``) raise ``RedactedOutputAccessError``
        carrying the ``audit_id``. A caller that accidentally tries to *use*
        the redacted value is loudly signaled rather than silently receiving an
        empty or wrong result.

    **Equality is type-only:** two ``RedactedOutput`` instances with different
    ``audit_id`` values compare equal (and hash equal) because the only
    semantically meaningful fact is that an output was redacted — distinguishing
    *which* redaction by id would falsely suggest the caller can act on it.

    ``audit_id`` back-links to the ``output_denied_redacted`` audit row (#40)
    so an operator can correlate a sentinel returned to a caller with the
    HIGH-severity trail entry written at the moment of redaction (D9).
    """

    audit_id: str

    # --- SPARE methods: return a safe marker, never raise ---------------------

    def __str__(self) -> str:
        return f"<output redacted: audit_id={self.audit_id}>"

    def __repr__(self) -> str:
        return f"<output redacted: audit_id={self.audit_id}>"

    def __format__(self, format_spec: str) -> str:
        # Honour the spare contract even when a format spec is supplied; the
        # spec itself is ignored — the caller always gets the marker text.
        return f"<output redacted: audit_id={self.audit_id}>"

    # --- POISON methods: raise RedactedOutputAccessError ----------------------

    def __getattr__(self, name: str) -> object:
        # ``__getattr__`` fires ONLY for attributes not found through the normal
        # lookup chain (i.e. ``__dict__`` / class). On a frozen dataclass,
        # ``audit_id`` is found via ``__dict__`` so this hook never fires for
        # it. Any OTHER attribute access — e.g. ``.text``, ``.data``,
        # ``.content`` — lands here and is poisoned.
        #
        # We must NOT access ``self.audit_id`` normally here (that would
        # recurse back into ``__getattr__`` if the field is not yet set during
        # ``__init__``). Use ``object.__getattribute__`` to bypass the hook.
        try:
            aid = object.__getattribute__(self, "audit_id")
        except AttributeError:
            aid = None
        from .errors import RedactedOutputAccessError
        raise RedactedOutputAccessError(audit_id=aid)

    def __getitem__(self, key: object) -> object:
        # Item access (``sentinel["key"]``, ``sentinel[0]``) is poison.
        try:
            aid = object.__getattribute__(self, "audit_id")
        except AttributeError:
            aid = None
        from .errors import RedactedOutputAccessError
        raise RedactedOutputAccessError(audit_id=aid)

    def __iter__(self) -> object:
        # Iteration (``for x in sentinel`` / unpacking) is poison.
        try:
            aid = object.__getattribute__(self, "audit_id")
        except AttributeError:
            aid = None
        from .errors import RedactedOutputAccessError
        raise RedactedOutputAccessError(audit_id=aid)

    # --- Equality is type-only ------------------------------------------------

    def __eq__(self, other: object) -> bool:
        # Two sentinels with different audit_ids are still "equal" — the only
        # semantically meaningful fact is that an output was redacted, not
        # which one. Callers must not branch on audit_id equality.
        return isinstance(other, RedactedOutput)

    def __hash__(self) -> int:
        # Consistent with the type-only equality: all instances share one hash.
        return hash(RedactedOutput)


# C0 ships exactly one output rail. The registry maps a configured rail name to its
# concrete classifier through this table; a configured rail with no entry is a
# fail-closed startup error (never a silently-skipped rail). C1 grows this into the
# provider-neutral Rail registry.
_RAIL_BUILDERS = {
    RegexPIIClassifier.name: lambda threshold, mode: RegexPIIClassifier(
        threshold=threshold, mode=mode
    ),
}


def build_output_classifier(
    name: str, *, threshold: float = 0.0, mode: str = "enforce"
) -> OutputClassifier:
    """Build the concrete :class:`OutputClassifier` for a configured rail *name*.

    Raises :class:`ValueError` for an unknown rail so the caller (registry) can
    fail closed at startup — a configured rail C0 cannot build must not be silently
    dropped, leaving an operator believing output is screened when it is not."""
    builder = _RAIL_BUILDERS.get(name)
    if builder is None:
        raise ValueError(
            f"unknown output rail {name!r}; C0 ships {sorted(_RAIL_BUILDERS)} "
            "(more rails arrive with the C1 ensemble)"
        )
    return builder(threshold, mode)
