# Spike #31 — AGT `PromptInjectionDetector` config surface (agent-os-kernel 3.7.0)

Probed against the **pinned** installed wheel (`agent-os-kernel==3.7.0`,
`agentmesh-platform==3.7.0`) on 2026-06-20. Investigation only — no production
code. Boundary rule intact: probe lived in `spike/`, not `src/`.

Module: `agent_os.prompt_injection`. Public members:
`PromptInjectionDetector`, `DetectionConfig`, `PromptInjectionConfig`,
`DetectionResult`, `InjectionType`, `ThreatLevel`, `AuditRecord`,
`load_prompt_injection_config`.

## AC1 — Does the detector accept an explicit rules config? How?

**Yes — via a dataclass, not a path or dict.** Two distinct, independent config params:

```python
PromptInjectionDetector(
    self,
    config: DetectionConfig | None = None,          # positional: runtime tuning
    *,
    injection_config: PromptInjectionConfig | None = None,  # kw-only: the RULE SET
) -> None
```

- `injection_config` (`PromptInjectionConfig`) is **the supported path for
  customising the detection rule set** (per the `__init__` docstring). When
  provided, the detector iterates these patterns instead of the module-level
  sample defaults. Built from YAML via `load_prompt_injection_config(path)`.
- `config` (`DetectionConfig`) is orthogonal runtime tuning:
  `sensitivity='balanced'` (str), `custom_patterns: list[re.Pattern]`,
  `blocklist: list[str]`, `allowlist: list[str]`.

`load_prompt_injection_config(path: str) -> PromptInjectionConfig`
reads a YAML file with a `detection_patterns` section.
**Raises** `FileNotFoundError` (missing file) or `ValueError` (missing required
sections) — both usable as the fail-closed startup trigger (#33/#36): catch →
refuse to start, never silently fall back to sample rules.

`PromptInjectionConfig` fields: `direct_override_patterns`, `delimiter_patterns`,
`role_play_patterns`, `context_manipulation_patterns`, `multi_turn_patterns`,
`encoding_patterns`, `base64_pattern`, `suspicious_decoded_keywords`,
`sensitivity_thresholds: dict[str,float]`, `sensitivity_min_threat: dict[str,str]`,
`disclaimer`.

## AC2 — Sample-rule warning: condition + how to detect "running on sample rules"

Constructing with **`injection_config=None`** (i.e. the bare `PromptInjectionDetector()`)
emits at construction time:

```
UserWarning: PromptInjectionDetector() uses built-in sample rules that may not
cover all prompt injection techniques. For production use, load an explicit
config with load_prompt_injection_config() and pass it as injection_config=.
See examples/policies/prompt-injection-safety.yaml for a sample configuration.
```

- **Detect "on sample rules"** = the `UserWarning` fires ⇔ `injection_config is None`.
- Passing an explicit `injection_config` suppresses the warning.
- **Design implication:** the fail-closed startup must (a) require an explicit
  `injection_config`, and (b) treat the bare-default path as a configuration
  error — promote that `UserWarning` to a hard refusal (`GovernanceNotConfigured`)
  rather than letting it ship sample rules. A sample reference policy exists at
  `examples/policies/prompt-injection-safety.yaml` (in the AGT wheel) and is a
  starting point for our own pinned rule set.

## AC3 — `detect()` signature and `DetectionResult` fields

```python
detect(self, text: str, source: str = 'unknown',
       canary_tokens: list[str] | None = None) -> DetectionResult
# also: detect_batch(...) exists
```

`DetectionResult` (dataclass):

| field | type | note |
|-------|------|------|
| `is_injection` | `bool` | the deny trigger |
| `threat_level` | `ThreatLevel` | `NONE/LOW/MEDIUM/HIGH/CRITICAL` |
| `injection_type` | `InjectionType \| None` | **singular**, not a list |
| `confidence` | `float` | 0.0–1.0 |
| `matched_patterns` | `list[str]` | **may echo pattern fragments / decoded input — do NOT forward to audit (D6 no-echo)** |
| `explanation` | `str` | human string; same no-echo caution |

`InjectionType`: `DIRECT_OVERRIDE, DELIMITER_ATTACK, ENCODING_ATTACK, ROLE_PLAY,
CONTEXT_MANIPULATION, CANARY_LEAK, MULTI_TURN_ESCALATION`.
`ThreatLevel`: `NONE/LOW/MEDIUM/HIGH/CRITICAL`.

Observed live: benign text → `is_injection=False, threat_level=NONE,
injection_type=None`. `"ignore all previous instructions…"` →
`is_injection=True, threat_level=HIGH, injection_type=DIRECT_OVERRIDE`.

**D6 note:** for the deny reason, name the offending FIELD + `injection_type` +
`threat_level` only. Never put `matched_patterns` or `explanation` (which can
contain the attacker payload / decoded bytes) into the deny reason or audit.

## AC4 — Is one detector instance safe to reuse across calls?

**Detection is pure; the built-in audit log is not bounded.**

- **Detection logic is stateless / cross-call-safe.** `_check_multi_turn` matches
  `multi_turn_patterns` against the *current* `text` only — it does NOT read any
  prior-call history. `_detect_impl` never reads `self._audit_log`. So the verdict
  for a given input is independent of prior calls and of other subjects → **no
  cross-subject state bleed in the verdict.** One instance can be reused for
  correctness, and reuse is the right call (compiling the pattern sets per call is
  wasteful).
- **BUT `audit_log` is a plain `list` (not a bounded `deque`)** and `_record_audit`
  appends to it on **every** `detect()` call (observed length 1 → 2 across two
  calls). A long-lived reused instance therefore leaks memory without bound.

**Design implication (injection lane, #33/#36):** construct **one** detector at
`AGTBoundary` build time with an explicit `injection_config` (reuse it — detection
is pure), but do NOT rely on its internal `audit_log` (we have our own audit seam)
and **mitigate the unbounded `list`** — clear it after each `detect()`, or confirm
whether a `DetectionConfig` field disables internal auditing. Track the
unbounded-`audit_log` mitigation alongside the existing bounded-cache work (A2).

## Confirmed assumptions vs. the design

| Design (Part 1) assumed | Reality | Status |
|---|---|---|
| `PromptInjectionDetector(config=...)` rule-loading | rule set is `injection_config=`, not `config=` | **corrected** |
| bare default ships SAMPLE rules + warns | confirmed `UserWarning` ⇔ `injection_config is None` | confirmed |
| fail-closed startup against config load | `load_prompt_injection_config` raises `FileNotFoundError`/`ValueError` → catchable | confirmed |
| reuse one detector instance | safe for the verdict; mitigate unbounded `audit_log` | **qualified** |
