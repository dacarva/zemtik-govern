## Summary

<!-- Describe what this PR does and why. -->

## Type of change

- [ ] Bug fix
- [ ] New feature / enhancement
- [ ] Refactor (no behaviour change)
- [ ] Documentation
- [ ] Test

## Checklist

- [ ] `ruff check src/` passes
- [ ] `ruff format src/` applied
- [ ] `pytest` passes locally
- [ ] If this PR touches the seam pipeline (`govern()`, `IdentityProvider`, `PolicyEngine`, `AuditSink`): tests in `tests/test_core.py` verify the fixed order and fail-closed behaviour
- [ ] If this PR touches `policy.py` (the deny-by-default override when `matched_rule is None`): the `docs/adr/001-agt-pins.md` conformance test still passes
- [ ] CHANGELOG.md updated under `[Unreleased]`

## Related issues

<!-- Closes # -->
