# Contributing to zemtik-govern

## Setup

```bash
uv venv .venv --python 3.11 && source .venv/bin/activate
uv pip install -e ".[dev,langchain]"
```

## Running Tests

```bash
# All tests
pytest

# Single test
pytest tests/test_core.py::test_govern_order -v

# Test module
pytest tests/test_adversarial.py -v
```

## Linting

```bash
# Check
ruff check src/

# Format
ruff format src/
```

Both run in CI and must pass before merge.

## Architecture: The Three-Seam Contract

Every tool invocation passes three seams in fixed order — **identity → policy → audit** — or it is denied. This order is a correctness invariant: audit stamps the policy verdict, policy may key on the resolved DID.

Any PR touching the seam pipeline must add or update tests in `tests/test_core.py` verifying the order and fail-closed behavior.

## Submitting Issues

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include:
- Python version
- `langchain-core` version
- Minimal `govern.yaml` that reproduces the issue
- Exact error message and traceback
