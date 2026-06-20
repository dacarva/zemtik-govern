---
name: Bug Report
about: Report a bug in zemtik-govern
labels: bug
---

## Environment

- **Python version**: <!-- e.g. 3.11.6 -->
- **zemtik-govern version**: <!-- e.g. 0.1.0 -->
- **langchain-core version**: <!-- e.g. 0.3.x -->
- **langgraph version** (if applicable): <!-- e.g. 0.2.x -->

## govern.yaml (minimal snippet)

```yaml
# Paste the smallest govern.yaml that triggers the bug
mode: strict
audit_sink: memory
rules: []
```

## Minimal Reproduce

```python
# Paste the shortest Python snippet that reproduces the bug
from zemtik_govern.langchain import govern_tool
...
```

## Expected Behavior

<!-- What should have happened? -->

## Actual Behavior

<!-- What actually happened? Include the full traceback. -->

```
Traceback (most recent call last):
  ...
```

## Additional Context

<!-- Any other context, screenshots, or logs. -->
