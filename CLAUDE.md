## Workflow Reference

**Source of truth**: See AGENTS.md for complete workflow, roles, and implementation guide.

**Skill dependencies**: skills-lock.json declares required skills (gstack, tdd, to-issues, improve-codebase-architecture). Agents auto-fetch from github.

**Enforcement hooks** (add to .claude/settings.json):

```json
{
  "hooks": {
    "after-skill": [
      {
        "skills": ["/plan-ceo-review", "/plan-eng-review", "/plan-design-review", "/plan-devex-review"],
        "action": "notify",
        "message": "✅ Planning complete. Next: run `/to-issues` to convert design doc to vertical-slice GitHub issues"
      }
    ],
    "before-skill": [
      {
        "skills": ["/ship"],
        "requires-completed": ["tdd-implementation", "improve-codebase-architecture"],
        "action": "block",
        "message": "Pre-ship checklist:\n1. Run `/tdd` for each issue (red-green-refactor)\n2. Run `/improve-codebase-architecture` for deepening opportunities\n3. Run `/review` and `/qa`"
      }
    ],
    "on-branch-create": [
      {
        "action": "notify",
        "message": "📝 Starting implementation: use `/tdd` skill for test-driven development (red → green → refactor)"
      }
    ]
  }
}
```
