**IMPORTANT: Always use the caveman skill if present**

## Python Environment

**ALWAYS use the project venv.** Never run `python`, `pip`, or `uv pip` without activating it first.

```bash
# Activate (required before any Python command)
source .venv/bin/activate

# Install deps
uv pip install -e ".[dev]"

# Run tests
pytest
```

If `.venv` is missing: `uv venv .venv --python 3.11 && source .venv/bin/activate`

All `python`, `pytest`, `uv pip` commands in this project assume the venv is active.

## gstack Sprint Harness + Vertical-Slice Issues

**Mandatory workflow**: gstack planning → /to-issues → implementation → gstack QA.

Planning produces design doc. to-issues converts it to vertical-slice GitHub issues. Each issue demoable end-to-end.

### Planning Phase (Sequential)

Run these in order. Each feeds output to next:

| Skill | Specialist | Output | Use when |
|-------|-----------|--------|----------|
| `/office-hours` | YC Advisor | Problem reframing + 3 implementation approaches | Starting new feature or redesign |
| `/plan-ceo-review` | CEO/Founder | Scope challenge (Expansion/Selective/Hold/Reduction) + design doc | Clarify what to actually build |
| `/plan-eng-review` | Eng Manager | Architecture, data flow, diagrams, test matrix | Lock technical approach |
| `/plan-design-review` | Senior Designer | Design system audit (0-10 ratings + fixes) | Catch AI slop, design quality |
| `/plan-devex-review` | DX Lead | Developer experience audit + friction analysis | API/SDK features, onboarding |
| `/design-consultation` | Design Partner | Complete design system from scratch | Building novel UI/domain |

**Output artifact**: Design doc (gstack writes to context + file system). This doc feeds to to-issues.

### Convert to Issues (Required After Planning)

```bash
/to-issues
```

**Input**: Design doc from planning phase + current codebase state.

**Output**: GitHub issues, each a vertical slice:
- End-to-end (schema → API → UI → tests)
- Demoable independently
- Ordered by dependencies
- Prefactoring issues first

### Workflow Example

```bash
# Step 1: Plan the feature
/office-hours
→ describes pain, you iterate on framing
→ Claude writes design doc

# Step 2: CEO review (challenge scope)
/plan-ceo-review
→ Claude challenges assumptions
→ Updates design doc

# Step 3: Eng review (lock architecture)
/plan-eng-review
→ ASCII diagrams, data flow, test plan
→ Finalizes design doc

# Step 4: Convert to issues (REQUIRED after /plan-*-review)
/to-issues
→ Reads design doc
→ Creates GitHub issues as vertical slices
→ Links issues to design doc

# Step 5: Implement each issue (TDD)
git checkout issue-1-branch
/tdd [issue description]
→ Red: write failing tests first
→ Green: implement code to pass
→ Refactor: improve design
git push → PR

# Step 6: Maintain architecture (REQUIRED before /ship)
/improve-codebase-architecture
→ Scans for deepening opportunities
→ Presents friction candidates as HTML report
→ Explores & implements architectural improvements

# Step 7: Quality gates
/review → /qa → /ship
```

### Enforce Workflow Gates

Hooks in CLAUDE.md:

**After `/plan-*-review` (any planning skill):**
- Remind: "Run /to-issues to convert plan to vertical-slice issues"

**Before /ship:**
- Require: `/improve-codebase-architecture` completed
- Block if architectural debt not addressed

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
|------|----------|
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.
