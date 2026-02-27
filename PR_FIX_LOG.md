# PR Fix Log

Append-only record of security fixes, architectural decisions, and regressions
caught in review. Used by CI gate `make gotchas-check` and by auditors to
verify that known issues have not been reintroduced.

Format per entry:
```
## FIX-NNN — <short title>
PR: #<number> | Date: YYYY-MM-DD | Severity: BLOCKER|HIGH|MEDIUM|LOW
GOTCHA: G-NNN (if captured in GOTCHAS.md)
<one paragraph: what was wrong, what changed, why it cannot regress>
Test/gate: <pytest path or CI job name that prevents regression>
```

---

## FIX-001 — Initial security audit baseline

PR: N/A | Date: 2026-02-27 | Severity: N/A
GOTCHA: G-001 through G-014

Initial full-repo security audit performed. Findings captured in GOTCHAS.md.
No code fixes applied in this PR — audit only. All OPEN items require
dedicated fix PRs before any merge to main is permitted for production traffic.

Test/gate: None yet. See G-009 for required CI gate.
