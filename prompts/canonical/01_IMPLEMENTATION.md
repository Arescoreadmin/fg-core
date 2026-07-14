# FROSTGATE IMPLEMENTATION TEMPLATE

You are implementing FrostGate Core.

This repository has a canonical execution system.

Before making any changes, read and reconcile all of the following:

- `artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md`
- `artifacts/audits/canonical_roadmap/roadmap_manifest.json`
- `artifacts/audits/canonical_roadmap/EXECUTION_STATE.json`

These documents are authoritative.

The roadmap determines what gets built.

The manifest determines what exists.

The execution state determines what is being worked on today.

## Mission

Every change must preserve:

- Every assessment becomes institutional memory.
- Every remediation becomes organizational improvement.
- Every interaction increases customer switching cost.
- Every client increases platform intelligence.

No implementation may reduce these properties.

## Execution rules

Implement only the current PR identified in `EXECUTION_STATE.json`.

Do not:

- begin a future PR
- reorder work
- modify roadmap sequencing
- perform unrelated refactors
- expand scope because something nearby looks improvable
- update `EXECUTION_STATE.json` before merge

If unrelated work is discovered, classify it as one of:

- Deferred
- Future PR
- Technical Debt
- Production Risk

Record it, but do not implement it.

## Required preflight

Before editing:

1. Confirm the repository root.
2. Record the current branch and commit SHA.
3. Confirm the working tree state.
4. Validate roadmap, manifest, and execution-state integrity.
5. Read the complete current-PR definition.
6. Inspect all named dependencies and existing implementations.
7. Confirm the current lane, phase, Revenue Gate, KPI, and operating metric.
8. Confirm no already-merged capability duplicates the requested work.

If the execution state is inconsistent with repository reality, stop and return:

`BLOCKED: <single precise reason>`

## Engineering standard

The implementation must be:

- enterprise-grade
- production-ready
- future-facing
- deterministic
- auditable
- tenant-isolated
- least-privilege
- fail-closed where security or integrity is involved
- horizontally scalable where required
- backward compatible unless the roadmap explicitly authorizes a breaking change
- reusable across FrostGate modules where appropriate
- aligned with the existing canonical authority model

Do not introduce:

- placeholders
- silent fallbacks
- hidden defaults for production secrets
- duplicate authorities
- mutable historical records
- unaudited mutation paths
- undocumented feature flags
- tests that only inspect source text when behavior can be exercised
- new waivers unless explicitly authorized by the roadmap

## Implementation process

1. Read the canonical roadmap.
2. Read the roadmap manifest.
3. Read the execution state.
4. Identify the exact current PR.
5. Produce a concise implementation plan.
6. Inspect existing code before creating anything new.
7. Implement only the current PR.
8. Add focused tests proving acceptance criteria.
9. Update contracts, inventories, migrations, documentation, and `PR_FIX_LOG` only when required.
10. Run the narrowest relevant tests first.
11. Run the required FrostGate validation gates.
12. Confirm the final diff contains only current-PR scope.

Do not update `EXECUTION_STATE.json`. It changes only after merge unless the current PR explicitly exists to repair execution-state integrity.

## Required validation

Run the validation required by the current PR and, where applicable:

- `ruff check`
- `ruff format --check`
- `mypy`
- focused pytest suites
- `make fmt-check`
- `make fg-contract`
- `make route-inventory-audit`
- `make soc-invariants test-quality-gate`
- `make fg-fast`
- `make fg-security`
- `bash codex_gates.sh`
- `git diff --check`
- `git status --short`

Do not claim a gate passed unless its final exit status is known.

## Completion standard

The PR is complete only when:

- every acceptance criterion is proven
- no future PR work was pulled forward
- no existing capability was duplicated
- security and tenant isolation are preserved
- required contracts and inventories are synchronized
- required tests pass
- the diff is cohesive and reviewable
- remaining discoveries are explicitly deferred

## Return format

Return:

1. Current PR
2. Current lane, phase, gate, KPI, and metric
3. Implementation summary
4. Files changed
5. Tests added or updated
6. Validation executed
7. Acceptance-criteria results
8. Security and tenant-isolation results
9. Deferred discoveries
10. Remaining blockers
11. Recommended commit message
12. PR title and summary

Do not propose the next PR.
