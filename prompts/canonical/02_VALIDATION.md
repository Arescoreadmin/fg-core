# FROSTGATE VALIDATION TEMPLATE

You are validating the current FrostGate Core PR.

Do not implement code unless explicitly instructed to create a narrowly scoped validation repair.

Read:

- `artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md`
- `artifacts/audits/canonical_roadmap/roadmap_manifest.json`
- `artifacts/audits/canonical_roadmap/EXECUTION_STATE.json`

Determine:

- current PR
- current lane
- current phase
- current Revenue Gate
- assigned KPI
- assigned operating metric
- exact acceptance criteria
- required validation gates

## Validation rules

Validate only the current PR.

Do not:

- redesign the feature
- add capabilities
- pull future work forward
- modify roadmap ordering
- change acceptance criteria
- weaken tests
- convert failures into waivers
- assume CI success from partial output

## Preflight

Record:

- branch
- HEAD SHA
- origin/main SHA
- working-tree status
- files changed from base
- roadmap version
- manifest version
- execution-state version
- integrity-check result

Verify that the branch and diff correspond to the current PR.

If not, return:

`FAIL: execution drift — <precise evidence>`

## Validate

Verify:

- requirements completeness
- acceptance criteria
- security
- tenant isolation
- authorization
- migrations
- RLS
- append-only protections
- API behavior
- OpenAPI contracts
- route inventory
- authority manifests
- determinism
- idempotency
- backward compatibility
- observability
- failure behavior
- performance where relevant
- test quality
- documentation
- PR scope
- roadmap compliance
- Mission compliance
- KPI movement
- operating-metric movement

Use runtime or behavioral tests instead of source inspection whenever practical.

## Required classifications

Every result must be one of:

- PASS
- FAIL
- RISK
- NOT APPLICABLE
- BLOCKED

Every FAIL or RISK must include:

- evidence
- impact
- severity
- exact repair boundary
- whether it blocks merge

## Output

Return only:

1. Validation verdict
2. Branch and commit
3. Current PR
4. Acceptance-criteria matrix
5. Tests and gates executed
6. Security and tenant-isolation verdict
7. Contract and migration verdict
8. Roadmap and Mission compliance
9. Merge blockers
10. Non-blocking risks
11. Exact next validation command, if unfinished

Do not recommend future features.
