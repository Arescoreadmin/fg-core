# FROSTGATE EXECUTION AUDIT TEMPLATE

You are conducting a read-only FrostGate execution audit.

Do not modify code.
Do not create commits.
Do not regenerate artifacts.
Do not alter the roadmap.

Read:

- `artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md`
- `artifacts/audits/canonical_roadmap/roadmap_manifest.json`
- `artifacts/audits/canonical_roadmap/EXECUTION_STATE.json`

Audit repository reality against the canonical execution system.

## Determine

- current PR
- current lane
- current phase
- current Revenue Gate
- current KPI
- current operating metric
- gate completion
- blocking items
- next unblocked work
- commercial milestones
- drift status

## Inspect for

- execution drift
- lane violations
- phase violations
- Revenue Gate bypass
- roadmap inconsistencies
- manifest hash mismatch
- execution-state mismatch
- Mission violations
- duplicated capabilities
- stale or orphaned modules
- already-completed work still marked open
- open work incorrectly marked complete
- security regressions
- tenant-isolation regressions
- customer-journey breaks
- first-invoice blockers
- portal blockers
- remediation-revenue blockers
- MRR blockers
- misleading commercial claims
- hidden manual operations
- technical work that does not move the active KPI

## Evidence standard

Every finding must include:

- severity
- evidence
- file and symbol or route
- current consequence
- customer consequence
- revenue consequence
- blocking PR
- recommended action
- whether it changes the roadmap or only execution state

Use:

- VERIFIED
- PARTIALLY VERIFIED
- CLAIMED
- INFERRED
- UNKNOWN

Do not present documentation claims as implementation truth.

## Severity

- P0: blocks client safety, first invoice, or causes catastrophic trust/security failure
- P1: blocks portal activation, remediation revenue, or first MRR
- P2: blocks client five or enterprise scaling
- P3: backlog or strategic improvement

## Output

Return:

1. Audit verdict
2. Branch and commit
3. Current execution position
4. Integrity result
5. Top findings by severity
6. Revenue Gate accuracy
7. Commercial milestone accuracy
8. Drift findings
9. Exact corrective actions
10. Whether roadmap modification is justified

Do not implement fixes.
