# FROSTGATE ROADMAP EVOLUTION TEMPLATE

Enter planning mode.

This template may be used only when one of these triggers exists:

- a Revenue Gate completed
- customer evidence invalidated an assumption
- production evidence invalidated an assumption
- a security requirement emerged
- a regulatory requirement changed
- a signed enterprise requirement emerged
- a dependency or platform constraint invalidated the current sequence

Read (in precedence order):

- `docs/plans/customer_one_verified_governance_roadmap_20260910.md` — **Level-2 sequencing authority** (supersedes the canonical roadmap below for sequencing decisions as of 2026-09-09)
- `customer_one/roadmap_authority.yaml` — machine-readable mirror of the Level-2 authority
- `artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md` — Level-5 historical evidence (superseded; read-only)
- `artifacts/audits/canonical_roadmap/roadmap_manifest.json`
- `artifacts/audits/canonical_roadmap/EXECUTION_STATE.json`

Assume the Level-2 document is authoritative for sequencing. The Level-5 canonical roadmap is historical evidence only.

Do not redesign the roadmap.

Evaluate only whether verified reality justifies a minimal change.

## Required evidence

For every proposed change provide:

- trigger
- evidence
- invalidated assumption
- customer impact
- revenue impact
- DTFR impact
- MRR impact
- Mission impact
- moat impact
- enterprise impact
- security impact
- dependency impact
- alternative considered
- cost of no change

Reject changes based only on:

- architectural preference
- new technology
- curiosity
- speculative scale
- unverified market assumptions
- work already assigned to a later lane
- desire to polish infrastructure

## Historical integrity

Never:

- rewrite completed phases
- reorder completed PRs
- delete historical execution
- change past gate results
- erase rejected decisions
- reclassify completed work without evidence

## Permitted updates

When approved, update only what is necessary:

- canonical roadmap
- roadmap manifest
- execution state
- decision log, when present
- affected hashes and changelog

Recalculate and verify integrity hashes.

## Output

Return:

1. Trigger validity
2. Evidence reviewed
3. Current roadmap position
4. Approved changes
5. Rejected changes
6. Revised PR sequence
7. Gate impact
8. KPI and metric impact
9. Commercial impact
10. Risk assessment
11. Required artifact updates
12. Integrity-verification plan

If evidence does not justify modification, return:

`NO CHANGE — continue the current canonical PR sequence.`
