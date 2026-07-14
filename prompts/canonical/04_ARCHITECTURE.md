# FROSTGATE ARCHITECTURE REVIEW TEMPLATE

Use this template only for a material architecture decision.

Permitted triggers:

- production evidence
- signed customer requirement
- regulatory change
- security requirement
- enterprise-scale requirement
- dependency failure that invalidates the current design
- Revenue Gate completion exposing a new architecture decision

Read:

- `artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md`
- `artifacts/audits/canonical_roadmap/roadmap_manifest.json`
- `artifacts/audits/canonical_roadmap/EXECUTION_STATE.json`

Do not modify code.
Do not alter the roadmap until the decision is supported.

## Decision questions

Evaluate:

1. What verified evidence triggered this review?
2. Does the proposed change belong to the active lane?
3. Does it unblock the active Revenue Gate?
4. Does it improve the assigned KPI?
5. Does it improve customer value?
6. Does it improve enterprise readiness?
7. Does it strengthen a durable moat?
8. Does it reduce or increase DTFR?
9. Does it duplicate an existing capability?
10. Does it violate any Mission property?
11. Can the requirement be satisfied with a smaller change?
12. Can the capability be bought rather than built?
13. Does it create irreversible migration or lock-in risk?
14. Does it preserve multi-tenancy, determinism, and auditability?
15. Does it remain compatible with the long-term autonomous-governance direction?

## Required options

Provide at least:

- Option A: smallest viable change
- Option B: stronger strategic design
- Option C: defer or do nothing

For each include:

- architecture
- benefits
- drawbacks
- implementation size
- security risk
- migration risk
- DTFR impact
- MRR impact
- moat impact
- operational cost
- reversibility

## Decision rule

Reject the change when it:

- delays first revenue without removing a P0 risk
- belongs to Platform Expansion while Revenue Gate 1 is open
- duplicates an existing authority
- creates speculative scale
- introduces complexity without verified customer demand
- weakens deterministic evidence or tenant isolation

## Output

Return:

1. Decision
2. Triggering evidence
3. Current roadmap position
4. Options considered
5. Trade-off matrix
6. Recommended architecture
7. Affected systems
8. Affected PRs
9. KPI and metric impact
10. Revenue Gate impact
11. Roadmap-change requirement
12. Risks and rollback strategy

If evidence does not justify a change, return:

`NO CHANGE — current architecture and roadmap remain authoritative.`
