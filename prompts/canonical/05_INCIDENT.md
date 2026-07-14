# FROSTGATE INCIDENT RESPONSE TEMPLATE

You are responding to a FrostGate production or security incident.

Feature work is suspended.

Read:

- `artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md`
- `artifacts/audits/canonical_roadmap/roadmap_manifest.json`
- `artifacts/audits/canonical_roadmap/EXECUTION_STATE.json`

The production-incident override is active only for the duration of containment and recovery.

## Priorities

1. Protect customers
2. Contain impact
3. Preserve evidence
4. Restore safe service
5. Determine root cause
6. Prevent recurrence
7. Reconcile execution state
8. Resume roadmap execution

Do not redesign the platform during incident response.

## Establish

- incident start time
- reporter
- affected environment
- affected tenants
- affected services
- affected data
- security impact
- customer impact
- revenue impact
- Mission impact
- current severity
- evidence sources
- known unknowns

## Severity

- SEV-0: active compromise, cross-tenant exposure, evidence corruption, unrecoverable outage
- SEV-1: major customer outage, integrity failure, unauthorized access, failed production controls
- SEV-2: degraded capability with safe workaround
- SEV-3: non-customer-facing defect or operational warning

## Response process

### Contain

Use the smallest safe action:

- disable affected route or feature
- revoke credentials
- isolate service
- stop worker
- block traffic
- freeze mutations
- preserve logs and database evidence

### Recover

- repair the narrow failure
- validate security and integrity
- restore service gradually
- monitor for recurrence

### Improve

Only after recovery:

- add regression tests
- add observability
- document root cause
- update runbooks
- determine whether roadmap changes are justified

## Roadmap rules

Do not modify the canonical roadmap unless the incident proves an assumption false.

If roadmap modification is required, document:

- incident evidence
- invalidated assumption
- minimal roadmap change
- affected PR sequence
- Revenue Gate impact
- recovery effect
- approval authority

Otherwise leave the roadmap unchanged.

## Output

Return:

1. Incident severity
2. Current status
3. Customer and tenant impact
4. Security and data-integrity impact
5. Containment actions
6. Recovery actions
7. Root cause
8. Evidence preserved
9. Validation performed
10. Regression prevention
11. Roadmap impact
12. Execution-state updates required
13. Post-incident follow-up PR

Do not resume feature work until the incident is closed.
