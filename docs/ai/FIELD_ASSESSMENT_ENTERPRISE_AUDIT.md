# Field Assessment Enterprise Audit

Date: 2026-06-02

Scope: `api/field_assessment.py`, Field Assessment persistence and migrations,
connector runners, console BFF and UI, governance report flow, and focused tests.
This audit targets the current worktree, including in-progress hardening edits.

## Executive Assessment

Field Assessment has a strong functional foundation: tenant-scoped application
queries, readiness gates, signed reports, QA approval scope separation, connector
normalization, soft-deleted observations, questionnaire fusion, governance
promotion, drift analysis, and a growing forensic test suite.

It is not enterprise-ready yet. The immediate blockers are:

1. A console audio proxy can forward the Vercel blob bearer token to an
   attacker-controlled HTTPS URL.
2. Outbound scanners accept arbitrary targets and can probe internal services or
   follow redirects into private networks.
3. Scan jobs and status are held in process memory rather than a durable,
   tenant-bound job system.
4. Drift tables are outside the Field Assessment RLS assertion and migration
   coverage.
5. Client portal access codes are plaintext, query-string capabilities, reused
   by client name, and returned in engagement responses.
6. Several mutations are missing durable audit events. Report generation appends
   its audit event after committing and does not commit the audit append.

## Priority Findings

### P0: Blob proxy can disclose its bearer token

`apps/console/app/api/field-assessment/audio-url/route.ts:23-35`

The proxy accepts a user-controlled URL, checks `url.includes(".blob.vercel-storage.com")`,
then fetches the URL with `Authorization: Bearer ${BLOB_READ_WRITE_TOKEN}`. A URL
such as `https://attacker.example/path?.blob.vercel-storage.com` passes the
substring check and receives the secret.

Required fix:

- Parse with `new URL()`.
- Require `protocol === "https:"`.
- Match `hostname` against an exact configured allowlist or a strict suffix
  boundary.
- Require the expected `field-assessment/` blob path prefix.
- Never forward the write token to arbitrary URLs. Prefer a server-side blob ID
  lookup bound to tenant, engagement, and observation.
- Add route tests for hostname confusion, redirects, encoded URLs, and
  cross-tenant retrieval.

### P0: Outbound scan surfaces permit network pivoting

`api/field_assessment.py:3267-3379`

`services/connectors/network_scan/runner.py:84-99`

`services/connectors/web_headers/runner.py:193-203`

The network scanner accepts arbitrary IPs, CIDRs, and hostnames and opens sockets
to common administrative and data-store ports. The web-header scanner accepts
arbitrary URLs and follows redirects. Neither path blocks loopback, private,
link-local, cloud metadata, or DNS-rebinding targets.

Required fix:

- Move outbound scans to an isolated scanner service with explicit egress policy.
- Require assessment target ownership verification and an approved target
  allowlist per engagement.
- Resolve DNS before connect and re-check each redirect hop.
- Block private, loopback, link-local, multicast, reserved, and metadata ranges
  unless an explicitly provisioned private-scanner agent is used.
- Add per-tenant quotas, concurrency limits, scan authorization records, and
  immutable operator acknowledgments.

### P0: Portal capability model is not suitable for client isolation

`api/field_assessment.py:761-784`

`api/field_assessment.py:5070-5087`

`api/middleware/portal_scope.py:35-75`

The portal code is stored and returned in plaintext, sent as a query parameter,
reused across engagements by matching `client_name`, and enforced only when a
caller supplies `X-Portal-Source: client-portal`. Query-string codes leak into
logs, browser history, analytics, and referrers. Client-name reuse can merge
unrelated customers with the same display name.

Required fix:

- Replace codes with hashed, revocable, expiring portal grants.
- Bind grants to a stable client account ID and authorized engagement IDs.
- Send credentials in a secure session or authorization header, never query
  parameters.
- Derive portal identity server-side. Do not use a caller-selected header as the
  security boundary.
- Return masked metadata only. Add rotation, revocation, lockout, and audit.

### P1: Field Assessment drift tables lack database tenant isolation

`api/db_models_drift.py:17-114`

`migrations/postgres/0075_fa_rls.sql:20-32`

`api/db_migrations.py:138-187`

The core Field Assessment tables received RLS and `FORCE ROW LEVEL SECURITY`, but
`fa_drift_baselines`, `fa_drift_alerts`, and `fa_connector_schedules` are omitted
from migration `0075` and the startup RLS assertion. Application queries usually
include tenant predicates, but database enforcement is incomplete.

Required fix:

- Add all three tables to an idempotent RLS migration and startup assertion.
- Add Postgres isolation tests for each table.
- Add composite foreign keys where tenant-scoped relationships exist.

### P1: Scan execution is non-durable and run status is not tenant-bound

`api/field_assessment.py:172-173`

`api/field_assessment.py:2940-2959`

`api/field_assessment.py:4079-4104`

All connector jobs share an in-memory `_MSGRAPH_RUNS` dictionary and FastAPI
background tasks. A restart loses status, multiple replicas disagree, jobs
cannot be retried safely, and there is no durable lease, heartbeat, or dead-letter
path. The status route verifies the requested engagement but does not verify that
the `run_id` belongs to that tenant and engagement.

Required fix:

- Add a tenant-scoped connector job table and queue-backed workers.
- Persist job ownership, state transitions, lease, attempts, timestamps, actor,
  target authorization, redacted errors, and result IDs.
- Authorize status reads by `(tenant_id, engagement_id, run_id)`.
- Add idempotency keys, cancellation, retry policy, timeout policy, and metrics.

### P1: Audit coverage is incomplete

`api/field_assessment.py:1092-1119`

`api/field_assessment.py:2227-2264`

`api/field_assessment.py:4689-4749`

`api/field_assessment.py:5735-5751`

Engagement metadata updates, remediation-hint edits, schedule upserts,
questionnaire response edits, and some asset promotion paths do not consistently
emit Field Assessment audit events. Report creation commits the report before
appending its audit event, and the appended event is not committed in the route.

Required fix:

- Treat mutation plus audit append as one transaction.
- Add a mutation-to-event matrix and tests for every write route.
- Hash-chain Field Assessment events or anchor them into the existing audit
  ledger.
- Add database-enforced report immutability after finalization.

### P1: Console authorization is coarse and actor attribution is lost

`apps/console/middleware.ts:8-32`

`apps/console/app/api/core/[...path]/route.ts:62-66`

`apps/console/app/api/core/[...path]/route.ts:181-216`

Any authenticated console user can reach the broad Field Assessment BFF prefix.
The BFF forwards a shared core API key, so backend audit actors resolve to the
service key prefix rather than the human user. Sensitive operations such as
connector initiation, baselines, schedules, promotion, evidence deletion, and
metadata toggles mostly share `governance:write`.

Required fix:

- Add console RBAC and per-action permission checks.
- Propagate a signed, server-derived human actor claim to core.
- Split scopes for scan authorization, evidence mutation, baseline pinning,
  schedule management, promotion, portal administration, and QA approval.
- Require step-up authentication for high-risk actions.

### P1: Evidence immutability is only partially enforced

`api/field_assessment.py:224-233`

`api/field_assessment.py:1814-1969`

`api/field_assessment.py:6441-6645`

New evidence ingestion is blocked after terminal engagement states, but
observation update/delete and questionnaire evidence-link changes do not apply
the same lifecycle guard. Finalized reports rely mainly on application behavior
rather than database triggers.

Required fix:

- Define one lifecycle policy for every mutation category.
- Freeze delivered evidence, or model post-delivery changes as append-only
  amendments with reason, approver, and supersession links.
- Add database triggers for finalized report records and protected evidence.

### P2: GET drift-report mutates state

`api/field_assessment.py:4450-4456`

`api/field_assessment.py:4611-4620`

`GET /drift-report` emits alert rows by default. Reads should be repeatable and
side-effect free, especially behind caches, retries, and monitoring.

Required fix:

- Make report computation read-only.
- Move alert emission to an explicit command or worker event.

### P2: API and console contracts have drifted

`apps/console/lib/fieldAssessmentApi.ts:40-48`

`apps/console/lib/fieldAssessmentApi.ts:76`

`api/field_assessment.py:537-542`

`apps/console/lib/fieldAssessmentApi.ts:181-185`

The UI scan-source union omits several supported connectors. UI finding statuses
use `accepted_risk` and `closed`, while the closed-loop backend accepts
`accepted` and `false_positive`. The UI finding list shape expects `total` and
`next_cursor`, while the API returns `total_count`. The generic request helper
always parses JSON, so successful `204` deletes can surface as client errors.

Required fix:

- Generate TypeScript contracts from OpenAPI.
- Add schema-level BFF integration tests, not source-text presence tests.
- Make the client request helper handle `204 No Content`.

### P2: Incomplete feature surfaces should not be marketed as automation

`services/connectors/drift/scheduler.py:1-19`

`services/connectors/drift/scheduler.py:36-39`

Schedules are a registry, not an executing scheduler. The defined source-type
allowlist is not enforced. PDF export remains optional at runtime. Document
analysis is registration-oriented rather than a governed upload, extraction,
malware-scan, DLP, review, and provenance pipeline.

Required fix:

- Label registry-only features accurately until workers exist.
- Add schedule execution, disable/delete API, audit events, and operational UI.
- Require PDF dependencies in production builds.
- Build a governed document ingestion lifecycle.

## Data Model Hardening

The substrate models rely heavily on application checks. Enterprise hardening
should add:

- Composite tenant-aware foreign keys from child tables to engagements.
- Check constraints for statuses, severities, source types, schema versions, and
  confidence-score ranges.
- Unique active-baseline enforcement.
- Retention classification, legal-hold state, deletion workflow, and purge proof.
- Encrypted object references for audio and document artifacts.
- Customer account IDs separate from mutable display names.
- Hash-chain fields or ledger anchors for engagement audit events.

## Verification Results

Focused command:

```bash
.venv/bin/pytest -q tests/test_field_assessment.py \
  tests/test_field_assessment_gate_enforcement.py \
  tests/test_field_assessment_reports.py tests/test_questionnaire.py \
  tests/test_fa_forensic_*.py
```

Result: `144 passed, 6 failed`.

Current failures:

- Three interview-role regressions: aliases are persisted as normalized playbook
  roles while existing tests expect display roles, and some aliases fail list
  expectations.
- Three QA-gate tests use a client without `governance:qa_approve`; the route now
  correctly returns `403`, but tests still expect route-level `404`.

Missing test lanes:

- Console audio-proxy SSRF and bearer-token exfiltration tests.
- Outbound scanner private-range, redirect, and DNS-rebinding tests.
- Postgres RLS tests for drift tables.
- Durable worker restart, retry, lease, and multi-replica tests.
- Portal grant rotation, revocation, expiry, lockout, and cross-client tests.
- Mutation-to-audit completeness tests.
- OpenAPI-to-TypeScript contract tests and browser workflow tests.

## Enterprise Delivery Plan

### Phase 0: Containment

- Disable the audio proxy or patch strict blob-host validation.
- Disable arbitrary outbound scan initiation outside isolated scanner workers.
- Stop issuing reusable plaintext portal codes.
- Fix report audit transaction ordering.

### Phase 1: Security Foundation

- Add drift-table RLS and Postgres tests.
- Introduce portal grants and console RBAC.
- Add durable connector jobs and tenant-bound status authorization.
- Complete lifecycle locks and audit coverage.

### Phase 2: Operational Readiness

- Add workers, queues, leases, retries, dead-letter handling, cancellation,
  quotas, metrics, and alerting.
- Add retention, legal hold, purge proof, key rotation, and artifact provenance.
- Enforce production dependency checks and SLO dashboards.

### Phase 3: Product Completion

- Build governed document ingestion and review.
- Add assessor assignment, approval workflows, client collaboration, amendment
  workflow, evidence requests, and remediation SLAs.
- Replace hand-maintained UI contracts with generated clients.

## Moat Roadmap

The defensible product is not a questionnaire UI. It is a continuously refreshed,
auditable evidence graph:

1. Build a tenant-specific longitudinal control graph linking scans, interviews,
   documents, findings, remediation, assets, owners, and signed report versions.
2. Turn every reassessment into measurable drift: control regression, evidence
   staleness, remediation velocity, recurring root causes, and confidence decay.
3. Accumulate an anonymized benchmark corpus with explicit tenant consent:
   sector baselines, peer percentiles, control-effort estimates, and evidence
   quality distributions.
4. Produce regulator- and insurer-ready evidence packs with replayable scoring,
   signed manifests, provenance, retention proofs, and amendment history.
5. Use the graph to recommend the next highest-leverage evidence request or
   remediation action, with deterministic rationale and human approval.

That moat compounds with completed assessments and verified remediation history.
It depends on fixing the security, durability, and audit gaps first.
