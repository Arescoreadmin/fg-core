# FrostGate Enterprise Plan

**Version:** 1.0  
**Date:** 2026-06-02  
**Author:** Jason Cosat  
**Authority:** This document is the single source of truth for all Phase 3+ enterprise work.  
**Input:** Codex forensic audit (`docs/ai/FIELD_ASSESSMENT_ENTERPRISE_AUDIT.md` + `docs/ai/FIELD_ASSESSMENT_SCOPED_ENTERPRISE_PLAN.md`, 2026-06-02)  
**Tracking:** Open findings tracked in `AUDIT_TRACKER.md`. PR progress tracked in `ROADMAP.md`.

---

## Current State

Field Assessment has a complete functional pipeline: tenant-scoped engagements, 9 scan
connectors, document registration, interview capture, NIST AI RMF questionnaire, readiness gates,
QA-approved signed reports, client delivery portal, and 6,347 passing tests across 15 forensic
modules. It is demonstrable internally and suitable for a closely supervised first engagement.

It is not safe for uncontrolled external access. Six security issues must be resolved before any
client can be given credentials, and ten more before multi-tenant commercial deployment.

The architecture has a second problem: Field Assessment and Autonomous Governance are tightly
coupled in code. FA delivery currently writes directly into governance tables. This blocks
selling FA standalone and makes the systems harder to operate and scale independently.

The moat — the reason clients stay and pay more over time — is not the questionnaire UI or the
PDF. It is the longitudinal evidence graph that accumulates verified evidence, control mappings,
findings, remediation outcomes, and signed report history across every reassessment. That graph
compounds with each engagement. Building it requires fixing the security and durability gaps first.

---

## Product Boundary

Field Assessment must be independently deployable without Autonomous Governance.

### Field Assessment owns:
- Engagement lifecycle, assessor assignment, playbooks, readiness gates, QA approval
- Evidence collection: scans, documents, interviews, observations, questionnaires
- Evidence normalization, control mapping, findings, confidence scoring, remediation recommendations
- Signed, versioned, QA-approved assessment reports
- Client delivery portal, engagement history, reassessment tracking

### Autonomous Governance owns (post-delivery activation only):
- Governance asset registry and topology graph
- Continuous posture and readiness simulations
- Governance workflows that persist beyond an engagement
- Governed RAG corpus, AI assistant, provider routing, AI plane policy
- Agent enrollment, telemetry, command execution, rings, missions, rules of engagement

### The boundary rule:
```
Field Assessment → [assessment.delivered event] → Autonomous Governance (optional consumer)
```

Assessment delivery must succeed without Autonomous Governance installed or enabled.
Report signing and evidence custody move to shared platform packages, not governance-named modules.

---

## Phase 0 — Containment
**Gate: Safe for controlled pilot | Estimate: Weeks 1–2**

These are stop-the-line items. No client credentials before all five are resolved.

### 0.1 — Fix audio proxy SSRF / bearer token exfiltration (C5) `P0`

**File:** `apps/console/app/api/field-assessment/audio-url/route.ts:23-35`

The proxy accepts a user-controlled URL, checks `url.includes(".blob.vercel-storage.com")`
(substring, not hostname boundary), then fetches with `Authorization: Bearer ${BLOB_READ_WRITE_TOKEN}`.
A URL like `https://attacker.example?x=.blob.vercel-storage.com` passes the check and receives
the storage write token.

**Required fix:**
1. Parse URL with `new URL()`. Reject on parse error.
2. Require `protocol === "https:"`.
3. Require `hostname.endsWith(".blob.vercel-storage.com")` — suffix match, not substring.
4. Require path starts with `/field-assessment/` (blob upload paths are tenant-prefixed).
5. Do not forward `BLOB_READ_WRITE_TOKEN` to any external URL. Issue a time-limited
   signed download token on the server side using a blob ID that is resolved from DB
   by `(tenant_id, engagement_id, observation_id)`.
6. Add route tests: hostname confusion, encoded URLs, redirect following, cross-tenant retrieval,
   valid URL path prefix enforcement.

**Longer term:** Replace the proxy with a tenant-bound artifact registry. Blob IDs stored
in DB per observation; download requires `(tenant_id, engagement_id, observation_id)` lookup.
Blob path is opaque and not user-supplied. The storage token never leaves the server.

### 0.2 — Block outbound scanner SSRF / private-range access (C6) `P0`

**Files:** `api/field_assessment.py:3267-3379`, `services/connectors/network_scan/runner.py:84-99`,
`services/connectors/web_headers/runner.py:193-203`

Scanners accept arbitrary IPs, CIDRs, hostnames, and URLs with no filtering. Any authenticated
assessor can scan `127.0.0.1`, `10.x.x.x`, `169.254.169.254` (cloud metadata), or use a
redirect chain to reach private services from FrostGate's infrastructure.

**Required fix (immediate — before any external use):**
1. Add a `_validate_scan_target(target)` function called before every scan dispatch.
2. Resolve DNS → get all A/AAAA records → reject if any resolved address is in:
   - Loopback: `127.0.0.0/8`, `::1`
   - Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-local: `169.254.0.0/16`, `fe80::/10`
   - Cloud metadata: `169.254.169.254/32`
   - Multicast: `224.0.0.0/4`, `ff00::/8`
   - Reserved: `0.0.0.0/8`, `240.0.0.0/4`
3. For web-header scanner: validate every redirect hop before following.
4. Add per-engagement target allowlist: assessor must declare the client's domain or IP range
   during engagement setup; scanners only reach approved targets.
5. Add per-tenant scan quota and concurrency limit.
6. Store a `scan_authorization_record` per scan initiation (actor, targets, timestamp, approval).

**Required fix (medium term — for commercial deployment):**
Move outbound scans to an isolated scanner microservice with explicit egress policy at the
network layer. FrostGate's core API submits scan jobs; an isolated worker executes them in a
network segment with no access to internal services.

### 0.3 — Replace plaintext portal codes with expiring grants (C7) `P0`

**Files:** `api/field_assessment.py:761-784,5070-5087`, `api/middleware/portal_scope.py:35-75`

`client_access_code` is an 8-character plaintext code stored in the engagement record and
sent as a query parameter. It leaks into logs, browser history, analytics, and referrers.
It is reused across any engagement matching the same `client_name`. The portal trust boundary
is enforced only when `X-Portal-Source: client-portal` header is present — a caller-selected
signal.

**Required fix:**
1. Replace `client_access_code` with `portal_grant`: cryptographically random (32 bytes,
   URL-safe base64), stored hashed (Argon2 or SHA-256 with tenant salt), never returned
   in API responses after creation.
2. Bind grant to a stable `client_account_id` (separate from mutable `client_name`).
3. Set expiry (default 90 days, operator-configurable). Store `expires_at`, `revoked_at`.
4. Deliver via secure session cookie (`HttpOnly`, `SameSite=Strict`, `Secure`), never query string.
5. Verify server-side: `portal_grant_sessions` table, not header-based trust.
6. Add rotation endpoint (operator-triggered), revocation endpoint, lockout after N failures.
7. Emit audit events on: grant creation, rotation, revocation, successful auth, failed attempts,
   lockout.

### 0.4 — Fix report audit atomicity (H13) `P1`

**Files:** `api/field_assessment.py:4689-4749,1092-1119,2227-2264,5735-5751`

Report creation commits the report row, then appends the audit event in a separate DB operation.
If the append fails, you have an evidence record with no audit trail — critical in regulated
industries where auditors verify evidence chain completeness. Several other mutation paths
(engagement metadata updates, schedule upserts, remediation-hint edits, some asset promotion
paths) emit no FA audit event at all.

**Required fix:**
1. Wrap every write route in a single transaction: `db.begin()`, mutation, audit append,
   `db.commit()`. If the audit append raises, the transaction rolls back and the mutation
   is rejected with a retryable error.
2. Create a mutation-to-audit matrix: enumerate every write route and its required audit event
   fields (actor, request_id, before, after, reason, outcome).
3. Add a test for every write route asserting that exactly one audit event was appended
   in the same transaction.
4. Database-enforce report immutability after QA approval: add a `BEFORE UPDATE` trigger
   on `fa_reports` that rejects changes when `qa_approved_at IS NOT NULL`.

### 0.5 — Extend evidence lifecycle locks to update/delete paths (H15) `P1`

**Files:** `api/field_assessment.py:224-233,1814-1969,6441-6645`

`_assert_engagement_accepts_evidence()` correctly blocks new evidence creation on terminal
engagements. But observation PATCH/DELETE and questionnaire evidence-link changes bypass the
same guard. A delivered engagement's evidence can be mutated silently.

**Required fix:**
1. Call `_assert_engagement_accepts_evidence(eng)` at the start of every observation
   PATCH and DELETE route.
2. Freeze questionnaire evidence-link changes on delivered/cancelled/closed engagements,
   or model them as append-only amendments (new row with `supersedes_id` + reason + actor).
3. Define one lifecycle policy enum and reference it from all mutation routes — no per-route
   custom logic.

### 0.6 — Fix GET drift-report state mutation (PI17) `P2`

**Files:** `api/field_assessment.py:4450-4456,4611-4620`

`GET /drift-report` emits alert rows as a side effect of reading. Reads must be repeatable
and side-effect-free.

**Required fix:** Extract alert emission into a separate `POST /drift-report/alerts/emit`
command or a background worker triggered by the drift computation. The GET route becomes
purely read-only.

---

## Phase 1 — Trusted Pilot Foundation
**Gate: First paying client | Estimate: Weeks 3–6**

### 1.1 — Drift table RLS + Postgres tests (H11) `P1`

**Files:** `api/db_models_drift.py:17-114`, `migrations/postgres/0075_fa_rls.sql`

`fa_drift_baselines`, `fa_drift_alerts`, `fa_connector_schedules` are absent from the RLS
migration and startup assertion. Add them to a new idempotent migration (0078+), add to the
startup RLS assertion, and add cross-tenant isolation tests for each table.

### 1.2 — Durable connector job store (H12) `P1`

**Files:** `api/field_assessment.py:172-173,2940-2959,4079-4104`

Replace `_MSGRAPH_RUNS` dict + FastAPI `BackgroundTask` with:
1. `fa_connector_jobs` table: `(id, tenant_id, engagement_id, connector_type, status,
   actor_id, target_spec_hash, lease_expires_at, attempt_count, last_error, result_ids,
   created_at, updated_at)`. All columns tenant-scoped.
2. Status route verifies `(tenant_id, engagement_id, run_id)` — not just engagement.
3. Job worker: polls for jobs, holds lease (heartbeat), retries on failure (configurable
   backoff), moves to dead-letter after max attempts.
4. Idempotency: job creation is idempotent on `(engagement_id, connector_type, target_hash)`.
5. Cancellation: operator can cancel a running job; worker checks cancelled flag on heartbeat.

### 1.3 — Console RBAC + actor attribution (H14) `P1`

**Files:** `apps/console/middleware.ts:8-32`, `apps/console/app/api/core/[...path]/route.ts`

**Required work:**
1. Add console-level RBAC roles: `operator`, `assessor`, `qa_reviewer`, `admin`, `viewer`.
2. Gate routes by role: scan authorization requires `assessor`; QA approval requires
   `qa_reviewer`; evidence deletion requires `admin`.
3. Forward a signed actor claim from the console BFF to the core API — not a shared service key.
   The claim includes `{actor_id, actor_email, actor_role, session_id, issued_at}`, signed with
   a console-held key verified by the core API.
4. All FA audit events resolve to the human actor, not the service key prefix.
5. Add scope splits:
   - `assessment:create`, `assessment:transition` (separate from generic `governance:write`)
   - `evidence:write`, `evidence:amend`
   - `scan:authorize` (initiate connector scans)
   - `baseline:pin`
   - `report:generate`, `report:qa_approve` (already exists, keep)
   - `portal:admin` (portal grant management)

### 1.4 — FA/Governance outbox boundary (PI20) `Architecture`

**Files:** `services/field_assessment/promotion.py`, `services/field_assessment/connectors/msgraph_bridge.py`,
`services/field_assessment/timeline.py`

Remove direct cross-tier writes. Replace with an outbox pattern:
1. On `assessment.delivered`, write an outbox event to `fa_delivery_outbox` table
   `(id, tenant_id, engagement_id, report_id, payload_hash, created_at, delivered_at)`.
2. A lightweight relay worker reads the outbox and publishes to the internal event bus (NATS
   or Postgres LISTEN/NOTIFY).
3. Autonomous Governance module subscribes and creates assets, workflows, graph entries,
   and corpus entries as a consumer — completely decoupled from the delivery transaction.
4. FA delivery succeeds even if the Governance module is not running.
5. Move `services/field_assessment/timeline.py` governance writes behind the same outbox.

### 1.5 — Database hardening (foundation for regulated sales) `P1`

For every FA child table, add:
1. Composite tenant-aware foreign key from `(tenant_id, engagement_id)` to `fa_engagements`.
2. Check constraints: status enums, severity enums, source type enums, confidence score
   range `[0, 100]`, schema version pattern.
3. Unique constraint: at most one active baseline per `(tenant_id, engagement_id)`.
4. Retention classification column on tables with evidence data.

### 1.6 — Portal session identity (dependency for C7 full fix) `P1`

After C7 establishes portal grants, add:
1. `portal_accounts` table: stable `(id, tenant_id, client_account_id, email, mfa_enrolled,
   created_at, last_login_at)`.
2. `portal_sessions` table: `(id, account_id, grant_id, device_fingerprint, created_at,
   expires_at, revoked_at)`.
3. Session cookie contains signed session ID only — all state server-side.
4. Failed auth attempts tracked per account; lockout after N failures with exponential backoff.
5. Add portal session audit events (login, logout, failed attempt, lockout, revocation).

---

## Phase 2 — Enterprise Production
**Gate: Multi-tenant commercial deployment | Estimate: Weeks 7–14**

### 2.1 — OpenAPI → TypeScript codegen (PI18)

Generate the console and portal TypeScript clients from `contracts/core/openapi.json`.
Eliminate the handwritten `fieldAssessmentApi.ts` drift (wrong status strings, missing
connectors, wrong response shapes, broken 204 handling). Add BFF integration tests that
verify the client against the actual API contract — not text-presence assertions.

### 2.2 — Governed document pipeline

Replace registration-only document handling with a full ingestion pipeline:
1. **Upload:** virus scan (ClamAV or cloud equivalent), file type enforcement, size limits.
2. **Classification:** DLP scan for PII/PHI/CUI before storing; reject or flag on hit.
3. **Extraction:** async text extraction (PDF, DOCX, XLSX) into `fa_document_analyses`.
4. **Review:** assessor marks document as reviewed; locked after QA approval.
5. **Provenance:** hash stored at upload, verified at report generation.
6. **Retention:** classification label drives retention period; legal-hold flag blocks deletion.

### 2.3 — Retention, legal hold, and deletion workflow

1. Add `retention_class`, `legal_hold`, `scheduled_purge_at`, `purge_completed_at` to
   evidence tables.
2. Purge workflow: soft-delete first, then hard-delete after retention period + legal hold
   clear; emit immutable purge proof event.
3. Export: operator can export all engagement evidence as a signed archive before deletion.
4. WORM option: flag engagement as WORM at delivery; blocks all subsequent mutations at
   DB trigger level.

### 2.4 — Scheduler execution (PI19)

`fa_connector_schedules` stores schedules but no worker executes them. Add:
1. A schedule worker that polls for due schedules (cron expression + next_run_at).
2. Worker submits jobs to `fa_connector_jobs` (Phase 1.2) rather than calling connector
   directly.
3. Disable/delete API for schedules.
4. Audit events on: schedule create, modify, trigger, disable, delete.
5. Operational UI: schedule list with last-run status, next-run time, consecutive failure count.

### 2.5 — Operational dashboards

**Assessor-facing (console):**
- Active job queue: status, attempt count, last error per connector job
- Evidence freshness heatmap: documents by age, observations by staleness
- QA aging: reports awaiting approval with time-in-queue
- Engagement completion forecast based on current readiness gate progress

**Operator-facing (admin):**
- Connector health: last successful run per tenant+connector, error rate
- SLA compliance: engagements past promised delivery date
- Scan authorization audit: who initiated which scans, against which targets

### 2.6 — Assessor assignment and approval workflows

1. `fa_assessor_assignments` table: `(engagement_id, assessor_id, role, assigned_by, assigned_at)`.
2. Evidence request workflow: assessor creates request (`fa_evidence_requests`); client sees
   request in portal with upload action; request closes when evidence linked.
3. Amendment workflow: post-delivery finding amendment requires assessor reason + QA re-approval.
4. Reassessment planning: clone scope, interview plan, document requirements, and
   unresolved findings from prior engagement into a new draft engagement.

### 2.7 — Client account identity

Replace `client_name` as the client key with a stable `client_account_id`:
1. `portal_client_accounts` table: `(id, tenant_id, display_name, industry, contact_email,
   created_at)`.
2. Engagements reference `client_account_id` not free-text name.
3. Portal grants bind to `client_account_id` — not engagement-scoped name string.
4. Multiple engagements for the same client are discoverable without name collisions.

---

## Phase 3 — Moat Layer
**Gate: Defensible competitive position | Estimate: Months 3–6**

The moat is not the questionnaire, the PDF, or the scan connectors. Competitors can copy any
of those. The moat is data and insight that compounds with every completed assessment.

### 3.1 — Longitudinal evidence graph (M1 priority)

**Why hard to copy:** Value compounds with every reassessment. After 10 assessments across
3 years for one client, FrostGate has a verified evidence timeline that no questionnaire tool
can reconstruct.

**Build:**
1. `fa_evidence_nodes` table: versioned, immutable snapshot of each evidence item at delivery.
   Columns: `(id, tenant_id, engagement_id, source_type, source_id, control_ids[], finding_ids[],
   confidence_score, verified_at, evidence_hash, snapshot_version)`.
2. `fa_evidence_edges` table: links between evidence items across engagements.
   `(from_node_id, to_node_id, relationship_type, created_at)`.
   Relationship types: `supersedes`, `corroborates`, `contradicts`, `references`.
3. Reassessment comparison: on new engagement delivery, diff against prior engagement's
   evidence graph. Surfaces: regression (control was met, now failed), new coverage,
   stale evidence (same doc, no update), remediation verification (finding closed, evidence supports).
4. API: `GET /engagements/{id}/evidence-graph` — returns nodes + edges with provenance.
5. Portal view: timeline of control evidence across all engagements for this client.

### 3.2 — Regulator-ready verification bundles (M2 priority)

**Why hard to copy:** A signed, replayable evidence bundle that an auditor or insurer can
independently verify is a strong differentiator in regulated sales. Building the signing
infrastructure correctly takes time; every delay builds the moat.

**Build:**
1. At delivery: generate a deterministic bundle: all evidence items, finding records,
   questionnaire responses, audit events, QA approval record, report manifest — serialized
   to canonical JSON + SHA-256 hash tree.
2. Sign the bundle root hash with an Ed25519 key (per-tenant signing key in HSM or KMS).
3. Store bundle: `fa_verification_bundles` table + immutable object storage path.
4. Verification API: `POST /engagements/{id}/verify-bundle` — takes bundle file + tenant
   public key, replays hash tree, returns pass/fail with provenance diff if mismatch.
5. Export: operator can download the bundle as a self-contained ZIP with `verify.sh` script.
6. Auditor portal: read-only view for external auditors — no login required, bundle hash
   is the credential.

### 3.3 — Reassessment intelligence (M1 priority)

**Why hard to copy:** This requires verified remediation outcome data, which only exists after
multiple real-client assessment cycles. Generic tools cannot fake it.

**Build:**
1. At each reassessment, compare all findings against prior engagement:
   - Remediated: finding was open, now closed with verified evidence — record `remediation_velocity`
     (days to close), `evidence_quality_delta` (confidence gain).
   - Regressed: finding was closed, now open again — record `regression_date`, `root_cause_category`.
   - New: net-new finding not present in prior assessment.
   - Persistent: same finding, same status — record `staleness_days`.
2. `fa_reassessment_deltas` table: persists the diff across engagement pairs.
3. Operator dashboard: per-client trend view — control regression, evidence staleness, finding
   velocity, remediation success rate.
4. Recommendations: for each open finding, surface similar findings from other engagements
   (same control, same industry) that were successfully closed, with the evidence type and
   remediation approach that worked. Anonymized, no PII.

### 3.4 — Consent-based sector benchmarks (M1 priority)

**Why hard to copy:** Requires a dataset of real, verified assessments. Every competing
tool that launches later has no data. Every client engagement FrostGate completes is a
permanent data advantage, with tenant consent.

**Build:**
1. Opt-in consent model: at engagement close, operator offers participation in the benchmark
   corpus. Consent stored with reason, scope, and revocation path.
2. Anonymization pipeline: strip all PII/PHI from consented engagement data; retain only
   sector, org size band, control IDs, scores, evidence types, finding severities, and
   remediation outcomes.
3. `benchmark_corpus` table (separate tenant, tenant_id=`benchmark`): anonymized,
   timestamped aggregate records.
4. Benchmark query API: `GET /benchmarks?sector=community_banking&size_band=mid&framework=nist_ai_rmf`
   → returns percentile bands per control, median remediation velocity, common finding patterns.
5. Portal integration: client sees "Your score vs. 23 similar organizations in your sector"
   for every control domain where benchmark data exists.

---

## Phase 4 — Regulated Enterprise
**Gate: Regulated industry commercial sales | Estimate: Months 4–12**

### 4.1 — SOC 2 Type II readiness

Instrumentation required (not certification — that requires an auditor):
1. Availability: uptime monitoring, incident response plan, SLA definition.
2. Confidentiality: encryption at rest (Postgres TDE or pgcrypto for sensitive columns),
   encryption in transit (TLS 1.3 everywhere), key rotation schedule.
3. Security: penetration test, vulnerability disclosure policy, patch SLA.
4. Processing integrity: evidence hash chain, audit trail completeness, report verification.
5. Privacy: data classification, retention schedules, deletion workflow, breach notification
   procedure.

### 4.2 — FedRAMP preparation (govcon market)

The govcon profile is already in the product (CMMC 2.0, NIST 800-171, DFARS). Enterprise
production requirements for FedRAMP boundary:
1. Air-gap mode: FA can run without external AI calls (questionnaire + scan connectors are
   all local; only report narrative generation requires AI — make it optional).
2. Data residency: all tenant data in US regions; no EU or APAC storage.
3. FIPS 140-2 cryptographic modules for signing and hashing.
4. Continuous monitoring (ConMon): automated vulnerability scanning, configuration drift alerts.

### 4.3 — HITRUST and HIPAA BAA (healthcare market)

1. Establish BAA with all sub-processors (Railway, Vercel, Anthropic, Auth0 — already started).
2. HITRUST CSF r2 self-assessment against the 19 control categories.
3. PHI handling audit: every endpoint that touches engagement data that could contain PHI must
   be mapped and documented.
4. Private interview vault (from H6 deferred list): signed URLs, retention controls, consent
   records, transcript redaction, audio purge proof.

### 4.4 — Penetration testing

Before regulated enterprise sales, commission an independent penetration test of:
- The audio proxy endpoint (C5 fix must be verified externally)
- The portal authentication model (C7 fix must be verified externally)
- The scan target validation (C6 fix must be verified externally)
- The tenant isolation model (RLS + application layer)
- The API authentication and authorization layer

---

## What NOT to Build (Explicitly Deferred)

These items are on the long-term platform roadmap but are not launch requirements for an
enterprise Field Assessment product. Build them after the moat is established.

| Item | Reason for deferral |
|------|---------------------|
| Endpoint agent fleet, rings, missions, command bus | Requires FA moat first; complex ops overhead |
| Continuous readiness simulations | Requires longitudinal graph (Phase 3.1) as prerequisite |
| Autonomous remediation agents | Requires remediation outcome dataset (Phase 3.3) |
| Governed AI assistant / RAG retrieval product | Autonomous Governance tier; not FA |
| Provider routing, AI plane policy, model evaluation lab | Tier 3/4; not FA |
| Workforce AI behavior analytics | Separate product; not core to FA |
| Real-time OPA policy enforcement on AI requests | AI gateway product; deferred to Tier 3 |

---

## Architecture Decisions

### 1. FA/Governance boundary: outbox pattern

Use a `fa_delivery_outbox` table + relay worker. The outbox event is written in the same
transaction as the delivery state change. The relay delivers the event asynchronously.
Governance modules are optional consumers. FA delivery never fails because Governance
is down.

### 2. Durable jobs: database-backed, not in-process

Use `fa_connector_jobs` table with lease heartbeat. Simple Postgres-based job queue is
sufficient at current scale. Upgrade to a dedicated queue (NATS JetStream, already available)
when throughput requires it. Do not use Redis for job state — it's not durable enough for
evidence chains.

### 3. Blob storage: artifact registry pattern

Never forward storage credentials to the client. Every audio/document blob is referenced
in DB by `(tenant_id, engagement_id, observation_id, blob_id)`. Download requires a
server-side lookup, not a client-controlled URL. Blob path is opaque — no `/tenants/xxx/audio/`
patterns that leak tenant structure.

### 4. Actor attribution: signed gateway claim

The console BFF signs an actor claim `{actor_id, email, role, session_id}` with a
console-held private key. The core API verifies the signature with the corresponding
public key (set at startup). All audit events record the human actor. The service key is
only used for machine-to-machine health/internal calls.

### 5. Evidence immutability: trigger + amendment model

Database triggers enforce report immutability after QA approval and evidence immutability
after delivery. Post-delivery changes are modeled as amendments: new rows with
`supersedes_id`, `amended_by`, `amended_at`, `reason`. The original is never mutated.
Amendments require a second QA approval.

### 6. Moat through data, not features

Features can be copied in 6 weeks. The evidence graph cannot. Every engagement that
completes before competitors adds another data point to the longitudinal graph,
the reassessment intelligence dataset, and the sector benchmark corpus. The
product compounds; competitors start from zero.

---

## Delivery Estimates

| Phase | Gate | Key risks | Estimate |
|-------|------|-----------|----------|
| **Phase 0 — Containment** | Safe for controlled pilot | C5 fix scope (artifact registry vs. quick hostname check) | Weeks 1–2 |
| **Phase 1 — Trusted Pilot** | First paying client | Durable job store adds operational complexity | Weeks 3–6 |
| **Phase 2 — Enterprise Production** | Multi-tenant commercial | Document pipeline regulatory requirements vary by market | Weeks 7–14 |
| **Phase 3 — Moat Layer** | Defensible position | Evidence graph schema needs careful versioning; benchmark consent pipeline | Months 3–6 |
| **Phase 4 — Regulated Enterprise** | Regulated sales | FedRAMP is a 12–18 month process; HITRUST self-assessment is 3–6 months | Months 4–12 |

**Fastest credible path to controlled pilot:** Fix C5, C6, C7, H13, H15 (4–6 days of focused
engineering). The product is demonstrable now; it needs those five items to be safe to demo
with real client credentials.

**Fastest credible path to first revenue:** Controlled pilot → collect payment → use payment
to fund Phase 1. The evidence graph moat work (Phase 3) starts accumulating value from the
first paid engagement.

---

*FrostGate — AI Governance for Regulated Industries*  
*Enterprise Plan v1.0 — 2026-06-02*
