# FrostGate Enterprise Plan

**Version:** 1.1  
**Date:** 2026-06-02  
**Author:** Jason Cosat  
**Authority:** This document is the single source of truth for all enterprise work.  
**Input:** Codex forensic audit (`docs/ai/FIELD_ASSESSMENT_ENTERPRISE_AUDIT.md` + `docs/ai/FIELD_ASSESSMENT_SCOPED_ENTERPRISE_PLAN.md`, 2026-06-02)  
**Tracking:** Open findings tracked in `AUDIT_TRACKER.md`. PR progress tracked in `ROADMAP.md`.

---

## Current State

Field Assessment has a complete functional pipeline: tenant-scoped engagements, 9 scan
connectors, document registration, interview capture, NIST AI RMF questionnaire, readiness gates,
QA-approved signed reports, client delivery portal, and 6,347 passing tests across 15 forensic
modules. It is demonstrable internally and suitable for a closely supervised first engagement.

The blockers to revenue are not feature gaps. They are trust gaps.

A bank, healthcare client, law firm, or government contractor will forgive missing features.
They will not forgive credential leakage, tenant crossover, or unverifiable evidence chains.
The audit shows five items that make it unsafe to hand a client real credentials today,
and five more that make it unsafe to scale beyond a handful of supervised engagements.
Fix those ten items and the path to first revenue is clear.

The architecture has a second problem: Field Assessment and Autonomous Governance are tightly
coupled in code. FA delivery currently writes directly into governance tables. This blocks
selling FA standalone, reduces deployment flexibility, limits acquisition potential, and
forecloses channel partnerships. Decoupling is Phase 0B, not Phase 1, because the revenue
diversification opportunity is worth protecting early.

The moat is not the questionnaire UI or the PDF. It is a data accumulation engine that
compounds with every completed engagement:

```
Asset → Evidence → Control → Finding → Remediation → Outcome → Drift → Reassessment → Outcome
```

Competitors can copy UI. Competitors can copy workflows. They cannot copy five years of
validated evidence relationships. Every real engagement completed in Phase 0A feeds the
graph. Build the collection infrastructure now; formalize the graph in Phase 3.

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
Decoupling this boundary (Phase 0B item 0B.4) unlocks: assessment-only customers,
governance-only customers, MSSP partnerships, and OEM opportunities.

---

## Phase 0A — Revenue-Safe Launch
**Gate: Safe to hand a client real credentials | Estimate: Weeks 1–2**

These are stop-the-line items. No client credentials before all five are resolved.

### 0A.1 — Fix audio proxy SSRF / bearer token exfiltration (C5) `P0`

**File:** `apps/console/app/api/field-assessment/audio-url/route.ts:23-35`

The proxy accepts a user-controlled URL, checks `url.includes(".blob.vercel-storage.com")`
(substring, not hostname boundary), then fetches with `Authorization: Bearer ${BLOB_READ_WRITE_TOKEN}`.
A URL like `https://attacker.example?x=.blob.vercel-storage.com` passes the check and receives
the storage write token.

**Required fix (immediate):**
1. Parse URL with `new URL()`. Reject on parse error.
2. Require `protocol === "https:"`.
3. Require `hostname.endsWith(".blob.vercel-storage.com")` — suffix match, not substring.
4. Require path starts with `/field-assessment/` (blob upload paths are tenant-prefixed).
5. Do not forward `BLOB_READ_WRITE_TOKEN` to any external URL. Issue a time-limited
   signed download token on the server side using a blob ID resolved from DB
   by `(tenant_id, engagement_id, observation_id)`.
6. Add route tests: hostname confusion, encoded URLs, redirect following, cross-tenant
   retrieval, valid URL path prefix enforcement.

**Required fix (Phase 1):** Replace the proxy with a tenant-bound artifact registry.
Blob IDs stored in DB per observation; download requires `(tenant_id, engagement_id,
observation_id)` lookup. Blob path is opaque and not user-supplied. The storage token
never leaves the server.

### 0A.2 — Block outbound scanner SSRF / private-range access (C6) `P0`

**Files:** `api/field_assessment.py:3267-3379`, `services/connectors/network_scan/runner.py:84-99`,
`services/connectors/web_headers/runner.py:193-203`

Scanners accept arbitrary IPs, CIDRs, hostnames, and URLs with no filtering.

**Required fix (immediate):**
1. Add a `_validate_scan_target(target)` function called before every scan dispatch.
2. Resolve DNS → get all A/AAAA records → reject if any resolved address is in:
   loopback (`127.0.0.0/8`, `::1`), private (`10/8`, `172.16/12`, `192.168/16`),
   link-local (`169.254/16`, `fe80::/10`), cloud metadata (`169.254.169.254/32`),
   multicast, or reserved ranges.
3. For web-header scanner: validate every redirect hop before following.
4. Add per-engagement target allowlist: assessor declares the client's domain or IP range
   during engagement setup; scanners only reach approved targets.
5. Add per-tenant scan quota and concurrency limit.
6. Store a `scan_authorization_record` per scan initiation (actor, targets, timestamp).

**Required fix (Phase 1):** Move outbound scans to an isolated scanner microservice with
explicit egress policy at the network layer. Core API submits jobs; isolated worker executes
in a network segment with no access to internal services.

### 0A.3 — Replace plaintext portal codes with expiring grants (C7) `P0`

**Files:** `api/field_assessment.py:761-784,5070-5087`, `api/middleware/portal_scope.py:35-75`

`client_access_code` is plaintext, sent as a query parameter (leaks to logs, browser history,
analytics, referrers), reused across any engagement matching the same `client_name`, and
the portal trust boundary is enforced only when the caller supplies `X-Portal-Source:
client-portal` — a caller-selected signal.

**Required fix:**
1. Replace `client_access_code` with `portal_grant`: 32-byte cryptographically random,
   URL-safe base64, stored hashed (Argon2 or SHA-256 with tenant salt), never returned
   in API responses after creation.
2. Bind grant to a stable `client_account_id` (separate from mutable `client_name`).
3. Set expiry (default 90 days, operator-configurable). Store `expires_at`, `revoked_at`.
4. Deliver via secure session cookie (`HttpOnly`, `SameSite=Strict`, `Secure`), never query string.
5. Verify server-side: `portal_grant_sessions` table, not header-based trust.
6. Add rotation, revocation, and lockout-after-N-failures endpoints.
7. Emit audit events on: grant creation, rotation, revocation, successful auth, failed auth, lockout.

### 0A.4 — Fix report audit atomicity (H13) `P1`

**Files:** `api/field_assessment.py:4689-4749,1092-1119,2227-2264,5735-5751`

Report creation commits the report row, then appends the audit event in a separate DB operation.
If the append fails, evidence exists with no audit trail — critical in regulated industries.
Several other mutation paths (metadata updates, schedule upserts, remediation-hint edits)
emit no FA audit event at all.

**Required fix:**
1. Wrap every write route in a single transaction: mutation + audit append in one `BEGIN`/`COMMIT`.
2. Create a mutation-to-audit matrix: every write route maps to required audit event fields.
3. Test every write route asserting exactly one audit event was appended in the same transaction.
4. Database-enforce report immutability after QA approval via `BEFORE UPDATE` trigger on
   `fa_reports` that rejects changes when `qa_approved_at IS NOT NULL`.

### 0A.5 — Extend evidence lifecycle locks to update/delete paths (H15) `P1`

**Files:** `api/field_assessment.py:224-233,1814-1969,6441-6645`

`_assert_engagement_accepts_evidence()` correctly blocks new evidence creation on terminal
engagements. But observation PATCH/DELETE and questionnaire evidence-link changes bypass it.
A delivered engagement's evidence can be mutated silently.

**Required fix:**
1. Call `_assert_engagement_accepts_evidence(eng)` at the start of every observation
   PATCH and DELETE route.
2. Freeze questionnaire evidence-link changes on terminal engagements, or model them as
   append-only amendments (new row with `supersedes_id` + reason + actor).
3. Define one lifecycle policy enum referenced from all mutation routes.

---

## Phase 0B — Enterprise Multi-Tenant Safety
**Gate: Scale beyond handful of supervised engagements | Estimate: Weeks 3–5**

You can technically get a pilot client with 0A alone. You cannot scale to multiple tenants
and multiple concurrent engagements without these four items.

### 0B.1 — Console RBAC + human actor attribution (H14) `P0 elevated`

**Files:** `apps/console/middleware.ts:8-32`, `apps/console/app/api/core/[...path]/route.ts`

Today any authenticated console user can reach all FA routes via the BFF prefix. The BFF
forwards a shared core API key, so backend audit actors resolve to the service key rather
than the human operator. If an auditor asks "who approved this assessment?" the current
answer is "the API key." That is not acceptable in regulated environments.

**Required fix:**
1. Add console-level RBAC roles: `operator`, `assessor`, `qa_reviewer`, `admin`, `viewer`.
2. Gate routes by role: scan authorization requires `assessor`; QA approval requires
   `qa_reviewer`; evidence deletion requires `admin`.
3. Forward a signed actor claim from the console BFF to the core API — not a shared service key.
   Claim: `{actor_id, actor_email, actor_role, session_id, issued_at}`, signed with a
   console-held key verified by the core API.
4. All FA audit events resolve to the human actor, not the service key prefix.
5. Add scope splits: `assessment:create`, `assessment:transition`, `evidence:write`,
   `evidence:amend`, `scan:authorize`, `baseline:pin`, `report:generate`,
   `report:qa_approve`, `portal:admin`.

### 0B.2 — Drift table RLS + Postgres isolation tests (H11) `P1`

**Files:** `api/db_models_drift.py:17-114`, `migrations/postgres/0075_fa_rls.sql`

`fa_drift_baselines`, `fa_drift_alerts`, `fa_connector_schedules` are absent from the RLS
migration and startup assertion. Application queries include tenant predicates but DB-level
enforcement is incomplete — a miscoded query can return cross-tenant data.

**Required fix:** Add all three tables to a new idempotent migration (0078+), add to the
startup RLS assertion, and add cross-tenant bleed tests for each table (insert row as
tenant A, assert tenant B query returns empty).

### 0B.3 — Durable connector job store (H12) `P1`

**Files:** `api/field_assessment.py:172-173,2940-2959,4079-4104`

All connector jobs share an in-memory `_MSGRAPH_RUNS` dict with FastAPI background tasks.
Restart loses status; replicas disagree; no durable lease, heartbeat, or dead-letter path.
Status route does not verify `run_id` belongs to the requesting tenant+engagement.

**Required fix:**
1. `fa_connector_jobs` table: `(id, tenant_id, engagement_id, connector_type, status,
   actor_id, target_spec_hash, lease_expires_at, attempt_count, last_error, result_ids,
   created_at, updated_at)`. All columns tenant-scoped.
2. Status route verifies `(tenant_id, engagement_id, run_id)` triplet.
3. Job worker: polls for jobs, holds lease via heartbeat, retries with configurable backoff,
   moves to dead-letter after max attempts.
4. Idempotency: job creation is idempotent on `(engagement_id, connector_type, target_hash)`.
5. Cancellation: operator can cancel a running job; worker checks cancelled flag on heartbeat.

### 0B.4 — FA/Governance outbox boundary (PI20) `Architecture`

**Files:** `services/field_assessment/promotion.py`, `services/field_assessment/connectors/msgraph_bridge.py`,
`services/field_assessment/timeline.py`

FA delivery currently writes directly into governance tables. This blocks standalone FA
deployment, MSSP licensing, OEM partnerships, and acquisition scenarios where FA and
Governance are treated as separate products.

**Required fix — outbox pattern:**
1. On `assessment.delivered`, write an outbox event to `fa_delivery_outbox` table
   `(id, tenant_id, engagement_id, report_id, payload_hash, created_at, delivered_at)`.
2. A lightweight relay worker reads the outbox and publishes to the internal event bus
   (NATS or Postgres LISTEN/NOTIFY).
3. Autonomous Governance subscribes and creates assets, workflows, graph entries, and
   corpus entries as a consumer — completely decoupled from the delivery transaction.
4. FA delivery succeeds even when Autonomous Governance is not running.
5. Move `services/field_assessment/timeline.py` governance writes behind the same outbox.

---

## Phase 1 — Trusted Pilot Foundation
**Gate: First paying client | Estimate: Weeks 6–10**

### 1.1 — Evidence Provenance Ledger `P1 new`

Every evidence item must carry a machine-readable provenance record. This is foundational
for both current regulatory requirements and future autonomous governance. Autonomous
compliance agents and autonomous assessors will ask one question before acting on evidence:
*"Can I trust this?"* Without a provenance ledger, future automation is probabilistic.
With it, automation is defensible.

**Schema — `fa_evidence_provenance`:**
```
evidence_id          — FK to source evidence row
collection_method    — enum: scan_connector | document_upload | interview_capture |
                              observation | questionnaire | import
collector_id         — actor who collected or authorized collection
collected_at         — timestamp of collection, not ingest
source_system        — connector ID or system name (e.g. "microsoft_graph", "assessor")
content_hash         — SHA-256 of raw evidence content at collection time
classification       — enum: public | internal | confidential | restricted | phi | cui
retention_policy     — enum: standard_3y | extended_7y | legal_hold | worm
chain_status         — enum: active | superseded | amended | purged
verification_status  — enum: unverified | assessor_reviewed | qa_approved | externally_audited
verified_by          — actor_id of QA reviewer or auditor
verified_at          — timestamp of verification
```

Add `GET /engagements/{id}/evidence/{evidence_id}/provenance` to the API.
Provenance rows are insert-only: no UPDATE or DELETE allowed. Amendments add a new row
with `chain_status=superseded` on the prior row and `chain_status=active` on the new row.

### 1.2 — OpenAPI → TypeScript codegen (PI18)

Generate the console and portal TypeScript clients from `contracts/core/openapi.json`.
Eliminate the handwritten `fieldAssessmentApi.ts` drift (wrong status strings, missing
connectors, wrong response shapes, broken 204 handling). Add BFF integration tests that
verify the client against the actual API contract.

### 1.3 — Private interview vault (H6 partial) `P1`

Signed URLs, retention controls, consent records, redaction, transcript provenance.
Required for healthcare, legal, and government sales. Closes the deferred H6 item on
OpenAI provider governance by moving audio through the platform provider abstraction
rather than a hardcoded `model-provider credential` call.

**Schema additions:** `fa_interview_consents`, `fa_audio_retention_policies`.
**API additions:** `POST /observations/{id}/audio/redact`, `GET /observations/{id}/audio/signed-url`.

### 1.4 — Evidence integrity score `P1`

Score every finding by source quality, freshness, corroboration count, and chain completeness.
Score fields feed the Evidence Confidence Engine in Phase 3 (M0). Start collecting now.

**Scoring dimensions:**
- Source quality: scan connector > document analysis > questionnaire response > manual observation
- Freshness: decay function over days since collection
- Corroboration: count of independent evidence items supporting the same control
- Chain completeness: provenance ledger `verification_status` ≥ `qa_approved`

Expose as `confidence_breakdown` in the finding response. Store component scores for later
aggregation into the Evidence Confidence Engine.

### 1.5 — Assessment health dashboard `P1`

Operator view: missing evidence, stale documents, failed scan jobs, unresolved QA blockers,
readiness gate progress, delivery forecast. Reduces delivery time by surfacing gaps before
the final QA review.

Key metrics: evidence coverage per control domain, days since last scan per connector,
questionnaire completion rate, open findings by severity, estimated delivery date.

### 1.6 — Retention, legal hold, and deletion workflow

1. Add `retention_class`, `legal_hold`, `scheduled_purge_at`, `purge_completed_at` to
   evidence tables (aligned with provenance ledger classification column).
2. Purge workflow: soft-delete first, hard-delete after retention period + legal hold clear;
   emit immutable purge proof event.
3. Export: operator can export all engagement evidence as a signed archive before deletion.
4. WORM option: flag engagement as WORM at delivery; DB trigger blocks all subsequent mutations.

### 1.7 — Portal session identity (dependency for C7 full fix) `P1`

After C7 establishes portal grants:
1. `portal_accounts` table: `(id, tenant_id, client_account_id, email, mfa_enrolled,
   created_at, last_login_at)`.
2. `portal_sessions` table: `(id, account_id, grant_id, device_fingerprint, created_at,
   expires_at, revoked_at)`.
3. Session cookie contains signed session ID only — all state server-side.
4. Failed auth tracked per account; lockout after N failures with exponential backoff.
5. Portal session audit events: login, logout, failed attempt, lockout, revocation.

### 1.8 — Database hardening

For every FA child table:
1. Composite tenant-aware FK from `(tenant_id, engagement_id)` to `fa_engagements`.
2. Check constraints: status enums, severity enums, source type enums, confidence score
   range `[0, 100]`, schema version pattern.
3. Unique constraint: at most one active baseline per `(tenant_id, engagement_id)`.
4. Retention classification column on tables with evidence data.

---

## Phase 2 — Enterprise Production
**Gate: Multi-tenant commercial deployment | Estimate: Weeks 11–18**

### 2.1 — Governed document pipeline

1. **Upload:** virus scan (ClamAV or cloud equivalent), file type enforcement, size limits.
2. **Classification:** DLP scan for PII/PHI/CUI before storing; reject or flag on hit.
3. **Extraction:** async text extraction (PDF, DOCX, XLSX) into `fa_document_analyses`.
4. **Review:** assessor marks document as reviewed; locked after QA approval.
5. **Provenance:** hash stored at upload, verified at report generation (hooks into 1.1 ledger).
6. **Retention:** classification label drives retention period; legal-hold flag blocks deletion.

### 2.2 — Scheduler execution (PI19)

`fa_connector_schedules` stores schedules but no worker executes them.
1. Schedule worker polls for due schedules (cron expression + `next_run_at`).
2. Worker submits jobs to `fa_connector_jobs` (Phase 0B.3) rather than calling connectors directly.
3. Disable/delete API for schedules.
4. Audit events on: schedule create, modify, trigger, disable, delete.
5. Operational UI: schedule list with last-run status, next-run time, consecutive failure count.

### 2.3 — Reassessment cloning

Clone scope, interview plan, document requirements, owners, and unresolved findings from
a prior engagement into a new draft engagement. Improves recurring revenue — a client's
second assessment should take a fraction of the time of the first.

Add `GET /engagements/{id}/reassessment-plan` to preview the clone diff (what has changed
since prior delivery, what is new, what was closed).

### 2.4 — Client remediation workspace

Owners, due dates, evidence upload, reviewer approval, reminders, and closure verification.
Converts one-time assessments into ongoing subscriptions. The client portal becomes a
live workspace between engagements, not just a delivery read-only view.

### 2.5 — Framework expansion engine

Map one verified evidence item across NIST AI RMF, HIPAA, SOC 2, ISO 27001, CMMC, PCI DSS,
DORA, FedRAMP, and NIST 800-171. Expands addressable market without collecting new evidence.
The crosswalk is the value; the evidence collection was already done.

### 2.6 — Assessor assignment and amendment workflows

1. `fa_assessor_assignments` table: `(engagement_id, assessor_id, role, assigned_by, assigned_at)`.
2. Evidence request workflow: assessor creates request; client sees upload action in portal;
   request closes when evidence linked.
3. Amendment workflow: post-delivery finding amendment requires assessor reason + QA re-approval
   (amendment row with `supersedes_id`, provenance ledger entry).

### 2.7 — Client account identity

Replace `client_name` as the client key with stable `client_account_id`:
1. `portal_client_accounts` table: `(id, tenant_id, display_name, industry, contact_email, created_at)`.
2. Engagements reference `client_account_id` not free-text name.
3. Portal grants bind to `client_account_id`.
4. Multiple engagements for the same client are discoverable without name collisions.

### 2.8 — Assessor workflow automation

Auto-generate interview agenda from playbook gaps, evidence request list from unmet control
requirements, next-best action from readiness gate state, and report completion forecast from
current evidence velocity. Improves assessor margin.

---

## Phase 3 — Compounding Moat
**Gate: Defensible competitive position | Estimate: Months 3–6**

The moat is not the questionnaire, the PDF, or the scan connectors. Competitors can copy any
of those in weeks. The moat is a data accumulation engine that compounds with every completed
engagement. Competitors who launch later start from zero.

### 3.1 — Autonomous Trust Fabric (M0 — foundational)

**Why this comes first in Phase 3:** Eventually every GRC and assessment tool will generate
reports with AI. Few will be able to answer the question: *"Why should I trust this report?"*
FrostGate's brand promise is *Trust but Verify*. The platform should operationalize it.

**Evidence Confidence Engine:**

Track per evidence item:
- `evidence_freshness_score` — decay function from `collected_at` to now
- `source_reliability_score` — connector scan > document > questionnaire > manual, weighted by
  collector reputation history
- `corroboration_count` — number of independent items supporting the same control
- `remediation_success_history` — for past findings linked to this control: was remediation
  verified by evidence in a subsequent engagement?

Aggregate into a hierarchy of confidence scores:

```
Evidence Confidence   (per evidence item)
        ↓
Control Confidence    (per control, across all linked evidence)
        ↓
Finding Confidence    (per finding, weighted by evidence quality)
        ↓
Assessment Confidence (per engagement, composite)
        ↓
Organization Confidence (per client, across all engagements)
```

Expose scores via API and display in portal. Over time, the confidence scores are trained
on outcomes — controls that passed on a confident assessment and stayed clean in the next
reassessment increase their reliability weight. Controls that regressed despite high-confidence
evidence trigger a reliability review.

### 3.2 — Longitudinal Evidence Graph (M1 — primary moat)

**Why hard to copy:** After 10 assessments across 3 years for one client, FrostGate has a
verified evidence timeline that no questionnaire tool can reconstruct.

**Schema:**
1. `fa_evidence_nodes` — versioned, immutable snapshot at delivery:
   `(id, tenant_id, engagement_id, source_type, source_id, control_ids[], finding_ids[],
   confidence_score, verified_at, evidence_hash, snapshot_version)`
2. `fa_evidence_edges` — links across engagements:
   `(from_node_id, to_node_id, relationship_type, created_at)`
   Types: `supersedes`, `corroborates`, `contradicts`, `references`

**Reassessment diff:** On new engagement delivery, diff against prior graph. Surfaces:
- Regression: control was met, now failed
- New coverage: net-new control met for first time
- Stale evidence: same document, no update since prior assessment
- Remediation verification: finding closed, evidence supports the fix

**API:** `GET /engagements/{id}/evidence-graph` — nodes + edges with provenance.
**Portal:** Timeline of control evidence across all engagements for this client.

### 3.3 — Regulator-ready verification bundles (M2)

At delivery, generate a deterministic bundle: all evidence items, findings, questionnaire
responses, audit events, QA approval, report manifest — serialized to canonical JSON
with SHA-256 hash tree. Sign the bundle root with an Ed25519 key (per-tenant, HSM/KMS).

A signed, replayable evidence bundle that an auditor or insurer can independently verify
is a strong differentiator in regulated sales. Building the signing infrastructure correctly
takes time; every delay builds the moat.

**API:** `POST /engagements/{id}/verify-bundle` — takes bundle + public key, replays hash
tree, returns pass/fail with provenance diff on mismatch.
**Export:** Self-contained ZIP with `verify.sh`. **Auditor portal:** read-only, no login — bundle hash is the credential.

### 3.4 — Reassessment intelligence (M1)

At each reassessment, compare all findings against prior engagement:
- Remediated: open → closed with verified evidence → record `remediation_velocity`, `evidence_quality_delta`
- Regressed: closed → open → record `regression_date`, `root_cause_category`
- New: net-new finding
- Persistent: same status → record `staleness_days`

`fa_reassessment_deltas` table persists the diff. Operator dashboard: per-client trend view.
Recommendations: surface similar findings from other engagements (same control, same industry)
that were successfully closed, with the evidence type and remediation approach that worked.
Anonymized; no PII.

### 3.5 — Sector benchmark network (M1)

Opt-in consent model: at engagement close, offer participation in the benchmark corpus.
Anonymization pipeline strips PII/PHI; retains only sector, org size band, control IDs,
scores, evidence types, finding severities, remediation outcomes.

`GET /benchmarks?sector=community_banking&size_band=mid&framework=nist_ai_rmf` → percentile
bands per control, median remediation velocity, common finding patterns.

Portal: "Your score vs. 23 similar organizations in your sector" for every control domain
where benchmark data exists.

### 3.6 — Continuous reassessment triggers (M1)

Detect drift from MS Graph, identity, OAuth, endpoint, DNS, web, and network connectors.
Automatically flag controls for focused reassessment when drift threshold is crossed.
Converts completed assessments into subscriptions — clients retain FrostGate to watch
their posture, not just to assess it once.

---

## Phase 4 — Regulated Enterprise
**Gate: Regulated industry commercial sales | Estimate: Months 4–12**

### 4.1 — SOC 2 Type II readiness

1. Availability: uptime monitoring, incident response plan, SLA definition.
2. Confidentiality: encryption at rest (Postgres TDE or pgcrypto for sensitive columns),
   TLS 1.3 everywhere, key rotation schedule.
3. Security: penetration test, vulnerability disclosure policy, patch SLA.
4. Processing integrity: evidence hash chain, audit trail completeness, report verification.
5. Privacy: data classification, retention schedules, deletion workflow, breach notification.

### 4.2 — HITRUST and HIPAA BAA (healthcare market)

1. Establish BAA with all sub-processors (Railway, Vercel, Anthropic, Auth0).
2. HITRUST CSF r2 self-assessment against the 19 control categories.
3. PHI handling audit: every endpoint that could touch PHI mapped and documented.
4. Private interview vault completion (from Phase 1.3): consent records, audio purge proof,
   transcript redaction verified.

### 4.3 — FedRAMP preparation + CMMC (govcon market)

The govcon profile is already in the product (CMMC 2.0, NIST 800-171, DFARS).

1. Air-gap mode: FA runs without external AI calls (report narrative generation becomes optional).
2. Data residency: all tenant data in US regions only.
3. FIPS 140-2 cryptographic modules for signing and hashing.
4. Continuous monitoring (ConMon): automated vulnerability scanning, configuration drift alerts.
5. Government expansion: DFARS clause compliance, CUI handling documentation, FedRAMP boundary definition.

### 4.4 — Penetration testing

Before regulated enterprise sales, commission an independent penetration test of:
- Audio proxy endpoint (C5 fix must be verified externally)
- Portal authentication model (C7 fix must be verified externally)
- Scan target validation (C6 fix must be verified externally)
- Tenant isolation model (RLS + application layer)
- API authentication and authorization layer

---

## What NOT to Build (Explicitly Deferred)

| Item | Reason for deferral |
|------|---------------------|
| Endpoint agent fleet, rings, missions, command bus | Requires FA moat first; complex ops overhead |
| Continuous readiness simulations | Requires longitudinal graph (Phase 3.2) as prerequisite |
| Autonomous remediation agents | Requires remediation outcome dataset (Phase 3.4) |
| Governed AI assistant / RAG retrieval product | Autonomous Governance tier; not FA |
| Provider routing, AI plane policy, model evaluation lab | Tier 3/4; not FA |
| Workforce AI behavior analytics | Separate product; not core to FA |
| Real-time OPA policy enforcement on AI requests | AI gateway product; deferred to Tier 3 |
| Spreadsheet + competitor import adapters | Phase 2+ when switching cost becomes relevant |

---

## Architecture Decisions

### 1. FA/Governance boundary: outbox pattern

Use a `fa_delivery_outbox` table + relay worker. The outbox event is written in the same
transaction as the delivery state change. The relay delivers the event asynchronously.
Governance modules are optional consumers. FA delivery never fails because Governance is down.

### 2. Durable jobs: database-backed, not in-process

Use `fa_connector_jobs` table with lease heartbeat. Postgres-based job queue is sufficient
at current scale. Upgrade to NATS JetStream (already available in the platform) when
throughput requires it. Do not use Redis for job state — not durable enough for evidence chains.

### 3. Blob storage: artifact registry pattern

Never forward storage credentials to the client. Every audio/document blob is referenced
in DB by `(tenant_id, engagement_id, observation_id, blob_id)`. Download requires a
server-side lookup. Blob path is opaque — no `/tenants/xxx/audio/` patterns that leak structure.

### 4. Actor attribution: signed gateway claim

The console BFF signs an actor claim `{actor_id, email, role, session_id}` with a
console-held private key. The core API verifies with the corresponding public key (set at
startup). All audit events record the human actor. The service key is only used for
machine-to-machine health/internal calls.

### 5. Evidence immutability: trigger + amendment model

Database triggers enforce report immutability after QA approval and evidence immutability
after delivery. Post-delivery changes are amendments: new rows with `supersedes_id`,
`amended_by`, `amended_at`, `reason`. Original is never mutated. Amendments require QA re-approval.
Provenance ledger (Phase 1.1) records every chain transition.

### 6. Moat through data, not features

Features can be copied in weeks. The evidence graph cannot. Every engagement completed
before competitors adds another data point to the longitudinal graph, the reassessment
intelligence dataset, and the sector benchmark corpus. The product compounds; competitors
start from zero. The confidence engine (Phase 3.1) is trained on those outcomes — it
gets smarter with every completed assessment.

---

## Delivery Estimates

| Phase | Gate | Key risks | Estimate |
|-------|------|-----------|----------|
| **Phase 0A — Revenue-Safe Launch** | Safe to hand client credentials | C5 scope: hostname check vs. full artifact registry | Weeks 1–2 |
| **Phase 0B — Multi-Tenant Safety** | Scale beyond supervised pilot | Durable job store adds operational complexity | Weeks 3–5 |
| **Phase 1 — Trusted Pilot** | First paying client | Provenance ledger schema needs careful versioning | Weeks 6–10 |
| **Phase 2 — Enterprise Production** | Multi-tenant commercial | Document pipeline regulatory requirements vary by market | Weeks 11–18 |
| **Phase 3 — Compounding Moat** | Defensible position | Evidence graph schema; benchmark consent pipeline; confidence calibration | Months 3–6 |
| **Phase 4 — Regulated Enterprise** | Regulated sales | FedRAMP is 12–18 month process; HITRUST self-assessment is 3–6 months | Months 4–12 |

**Fastest path to controlled pilot:** Close 0A.1–0A.5 (4–6 days focused engineering).
The product is demonstrable now; those five items make it safe to demo with real client credentials.

**Fastest path to first revenue:** Controlled pilot → collect payment → use payment to fund 0B.
The evidence graph moat (Phase 3) starts accumulating value from the first paid engagement.
Every completed assessment is a permanent data advantage. The mistake most founders make here
is chasing FedRAMP, HITRUST, dashboards, and AI features before closing the trust gaps.
The next dollar is hiding behind security closure and evidence integrity, not another screen.

---

*FrostGate — AI Governance for Regulated Industries*  
*Enterprise Plan v1.1 — 2026-06-02*
