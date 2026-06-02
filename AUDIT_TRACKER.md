# FrostGate Security & Integrity Audit Tracker

**Audited:** `main` at `d15699e7`  
**Opened:** 2026-06-02  
**Authority:** All items from forensic audit + user-specified ROI enhancements + moat builders.  
Nothing in this file can be closed without a PR reference and explicit review.

---

## Critical Findings

| # | Finding | Location | Status | PR |
|---|---------|----------|--------|----|
| C1 | **QA approval bypasses readiness gates** — `qa_approve_report` directly sets `delivered` without running `_evaluate_execution_state`. Missing scans, questionnaires, evidence links, and remediation can ship as complete. | `api/field_assessment.py:4877` vs `:1179` | 🔴 Open | — |
| C2 | **Fresh Postgres deployments can fail** — startup runs migrations before `create_all()`, while migrations 0073 and 0074 alter FA tables that have no earlier create migration. | `api/db.py:1344`, `migrations/postgres/0073` | 🔴 Open | — |
| C3 | **FA tenant tables lack Postgres RLS** — questionnaires and governance promotions have no DB-level row security. Application filters present but not enforced at DB layer. | `api/db_migrations.py:137`, `migrations/postgres/0067` | 🔴 Open | — |
| C4 | **Portal IDOR — client-wide not engagement-scoped** — BFF appends `client_access_code` as query param but item endpoints scope only on `(engagement_id, tenant_id)`. A client with another engagement UUID can read or mutate data. | `apps/portal/app/api/core/[...path]/route.ts:110`, `api/field_assessment.py:1031,1944` | 🔴 Open | — |

---

## High Findings

| # | Finding | Location | Status | PR |
|---|---------|----------|--------|----|
| H5 | **Audit events not immutable** — `fa_engagement_audit_events` claims append-only semantics in code but no Postgres trigger enforces it; table absent from RLS startup assertion. | `api/db_models_field_assessment.py:12` | 🔴 Open | — |
| H6 | **Audio uploaded as public blob, sent to hardcoded OpenAI** — sensitive regulated-industry recordings bypass platform provider-governance path. | `apps/console/app/api/field-assessment/transcribe/route.ts:109,128` | 🔴 Open | — |
| H7 | **`evidence_doc_id` accepts arbitrary values** — `patch_questionnaire_response` does not verify the document belongs to the same engagement/tenant. Stale `finding → document_analysis` auto-links not cleaned when response status drops. | `api/field_assessment.py:6274` | ✅ Fixed | — |
| H8 | **Observation delete leaves dangling evidence links** — cascade removes source links but not target links (common remediation path). Source link delete also missing `engagement_id` predicate. | `api/field_assessment.py:1827` | ✅ Fixed | — |
| H9 | **Observation edits bypass audio-evidence validator** — structured evidence and linked finding IDs replaceable without validation; audit diff omits both fields. | `api/field_assessment.py:1729` | 🔴 Open | — |
| H10 | **QA approval is mutable** — re-approving overwrites reviewer metadata instead of rejecting changes to the legal artifact. Response returns JWT actor instead of reviewer display name. | `api/field_assessment.py:4850` | 🔴 Open | — |

---

## Product Integrity Findings

| # | Finding | Location | Status | PR |
|---|---------|----------|--------|----|
| PI11 | **MS Graph import bypasses governance promotion lock** — auto-promotes governance assets and rebuilds graph before delivery, violating the locked rule. Errors silently swallowed. | `services/field_assessment/connectors/msgraph_bridge.py:239` | 🔴 Open | — |
| PI12 | **Corpus feed unfinished** — architecture promises async document ingestion; implementation synchronously indexes finding summaries only. | `services/field_assessment/promotion.py:324` | 🔴 Open | — |
| PI13 | **Readiness evaluation silently caps at 100** — scans, docs, observations, findings, and links all capped; promotion creates workflows for only first 100 findings. Larger assessments partially evaluated. | `api/field_assessment.py:2377`, `services/field_assessment/promotion.py:152` | 🔴 Open | — |
| PI14 | **Soft-deleted observations counted in summary** — `engagement_summary` count query does not filter `deleted_at IS NULL`. | `api/field_assessment.py:2308` | ✅ Fixed | — |
| PI15 | **Postgres schema evolution incomplete** — ORM fields (`finding_count`, `asset_id`) have no FA migration; `create_all(checkfirst=True)` does not add missing columns on existing tables. | `api/db_models_field_assessment.py:87` | 🔴 Open | — |

---

## ROI Enhancements

| Priority | Enhancement | Rationale | Status | PR |
|----------|-------------|-----------|--------|----|
| P0 | **One-click defensible delivery gate** | Prevent report delivery until evidence, questionnaire, QA, and promotion checks pass. Reduces manual QA risk. | 🔴 Open | — |
| P0 | **Client-scoped portal permissions** | Replace shared tenant-wide portal access with explicit per-client + per-engagement grants. Enables secure multi-client scaling. Closes C4. | 🔴 Open | — |
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

*Last updated: 2026-06-02 — H7, H8, PI14 fixed (quick wins batch); 12 items remain open.*
