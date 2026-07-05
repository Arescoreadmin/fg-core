# PR 18.6.6 — Enterprise Customer Portal Experience

## Overview

PR 18.6.6 delivers the full enterprise customer portal — a customer-facing surface for AI governance assessment clients to view findings, reports, remediation, trust verification, and engagement artifacts. All components are MCIM-registered, portal-safe, and wired to the portal BFF API.

---

## MCIM Registration

Every component carries:

| Constant | Value |
|---|---|
| `MCIM_ID` | `MCIM-18.6-PORTAL-[NAME]` |
| `AUTHORITY` | `[Name] Authority` |
| `sourceOfTruth` | `/api/core/field-assessment/engagements` |
| `drillDown` | Portal route for this component |
| `customerSafe` | `true` |

All five constants are declared at the top of every file and voided at the bottom.

---

## Component Registry

### Shell

| File | MCIM ID | Purpose |
|---|---|---|
| `PortalShell.tsx` | `MCIM-18.6-PORTAL-SHELL` | Card wrapper with collapsible source metadata footer |

### Core Components (from Agent A)

| File | MCIM ID | Data Source |
|---|---|---|
| `CustomerDashboard.tsx` | `MCIM-18.6-PORTAL-DASHBOARD` | `getEngagementSummary` |
| `EngagementOverview.tsx` | `MCIM-18.6-PORTAL-ENGAGEMENT` | `getEngagement` |
| `FindingsView.tsx` | `MCIM-18.6-PORTAL-FINDINGS` | `listFindings`, `explainFinding` |
| `EvidenceSummary.tsx` | `MCIM-18.6-PORTAL-EVIDENCE` | `listEvidenceLinks` |
| `ReportDelivery.tsx` | `MCIM-18.6-PORTAL-REPORTS` | `listReports`, `exportReport`, `verifyReport` |
| `AttestationCenter.tsx` | `MCIM-18.6-PORTAL-ATTESTATION` | `listAssets`, `submitAttestation` |
| `RemediationCenter.tsx` | `MCIM-18.6-PORTAL-REMEDIATION` | `getRemediationRoadmap` |
| `ChangeSummary.tsx` | `MCIM-18.6-PORTAL-CHANGES` | Baseline snapshot diff |
| `TrustVerificationCenter.tsx` | `MCIM-18.6-PORTAL-TRUST-VERIFY` | `getVerificationBundle` |
| `CustomerTrustTimeline.tsx` | `MCIM-18.6-PORTAL-TIMELINE` | `listAuditEvents` (portal-safe filter) |
| `CustomerActionQueue.tsx` | `MCIM-18.6-PORTAL-ACTIONS` | `listFindings` (open) |
| `CustomerExportCenter.tsx` | `MCIM-18.6-PORTAL-EXPORT` | `exportReport`, `listReports` |
| `AssessmentDelivery.tsx` | `MCIM-18.6-PORTAL-ASSESSMENT` | `getEngagement` |

### Extended Components (PR 18.6.6)

| File | MCIM ID | Data Source |
|---|---|---|
| `NotificationCenter.tsx` | `MCIM-18.6-PORTAL-NOTIFICATIONS` | `listAuditEvents` (mapped) |
| `SupportCenter.tsx` | `MCIM-18.6-PORTAL-SUPPORT` | Static operator-provided topics |
| `ObservationsPanel.tsx` | `MCIM-18.6-PORTAL-OBSERVATIONS` | `listObservations` |
| `AuditEventsLog.tsx` | `MCIM-18.6-PORTAL-AUDIT-EVENTS` | `listAuditEvents` |
| `DocumentCenter.tsx` | `MCIM-18.6-PORTAL-DOCUMENTS` | `listDocuments` |
| `ScanHistoryPanel.tsx` | `MCIM-18.6-PORTAL-SCANS` | `listScans` |
| `QuestionnaireSummary.tsx` | `MCIM-18.6-PORTAL-QUESTIONNAIRE` | `listQuestionnaires` |
| `ComplianceOverview.tsx` | `MCIM-18.6-PORTAL-COMPLIANCE` | `getRemediationRoadmap` + `listQuestionnaires` |

---

## New Page Routes

| Route | Component | data-testid |
|---|---|---|
| `/dashboard` | `CustomerDashboard` | `dashboard-page` |
| `/trust` | `TrustVerificationCenter` | `trust-page` |
| `/timeline` | `CustomerTrustTimeline` | `timeline-page` |
| `/actions` | `CustomerActionQueue` | `actions-page` |
| `/changes` | `ChangeSummary` | `changes-page` |
| `/export` | `CustomerExportCenter` | `export-page` |
| `/notifications` | `NotificationCenter` | `notifications-page` |
| `/support` | `SupportCenter` | `support-page` |

All pages use `'use client'` + Suspense + inner component pattern, matching the existing portal page conventions.

---

## Security Model

### Portal invariants enforced by CI (`check_customer_portal.py`)

- No `tenant_id` in any client code
- No `dangerouslySetInnerHTML` (layout.tsx exception already present — no new instances)
- No console UI component imports (`@/components/ui/badge`, `@/components/ui/button`, `@/components/ui/card`)
- No `Math.random()` (non-deterministic state)
- No `sessionStorage`
- `customerSafe = true` declared and voided in every component

### Portal-safe data rules

- All data via `portalApi.*` BFF client — never raw `fetch` to internal paths
- `localStorage` used only for engagement ID UX (`engagementStore`) and read-state tracking (notifications, change baseline) — never for authoritative state
- `listAuditEvents` results filtered to `PORTAL_SAFE_EVENT_TYPES` set before display on timeline
- Raw scan payloads never exposed — `ScanHistoryPanel` shows only metadata
- No admin routes referenced in any portal component

### Required disclaimers

- `TrustVerificationCenter`: "do not constitute legal certification"
- `CustomerExportCenter`: "do not constitute legal certification"
- `ComplianceOverview`: "do not constitute legal certification"
- `SupportCenter`: "Support content is provided by your operator"
- `AuditEventsLog`: "portal-visible governance actions"
- `ScanHistoryPanel`: "No raw scan payloads are displayed"

---

## CI Validation

### `tools/ci/check_customer_portal.py`

Checks 22 components + 8 pages:

- MCIM ID prefix: `MCIM-18.6-PORTAL-`
- `customerSafe = true` declaration and void
- `void MCIM_ID` at bottom
- PortalShell usage in non-shell components
- `aria-label` on content sections
- Forbidden patterns: `tenant_id`, `dangerouslySetInnerHTML`, console imports, `Math.random()`
- Per-component domain checks (trust disclaimer, hash fields, operator notice, etc.)
- Page `data-testid` anchors
- Page `'use client'` directive

### `tests/portal/customer-portal.test.js`

564 static source-scan tests across 20 suites:

- Per-component suites (22 components × ~7 checks)
- Cross-cutting MCIM compliance (22 × 6 = 132 tests)
- Cross-cutting security invariants (22 × 7 = 154 tests)
- Non-shell PortalShell usage (21 × 5 = 105 tests)
- Non-shell empty state handling (21 × 1 = 21 tests)
- Page existence + testid + security (8 × 4+ checks)
- CI script existence and coverage

---

## Machine-Readable Appendix

### portal_component_registry

```json
[
  {"mcim_id": "MCIM-18.6-PORTAL-SHELL", "file": "PortalShell.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-DASHBOARD", "file": "CustomerDashboard.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-ENGAGEMENT", "file": "EngagementOverview.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-FINDINGS", "file": "FindingsView.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-EVIDENCE", "file": "EvidenceSummary.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-REPORTS", "file": "ReportDelivery.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-ATTESTATION", "file": "AttestationCenter.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-REMEDIATION", "file": "RemediationCenter.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-CHANGES", "file": "ChangeSummary.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-TRUST-VERIFY", "file": "TrustVerificationCenter.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-TIMELINE", "file": "CustomerTrustTimeline.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-ACTIONS", "file": "CustomerActionQueue.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-EXPORT", "file": "CustomerExportCenter.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-ASSESSMENT", "file": "AssessmentDelivery.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-NOTIFICATIONS", "file": "NotificationCenter.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-SUPPORT", "file": "SupportCenter.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-OBSERVATIONS", "file": "ObservationsPanel.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-AUDIT-EVENTS", "file": "AuditEventsLog.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-DOCUMENTS", "file": "DocumentCenter.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-SCANS", "file": "ScanHistoryPanel.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-QUESTIONNAIRE", "file": "QuestionnaireSummary.tsx", "customer_safe": true},
  {"mcim_id": "MCIM-18.6-PORTAL-COMPLIANCE", "file": "ComplianceOverview.tsx", "customer_safe": true}
]
```

### portal_page_registry

```json
[
  {"route": "/dashboard", "component": "CustomerDashboard", "testid": "dashboard-page"},
  {"route": "/trust", "component": "TrustVerificationCenter", "testid": "trust-page"},
  {"route": "/timeline", "component": "CustomerTrustTimeline", "testid": "timeline-page"},
  {"route": "/actions", "component": "CustomerActionQueue", "testid": "actions-page"},
  {"route": "/changes", "component": "ChangeSummary", "testid": "changes-page"},
  {"route": "/export", "component": "CustomerExportCenter", "testid": "export-page"},
  {"route": "/notifications", "component": "NotificationCenter", "testid": "notifications-page"},
  {"route": "/support", "component": "SupportCenter", "testid": "support-page"}
]
```
