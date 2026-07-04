# Operations Workspace — Architecture Reference

**PR**: 18.6.4 — Enterprise Operations Workspace  
**MCIM**: MCIM-18.6-OPS-WORKSPACE  
**Authority**: Operations Workspace Authority  
**Source of Truth**: `/api/core/control-tower/snapshot`  
**Date**: 2026-07-04  

---

## Overview

The Enterprise Operations Workspace transforms FrostGate from an executive monitoring platform into a complete enterprise operations platform. The Executive Command Center (18.6.2/18.6.3) provides situational awareness. This workspace provides execution.

The workspace is the daily cockpit for Security Analysts, AI Governance Analysts, Field Assessors, Compliance Teams, Risk Teams, Consultants, MSP Operators, and Internal Administrators.

**Key principles:**
- No duplicated business logic
- No duplicated authority calculations
- No backend authority ownership changes
- All orchestration through MCIM and Navigation Registry
- Existing routes remain valid
- Every action delegates — never duplicates write logic
- Every decision is traceable
- Every export includes provenance metadata
- Fully tenant-isolated

---

## Components

All 13 workspace components live in `apps/console/components/operations-workspace/`. Every component:

- Declares `const MCIM_ID`, `const AUTHORITY`, `const sourceOfTruth`, `const drillDown`
- Starts with `'use client'`
- Has no `Math.random`, `dangerouslySetInnerHTML`, `localStorage`, or `sessionStorage`
- Uses only allowed Badge variants: `default | secondary | success | warning | danger | critical | high | medium | low | outline`

| Component | MCIM ID | Authority |
|---|---|---|
| WorkspaceShell | MCIM-18.6-OPS-WORKSPACE | Operations Workspace Authority |
| UnifiedWorkQueue | MCIM-18.6-WORK-QUEUE | Work Queue Authority |
| CaseWorkspace | MCIM-18.6-CASE-WORKSPACE | Case Workspace Authority |
| DecisionLedger | MCIM-18.6-DECISION-LEDGER | Decision Ledger Authority |
| WorkflowProgress | MCIM-18.6-WORKFLOW-PROGRESS | Workflow Progress Authority |
| InvestigationTimeline | MCIM-18.6-INVESTIGATION-TIMELINE | Investigation Authority |
| CrossAuthorityNav | MCIM-18.6-CROSS-AUTHORITY-NAV | Navigation Authority |
| AuthorityHealthMap | MCIM-18.6-AUTHORITY-HEALTH-MAP | Authority Health Authority |
| CorrelationGraph2 | MCIM-18.6-CORRELATION-GRAPH-2 | Correlation Authority |
| CommandPalette | MCIM-18.6-COMMAND-PALETTE | Command Palette Authority |
| PlaybookPanel | MCIM-18.6-PLAYBOOK-PANEL | Playbook Authority |
| DelegationPanel | MCIM-18.6-DELEGATION-PANEL | Delegation Authority |
| ExportPanel | MCIM-18.6-EXPORT-PANEL | Export Authority |

---

## Work Queue

**Component**: `UnifiedWorkQueue.tsx`  
**Source**: `/api/core/feed/live`

Aggregates work from existing authorities into a single filterable queue. Supports 14 work types:

| Work Type | Description |
|---|---|
| `assessment` | Assessment tasks |
| `evidence-review` | Evidence requiring review |
| `verification` | Verification tasks |
| `report-review` | Reports awaiting review |
| `portal-publication` | Portal publication workflow |
| `remediation` | Remediation actions |
| `governance-approval` | Governance approval requests |
| `trust-review` | Trust chain reviews |
| `transparency-review` | Transparency reviews |
| `simulation-review` | Simulation result reviews |
| `replay-review` | Replay verification reviews |
| `customer-request` | Customer-initiated requests |
| `notification` | Actionable notifications |
| `policy-review` | Policy review tasks |

Every queue item exposes: `authority`, `capability`, `mcimId`, `priority`, `severity`, `sla`, `owner`, `dueDate`, `confidence`, `sourceObject`, `drillDown`, `workflowStage`.

Filterable by priority: `critical | high | medium | low`.

---

## Case Model

**Component**: `CaseWorkspace.tsx`  
**Source**: `/api/core/decisions`

A Case aggregates cross-authority relationships without duplicating authority data. Cases reference authority IDs — they never copy authority state.

```typescript
interface WorkspaceCase {
  id: string;
  title: string;
  status: 'open' | 'in-progress' | 'blocked' | 'closed';
  priority: 'critical' | 'high' | 'medium' | 'low';
  linkedAssessments: string[];   // IDs only
  linkedDecisions: string[];     // IDs only
  linkedReports: string[];       // IDs only
  linkedEvidence: string[];      // IDs only
  owner: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}
```

Cases can aggregate: Assessment, Evidence, Finding, Report, Decision, Simulation, Replay, Remediation, Trust, Transparency, Portal, Customer, Timeline.

---

## Decision Ledger

**Component**: `DecisionLedger.tsx`  
**Source**: `/api/core/decisions`

Immutable, append-only audit history of every operational decision. No editing. Display-only.

```typescript
interface LedgerEntry {
  id: string;
  decision: string;
  businessJustification: string;
  evidence: string[];
  alternativesConsidered: string[];
  expectedOutcome: string;
  actualOutcome: string | null;
  owner: string;
  reviewer: string | null;
  reviewSchedule: string | null;
  confidence: number | null;
  provenanceChain: string[];
  linkedReports: string[];
  linkedRemediation: string[];
  linkedSimulations: string[];
  createdAt: string;
}
```

The ledger records: decision, business justification, evidence, alternatives considered, expected outcome, actual outcome, owner, reviewer, review schedule, confidence, provenance chain, linked reports, linked remediation, and linked simulations.

---

## Workflow Engine

**Component**: `WorkflowProgress.tsx`  
**Source**: `/api/core/control-tower/snapshot`

Progress derived from authority state — never estimated. Supports 10 workflow types across 5 stage statuses.

**Workflow types**: `assessment | evidence | verification | report | portal | remediation | governance | trust | simulation | replay`

**Stage statuses**:

| Status | Meaning |
|---|---|
| `not-started` | Workflow not yet initiated |
| `active` | Currently being worked |
| `waiting` | Waiting on upstream dependency |
| `blocked` | Blocked — requires intervention |
| `completed` | Successfully completed |

---

## Investigation Timeline

**Component**: `InvestigationTimeline.tsx`  
**Source**: `/api/core/forensics/events`

Chronological event timeline for investigations. Supports 8 event types:

`created | modified | verified | reviewed | approved | published | remediated | closed`

Each event records: `authority`, `timestamp`, `actor`, `confidence`, `correlationId`, `sourceObject`, `drillDown`.

---

## Cross-Authority Navigation

**Component**: `CrossAuthorityNav.tsx`  
**Source**: `/api/core/control-tower/snapshot`

The 11-step authority chain supports seamless movement between authorities while preserving context via URL state — never `localStorage` or `sessionStorage`.

```
Assessment → Evidence → Verification → Findings → Report →
Governance → Decision → Simulation → Replay → Portal → Customer
```

Every transition preserves context. Navigation is keyboard-accessible with tabIndex support.

---

## Authority Health Map

**Component**: `AuthorityHealthMap.tsx`  
**Source**: `/api/core/control-tower/snapshot`

Derives all health, freshness, and coverage values from `ControlTowerSnapshotV1` fields. No fabricated latency numbers.

Mapped authorities from `ControlTowerSnapshotV1`:

| Authority | Snapshot Field | Health Derivation |
|---|---|---|
| Chain Integrity | `chain_integrity.status` | `pass` → OK, else Error |
| Key Lifecycle | `key_lifecycle.active_key_count` | `> 0` → OK, else Warning |
| Connectors | `connectors.errors.length` | `0` → OK, else Warning |
| Agents | `agents.quarantine_count` | `0` → OK, else Warning |
| Lockers | `lockers.status` | `running` → OK, else Warning |
| Audit Incidents | `audit_incidents.recent_events` | Always OK if data present |

Freshness is derived from timestamps in the snapshot (`last_rotation`, `last_sync`, `last_restart`). No hardcoded `ms` latency values.

---

## Correlation Graph 2.0

**Component**: `CorrelationGraph2.tsx`  
**Source**: `/api/core/forensics/events`

Enhanced graph nodes with full authority context. Pure HTML/CSS rendering — no canvas. Nodes are deterministic (no `Math.random` positions).

```typescript
interface GraphNode2 {
  id: string;
  label: string;
  authority: string;
  confidence: number | null;
  freshness: string | null;
  owner: string | null;
  lifecycle: string | null;
  trustStatus: string | null;
  verificationState: string | null;
  nodeType: string;
}

interface GraphEdge2 {
  from: string;
  to: string;
  relationship: string;
}
```

---

## Command Palette

**Component**: `CommandPalette.tsx`  
**Source**: `/api/core/control-tower/snapshot`

Ctrl+K opens the command palette. Escape closes it. Keyboard-navigable with ArrowUp/ArrowDown.

Modal overlay: `role="dialog"`, `aria-modal="true"`.

**12 search scopes**: Authorities, Capabilities, Assessments, Evidence, Reports, Customers, Policies, Findings, Simulations, Replay, Remediation, Portal.

Static search map based on scope entries — no external navigation package dependency.

---

## Playbooks

**Component**: `PlaybookPanel.tsx`  
**Source**: `/api/core/control-tower/snapshot`

Surfaces existing playbooks as read-only orchestration guides. No write operations. Each playbook links: Authorities, Workflow (with steps), Evidence, Reports, Remediation, Policies, Simulations, Timeline.

```typescript
interface Playbook {
  id: string;
  name: string;
  description: string;
  authorities: string[];
  workflow: PlaybookStep[];
  evidence: string[];
  reports: string[];
  remediation: string[];
  policies: string[];
  simulations: string[];
  timeline: string[];
}
```

---

## Delegation

**Component**: `DelegationPanel.tsx`  
**Source**: `/api/core/decisions`

Every operational action delegates — never duplicates write logic. Delegation target is captured and passed to `onDelegate` callback which routes to the authoritative service.

**11 action types**: `approve | reject | assign | delegate | escalate | review | verify | generate-report | publish | archive | close`

```typescript
interface DelegationAction {
  id: string;
  actionType: DelegationActionType;
  title: string;
  authority: string;
  mcimId: string;
  sourceObject: string;
  drillDown: string;
  delegatedTo: string | null;
}
```

---

## Export Model

**Component**: `ExportPanel.tsx`  
**Source**: `/api/core/control-tower/snapshot`

Every export includes provenance metadata. Formats: JSON and CSV.

```typescript
interface WorkspaceSnapshot {
  exportedAt: string;
  tenantId: string;
  queue: unknown[];
  cases: unknown[];
  timeline: unknown[];
  decisionLedger: unknown[];
  workflowState: unknown[];
  healthMap: unknown[];
  provenanceMetadata: {
    mcimId: string;
    authority: string;
    sourceOfTruth: string;
    exportedBy: string;
  };
}
```

Provenance metadata is always included — `mcimId`, `authority`, `sourceOfTruth`, `exportedBy` are required fields.

---

## Workspace Page

**Path**: `apps/console/app/workspace/page.tsx`  
**Type**: Next.js 14 async server component  
**Function**: `async function WorkspaceOverviewPage()`

Uses `Promise.allSettled` to load snapshot and feed data. Passes empty arrays for cases, ledger entries, workflows, timeline events (pending dedicated API endpoints). CommandPalette is client-side only — toggled by a server-rendered button.

Required `data-testid` anchors:
- `workspace-page`, `workspace-heading`
- `workspace-queue-heading`, `workspace-case-heading`
- `workspace-ledger-heading`, `workspace-workflow-heading`
- `workspace-timeline-heading`, `workspace-health-heading`
- `workspace-command-palette-toggle`

---

## CI Validation

**Script**: `tools/ci/check_operations_workspace.py`

Validates every workspace component for:
- MCIM_ID declaration (must match `MCIM-18.6-`)
- AUTHORITY declaration
- sourceOfTruth declaration
- drillDown declaration or href reference
- Absence of prohibited patterns: `Math.random`, `dangerouslySetInnerHTML`, `localStorage`, `sessionStorage`, `variant="destructive"`
- `export default function` present
- No `aria-expanded` on `role="complementary"` elements
- ExportPanel contains `provenanceMetadata`
- CommandPalette contains `role="dialog"` and `aria-modal`
- No direct core URL fetches
- No NEXT_PUBLIC env var references

WorkspaceShell is exempt from authority checks (shared wrapper).

---

## Testing

**File**: `tests/console/operations-workspace.test.js`  
**Count**: 800+ deterministic static-analysis tests

Tests read source files and assert on structure — no runtime execution, no mocking, no network calls. Covers:

- All 13 workspace components (fields, types, MCIM compliance)
- Workspace page (anchors, server component pattern, imports)
- CI script (prohibited patterns, validation logic)
- Architecture documentation
- Accessibility (ARIA, keyboard navigation, focus management)
- No-fake-data enforcement
- Cross-component consistency

---

## Accessibility

**Standard**: WCAG AA

- All panels have `aria-label` on their main container
- Icons have `aria-hidden="true"`
- Lists use `role="list"` or `<ul>`
- CommandPalette uses `role="dialog"`, `aria-modal="true"`, focus management
- CrossAuthorityNav uses `<nav>` with keyboard navigation
- DelegationPanel target input has `aria-label`
- No `aria-expanded` on `role="complementary"` elements
- All interactive elements keyboard-accessible

---

## Performance

- Lazy loading via Next.js server component streaming
- Deterministic ordering (no Math.random)
- No duplicate fetches (Promise.allSettled at page level)
- No duplicate authority calculations

---

## Telemetry

Tracked (all tenant-safe):
- Work queue usage (view, filter, open)
- Case creation and updates
- Investigation opens
- Workflow stage transitions
- Authority navigation
- Command palette usage and search
- Playbook opens
- Delegation submissions
- Export downloads

---

## Context Persistence

Context is preserved through URL state. Never `localStorage`. Never `sessionStorage`. Server-backed preferences when available.

---

## MCIM Compliance

Every workspace panel is registered in the Master Command Information Model under `MCIM-18.6-OPS-WORKSPACE`. All panels declare:

- `MCIM_ID` — unique panel identifier
- `AUTHORITY` — owning authority
- `sourceOfTruth` — API endpoint backing the panel
- `drillDown` — deep-link to authoritative UI
- `refreshPolicy` — data freshness policy

The workspace orchestrates existing authorities through the MCIM — it does not duplicate or override them.
