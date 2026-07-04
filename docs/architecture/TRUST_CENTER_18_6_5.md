# Trust Center Architecture — PR 18.6.5

## Overview

PR 18.6.5 delivers the Enterprise Trust Center — a dedicated surface within the FG Console that provides operators and enterprise customers with a comprehensive, auditable, and deterministic view of the platform's governance posture, decision quality, and compliance state.

The Trust Center is composed of 19 React components (including the shared shell wrapper) rendered at `apps/console/app/trust-center/page.tsx` — a Next.js App Router server component that coordinates data fetching via `Promise.allSettled` and renders each panel inside a `Suspense` boundary with `PanelSkeleton` fallbacks.

The Trust Center surfaces 23 distinct governance objectives across six trust domains: Assurance, Provenance, Compliance, Operational Intelligence, SLA Integrity, and Customer Transparency. Every panel is identified by a unique MCIM ID from the `MCIM-18.6-TRUST-*` namespace, declares its data authority, source-of-truth reference, and drill-down target — making the entire surface navigable, auditable, and compliant with the platform's Master Command Information Model.

## Design Principles

### 1. No Fabricated Data
No component may call `Math.random()`. All metrics, scores, statuses, and counts are derived exclusively from server-authoritative data sources. Hardcoded percentage literals (e.g., `85%`, `72%`) used as data values are prohibited and caught by CI.

### 2. No Browser Storage
Components must not read from or write to `localStorage` or `sessionStorage`. All state is either server-rendered, passed as props from the server component, or managed ephemerally in React state (UI-only). `OperationalMemory.tsx` explicitly declares "no browser storage" or "server-authoritative" to make this contract visible.

### 3. Deterministic Logic
All scoring, ranking, and forecasting logic is deterministic given the same inputs. The `WorkspaceIntelligence` component explicitly declares this property. `SLAForecasting` gates all forecasts behind a `hasHistoricalData` guard to prevent fabricated predictions when the underlying data window is insufficient.

### 4. Authoritative Data Only
`TrustBenchmarks` sources all comparison data from authoritative external registries, never from synthetic peer profiles. `CaseRelationships` surfaces only explicitly recorded relationships — the word "inferred" is prohibited to prevent implicit assumption chains from appearing as facts.

### 5. MCIM Compliance
Every component declares a `const MCIM_ID` string, a `const AUTHORITY` describing the owning authority, a `const sourceOfTruth` referencing the canonical data source, and a `const drillDown` pointing to the relevant drill-down route. These are consumed by the `TrustCenterShell` wrapper and used in audit logs. All four values are referenced via `void` statements to satisfy TypeScript's unused-variable rules while preserving traceability.

### 6. No Direct Network Access
Components must not call `fetch(` directly. All data must arrive through the page's server-side fetch layer (props) or through the platform's internal API route layer. `NEXT_PUBLIC_*` environment variables are prohibited in components — they would expose platform internals to the client bundle.

### 7. No Dangerous HTML Injection
`dangerouslySetInnerHTML` is prohibited across all Trust Center components. All content is rendered via typed React components.

### 8. No Destructive Badge Variants
The `'destructive'` Badge variant from shadcn/ui is banned. Use `'danger'` or severity-specific variants to maintain design-system consistency.

### 9. Accessibility First
Every non-shell component must include at least one `aria-label`. The shell (`TrustCenterShell`) legitimately uses `aria-expanded` on the meta toggle. No other component may pair `aria-expanded` with `role="complementary"` — that combination is flagged by the CI validator as a misuse of ARIA landmark semantics.

### 10. Legal Clarity for Certificates
`TrustCertificates` must include a disclaimer stating that the generated artifacts are not legal certificates. The component must also expose `signedHash` and `manifestHash` fields to provide cryptographic verifiability without making legal attestation claims.

## Component Inventory

| # | Component | MCIM ID | Trust Domain |
|---|-----------|---------|--------------|
| 1 | TrustCenterShell | MCIM-18.6-TRUST-SHELL | Infrastructure |
| 2 | TrustScorecard | MCIM-18.6-TRUST-SCORECARD | Assurance |
| 3 | ContinuousAssurancePanel | MCIM-18.6-TRUST-ASSURANCE | Assurance |
| 4 | TrustEvidenceGraph | MCIM-18.6-TRUST-EVIDENCE-GRAPH | Provenance |
| 5 | DecisionProvenanceExplorer | MCIM-18.6-TRUST-PROVENANCE | Provenance |
| 6 | GovernanceReplayCenter | MCIM-18.6-TRUST-REPLAY | Provenance |
| 7 | ChangeIntelligence | MCIM-18.6-TRUST-CHANGE-INTEL | Operational Intelligence |
| 8 | TrustCertificates | MCIM-18.6-TRUST-CERTIFICATES | Compliance |
| 9 | AuditReadinessWorkspace | MCIM-18.6-TRUST-AUDIT-READY | Compliance |
| 10 | CustomerTrustView | MCIM-18.6-TRUST-CUSTOMER-VIEW | Customer Transparency |
| 11 | TrustTimeline | MCIM-18.6-TRUST-TIMELINE | Provenance |
| 12 | OperationalMemory | MCIM-18.6-TRUST-MEMORY | Operational Intelligence |
| 13 | DecisionEffectiveness | MCIM-18.6-TRUST-EFFECTIVENESS | Operational Intelligence |
| 14 | BottleneckAnalysis | MCIM-18.6-TRUST-BOTTLENECK | Operational Intelligence |
| 15 | TrustBenchmarks | MCIM-18.6-TRUST-BENCHMARKS | Assurance |
| 16 | CaseRelationships | MCIM-18.6-TRUST-CASE-REL | Provenance |
| 17 | WorkspaceIntelligence | MCIM-18.6-TRUST-WORKSPACE-INTEL | Operational Intelligence |
| 18 | SLAForecasting | MCIM-18.6-TRUST-SLA | SLA Integrity |
| 19 | CommandCenterIntegration | MCIM-18.6-TRUST-CMD-CENTER | Infrastructure |

## Trust Domains

### Assurance
Covers the platform's ongoing assurance posture. `TrustScorecard` aggregates multi-dimensional trust scores from the governance engine. `ContinuousAssurancePanel` surfaces live control check statuses. `TrustBenchmarks` compares platform performance against industry-authoritative baselines.

### Provenance
Covers decision lineage, evidence, and historical state. `TrustEvidenceGraph` renders the graph of evidence nodes and edges that support governance decisions. `DecisionProvenanceExplorer` lets operators trace the full rationale chain for any decision. `GovernanceReplayCenter` replays historical governance state snapshots. `TrustTimeline` provides a chronological view of trust-affecting events. `CaseRelationships` surfaces explicitly recorded relationships between cases without inference.

### Compliance
Covers audit readiness and cryptographic accountability. `AuditReadinessWorkspace` tracks control checklists, requirements, and compliance gaps. `TrustCertificates` surfaces cryptographically signed governance artifacts (with `signedHash` and `manifestHash`) alongside a clear disclaimer that these are operational records, not legal certificates.

### Operational Intelligence
Covers internal operational health and learning. `ChangeIntelligence` tracks how governance rule changes propagate and their impact. `OperationalMemory` presents server-authoritative memory windows without relying on browser storage. `DecisionEffectiveness` measures decision outcome quality. `BottleneckAnalysis` identifies delay and latency patterns in governance workflows. `WorkspaceIntelligence` surfaces deterministic prioritization signals using `priorityScore`.

### SLA Integrity
`SLAForecasting` predicts SLA outcomes from `historicalAvgHours` data, gated by `hasHistoricalData` to ensure forecasts are never fabricated.

### Customer Transparency
`CustomerTrustView` provides the operator-facing preview of the trust summary that enterprise customers see — clearly marked as "operator preview" to prevent confusion about the customer-facing scope.

## Authority Chain

Each Trust Center component participates in the platform's authority chain:

```
Platform Governance Engine (server)
  └─ Trust Center Page (server component, no 'use client')
       └─ Promise.allSettled (parallel data fetch per panel)
            └─ TrustCenterShell (client component, MCIM-aware wrapper)
                 └─ Panel Component (client, MCIM_ID + AUTHORITY + sourceOfTruth + drillDown)
```

The server component is responsible for all data fetching. No panel fetches data independently. This ensures:
- A single request waterfall per page load
- Full server-side rendering for initial paint
- Consistent data freshness across all panels
- No client-side secrets or API key exposure

## Data Flow

```
1. Page request hits trust-center/page.tsx (server component)
2. Page calls Promise.allSettled([
     fetchTrustScorecard(),
     fetchAssuranceChecks(),
     fetchEvidenceGraph(),
     fetchDecisionProvenance(),
     fetchGovernanceReplayEvents(),
     fetchChangeIntelligence(),
     fetchTrustCertificates(),
     fetchAuditReadiness(),
     fetchCustomerTrustSummary(),
     fetchTrustTimeline(),
     fetchOperationalMemory(),
     fetchDecisionEffectiveness(),
     fetchBottleneckData(),
     fetchTrustBenchmarks(),
     fetchCaseRelationships(),
     fetchWorkspaceIntelligence(),
     fetchSLAForecast(),
     fetchCommandCenterLinks(),
   ])
3. Each result (or null on failure) is passed as a prop to the respective component
4. Components wrapped in <Suspense fallback={<PanelSkeleton />}>
5. Each component renders inside <TrustCenterShell> which handles:
   - Collapsible meta panel (aria-expanded)
   - MCIM ID badge
   - Drill-down link rendering
   - Authority and sourceOfTruth display
```

## MCIM Compliance

All 19 Trust Center components are registered in the `MCIM-18.6-TRUST-*` namespace of the platform's Master Command Information Model. Each registration specifies:

- **MCIM ID**: Globally unique stable identifier for the component's data contract
- **Authority**: The system or team that owns the data feeding this component
- **Source of Truth**: The canonical database table, API endpoint, or service that is the authoritative data source
- **Drill-Down**: The route or action a user reaches when they click through from this panel

The CI validator (`tools/ci/check_trust_center.py`) enforces all MCIM compliance rules on every pull request. The test suite (`tests/console/trust-center.test.js`) provides 1000+ static-analysis assertions that must pass before the build gate opens.

## Test Coverage

The test suite is organized into:

- **19 per-component describe blocks** — each with 45+ assertions covering structure, MCIM declarations, accessibility, banned patterns, and component-specific invariants
- **1 page describe block** — 50+ assertions covering server-component contract, all 20 data-testid anchors, all 18 component imports, MCIM reference, Suspense usage, and PanelSkeleton
- **7 cross-cutting describe blocks**:
  - All non-shell components use TrustCenterShell (18 assertions)
  - All non-shell components have all 4 void declarations (72 assertions)
  - All components have 'use client' (19 assertions)
  - No component uses banned patterns — Math.random, dangerouslySetInnerHTML, localStorage, sessionStorage, fetch( (95 assertions)
  - All non-shell components have correct MCIM-18.6-TRUST- prefix (18 assertions)
  - All non-shell components have data-testid (18 assertions)
  - All non-shell components have aria-label (18 assertions)

Total: 855+ per-component + 50+ page + 258+ cross-cutting = 1163+ assertions.

All tests are static analysis — they read `.tsx` source files and assert on their textual content. No browser environment, no mocking framework, no network access. Tests run with: `node --test tests/console/trust-center.test.js`

## Appendix

### MCIM Registry

```json
{
  "MCIM-18.6-TRUST-SHELL": "TrustCenterShell",
  "MCIM-18.6-TRUST-SCORECARD": "TrustScorecard",
  "MCIM-18.6-TRUST-ASSURANCE": "ContinuousAssurancePanel",
  "MCIM-18.6-TRUST-EVIDENCE-GRAPH": "TrustEvidenceGraph",
  "MCIM-18.6-TRUST-PROVENANCE": "DecisionProvenanceExplorer",
  "MCIM-18.6-TRUST-REPLAY": "GovernanceReplayCenter",
  "MCIM-18.6-TRUST-CHANGE-INTEL": "ChangeIntelligence",
  "MCIM-18.6-TRUST-CERTIFICATES": "TrustCertificates",
  "MCIM-18.6-TRUST-AUDIT-READY": "AuditReadinessWorkspace",
  "MCIM-18.6-TRUST-CUSTOMER-VIEW": "CustomerTrustView",
  "MCIM-18.6-TRUST-TIMELINE": "TrustTimeline",
  "MCIM-18.6-TRUST-MEMORY": "OperationalMemory",
  "MCIM-18.6-TRUST-EFFECTIVENESS": "DecisionEffectiveness",
  "MCIM-18.6-TRUST-BOTTLENECK": "BottleneckAnalysis",
  "MCIM-18.6-TRUST-BENCHMARKS": "TrustBenchmarks",
  "MCIM-18.6-TRUST-CASE-REL": "CaseRelationships",
  "MCIM-18.6-TRUST-WORKSPACE-INTEL": "WorkspaceIntelligence",
  "MCIM-18.6-TRUST-SLA": "SLAForecasting",
  "MCIM-18.6-TRUST-CMD-CENTER": "CommandCenterIntegration"
}
```

### Component Manifest

```json
[
  {
    "id": 1,
    "file": "TrustCenterShell.tsx",
    "mcimId": "MCIM-18.6-TRUST-SHELL",
    "authority": "Trust Center Infrastructure Team",
    "sourceOfTruth": "internal/trust-center/shell",
    "drillDown": "/trust-center"
  },
  {
    "id": 2,
    "file": "TrustScorecard.tsx",
    "mcimId": "MCIM-18.6-TRUST-SCORECARD",
    "authority": "Governance Engine — Trust Scoring Service",
    "sourceOfTruth": "governance.trust_scores",
    "drillDown": "/trust-center/scorecard"
  },
  {
    "id": 3,
    "file": "ContinuousAssurancePanel.tsx",
    "mcimId": "MCIM-18.6-TRUST-ASSURANCE",
    "authority": "Governance Engine — Control Assurance Service",
    "sourceOfTruth": "governance.assurance_checks",
    "drillDown": "/trust-center/assurance"
  },
  {
    "id": 4,
    "file": "TrustEvidenceGraph.tsx",
    "mcimId": "MCIM-18.6-TRUST-EVIDENCE-GRAPH",
    "authority": "Governance Engine — Evidence Graph Service",
    "sourceOfTruth": "governance.evidence_graph",
    "drillDown": "/trust-center/evidence"
  },
  {
    "id": 5,
    "file": "DecisionProvenanceExplorer.tsx",
    "mcimId": "MCIM-18.6-TRUST-PROVENANCE",
    "authority": "Governance Engine — Decision Provenance Service",
    "sourceOfTruth": "governance.decision_provenance",
    "drillDown": "/trust-center/provenance"
  },
  {
    "id": 6,
    "file": "GovernanceReplayCenter.tsx",
    "mcimId": "MCIM-18.6-TRUST-REPLAY",
    "authority": "Governance Engine — Replay Service",
    "sourceOfTruth": "governance.replay_snapshots",
    "drillDown": "/trust-center/replay"
  },
  {
    "id": 7,
    "file": "ChangeIntelligence.tsx",
    "mcimId": "MCIM-18.6-TRUST-CHANGE-INTEL",
    "authority": "Governance Engine — Change Intelligence Service",
    "sourceOfTruth": "governance.change_events",
    "drillDown": "/trust-center/change-intelligence"
  },
  {
    "id": 8,
    "file": "TrustCertificates.tsx",
    "mcimId": "MCIM-18.6-TRUST-CERTIFICATES",
    "authority": "Governance Engine — Certificate Issuance Service",
    "sourceOfTruth": "governance.trust_certificates",
    "drillDown": "/trust-center/certificates"
  },
  {
    "id": 9,
    "file": "AuditReadinessWorkspace.tsx",
    "mcimId": "MCIM-18.6-TRUST-AUDIT-READY",
    "authority": "Governance Engine — Audit Readiness Service",
    "sourceOfTruth": "governance.audit_checklists",
    "drillDown": "/trust-center/audit-readiness"
  },
  {
    "id": 10,
    "file": "CustomerTrustView.tsx",
    "mcimId": "MCIM-18.6-TRUST-CUSTOMER-VIEW",
    "authority": "Governance Engine — Customer Trust Service",
    "sourceOfTruth": "governance.customer_trust_summaries",
    "drillDown": "/trust-center/customer-view"
  },
  {
    "id": 11,
    "file": "TrustTimeline.tsx",
    "mcimId": "MCIM-18.6-TRUST-TIMELINE",
    "authority": "Governance Engine — Timeline Service",
    "sourceOfTruth": "governance.trust_timeline_events",
    "drillDown": "/trust-center/timeline"
  },
  {
    "id": 12,
    "file": "OperationalMemory.tsx",
    "mcimId": "MCIM-18.6-TRUST-MEMORY",
    "authority": "Governance Engine — Operational Memory Service",
    "sourceOfTruth": "governance.operational_memory_windows",
    "drillDown": "/trust-center/memory"
  },
  {
    "id": 13,
    "file": "DecisionEffectiveness.tsx",
    "mcimId": "MCIM-18.6-TRUST-EFFECTIVENESS",
    "authority": "Governance Engine — Effectiveness Measurement Service",
    "sourceOfTruth": "governance.decision_outcomes",
    "drillDown": "/trust-center/effectiveness"
  },
  {
    "id": 14,
    "file": "BottleneckAnalysis.tsx",
    "mcimId": "MCIM-18.6-TRUST-BOTTLENECK",
    "authority": "Governance Engine — Workflow Analytics Service",
    "sourceOfTruth": "governance.workflow_latency_records",
    "drillDown": "/trust-center/bottlenecks"
  },
  {
    "id": 15,
    "file": "TrustBenchmarks.tsx",
    "mcimId": "MCIM-18.6-TRUST-BENCHMARKS",
    "authority": "Governance Engine — Benchmarking Service",
    "sourceOfTruth": "governance.benchmark_registry",
    "drillDown": "/trust-center/benchmarks"
  },
  {
    "id": 16,
    "file": "CaseRelationships.tsx",
    "mcimId": "MCIM-18.6-TRUST-CASE-REL",
    "authority": "Governance Engine — Case Graph Service",
    "sourceOfTruth": "governance.case_relationships",
    "drillDown": "/trust-center/case-relationships"
  },
  {
    "id": 17,
    "file": "WorkspaceIntelligence.tsx",
    "mcimId": "MCIM-18.6-TRUST-WORKSPACE-INTEL",
    "authority": "Governance Engine — Workspace Intelligence Service",
    "sourceOfTruth": "governance.workspace_intelligence_signals",
    "drillDown": "/trust-center/workspace-intelligence"
  },
  {
    "id": 18,
    "file": "SLAForecasting.tsx",
    "mcimId": "MCIM-18.6-TRUST-SLA",
    "authority": "Governance Engine — SLA Forecasting Service",
    "sourceOfTruth": "governance.sla_historical_windows",
    "drillDown": "/trust-center/sla-forecasting"
  },
  {
    "id": 19,
    "file": "CommandCenterIntegration.tsx",
    "mcimId": "MCIM-18.6-TRUST-CMD-CENTER",
    "authority": "Governance Engine — Command Center Integration Service",
    "sourceOfTruth": "governance.command_center_links",
    "drillDown": "/command-center"
  }
]
```
