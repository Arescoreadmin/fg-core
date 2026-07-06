# OPERATIONS CENTER 18.7 — Autonomous Governance Operations Center (AGOC)

**MCIM Authority:** `OPERATIONS-CENTER`  
**Route:** `/dashboard/operations-center`  
**PR:** 18.7  
**Status:** Complete  
**Classification:** Enterprise / AGI-Ready

---

## 1. Architecture Overview

The Autonomous Governance Operations Center is the command surface for real-time governance intelligence across the FrostGate platform. It aggregates and presents authoritative state from all platform authorities — Decision Engine, Forensics Chain, Governance Graph, Control Tower — into a single, read-only, fail-closed operations panel.

**Design principles:**

- **Fail closed.** Every panel gated on API success. No data shown on error or insufficient evidence.
- **No fabricated metrics.** All values derived from authoritative platform sources. Zero `Math.random`, zero mock data, zero synthetic fills.
- **Deterministic presentation.** Same API state always produces identical rendered output.
- **MCIM-compliant.** Every widget declares `data-mcim`, `data-authority`, and `data-section`. Page root carries `data-mcim="OPERATIONS-CENTER"`.
- **AGI-forward.** Data models already accommodate `actor_type` values covering autonomous agents, agent fleets, and AGI systems without schema migration.

**Technology stack:**

- Next.js App Router (server component page, client component panels)
- React 18 with TanStack Query for data fetching
- `operationsCenterApi.ts` — typed API layer, `LoadResult<T>` discriminated union
- MCIM widget metadata on all 10 components

---

## 2. MCIM Authority Graph

```
OPERATIONS-CENTER (page root)
├── MCIM-18.7-EXEC-QUEUE        ExecutiveOperationsQueue
│     └── authority: /decisions
├── MCIM-18.7-AUTO-QUEUE        GovernanceAutomationQueue
│     └── authority: /ui/forensics/events
├── MCIM-18.7-PIPELINE          DecisionExecutionPipeline
│     └── authority: /decisions
├── MCIM-18.7-RISK-HEATMAP      OperationalRiskHeatmap
│     └── authority: /governance/graph/stats + /governance/graph/anomalies
├── MCIM-18.7-EVIDENCE-FRESH    EvidenceFreshnessMonitor
│     └── authority: /governance/graph/nodes
├── MCIM-18.7-POLICY-CONFLICT   PolicyConflictCenter
│     └── authority: /governance/graph/anomalies
├── MCIM-18.7-SLA               GovernanceSLAMonitor
│     └── authority: /decisions
├── MCIM-18.7-SAFETY            AutomationSafetyCenter
│     └── authority: /control-tower/snapshot
├── MCIM-18.7-TIMELINE          CrossAuthorityTimeline
│     └── authority: /ui/forensics/events + /feed/live
└── MCIM-18.7-BRIEFING          ExecutiveOperationalBriefing
      └── authority: composite (/decisions + /governance/graph/stats + /ui/forensics/events)
```

---

## 3. Panel Descriptions and Data Sources

### Panel 1 — Executive Operations Queue (`ExecutiveOperationsQueue`)

**MCIM ID:** `MCIM-18.7-EXEC-QUEUE`  
**Data source:** `GET /decisions` (Decision Engine)  
**Function:** Surfaces the highest-priority governance decisions requiring executive attention. Sorted by severity (critical → info), grouped by workflow state. Each item shows owner, policy reference, evidence count, confidence, due date, and business impact.  
**Key fields:** `severity`, `workflowState`, `evidenceCount`, `confidence`, `dueAt`, `businessImpact`  
**Drill-down:** Links to `/dashboard/decisions?id={id}`

### Panel 2 — Governance Automation Queue (`GovernanceAutomationQueue`)

**MCIM ID:** `MCIM-18.7-AUTO-QUEUE`  
**Data source:** `GET /ui/forensics/events?event_type=automation`  
**Function:** Displays all in-flight automation events across the governance platform. Status lifecycle: `pending → running → completed` or `approval_required → blocked → failed`. Shows rollback availability and severity.  
**Key fields:** `status`, `rollbackAvailable`, `reason`, `severity`  
**Drill-down:** Links to `/dashboard/forensics?event={id}`

### Panel 3 — Decision Execution Pipeline (`DecisionExecutionPipeline`)

**MCIM ID:** `MCIM-18.7-PIPELINE`  
**Data source:** `GET /decisions`  
**Function:** Visualizes the 10-stage governance decision lifecycle: `detected → evaluated → policy_matched → simulation_completed → approval_required → approved → executing → executed → verified → archived`. Each decision is deterministically mapped to its current stage via `derivePipelineStage()`. No stage is ever fabricated.  
**Key fields:** `stage`, `confidence`, `deterministic`, `eventType`  
**Drill-down:** Links to `/dashboard/decisions?stage={stage}`

### Panel 4 — Operational Risk Heatmap (`OperationalRiskHeatmap`)

**MCIM ID:** `MCIM-18.7-RISK-HEATMAP`  
**Data source:** `GET /governance/graph/stats` + `GET /governance/graph/anomalies`  
**Function:** Two-dimensional grid of governance risk by dimension (Governance, Anomaly) and category (node type, anomaly pattern). Each cell severity is derived from active anomaly counts — never estimated. Shows total anomaly count, node count, edge count.  
**Key fields:** `dimension`, `category`, `count`, `severity`, `totalAnomalies`  
**Drill-down:** Links to governance graph view by node type

### Panel 5 — Evidence Freshness Monitor (`EvidenceFreshnessMonitor`)

**MCIM ID:** `MCIM-18.7-EVIDENCE-FRESH`  
**Data source:** `GET /governance/graph/nodes`  
**Function:** Per-node evidence freshness status across the governance graph. Five statuses: `current`, `stale`, `missing`, `expiring`, `unverified`. Trust score and confidence per node. Age in hours calculated from `derived_at`. Average trust score across all nodes.  
**Key fields:** `trustScore`, `confidence`, `status`, `ageHours`, `averageTrustScore`  
**Drill-down:** Links to governance node detail

### Panel 6 — Policy Conflict Center (`PolicyConflictCenter`)

**MCIM ID:** `MCIM-18.7-POLICY-CONFLICT`  
**Data source:** `GET /governance/graph/anomalies`  
**Function:** Surfaces active policy conflicts detected by the governance anomaly engine. Seven conflict types: `duplicate_policy`, `conflicting_policy`, `overlapping_authority`, `missing_ownership`, `contradicting_requirements`, `dead_policy`, `orphaned_control`. Shows resolved vs. active state, orphaned node count.  
**Key fields:** `type`, `severity`, `nodeIds`, `resolved`, `orphanedNodes`  
**Drill-down:** Links to anomaly detail by `anomaly_id`

### Panel 7 — Governance SLA Monitor (`GovernanceSLAMonitor`)

**MCIM ID:** `MCIM-18.7-SLA`  
**Data source:** `GET /decisions`  
**Function:** Tracks SLA compliance across all governance decisions. Shows breached, upcoming, and on-track items. Age in hours calculated from `created_at`. Breached items flagged with `role="alert"`. Average age across all decisions.  
**Key fields:** `slaBreached`, `dueAt`, `ageHours`, `breached`, `upcoming`, `averageAgeHours`  
**Drill-down:** Links to `/dashboard/decisions?id={id}&sla=1`

### Panel 8 — Automation Safety Center (`AutomationSafetyCenter`)

**MCIM ID:** `MCIM-18.7-SAFETY`  
**Data source:** `GET /control-tower/snapshot`  
**Function:** Real-time view of the platform's automation safety envelope. Derived from chain integrity, agent quarantine state, connector errors, and locker status. Kill switch active when `quarantine_count > 0`. Blast radius: none/contained/partial/full. Human approval and simulation thresholds at risk scores ≥85 and ≥70 respectively.  
**Key fields:** `riskScore`, `killSwitchActive`, `blastRadius`, `humanApprovalRequired`, `simulationRequired`, `chainIntegrity`, `executionConfidence`  
**Alert:** Kill switch status emits `role="alert"` with `aria-live="assertive"`

### Panel 9 — Cross-Authority Timeline (`CrossAuthorityTimeline`)

**MCIM ID:** `MCIM-18.7-TIMELINE`  
**Data source:** `GET /ui/forensics/events` + `GET /feed/live`  
**Function:** Immutable, auditable event log spanning the Forensics Chain and Event Feed. All events are marked `immutable: true, auditable: true`. Sorted newest-first. Authority filter UI to narrow by source. Total event count displayed.  
**Key fields:** `ts`, `authority`, `eventType`, `severity`, `immutable`, `auditable`, `requestId`  
**Drill-down:** Forensics events link to `/dashboard/forensics?event={id}`

### Panel 10 — Executive Operational Briefing (`ExecutiveOperationalBriefing`)

**MCIM ID:** `MCIM-18.7-BRIEFING`  
**Data source:** Composite: `/decisions` + `/governance/graph/stats` + `/ui/forensics/events`  
**Function:** Executive-level governance summary synthesized from three authoritative sources. Gated: briefing lines shown only when `sufficientEvidence = true` (requires ≥3 evidence lines AND `graphStats.node_count > 0`). When insufficient: displays "Insufficient authoritative evidence — governance graph may not be populated." No synthetic content ever injected.  
**Key fields:** `lines`, `sufficientEvidence`, `insufficiencyReason`, `authorityCount`  
**Suppression:** Fail-closed gating prevents fabricated briefings in ungoverned tenants

---

## 4. Decision Lifecycle Diagram

```
                    ┌─────────────┐
                    │  detected   │ ◄── event ingested from platform
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  evaluated  │ ◄── policy engine scores event
                    └──────┬──────┘
                           │
                  ┌────────▼────────┐
                  │ policy_matched  │ ◄── matching policy found
                  └────────┬────────┘
                           │
              ┌────────────▼────────────┐
              │  simulation_completed   │ ◄── blast radius simulated
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  approval_required      │ ◄── risk score ≥ 85 or quarantine
              └────────────┬────────────┘
                           │
                    ┌──────▼──────┐
                    │  approved   │ ◄── human approver confirms
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  executing  │ ◄── automation runner active
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  executed   │ ◄── action completed
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  verified   │ ◄── outcome verified against expected state
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  archived   │ ◄── terminal: append-only record
                    └─────────────┘
```

---

## 5. Automation Model

The automation safety envelope is governed by four thresholds derived exclusively from `ControlTowerSnapshotV1`:

| Condition | Threshold | Effect |
|-----------|-----------|--------|
| Chain integrity degraded | `status !== 'ok'` | +40 to risk score |
| Agents quarantined | `quarantine_count > 0` | +20 to risk score; kill switch active |
| Connector errors present | `errors.length > 0` | +15 to risk score |
| Locker degraded | `lockers.status !== 'ok'` | +15 to risk score |
| Simulation required | `riskScore >= 70` | automations must be simulated first |
| Human approval required | `riskScore >= 85 OR quarantine` | no autonomous execution |
| Kill switch active | `quarantine_count > 0` | blast radius: partial or full |

**Blast radius derivation:**

- `agents.total = 0` → `none`
- `quarantine_count >= total` → `full`
- `quarantine_count > 0` → `partial`
- otherwise → `contained`

**Execution confidence:** `chainOk ? round(100 - riskScore × 0.3) : 0`

All thresholds are compile-time constants. No runtime configuration. No probability estimates.

---

## 6. Evidence Authority Chain

```
Governance Graph Nodes  (/governance/graph/nodes)
        │
        ├── trustScore      [0.0–1.0] platform-derived
        ├── confidence      [0.0–1.0] platform-derived
        ├── derived_at      ISO timestamp
        └── node_type       policy | control | vendor | ...
                │
                ▼
        EvidenceFreshnessMonitor
                │
        ┌───────┴────────┐
        │  Status Rules  │
        ├── missing       trustScore < 0.10
        ├── unverified    trustScore < 0.40
        ├── stale         ageHours > 168 (7 days)
        ├── expiring      ageHours > 120 (5 days)
        └── current       all others
                │
                ▼
        Average trust score across all nodes
        Displayed only when records.length > 0
```

Trust scores are never imputed, averaged with fabricated values, or adjusted client-side. The displayed `averageTrustScore` is computed server-side in `getEvidenceFreshness()` using only records returned by the governance graph API.

---

## 7. Execution Pipeline Stages

The `DecisionExecutionPipeline` maps every decision to one of 10 stages via `derivePipelineStage()`. The mapping is deterministic: same `workflow_state` always produces the same stage. The function is a pure switch statement — no probability, no heuristics.

| `workflow_state` (API) | Pipeline stage |
|------------------------|----------------|
| (default / unrecognized) | `detected` |
| `evaluated` | `evaluated` |
| `policy_matched` | `policy_matched` |
| `simulated` | `simulation_completed` |
| `pending_approval` | `approval_required` |
| `approved` | `approved` |
| `executing` | `executing` |
| `executed` | `executed` |
| `verified` | `verified` |
| `archived` | `archived` |

Pipeline stage counts (`byStage`) are computed from real items only. No stage is pre-populated with dummy data.

---

## 8. Operational Philosophy — "Trust but Verify" Enforcement

The AGOC enforces "Trust but Verify" at four levels:

**Level 1 — Data sourcing.** Every value traces to a specific API endpoint. The `authority` field in every `LoadResult<T>` records the source route(s). No value is synthesized.

**Level 2 — Fail closed.** Every panel uses a `LoadResult<T>` discriminated union. When `ok = false`, the UI renders an error state and zero data items. No stale data is shown. No placeholder metrics are injected.

**Level 3 — Evidence sufficiency gate.** `ExecutiveOperationalBriefing` will not render briefing content unless `sufficientEvidence = true`. Sufficiency requires ≥3 evidence lines AND a non-empty governance graph. This prevents AI-adjacent executive summaries from appearing in ungoverned tenants where the data would be meaningless.

**Level 4 — Automation safety gate.** `AutomationSafetyCenter` computes `simulationRequired` and `humanApprovalRequired` from the control tower snapshot. Neither flag is configurable by the user. Both default to the more restrictive state in the absence of data (fail closed).

---

## 9. Moat Strategy

The AGOC's defensibility derives from its tight coupling to the FrostGate platform's evidence substrate:

1. **Authority binding.** Every widget declares its authoritative data source. The CI gate (`check_operations_center.py`) enforces this at merge time — no component may omit `data-mcim` or `data-authority`.

2. **Immutability indicators.** The Cross-Authority Timeline surfaces `immutable: true` and `auditable: true` on every event. Forensics Chain events are cryptographically immutable at the platform layer.

3. **Evidence freshness as a first-class concept.** The Evidence Freshness Monitor exposes per-node trust scores and age, making governance decay visible. Competitors showing "health scores" without this level of evidence attribution are presenting opinion, not fact.

4. **Suppression over fabrication.** When evidence is insufficient, AGOC shows nothing rather than a confident-looking fabrication. This is a hard product commitment enforced in CI.

5. **Kill switch visibility.** The Automation Safety Center surfaces the kill switch state to operators. No other governance product in this space exposes this control. It is non-negotiable for autonomous governance at scale.

6. **Cross-authority aggregation.** The timeline spans both the Forensics Chain and the Event Feed in a single view. This cross-authority merge is the kind of integration that takes months to replicate without the FrostGate substrate.

---

## 10. Future AGI Integration Points

The AGOC data model is designed so that AGI systems can be governed without schema migrations. The following fields are already present or easily extended:

| Integration point | Current state | AGI extension |
|-------------------|---------------|---------------|
| `actor_type` on automation events | `human \| service \| agent` | Add `autonomous_system \| agi \| agent_swarm` — no migration |
| `AutomationSafetyCenter.riskScore` | Derived from 4 platform signals | Extend `deriveRiskScore()` with AGI-specific signals (e.g., model confidence drift, instruction drift) |
| `ExecutiveOperationalBriefing.sufficientEvidence` | Based on evidence count + graph node count | Add AGI evidence types (reasoning trace, inference log) as additional sufficiency factors |
| `CrossAuthorityTimeline` authorities | `Forensics Chain \| Event Feed` | Add `AGI Decision Log \| Model Governance Chain` as additional authorities |
| `DecisionExecutionPipeline` stages | 10-stage pipeline | Add `agi_reviewed`, `model_validated` stages between `simulation_completed` and `approval_required` |
| `EvidenceFreshnessMonitor` node types | `policy \| control \| vendor \| ...` | Add `model_card \| training_dataset \| inference_endpoint` node types |
| `PolicyConflictCenter` conflict types | 7 types | Add `model_policy_conflict \| capability_boundary_violation` conflict types |

---

## 11. Machine-Readable Appendix

```json
{
  "mcim_authority": "OPERATIONS-CENTER",
  "mcim_version": "18.7",
  "route": "/dashboard/operations-center",
  "enterprise_ready": true,
  "agi_ready": true,
  "fail_closed": true,
  "widgets": [
    {
      "mcim_id": "MCIM-18.7-EXEC-QUEUE",
      "component": "ExecutiveOperationsQueue",
      "authority": "/decisions",
      "data_function": "getOperationsQueue",
      "result_type": "OperationsQueueResult",
      "empty_state": true,
      "error_state": true,
      "loading_state": true,
      "drilldown": "/dashboard/decisions"
    },
    {
      "mcim_id": "MCIM-18.7-AUTO-QUEUE",
      "component": "GovernanceAutomationQueue",
      "authority": "/ui/forensics/events",
      "data_function": "getAutomationQueue",
      "result_type": "AutomationQueueResult",
      "empty_state": true,
      "error_state": true,
      "loading_state": true,
      "drilldown": "/dashboard/forensics"
    },
    {
      "mcim_id": "MCIM-18.7-PIPELINE",
      "component": "DecisionExecutionPipeline",
      "authority": "/decisions",
      "data_function": "getDecisionPipeline",
      "result_type": "PipelineResult",
      "empty_state": true,
      "error_state": true,
      "loading_state": true,
      "stages": ["detected", "evaluated", "policy_matched", "simulation_completed",
                 "approval_required", "approved", "executing", "executed", "verified", "archived"],
      "drilldown": "/dashboard/decisions"
    },
    {
      "mcim_id": "MCIM-18.7-RISK-HEATMAP",
      "component": "OperationalRiskHeatmap",
      "authority": "/governance/graph/stats + /governance/graph/anomalies",
      "data_function": "getRiskHeatmap",
      "result_type": "RiskHeatmapResult",
      "empty_state": true,
      "error_state": true,
      "loading_state": true,
      "drilldown": "/dashboard/governance"
    },
    {
      "mcim_id": "MCIM-18.7-EVIDENCE-FRESH",
      "component": "EvidenceFreshnessMonitor",
      "authority": "/governance/graph/nodes",
      "data_function": "getEvidenceFreshness",
      "result_type": "EvidenceFreshnessResult",
      "key_fields": ["trustScore", "status", "ageHours", "averageTrustScore"],
      "status_values": ["current", "stale", "missing", "expiring", "unverified"],
      "empty_state": true,
      "error_state": true,
      "loading_state": true,
      "drilldown": "/dashboard/governance/nodes"
    },
    {
      "mcim_id": "MCIM-18.7-POLICY-CONFLICT",
      "component": "PolicyConflictCenter",
      "authority": "/governance/graph/anomalies",
      "data_function": "getPolicyConflicts",
      "result_type": "PolicyConflictResult",
      "conflict_types": ["duplicate_policy", "conflicting_policy", "overlapping_authority",
                        "missing_ownership", "contradicting_requirements", "dead_policy", "orphaned_control"],
      "empty_state": true,
      "error_state": true,
      "loading_state": true,
      "drilldown": "/dashboard/governance/anomalies"
    },
    {
      "mcim_id": "MCIM-18.7-SLA",
      "component": "GovernanceSLAMonitor",
      "authority": "/decisions",
      "data_function": "getGovernanceSLA",
      "result_type": "SLAResult",
      "key_fields": ["slaBreached", "dueAt", "ageHours", "breached", "upcoming"],
      "empty_state": true,
      "error_state": true,
      "loading_state": true,
      "drilldown": "/dashboard/decisions"
    },
    {
      "mcim_id": "MCIM-18.7-SAFETY",
      "component": "AutomationSafetyCenter",
      "authority": "/control-tower/snapshot",
      "data_function": "getAutomationSafety",
      "result_type": "AutomationSafetyState",
      "key_fields": ["riskScore", "killSwitchActive", "blastRadius",
                     "humanApprovalRequired", "simulationRequired",
                     "chainIntegrity", "executionConfidence"],
      "kill_switch_threshold": "quarantineCount > 0",
      "simulation_threshold": "riskScore >= 70",
      "human_approval_threshold": "riskScore >= 85 OR quarantineCount > 0",
      "empty_state": true,
      "error_state": true,
      "loading_state": true
    },
    {
      "mcim_id": "MCIM-18.7-TIMELINE",
      "component": "CrossAuthorityTimeline",
      "authority": "/ui/forensics/events + /feed/live",
      "data_function": "getCrossAuthorityTimeline",
      "result_type": "CrossAuthorityTimelineResult",
      "immutable": true,
      "auditable": true,
      "sort_order": "newest_first",
      "authorities": ["Forensics Chain", "Event Feed"],
      "empty_state": true,
      "error_state": true,
      "loading_state": true,
      "drilldown": "/dashboard/forensics"
    },
    {
      "mcim_id": "MCIM-18.7-BRIEFING",
      "component": "ExecutiveOperationalBriefing",
      "authority": "composite: /decisions + /governance/graph/stats + /ui/forensics/events",
      "data_function": "getOperationalBriefing",
      "result_type": "OperationalBriefingResult",
      "sufficiency_gate": true,
      "sufficiency_condition": "lines.length >= 3 AND graphStats.node_count > 0",
      "insufficient_message": "Insufficient authoritative evidence — governance graph may not be populated.",
      "fail_closed": true,
      "fabrication_prohibited": true,
      "empty_state": true,
      "error_state": true,
      "loading_state": true
    }
  ]
}
```
