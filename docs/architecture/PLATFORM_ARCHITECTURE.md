# FrostGate Platform Architecture

**Status**: Authoritative  
**Maintained by**: Engineering  
**Last updated**: 2026-05-21

This document is the canonical reference for how FrostGate is structured, how data flows through the platform, and what the rules are at every boundary. All PRs that touch module ownership, data flow, or layer boundaries must be consistent with this document. If a PR changes the architecture, update this document in the same commit.

---

## 1. Platform Model

FrostGate is a single unified platform with two activation tiers:

| Tier | What is active | Client profile |
|---|---|---|
| **Assessment** | Field Assessment layer only | One-time or periodic AI readiness assessments |
| **Governance** | Field Assessment + full Governance Platform | Clients who graduate to continuous, provable AI governance |

There is no separate codebase or separate deployment. The split is a feature-activation boundary controlled by the presence of a `GovernancePromotion` record. Assessment-only clients have no promotion record. Governance clients do.

The upgrade path is zero-migration: assessment evidence is already structured for governance. When a client delivers a QA-approved assessment, the platform automatically promotes it into the governance layer.

---

## 2. The Evidence Spine

Evidence is the common key across every layer. Every entity in the platform traces back to a piece of verified evidence.

**Ownership rule**: Evidence is **tenant-scoped, engagement-tagged**. A scan result belongs to the tenant. The engagement is the collection context, not the ownership boundary. This means:
- Evidence from Engagement A can inform Engagement B (drift, re-assessment, baseline comparison).
- The RAG corpus indexes all tenant evidence regardless of which engagement produced it.
- Promotion carries evidence forward without copying or re-ingesting it.

**Evidence types and their sources**:

| Evidence type | Produced by | DB model |
|---|---|---|
| Scan result | Connector import / manual ingest | `FaScanResult` |
| Document | Document registration | `FaDocument` |
| Interview | Interview capture | `FaInterview` |
| Field observation | Observation capture | `FaFieldObservation` |
| Normalized finding | Scan normalization | `FaNormalizedFinding` |
| Evidence link | Finding-to-evidence linkage | `FaEvidenceLink` |

**The chain rule**: Every finding must be linked to at least one evidence record via `FaEvidenceLink`. Every governance workflow must link to a finding. Every report must enumerate its finding and evidence chain. This chain is what makes the audit trail legally defensible.

---

## 3. Field Assessment Layer

### What it owns

The Field Assessment layer owns operator-scoped engagement execution. It does not own tenant-level governance state.

| Responsibility | Module |
|---|---|
| Engagement lifecycle (status machine) | `api/field_assessment.py`, `services/field_assessment/` |
| Playbook-driven gate enforcement | `services/field_assessment/playbooks.py`, `services/field_assessment/readiness.py` |
| Scan ingest and finding normalization | `services/field_assessment/normalizer.py`, `services/connectors/` |
| Document, interview, observation capture | `services/field_assessment/store.py` |
| Evidence linking | `services/field_assessment/store.py` |
| Engagement-scoped audit events | `api/field_assessment.py` (`FaEngagementAuditEvent`) |
| Drift detection (engagement baseline) | `services/connectors/drift/` |
| MS Graph connector bridge | `services/connectors/msgraph_bridge.py` |
| Field Assessment console UI | `apps/console/app/field-assessment/` |

### What it does NOT own

- Tenant-level readiness posture
- Governance workflows (remediation tracking)
- Governance asset registry
- Topology graph
- RAG corpus
- AI chat / AI plane
- Governance reports (platform-owned after promotion)

### Engagement lifecycle

```
scheduled
    └─ pre_visit          (ungated)
         └─ in_progress   (ungated)
              └─ evidence_collected   (GATED — playbook evidence gates)
                   └─ report_generation   (GATED — link + finding + remediation gates)
                        └─ delivered   (GATED — all above + escalation.critical + report.qa.approved)
                             └─ PROMOTION FIRES AUTOMATICALLY
```

**Gated statuses**: `evidence_collected`, `report_generation`, `delivered`

Gate enforcement reads from `playbook.status_transition_requirements[target_status]`. A gate must appear in that tuple to actually block a transition. The gate's own `blocks_status_transition` field is informational only — it does not drive enforcement.

### Playbooks

A `FieldAssessmentPlaybook` is a deterministic, versioned, frozen specification of what constitutes a complete and defensible assessment. It defines:
- Required steps, scan sources, document classes, interview roles, observation domains
- Minimum evidence expectations (type, count, freshness)
- Required evidence links
- Blocking gates per status transition

Playbooks are immutable at runtime (`frozen=True` dataclass, `MappingProxyType` dicts). They are the authoritative enforcement source — not config, not the database.

Current playbooks: `ai_governance` (v1), `comprehensive` (v1). Frameworks `cmmc`, `hipaa`, `soc2`, `iso27001` fall back to `comprehensive`.

### Report QA gate

The `report.qa.approved` gate blocks the `delivered` transition until a `GovernanceReportRecord` with `qa_approved_by` set exists for the engagement. The QA approval route is `POST /field-assessment/engagements/{id}/reports/{report_id}/qa-approve`.

This gate is the final checkpoint before promotion. Once the engagement is `delivered`, the evidence chain is complete, the report is signed, and governance can begin.

---

## 4. The Promotion Event

Promotion is the hinge between the Field Assessment layer and the Governance Platform. It fires **automatically** when an engagement transitions to `delivered`.

### Trigger

Inside `transition_engagement_route()`, after the `delivered` status write and audit event, `promote_engagement_to_governance()` is called synchronously in the same request. The response returns only after promotion completes.

The `POST /field-assessment/engagements/{id}/promote` route exists as an **admin retry path** only. It is not the primary trigger.

### What promotion does (in a single transaction)

```
promote_engagement_to_governance(db, *, tenant_id, engagement_id)
    │
    ├─ GUARD: raises if not delivered, or promotion already completed (idempotent)
    │
    ├─ WORKFLOWS: one GovernanceWorkflow per FaNormalizedFinding
    │    └─ finding_id linked (required — no freeform workflow creation)
    │    └─ title, severity, framework_mappings carried over
    │    └─ state = active
    │
    ├─ ASSETS: FaScanResult asset candidates → GovernanceAsset
    │    └─ source_scan_result_id + source_engagement_id set (provenance chain)
    │    └─ deduplicates by asset fingerprint at tenant level
    │
    ├─ BASELINE: gate snapshot from delivered audit event → ReadinessBaseline
    │    └─ tenant-scoped, promotion-dated
    │    └─ feeds continuous readiness monitoring as starting posture
    │
    └─ RECORD: GovernancePromotion written
         └─ status: completed
         └─ asset_count, workflow_count, baseline_readiness_score, corpus_entries_added
```

### What promotion produces (async background task)

```
feed_corpus(tenant_id, engagement_id)
    └─ Each FaDocument → RagCorpusEntry
         └─ tenant-scoped, source_engagement_id + source_document_id tagged
         └─ idempotent: skips if corpus entry with same content hash exists
         └─ updates GovernancePromotion.corpus_entries_added when complete
```

### Promotion failure behavior

Promotion failure does **not** roll back the `delivered` status. The assessment is complete. The promotion record gets `status="failed"`. The engagement appears as "Governance activation pending" in the UI. Operators retry via the admin route.

### Idempotency

`promote_engagement_to_governance()` is safe to call multiple times. If a `GovernancePromotion` record with `status="completed"` exists for the engagement, the function returns the existing record without side effects.

---

## 5. Governance Platform Layer

### What it owns

The Governance Platform owns continuous, tenant-level governance state. It consumes evidence produced by Field Assessment and maintains it forward in time.

| Responsibility | Module |
|---|---|
| Governance asset registry | `api/governance_assets.py`, `services/governance_asset_registry/` |
| Asset topology graph | `api/governance_graph.py`, `services/governance_graph/` |
| Governance workflows (remediation) | `api/governance_workflows.py`, `services/governance_workflows/` |
| Readiness monitoring + gap analysis | `api/readiness_manager.py`, `services/readiness/` |
| RAG corpus + retrieval policy | `api/rag/`, `api/rag_corpus_console.py`, `api/rag_retrieval_policy.py` |
| AI chat + AI plane | `api/ui_ai_console.py`, `api/ai_plane_extension.py`, `services/ai/`, `services/ai_plane_extension/` |
| Governance reporting | `api/governance_report_manager.py`, `services/governance/report/` |
| Drift monitoring (tenant-level) | `services/connectors/drift/` |
| Promotion record | `GovernancePromotion` model |

### Continuous governance loop

```
GovernancePromotion established (baseline)
    │
    ├─ Workflows drive remediation
    │    └─ Each workflow links to finding_id → evidence chain
    │    └─ Completion triggers readiness delta recalculation
    │
    ├─ Drift monitoring detects change
    │    └─ New scan result vs baseline → drift delta
    │    └─ Significant drift → new FaNormalizedFinding → new GovernanceWorkflow
    │
    ├─ Readiness monitoring updates posture continuously
    │    └─ Starts from promotion baseline
    │    └─ Updates on workflow completion, drift events, new evidence
    │
    ├─ RAG / AI answers governed by retrieval policy + provenance
    │    └─ Corpus fed from assessment documents at promotion
    │    └─ New documents added continuously as client submits evidence
    │    └─ Every answer carries source provenance chain
    │
    └─ Re-assessment trigger (when drift exceeds threshold)
         └─ New engagement created, inherits tenant evidence baseline
         └─ Delivers → new promotion → baseline updated
```

### Workflow rules

Every `GovernanceWorkflow` must have a `finding_id` set. This is enforced at the store layer. No freeform workflow creation. Every remediation task exists because a specific evidence-backed finding required it — this is what makes remediation tracking defensible.

### Readiness

Readiness has two modes that are complementary, not competing:

| Mode | Scope | Driver | Location |
|---|---|---|---|
| Execution readiness | Engagement | Playbook gate evaluation | `services/field_assessment/readiness.py` |
| Continuous readiness | Tenant | Framework controls, evidence, workflow completion | `services/readiness/` |

Continuous readiness posture starts from the `GovernancePromotion.baseline_readiness_score` and evolves forward. Execution readiness is a point-in-time gate check that does not persist to the governance layer.

---

## 6. Full Platform Data Flow

```
ASSESSMENT TIER
═══════════════════════════════════════════════════════════════

Engagement created (assessment_type → playbook assigned)
    │
    ├─ Scan results imported (connector / manual ingest)
    │    └─ normalize_scan_findings() → FaNormalizedFinding rows
    │    └─ FaEvidenceLink: finding ↔ scan_result
    │
    ├─ Documents registered → FaDocument + FaEvidenceLink
    ├─ Interviews captured → FaInterview + FaEvidenceLink
    ├─ Observations captured → FaFieldObservation + FaEvidenceLink
    │
    └─ Status transitions (gated by playbook)
         └─ evidence_collected → report_generation → delivered
              └─ report.qa.approved gate requires QA sign-off
                   └─ GovernanceReportRecord.qa_approved_by set

PROMOTION GATE (automatic on delivered)
═══════════════════════════════════════════════════════════════

promote_engagement_to_governance()
    ├─ Findings → GovernanceWorkflows (finding_id required)
    ├─ Scan discoveries → GovernanceAssets (source provenance)
    ├─ Gate snapshot → ReadinessBaseline (tenant-level starting posture)
    └─ GovernancePromotion record (status=completed)

BackgroundTask: feed_corpus()
    └─ Documents → RagCorpusEntries (tenant-scoped, source-tagged)

GOVERNANCE TIER
═══════════════════════════════════════════════════════════════

GovernanceAssets ──► Topology Graph (graph rebuild on promotion + drift)
GovernanceWorkflows ──► Remediation tracking (finding_id chain)
ReadinessBaseline ──► Continuous monitoring (posture evolves forward)
RagCorpus ──► AI chat answers (governed by retrieval policy + provenance)
Drift events ──► New findings ──► New workflows ──► Readiness delta
Re-assessment ──► New engagement ──► New promotion ──► Baseline update
```

---

## 7. Module Ownership Rules

These rules resolve ambiguity when deciding where code belongs.

1. **Field Assessment owns engagement-scoped state.** If it is scoped to an engagement and does not exist after the engagement closes, it belongs in the FA layer.

2. **Governance Platform owns tenant-scoped state.** If it persists beyond an engagement, evolves continuously, or is shared across engagements, it belongs in the governance layer.

3. **Promotion is the only bridge.** Evidence does not directly mutate governance state. Promotion does. No code in `api/field_assessment.py` or `services/field_assessment/` should write directly to governance tables except through `promote_engagement_to_governance()`.

4. **Workflows must link to findings.** There is no valid governance workflow without a `finding_id`. Enforcement is at the store layer, not convention.

5. **Assets carry provenance.** Every `GovernanceAsset` must have `source_scan_result_id` and `source_engagement_id`. Assets without provenance are not permissible.

6. **RAG corpus is read-only from Field Assessment.** Assessment documents become corpus entries at promotion. Field Assessment never writes directly to the corpus.

7. **Readiness scoring uses two separate paths.** Execution readiness (gate-based, engagement-scoped) does not write to the continuous readiness layer. They share terminology but not data.

8. **Reports are immutable after QA approval.** `GovernanceReportRecord` with `qa_approved_by` set must not be modified. New reports require a new record.

---

## 8. Tiered Activation

The presence of a `GovernancePromotion` record with `status="completed"` is the authoritative signal that a tenant has been activated for continuous governance.

| Signal | Meaning |
|---|---|
| No promotion record | Assessment-only client |
| `GovernancePromotion.status = "failed"` | Delivered, governance activation pending (retry available) |
| `GovernancePromotion.status = "completed"` | Full governance client |

UI surfaces, billing, and feature gating should key off this record, not off engagement status alone.

---

## 9. Architectural Decisions (Locked)

These decisions are settled. Changing them requires an explicit architecture review and an update to this document.

| Decision | Choice | Reason |
|---|---|---|
| Evidence scoping | Tenant-scoped, engagement-tagged | Enables drift, re-assessment baseline, cross-engagement RAG without re-ingest |
| Promotion trigger | Automatic on `delivered` | Zero operator friction; promotion is a contract consequence of delivery, not an optional step |
| Promotion failure behavior | Engagement stays `delivered`, promotion retryable | Assessment validity must not depend on governance bootstrap success |
| Workflow-finding linkage | Required (enforced at store layer) | Makes remediation tracking legally defensible; every task must trace to evidence |
| Asset provenance | Required (source_scan_result_id + source_engagement_id) | Graph topology and drift tracking require knowing where an asset was first seen |
| Playbook as enforcement authority | Playbook `status_transition_requirements` is the gate enforcement source | Gate's own `blocks_status_transition` is informational only; gate must appear in playbook tuple to block |
| RAG corpus feed | Background task after promotion | Embedding/indexing latency must not block delivery confirmation |
| Report immutability | Enforced after `qa_approved_by` is set | Signed, QA-approved reports are legal artifacts |

---

## 10. Cross-References

| Topic | Document |
|---|---|
| Tenant isolation rules | `docs/architecture/tenant_model.md` |
| Auth boundary | `docs/architecture/auth_boundary.md` |
| Audit event contract | `docs/architecture/audit_model.md` |
| Service topology | `docs/architecture/service_map.md` |
| RAG retrieval policy | `docs/ai/RETRIEVAL_POLICY_ENGINE.md` |
| RAG flow | `docs/ai/RAG_FLOW.md` |
| Evidence artifact policy | `docs/EVIDENCE_ARTIFACT_POLICY.md` |
| Governance rules | `docs/GOVERNANCE_RULES.md` |
| SOC architecture review | `docs/SOC_ARCH_REVIEW_2026-02-15.md` |
