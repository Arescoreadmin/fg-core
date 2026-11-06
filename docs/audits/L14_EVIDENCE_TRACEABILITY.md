# L14 Evidence Traceability Analysis

**Generated:** 2026-11-06
**Branch:** audit/l14-field-assessment-report-readiness-001
**Commit:** ab72e44f922e60c48a48259ff32930c15dfb81d5

---

## 1. The Evidence Chain

The canonical evidence chain in FrostGate's field assessment is:

```
Engagement → Evidence Artifact → Evidence Provenance → Normalized Finding → Evidence Report Link → Report
```

Broken down:

```
FaEngagement
  └── FaScanResult / FaDocumentAnalysis / FaFieldObservation / FaArtifact
        └── FaEvidenceProvenance  [chain_status=active, one per evidence object]
              └── FaNormalizedFinding  [evidence_ref_ids + findings_hash]
                    └── FaEvidenceLink  [source=finding → evidence=scan_result]
                          └── FaEvidenceReportLink  [evidence_id → report_id]
                                └── FaReport / GovernanceReport  [quality score, PDF]
```

---

## 2. Step-by-Step Chain Analysis

### Step 1: Engagement → Evidence Artifact

**Source file:** `api/field_assessment.py` → `ingest_scan_result_route`, `register_document_analysis_route`, `capture_observation_route`

**How it links:** Every evidence ingestion function validates that `engagement_id` is a known engagement for the tenant (via `get_engagement(db, engagement_id, tenant_id)`). The evidence record stores `engagement_id` as a non-nullable column.

**Validation:** `_assert_engagement_accepts_evidence(eng)` at line 322 blocks evidence ingestion if the engagement is in a terminal state.

**What can break it:** None identified. Engagement deletion is not supported (soft-cancel only, which does not break existing evidence).

**Test coverage:** `test_ingest_scan_result`, `test_register_document_analysis`, `test_capture_observation` — all pass.

---

### Step 2: Evidence Artifact → Provenance Record

**Source file:** `services/field_assessment/evidence_provenance.py` → `create_evidence_provenance`

**How it links:** Every evidence ingestion call invokes `create_evidence_provenance(db, ...)` within the same DB transaction. The provenance record stores `evidence_id` (pointing to the scan_result/document_analysis/observation), `engagement_id`, `source_type`, `artifact_hash`, `collected_by_id`, `chain_status`.

**Validation:** The provenance record is append-only (`fa_evidence_provenance` has SQLAlchemy event hooks blocking UPDATE/DELETE). Chain integrity: each new provenance amendment creates a new row with `previous_hash` linking to the prior record.

**What can break it:**
- If the evidence creation fails mid-transaction, provenance is rolled back atomically.
- If `create_evidence_provenance` is not called (bug), evidence exists without provenance. No test verifies that ALL evidence types always have provenance.

**Test coverage:** `tests/test_fa_evidence_provenance.py` — 22 tests pass. Tests cover: creation per evidence type, append-only enforcement, chain linkage.

---

### Step 3: Evidence Artifact → Normalized Finding

**Source file:** `api/field_assessment.py` → `_auto_link_scan_evidence` (line 1119)

**How it links:** When a scan result is ingested, findings extracted from the `normalized_payload` are written to `fa_normalized_findings`. Each finding stores `evidence_ref_ids` (a JSON array of scan_result_ids that support the finding). `findings_hash` provides deduplication — if the same logical finding is ingested twice, the unique constraint `uq_fa_finding_hash` prevents a duplicate row.

**Validation:** `confidence_score` (0–100) and `source_attribution` are required. `framework_mappings` and `nist_ai_rmf_mappings` are populated from the finding's control identifiers.

**What can break it:**
- If `normalized_payload` does not contain findings, no findings are auto-created. Assessor must create findings manually via observation records.
- If a scan result has no normalized payload, findings count stays zero — the engagement can still reach "delivered" with zero findings (the gate checks for _presence_ of evidence, not for minimum findings count).

**Test coverage:** `tests/test_field_assessment_normalizer.py` — covers normalization logic. Finding dedup via hash tested in `test_finding_id_determinism`.

---

### Step 4: Evidence Artifact ↔ Finding via Evidence Links

**Source file:** `api/field_assessment.py` → `create_evidence_link_route` (line 2779)

**How it links:** `FaEvidenceLink` is a graph edge between any two entity types. A finding can be linked to a scan_result, document_analysis, or observation. The edge stores `source_entity_type`, `source_entity_id`, `evidence_entity_type`, `evidence_entity_id`. Unique constraint: `uq_fa_evidence_link` prevents duplicate edges.

**Validation:** Both entity IDs are validated against the same engagement + tenant before the link is created (orphan prevention tested in `test_evidence_link_orphan_rejected`).

**What can break it:**
- Evidence links are bidirectional by convention but not enforced. A finding may reference evidence in `evidence_ref_ids` without a corresponding `FaEvidenceLink` row (the two mechanisms are parallel, not synchronized).
- The `FaEvidenceReportLink` creation at report generation time (`_create_report_links_for_report`) uses `_collect_report_evidence_ids(report_json)` to extract evidence IDs from the report JSON — this uses the report JSON contents, not the evidence link graph.

**Test coverage:** `test_evidence_link_creation`, `test_evidence_link_duplicate_rejected`, `test_evidence_link_orphan_rejected` — all pass.

---

### Step 5: Finding → Report (via Evidence Report Links)

**Source file:** `api/field_assessment.py` → `_create_report_links_for_report` (line 1245)

**How it links:** At report generation time (`create_engagement_report_route`), `_collect_report_evidence_ids(report_json)` traverses the report JSON to extract evidence IDs referenced in findings. For each discovered evidence ID, a `FaEvidenceReportLink` row is created linking `evidence_id → report_id`. These are append-only.

**Validation:** Evidence IDs are extracted from `report_json["findings"]` section. The latest provenance record for each evidence ID is also fetched and linked.

**What can break it:**
- If the report JSON does not include the full findings section, some evidence IDs may be missed.
- Evidence IDs in the report JSON must match actual `FaScanResult.id`, `FaDocumentAnalysis.id`, or `FaFieldObservation.id` values. If a finding references a stale or deleted scan_result_id, the link creation will produce a dangling reference (no foreign key enforces this in SQLite test mode).

**Test coverage:** `test_report_generation_creates_evidence_report_links` — passes.

---

### Step 6: Report → PDF Export

**Source file:** `services/report_authority/renderer_pdf.py` → `render_pdf`
**Source file:** `services/report_authority/engine.py` → `generate_report`

**How it links:** `GenerateReportRequest.assessment_id` is used as the `engagement_id` when calling `compute_quality_inputs(db, tenant_id, engagement_id)`. Quality inputs are derived from:
- `FaNormalizedFinding` count vs evidence-linked findings
- `FaEvidenceProvenance` reviewed_at vs total
- `FaEvidenceProvenance` freshness window
- Confidence scores from findings

The PDF renderer takes the `report_data` dict assembled from `_build_report_content(engine, report_id)` — this is a schema reconstruction from the stored `FaReport` row, not the original FA evidence.

**What can break it:**
- The `assessment_id` parameter to `POST /reports/generate` is a free string — it is NOT validated against `fa_engagements.id`. If the engagement doesn't exist for the tenant, `compute_quality_inputs` will return zero scores (empty evidence) but will not raise an error.
- The FA-native report (`/engagements/{id}/reports`) and the Report Authority report (`/reports/generate`) use different data models. The FA-native report JSON is not stored in `fa_report_authority` tables; the PDF renderer reads from `fa_report_authority` tables. The two systems are parallel, not integrated.

**Test coverage:** `test_export_pdf_returns_200_or_501`, `test_export_json_works` — pass. Quality input computation tested in `test_field_assessment_reports.py`.

---

## 3. Chain Integrity Summary

| Link | Source | Destination | Enforced | Tested |
|------|--------|-------------|----------|--------|
| Engagement → Evidence | engagement_id FK | FaScanResult.engagement_id | No FK (application-level) | Yes |
| Evidence → Provenance | create_evidence_provenance() | fa_evidence_provenance.evidence_id | Application-level, same tx | Yes |
| Evidence → Finding | normalized_payload extraction | fa_normalized_findings.evidence_ref_ids | Application-level | Yes (normalizer) |
| Finding ↔ Evidence Link | FaEvidenceLink graph | bidirectional edges | Orphan check in route | Yes |
| Finding → Report | _collect_report_evidence_ids() | fa_evidence_report_links | Application-level, same tx | Yes |
| Report → PDF | ReportAuthorityEngine.get_report() | renderer_pdf.render_pdf() | Application-level | Yes (HTTP 200) |

---

## 4. Identified Gaps in Chain

### Gap 1: No Foreign Key from FaEvidenceReportLink to FaScanResult
Evidence IDs in the report JSON are not validated against actual evidence table IDs in a foreign key sense. In SQLite test mode, this is not enforced. In Postgres, there are also no FK constraints on these tables (they are intentionally append-only audit records).

**Risk:** Low for current scale. A finding referencing a deleted scan_result creates a dangling reference in the report link table but does not break PDF generation.

### Gap 2: Parallel Report Systems Not Bridged
The FA-native `GovernanceReport` JSON and the Report Authority `FaReport` row are created separately. Quality inputs in the Report Authority are computed fresh from the evidence tables at generation time, not from the FA-native report JSON. The two reports may show different data if evidence changes between the two generation calls.

**Risk:** Medium. Operator should generate the Report Authority report immediately after the FA-native report is finalized, not days later.

### Gap 3: Evidence Provenance Created-By Not Validated Against Identity Registry
The `collected_by_id` field in `FaEvidenceProvenance` is a free string. It captures the assessor_id from the engagement, but this is not validated against an identity registry.

**Risk:** Low for current founder-operated model.

---

## 5. Automated Traceability Check

The following check can be run on a live engagement to verify chain completeness:

```python
# Verify that all normalized findings have at least one provenance-linked evidence record
from api.db import get_sessionmaker
from api.db_models_field_assessment import (
    FaNormalizedFinding, FaEvidenceProvenance, FaEvidenceReportLink
)
from sqlalchemy.orm import Session

def verify_evidence_chain(db: Session, tenant_id: str, engagement_id: str) -> dict:
    findings = db.query(FaNormalizedFinding).filter(
        FaNormalizedFinding.tenant_id == tenant_id,
        FaNormalizedFinding.engagement_id == engagement_id,
        FaNormalizedFinding.status.in_(["open", "in_progress"]),
    ).all()

    results = {
        "findings_total": len(findings),
        "findings_with_evidence": 0,
        "findings_without_evidence": 0,
        "unlinked_findings": [],
    }

    for f in findings:
        evidence_ids = f.evidence_ref_ids or []
        has_provenance = any(
            db.query(FaEvidenceProvenance).filter(
                FaEvidenceProvenance.tenant_id == tenant_id,
                FaEvidenceProvenance.engagement_id == engagement_id,
                FaEvidenceProvenance.evidence_id == eid,
            ).first() is not None
            for eid in evidence_ids
        )
        if has_provenance:
            results["findings_with_evidence"] += 1
        else:
            # Counts both: findings with no evidence_ref_ids AND findings whose
            # ref_ids exist but resolve to no provenance record (broken chain).
            # Using `or` here would incorrectly count dangling references as
            # evidence-backed — the exact failure mode this check must catch.
            results["findings_without_evidence"] += 1
            results["unlinked_findings"].append({
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity,
                "evidence_ref_ids": evidence_ids,  # [] = no refs; non-empty = broken chain
            })

    return results
```

This check is NOT implemented as a test because it requires a live engagement with actual data. It is provided here as a runbook verification step.
