from __future__ import annotations

import json
from dataclasses import replace
from collections.abc import Mapping, Sequence
from typing import Any, cast
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
from api.db_models_control_registry import ControlRegistry
from api.db_models_evidence_authority import (
    FaEvidence,
    FaEvidenceControlLink,
    FaEvidenceRiskLink,
)
from api.db_models_field_assessment import (
    FaEngagement,
    FaEvidenceReportLink,
    FaNormalizedFinding,
)
from api.db_models_framework_authority import (
    ControlFrameworkMappingRecord,
    FrameworkAuthorityFrameworkControlRecord,
    FrameworkAuthorityFrameworkRecord,
)
from api.db_models_governance_decision import FaGovernanceDecision
from api.db_models_governance_orchestration import (
    GovOrchPolicy,
    GovOrchSimulation,
    GovOrchWorkflow,
)
from api.db_models_governance_workflows import GovernanceWorkflow
from api.db_models_portal import PortalGrant
from api.db_models_remediation import RemediationTask
from api.db_models_report_authority import FaReport
from api.db_models_simulation import SimulationRunModel
from services.governance_digital_twin import (
    FORBIDDEN_FIELD_KEYS,
    GovernanceDigitalTwinBuildError,
    GovernanceDigitalTwinService,
    GOVERNANCE_DIGITAL_TWIN_FINGERPRINT_DOMAIN,
    build_governance_digital_twin_snapshot,
    compute_entity_hash,
    compute_relationship_hash,
    compute_snapshot_fingerprint,
    create_comparison_baseline,
    validate_governance_digital_twin_snapshot,
)


TENANT_A = "tenant-gdt-a"
TENANT_B = "tenant-gdt-b"


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _tables() -> list:
    return [
        GovOrchPolicy.__table__,
        ControlRegistry.__table__,
        FaEvidence.__table__,
        FaEvidenceControlLink.__table__,
        FaEvidenceRiskLink.__table__,
        FaEngagement.__table__,
        FaNormalizedFinding.__table__,
        FaEvidenceReportLink.__table__,
        RemediationTask.__table__,
        FaReport.__table__,
        FaGovernanceDecision.__table__,
        GovernanceWorkflow.__table__,
        GovOrchWorkflow.__table__,
        GovOrchSimulation.__table__,
        SimulationRunModel.__table__,
        FrameworkAuthorityFrameworkRecord.__table__,
        FrameworkAuthorityFrameworkControlRecord.__table__,
        ControlFrameworkMappingRecord.__table__,
        PortalGrant.__table__,
    ]


def _make_session(*, tables: list | None = None) -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=tables or _tables())
    return Session(engine)


def _seed_full_state(
    session: Session,
    *,
    tenant_id: str = TENANT_A,
    reverse_insert: bool = False,
    inject_forbidden_payload: bool = False,
) -> None:
    policy_payload = {
        "control_ids": ["ctl-1"],
        "reassessment_interval_days": 45,
        "framework_ids": ["fw-1"],
    }
    if inject_forbidden_payload:
        policy_payload["provider_payload"] = {"secret": "never-export"}

    records = [
        GovOrchPolicy(
            id="pol-1",
            tenant_id=tenant_id,
            name="Vendor Access Governance",
            description="Reviews vendor access pathways.",
            risk_level="HIGH",
            policy_data=json.dumps(policy_payload, sort_keys=True),
            active=1,
            version="1.2",
            created_at="2026-07-01T01:00:00Z",
            updated_at="2026-07-02T01:00:00Z",
        ),
        ControlRegistry(
            id="ctl-1",
            tenant_id=tenant_id,
            schema_version="1.0",
            control_id="control-external-access",
            title="External Access Review",
            description="Quarterly review of third-party access.",
            control_type="administrative",
            criticality="high",
            owner="secops",
            owner_email="secops@example.com",
            business_unit="Security",
            effectiveness_rating="effective",
            verification_status="verified",
            control_status="active",
            review_frequency_days=90,
            next_review_at="2026-09-30T00:00:00Z",
            last_review_at="2026-07-01T00:00:00Z",
            last_verified_at="2026-07-02T00:00:00Z",
            created_at="2026-07-01T02:00:00Z",
            updated_at="2026-07-02T02:00:00Z",
        ),
        FaEvidence(
            id="ev-1",
            tenant_id=tenant_id,
            evidence_ref="evidence/vendor-access-scan-1",
            lifecycle_state="VERIFIED",
            classification="INTERNAL",
            classification_labels="[]",
            source_type="SCAN",
            source_system="scanner",
            source_ref="scan:vendor-access:1",
            collection_method="API",
            title="Vendor Access Scan",
            description="Validated vendor access inventory.",
            content_hash="a" * 64,
            content_hash_algorithm="sha256",
            integrity_hash="b" * 64,
            integrity_hash_algorithm="sha256",
            provenance_chain_head="prov-1",
            trust_state="VERIFIED",
            verification_count=2,
            trust_score=91,
            last_verification_source="manual_review",
            last_verifier_id="auditor-1",
            freshness_score=95,
            verification_score=92,
            completeness_score=88,
            quality_last_computed_at="2026-07-02T03:00:00Z",
            review_due_at="2026-09-30T00:00:00Z",
            verification_due_at="2026-09-30T00:00:00Z",
            freshness_due_at="2026-08-30T00:00:00Z",
            benchmark_freshness_percentile=90,
            benchmark_verification_percentile=85,
            benchmark_density_percentile=70,
            benchmark_coverage_percentile=80,
            owner_id="owner-1",
            owner_type="human",
            creator_id="creator-1",
            creator_type="human",
            engagement_id="eng-1",
            collected_at="2026-07-01T03:00:00Z",
            submitted_at="2026-07-01T04:00:00Z",
            reviewed_at="2026-07-02T02:00:00Z",
            verified_at="2026-07-02T03:00:00Z",
            expires_at="2026-12-31T00:00:00Z",
            revoked_at=None,
            archived_at=None,
            evidence_version="1",
            superseded_by=None,
            schema_version="1.0",
            created_at="2026-07-01T03:00:00Z",
            updated_at="2026-07-02T03:00:00Z",
        ),
        FaEvidenceControlLink(
            id="ecl-1",
            tenant_id=tenant_id,
            evidence_id="ev-1",
            control_id="ctl-1",
            linked_by="auditor-1",
            linked_at="2026-07-02T03:00:00Z",
            schema_version="1.0",
            created_at="2026-07-02T03:00:00Z",
        ),
        FaEvidenceRiskLink(
            id="erl-1",
            tenant_id=tenant_id,
            evidence_id="ev-1",
            linked_resource_id="find-1",
            link_type="FINDING",
            linked_by="auditor-1",
            linked_at="2026-07-02T03:00:00Z",
            schema_version="1.0",
            created_at="2026-07-02T03:00:00Z",
        ),
        FaEngagement(
            id="eng-1",
            tenant_id=tenant_id,
            client_name="Acme Health",
            client_domain="acme.example",
            assessor_id="assessor-1",
            assessment_type="SOC2",
            status="in_progress",
            scheduled_date="2026-07-01T00:00:00Z",
            client_access_code=None,
            engagement_metadata={"region": "us-east-1"},
            schema_version="1.0",
            created_at="2026-07-01T00:00:00Z",
            updated_at="2026-07-02T00:00:00Z",
        ),
        FaNormalizedFinding(
            id="find-1",
            tenant_id=tenant_id,
            engagement_id="eng-1",
            finding_type="ACCESS_GOVERNANCE",
            findings_hash="c" * 64,
            severity="HIGH",
            status="open",
            title="Unreviewed Third-Party Access",
            description="Legacy vendor access path lacks quarterly review evidence.",
            source_attribution="scanner",
            confidence_score=83,
            framework_mappings=["NIST-AI-RMF:GV-1"],
            nist_ai_rmf_mappings=["GV-1"],
            evidence_ref_ids=["ev-1"],
            remediation_hint="Disable stale access and require review.",
            asset_id=None,
            schema_version="1.0",
            created_at="2026-07-01T05:00:00Z",
            updated_at="2026-07-02T05:00:00Z",
        ),
        RemediationTask(
            id="rem-1",
            tenant_id=tenant_id,
            finding_id="find-1",
            assessment_id="eng-1",
            title="Disable legacy vendor access",
            description="Remove stale entitlement and document approval.",
            recommended_action="Disable account and validate owner approval.",
            priority="high",
            status="open",
            created_by="ops-1",
            assigned_to="secops",
            created_at="2026-07-02T06:00:00Z",
            updated_at="2026-07-02T06:30:00Z",
            closed_at=None,
            task_metadata={"ticket": "FG-1234"},
            schema_version="1.0",
            assigned_user_id="user-1",
            assigned_user_email="secops@example.com",
            assigned_display_name="SecOps",
            assigned_at=_dt("2026-07-02T06:00:00Z"),
            due_date=_dt("2026-07-16T00:00:00Z"),
            sla_target_days=14,
            sla_breach_at=_dt("2026-07-17T00:00:00Z"),
            ownership_reason="Critical vendor access remediation",
            last_assignment_change_at=_dt("2026-07-02T06:00:00Z"),
        ),
        FaReport(
            id="rep-1",
            tenant_id=tenant_id,
            report_ref="report/acme/soc2/1",
            report_type="ASSESSMENT",
            lifecycle_state="PUBLISHED",
            schema_version="1.0",
            assessment_id="eng-1",
            title="Acme Health SOC 2 Readout",
            scope="Third-party access governance",
            objectives="Demonstrate closure path",
            assessor_id="assessor-1",
            reviewer_id="reviewer-1",
            generator_id="generator-1",
            quality_score=0.93,
            evidence_coverage_score=0.91,
            verification_coverage_score=0.95,
            freshness_score=0.89,
            confidence_score=0.94,
            completeness_score=0.92,
            quality_grade="A",
            report_hash_sha256="d" * 64,
            report_hash_sha512="e" * 128,
            manifest_hash="f" * 64,
            manifest_hash_sha256="a" * 64,
            manifest_hash_sha512="b" * 128,
            transparency_root=None,
            merkle_root=None,
            signing_algorithm="ed25519",
            signature="sig",
            report_version="1.0.0-r1",
            major_version=1,
            minor_version=0,
            patch_version=0,
            report_revision=1,
            branding_config="{}",
            regulatory_profile="SOC2",
            generator_version="1.0",
            provider_version="1.0",
            export_version="1.0",
            manifest_schema_version="1.0",
            created_at="2026-07-02T07:00:00Z",
            updated_at="2026-07-02T07:30:00Z",
            published_at="2026-07-02T08:00:00Z",
            superseded_at=None,
            archived_at=None,
            generation_started_at="2026-07-02T07:00:00Z",
            generation_completed_at="2026-07-02T07:20:00Z",
            has_pdf=1,
            has_html=1,
            has_json=1,
        ),
        FaEvidenceReportLink(
            id="erl-report-1",
            tenant_id=tenant_id,
            engagement_id="eng-1",
            evidence_id="ev-1",
            provenance_record_id=None,
            report_id="rep-1",
            report_hash="d" * 64,
            report_signature="sig",
            linked_at="2026-07-02T08:00:00Z",
            linked_by="generator-1",
            authority_version="1.0",
            link_version="1.0",
            event_hash="1" * 64,
            previous_hash=None,
            signature="sig",
            signing_key_id="key-1",
            signed_at="2026-07-02T08:00:00Z",
            signature_version="1.0",
            created_at="2026-07-02T08:00:00Z",
            schema_version="1.0",
        ),
        FaGovernanceDecision(
            id="dec-1",
            tenant_id=tenant_id,
            engagement_id="eng-1",
            decision_type="policy_approved",
            entity_type="policy",
            entity_id="pol-1",
            actor_id="ciso-1",
            actor_subject=None,
            actor_name="Chief Security Officer",
            actor_email="ciso@example.com",
            actor_role="CISO",
            actor_auth_source="oidc",
            creator_id="ciso-1",
            reviewer_id=None,
            approver_id="ciso-1",
            decision_reason="Quarterly review completed.",
            decision_notes="Proceed with remediation.",
            status="active",
            evidence_snapshot_hash="2" * 64,
            evidence_refs=json.dumps(["ev-1"]),
            related_finding_ids=json.dumps(["find-1"]),
            related_control_ids=json.dumps(["ctl-1"]),
            decision_at="2026-07-02T09:00:00Z",
            effective_until=None,
            review_date="2026-10-01T00:00:00Z",
            transaction_id="txn-1",
            correlation_id="corr-1",
            decision_metadata=json.dumps(
                {"remediation_task_id": "rem-1"}, sort_keys=True
            ),
        ),
        GovernanceWorkflow(
            id="wf-1",
            tenant_id=tenant_id,
            engagement_id="eng-1",
            template_name="policy_follow_up",
            title="Policy Follow-Up Workflow",
            description="Track closure of access governance finding.",
            state="active",
            priority="high",
            assigned_to_role="security",
            context_ref_type="decision",
            context_ref_id="dec-1",
            due_at="2026-07-15T00:00:00Z",
            created_by="workflow-bot",
            created_at="2026-07-02T10:00:00Z",
            updated_at="2026-07-02T10:30:00Z",
            finding_id="find-1",
            resolved_at=None,
            archived_at=None,
            metadata_={"trace": "wf-trace-1"},
            schema_version="1.0",
        ),
        GovOrchWorkflow(
            id="owf-1",
            tenant_id=tenant_id,
            name="Vendor Access Approval Chain",
            workflow_state="PENDING",
            playbook_id=None,
            trigger_id=None,
            context=json.dumps({"decision_id": "dec-1"}, sort_keys=True),
            created_at="2026-07-02T10:15:00Z",
            updated_at="2026-07-02T10:45:00Z",
            completed_at=None,
        ),
        GovOrchSimulation(
            id="sim-1",
            tenant_id=tenant_id,
            name="Vendor Access What-If",
            change_type="ACCESS_REVIEW_ENFORCEMENT",
            change_data=json.dumps(
                {
                    "policy_ids": ["pol-1"],
                    "control_ids": ["ctl-1"],
                    "finding_ids": ["find-1"],
                },
                sort_keys=True,
            ),
            simulation_state="COMPLETE",
            result=json.dumps({"projected_controls": ["ctl-1"]}, sort_keys=True),
            created_at="2026-07-02T11:00:00Z",
            updated_at="2026-07-02T11:30:00Z",
        ),
        SimulationRunModel(
            run_id="run-1",
            tenant_id=tenant_id,
            assessment_id="eng-1",
            framework_id="fw-1",
            scenario_type="ACCESS_REDUCTION",
            simulation_contract_version="1.0",
            simulation_engine_version="1.0",
            snapshot_id="sim-snapshot-1",
            projection_json=json.dumps(
                {"affected_control_ids": ["ctl-1"]}, sort_keys=True
            ),
            uncertainty="LOW",
            total_warnings=0,
            total_impacts=1,
            total_critical_warnings=0,
            simulated_at_iso="2026-07-02T12:00:00Z",
            completed=True,
            error_summary=None,
            created_by_actor_id="analyst-1",
            actor_type="human",
            request_id="req-1",
            trace_id="trace-1",
            auth_scope_snapshot="governance:read",
            input_hash="3" * 64,
            projection_hash="4" * 64,
            contract_hash="5" * 64,
            classification="internal",
            created_at=_dt("2026-07-02T11:45:00Z"),
        ),
        FrameworkAuthorityFrameworkRecord(
            id="fw-1",
            tenant_id=None,
            scope_type="SYSTEM",
            framework_key="nist-ai-rmf",
            name="NIST AI RMF",
            version="1.0",
            category="AI",
            publisher="NIST",
            description="AI governance framework",
            status="ACTIVE",
            effective_date=date(2024, 1, 1),
            retired_date=None,
            schema_version=1,
            created_at=_dt("2026-06-01T00:00:00Z"),
            updated_at=_dt("2026-07-01T00:00:00Z"),
        ),
        FrameworkAuthorityFrameworkControlRecord(
            id="fwc-1",
            framework_id="fw-1",
            tenant_id=None,
            scope_type="SYSTEM",
            control_ref="GV-1",
            title="Establish Governance Policies",
            description="Governance policy requirement",
            domain="GOVERN",
            family="GV",
            clause="GV-1",
            objective="Define governance policy",
            implementation_guidance="Document and review policy",
            status="ACTIVE",
            schema_version=1,
            created_at=_dt("2026-06-01T00:00:00Z"),
            updated_at=_dt("2026-07-01T00:00:00Z"),
        ),
        ControlFrameworkMappingRecord(
            id="map-1",
            tenant_id=tenant_id,
            control_id="ctl-1",
            framework_id="fw-1",
            framework_control_id="fwc-1",
            mapping_type="FULL",
            coverage_level="HIGH",
            confidence=97,
            rationale="Control fully satisfies policy review requirement",
            mapped_by="mapper-1",
            mapped_at=_dt("2026-07-02T12:30:00Z"),
            status="ACTIVE",
            schema_version=1,
            created_at=_dt("2026-07-02T12:30:00Z"),
            updated_at=_dt("2026-07-02T12:45:00Z"),
        ),
        PortalGrant(
            id="pg-1",
            tenant_id=tenant_id,
            client_id="client-acme",
            engagement_id="eng-1",
            grant_type="client_portal",
            grant_hash="sha256:portal",
            created_by="portal-admin",
            created_at="2026-07-02T13:00:00Z",
            expires_at="2026-12-31T00:00:00Z",
            last_used_at="2026-07-02T13:30:00Z",
            revoked_at=None,
            revoked_by=None,
            status="active",
            rotation_counter=0,
        ),
    ]
    if reverse_insert:
        records = list(reversed(records))
    session.add_all(records)
    session.commit()


def _seed_other_tenant_state(session: Session) -> None:
    session.add(
        GovOrchPolicy(
            id="pol-b",
            tenant_id=TENANT_B,
            name="Tenant B Policy",
            description="Other tenant policy",
            risk_level="LOW",
            policy_data=json.dumps({"control_ids": ["ctl-b"]}, sort_keys=True),
            active=1,
            version="1.0",
            created_at="2026-07-03T00:00:00Z",
            updated_at="2026-07-03T00:00:00Z",
        )
    )
    session.add(
        ControlRegistry(
            id="ctl-b",
            tenant_id=TENANT_B,
            schema_version="1.0",
            control_id="control-b",
            title="Tenant B Control",
            description="Other tenant control",
            control_type="technical",
            criticality="low",
            owner="owner-b",
            owner_email="owner-b@example.com",
            business_unit="Ops",
            effectiveness_rating="adequate",
            verification_status="unverified",
            control_status="draft",
            review_frequency_days=90,
            next_review_at=None,
            last_review_at=None,
            last_verified_at=None,
            created_at="2026-07-03T00:00:00Z",
            updated_at="2026-07-03T00:00:00Z",
        )
    )
    session.commit()


def _entity_types(snapshot) -> set[str]:
    return {entity.type for entity in snapshot.entities}


def _relationship_triplets(snapshot) -> set[tuple[str, str, str]]:
    entity_by_id = {entity.id: entity for entity in snapshot.entities}
    return {
        (
            relationship.type,
            entity_by_id[relationship.from_entity_id].type,
            entity_by_id[relationship.to_entity_id].type,
        )
        for relationship in snapshot.relationships
    }


def _find_entity(snapshot, entity_type: str, title: str):
    for entity in snapshot.entities:
        if entity.type == entity_type and entity.title == title:
            return entity
    raise AssertionError(f"entity not found: {entity_type} {title}")


def _contains_forbidden_key(payload) -> bool:
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if str(key).strip().lower() in FORBIDDEN_FIELD_KEYS:
                return True
            if _contains_forbidden_key(value):
                return True
        return False
    if isinstance(payload, Sequence) and not isinstance(
        payload, (str, bytes, bytearray)
    ):
        return any(_contains_forbidden_key(item) for item in payload)
    return False


def test_snapshot_construction_core_structure() -> None:
    session = _make_session()
    _seed_full_state(session)

    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    assert snapshot.tenant_id == TENANT_A
    assert snapshot.snapshot_version == "18.8.1"
    assert snapshot.snapshot_id.startswith("gdts-")
    assert len(snapshot.fingerprint) == 64
    assert snapshot.redaction_profile == "replay_safe"
    assert snapshot.replay_safe_export["snapshot_id"] == snapshot.snapshot_id
    assert snapshot.replay_safe_export["fingerprint"] == snapshot.fingerprint
    assert snapshot.generated_at == "2026-07-02T12:30:00Z"
    assert snapshot.canonical_snapshot_id == snapshot.snapshot_id
    assert snapshot.graph_schema_version == "1.0"
    assert snapshot.builder_version == "1.2.0"
    assert snapshot.category == "operational"
    assert snapshot.parent_snapshot_id is None
    assert snapshot.previous_fingerprint is None
    assert snapshot.generation == 0
    assert snapshot.lineage_id.startswith("gdtl-")
    assert snapshot.twin_identity.twin_class == "governance_digital_twin"
    assert snapshot.twin_identity.tenant_id == TENANT_A
    assert snapshot.manifest is not None
    assert snapshot.manifest.fingerprint == snapshot.fingerprint
    assert snapshot.validation_report is not None
    assert snapshot.validation_report.valid is True
    assert snapshot.completeness["method"] == "available_core_authorities_ratio_v2"
    assert snapshot.completeness["score"] == 100
    assert snapshot.completeness["missing_authorities"] == ()
    assert len(snapshot.source_authorities) >= 8
    assert len(snapshot.entities) >= 13
    assert len(snapshot.relationships) >= 12
    assert snapshot.baselines == ()
    assert "policy" in _entity_types(snapshot)
    assert "control" in _entity_types(snapshot)
    assert "evidence" in _entity_types(snapshot)
    assert "finding" in _entity_types(snapshot)
    assert "remediation" in _entity_types(snapshot)
    assert "assessment" in _entity_types(snapshot)
    assert "report" in _entity_types(snapshot)
    assert "decision" in _entity_types(snapshot)
    assert "workflow" in _entity_types(snapshot)
    assert "simulation" in _entity_types(snapshot)
    assert "customer" in _entity_types(snapshot)
    assert "framework" in _entity_types(snapshot)
    assert "authority" in _entity_types(snapshot)


def test_tenant_isolation() -> None:
    session = _make_session()
    _seed_full_state(session)
    _seed_other_tenant_state(session)

    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    titles = {entity.title for entity in snapshot.entities}
    source_refs = {entity.source_ref for entity in snapshot.entities}
    assert "Tenant B Policy" not in titles
    assert "Tenant B Control" not in titles
    assert all(entity.tenant_scope == TENANT_A for entity in snapshot.entities)
    assert all("pol-b" not in ref for ref in source_refs)
    assert all("ctl-b" not in ref for ref in source_refs)
    assert snapshot.tenant_id == TENANT_A
    assert snapshot.completeness["score"] == 100


def test_deterministic_repeated_snapshot_fingerprint() -> None:
    session = _make_session()
    _seed_full_state(session)

    first = build_governance_digital_twin_snapshot(session, TENANT_A)
    second = build_governance_digital_twin_snapshot(session, TENANT_A)

    assert first.snapshot_id == second.snapshot_id
    assert first.fingerprint == second.fingerprint
    assert compute_snapshot_fingerprint(first) == compute_snapshot_fingerprint(second)


def test_deterministic_fingerprint_across_insert_order() -> None:
    session_a = _make_session()
    _seed_full_state(session_a, reverse_insert=False)
    snapshot_a = build_governance_digital_twin_snapshot(session_a, TENANT_A)

    session_b = _make_session()
    _seed_full_state(session_b, reverse_insert=True)
    snapshot_b = build_governance_digital_twin_snapshot(session_b, TENANT_A)

    assert snapshot_a.fingerprint == snapshot_b.fingerprint
    assert snapshot_a.snapshot_id == snapshot_b.snapshot_id
    assert snapshot_a.generated_at == snapshot_b.generated_at
    assert snapshot_a.replay_safe_export == snapshot_b.replay_safe_export


def test_entity_hashing_is_deterministic() -> None:
    session = _make_session()
    _seed_full_state(session)
    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    entity = _find_entity(snapshot, "policy", "Vendor Access Governance")
    entity_hash_1 = compute_entity_hash(entity)
    entity_hash_2 = compute_entity_hash(entity)

    assert len(entity_hash_1) == 64
    assert entity_hash_1 == entity_hash_2
    assert entity.metadata_hash
    assert entity.redaction_state == "metadata_hashed"
    assert entity.replay_safe is True


def test_relationship_hashing_is_deterministic() -> None:
    session = _make_session()
    _seed_full_state(session)
    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    relationship = snapshot.relationships[0]
    relationship_hash_1 = compute_relationship_hash(relationship)
    relationship_hash_2 = compute_relationship_hash(relationship)

    assert len(relationship_hash_1) == 64
    assert relationship_hash_1 == relationship_hash_2
    assert relationship.metadata_hash
    assert relationship.replay_safe is True
    assert relationship.created_at.endswith("Z")


def test_replay_safe_export_redaction() -> None:
    session = _make_session()
    _seed_full_state(session, inject_forbidden_payload=True)

    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)
    export = snapshot.replay_safe_export

    assert export["snapshot_id"] == snapshot.snapshot_id
    assert export["fingerprint"] == snapshot.fingerprint
    assert export["redaction_profile"] == "replay_safe"
    assert export["replay_instructions"]["replay_safe"] is True
    assert not _contains_forbidden_key(export)
    assert "provider_payload" not in json.dumps(export, sort_keys=True)
    assert "raw_prompt" not in json.dumps(export, sort_keys=True)
    assert "raw_vector" not in json.dumps(export, sort_keys=True)
    assert "authorization" not in json.dumps(export, sort_keys=True)
    assert len(export["entity_summaries"]) == len(snapshot.entities)
    assert len(export["relationship_summaries"]) == len(snapshot.relationships)


def test_forbidden_field_stripping_and_warning_recording() -> None:
    session = _make_session()
    _seed_full_state(session, inject_forbidden_payload=True)

    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    assert any("forbidden sensitive fields" in warning for warning in snapshot.warnings)
    assert all("provider_payload" not in warning for warning in snapshot.warnings)
    assert all("secret" not in warning for warning in snapshot.warnings)
    assert all("never-export" not in warning for warning in snapshot.warnings)
    assert not _contains_forbidden_key(snapshot.replay_safe_export)
    assert "never-export" not in json.dumps(snapshot.replay_safe_export, sort_keys=True)
    assert snapshot.replay_safe_export["warnings"]
    assert snapshot.replay_safe_export["entity_summaries"]
    assert snapshot.replay_safe_export["relationship_summaries"]


def test_baseline_creation() -> None:
    session = _make_session()
    _seed_full_state(session)
    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    baseline = create_comparison_baseline(
        snapshot,
        label="quarterly-baseline",
        created_by="analyst-1",
        purpose="executive comparison",
    )

    assert baseline.tenant_id == TENANT_A
    assert baseline.snapshot_id == snapshot.snapshot_id
    assert baseline.fingerprint == snapshot.fingerprint
    assert baseline.label == "quarterly-baseline"
    assert baseline.created_by == "analyst-1"
    assert baseline.purpose == "executive comparison"
    assert baseline.replay_safe is True
    assert baseline.entity_counts["policy"] >= 1
    assert baseline.relationship_counts["governs"] >= 1
    assert "field_assessment" in baseline.authority_counts
    assert baseline.completeness["score"] == 100
    assert baseline.snapshot_category == snapshot.category
    assert baseline.twin_id == snapshot.twin_identity.twin_id


def test_authority_graph_construction() -> None:
    session = _make_session()
    _seed_full_state(session)
    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    authorities = {
        node.authority: node for node in snapshot.authority_graph.authorities
    }
    dependencies = {
        (edge.authority, edge.downstream_authority, edge.relationship_type)
        for edge in snapshot.authority_graph.dependencies
    }

    assert "field_assessment" in authorities
    assert "control_registry" in authorities
    assert "framework_authority" in authorities
    assert authorities["field_assessment"].available is True
    assert authorities["field_assessment"].confidence_weight >= 80
    assert authorities["field_assessment"].coverage_percent == 100
    assert authorities["field_assessment"].trust_level in {"high", "moderate"}
    assert "assessment" in authorities["field_assessment"].produced_entity_types
    assert "control" in authorities["control_registry"].produced_entity_types
    assert "framework" in authorities["framework_authority"].produced_entity_types
    assert any(
        dep[0] == "control_registry" and dep[1] == "framework_authority"
        for dep in dependencies
    )
    assert any(
        dep[0] == "report_authority" and dep[1] == "field_assessment"
        for dep in dependencies
    )
    assert any(
        dep[0] == "field_assessment" and dep[1] == "evidence_authority"
        for dep in dependencies
    )


def test_link_extraction() -> None:
    session = _make_session()
    _seed_full_state(session)
    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    triplets = _relationship_triplets(snapshot)

    assert ("governs", "policy", "control") in triplets
    assert ("maps_to", "control", "framework") in triplets
    assert ("generated_from", "finding", "evidence") in triplets
    assert ("affects", "finding", "control") in triplets
    assert ("affects", "finding", "remediation") in triplets
    assert ("remediates", "remediation", "finding") in triplets
    assert ("derived_from", "finding", "assessment") in triplets
    assert ("derived_from", "report", "assessment") in triplets
    assert ("generated_from", "report", "evidence") in triplets
    assert ("affects", "decision", "policy") in triplets
    assert ("affects", "decision", "remediation") in triplets
    assert ("depends_on", "workflow", "decision") in triplets
    assert ("affects", "simulation", "control") in triplets
    assert ("affects", "simulation", "finding") in triplets
    assert ("published_to", "report", "customer") in triplets


def test_missing_data_produces_limitations_not_crash() -> None:
    session = _make_session(tables=[FaEngagement.__table__])
    session.add(
        FaEngagement(
            id="eng-only",
            tenant_id=TENANT_A,
            client_name="Sparse Tenant",
            client_domain="sparse.example",
            assessor_id="assessor",
            assessment_type="SOC2",
            status="planned",
            scheduled_date="2026-07-01T00:00:00Z",
            client_access_code=None,
            engagement_metadata={},
            schema_version="1.0",
            created_at="2026-07-01T00:00:00Z",
            updated_at="2026-07-01T00:00:00Z",
        )
    )
    session.commit()

    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    assert snapshot.snapshot_id.startswith("gdts-")
    assert snapshot.tenant_id == TENANT_A
    assert snapshot.entities
    assert snapshot.warnings
    assert snapshot.limitations
    assert any(
        "source unavailable" in limitation for limitation in snapshot.limitations
    )


def test_stable_entity_and_relationship_ordering() -> None:
    session = _make_session()
    _seed_full_state(session)
    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    entity_sort_keys = [
        (entity.type, entity.authority, entity.title, entity.id)
        for entity in snapshot.entities
    ]
    relationship_sort_keys = [
        (
            relationship.type,
            relationship.from_entity_id,
            relationship.to_entity_id,
            relationship.id,
        )
        for relationship in snapshot.relationships
    ]

    assert entity_sort_keys == sorted(entity_sort_keys)
    assert relationship_sort_keys == sorted(relationship_sort_keys)
    assert len(entity_sort_keys) == len(set(entity.id for entity in snapshot.entities))
    assert len(relationship_sort_keys) == len(
        set(relationship.id for relationship in snapshot.relationships)
    )
    assert all(entity.created_at.endswith("Z") for entity in snapshot.entities)
    assert all(entity.updated_at.endswith("Z") for entity in snapshot.entities)
    assert all(
        relationship.created_at.endswith("Z") for relationship in snapshot.relationships
    )


def test_unsupported_redaction_profile_fails_closed() -> None:
    session = _make_session()
    _seed_full_state(session)

    with pytest.raises(GovernanceDigitalTwinBuildError):
        build_governance_digital_twin_snapshot(
            session,
            TENANT_A,
            redaction_profile="unsafe_raw",
        )


def test_baseline_reference_is_captured_when_requested() -> None:
    session = _make_session()
    _seed_full_state(session)

    snapshot = build_governance_digital_twin_snapshot(
        session,
        TENANT_A,
        baseline_ref="baseline-2026-q2",
    )

    assert len(snapshot.baselines) == 1
    assert snapshot.baselines[0].baseline_id == "baseline-2026-q2"
    assert snapshot.baselines[0].available is False
    assert any(
        "Baseline lookup storage is deferred" in limitation
        for limitation in snapshot.limitations
    )


def test_snapshot_lineage_manifest_and_internal_contract() -> None:
    session = _make_session()
    _seed_full_state(session)
    service = GovernanceDigitalTwinService()

    snapshot = service.build(
        session,
        TENANT_A,
        parent_snapshot_id="gdts-parent-001",
        previous_fingerprint="a" * 64,
        generation=4,
        lineage_id="lineage-001",
        snapshot_category="audit",
        created_by="architect-1",
        twin_id="twin-001",
        memory_reference="memory-001",
        memory_sequence=9,
        timeline_anchor="timeline-001",
    )

    assert snapshot.parent_snapshot_id == "gdts-parent-001"
    assert snapshot.previous_fingerprint == "a" * 64
    assert snapshot.generation == 4
    assert snapshot.lineage_id == "lineage-001"
    assert snapshot.category == "audit"
    assert snapshot.twin_identity.twin_id == "twin-001"
    assert snapshot.twin_identity.created_by == "architect-1"
    assert snapshot.state_extensions.memory_reference == "memory-001"
    assert snapshot.state_extensions.memory_sequence == 9
    assert snapshot.state_extensions.timeline_anchor == "timeline-001"
    assert snapshot.future_references.simulation_overlay is None
    assert snapshot.manifest is not None
    assert snapshot.manifest.snapshot_category == "audit"
    assert snapshot.manifest.lineage_id == "lineage-001"
    assert snapshot.manifest.generation == 4
    assert snapshot.replay_safe_export["manifest"]["lineage_id"] == "lineage-001"
    assert service.fingerprint(snapshot) == snapshot.fingerprint
    assert service.validate(snapshot).valid is True
    baseline = service.baseline(
        snapshot, label="audit-baseline", created_by="architect-1", purpose="timeline"
    )
    assert baseline.snapshot_category == "audit"
    assert baseline.twin_id == "twin-001"


def test_snapshot_payloads_are_deeply_immutable() -> None:
    session = _make_session()
    _seed_full_state(session)

    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)
    baseline = create_comparison_baseline(
        snapshot,
        label="immutable-baseline",
        created_by="analyst-1",
        purpose="immutability",
    )

    with pytest.raises(TypeError):
        cast(Any, snapshot.replay_safe_export)["fingerprint"] = "mutated"
    with pytest.raises(TypeError):
        cast(Any, snapshot.replay_safe_export)["replay_instructions"]["generation"] = 99
    with pytest.raises(TypeError):
        cast(Any, snapshot.completeness)["score"] = 0
    with pytest.raises(TypeError):
        cast(Any, baseline.entity_counts)["policy"] = 0


def test_fingerprint_domain_constant_is_pinned() -> None:
    session = _make_session()
    _seed_full_state(session)

    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    assert GOVERNANCE_DIGITAL_TWIN_FINGERPRINT_DOMAIN == "FG_GOVERNANCE_DIGITAL_TWIN_V1"
    assert snapshot.fingerprint == compute_snapshot_fingerprint(snapshot)


def test_validator_severity_model_captures_warning_and_error_states() -> None:
    session = _make_session()
    _seed_full_state(session)
    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    advisory_snapshot = replace(
        snapshot,
        warnings=("deterministic warning",),
        limitations=("deterministic limitation",),
        validation_report=None,
    )
    advisory_report = validate_governance_digital_twin_snapshot(
        advisory_snapshot,
        require_replay_integrity=False,
    )

    assert advisory_report.valid is True
    assert advisory_report.highest_severity == "WARNING"
    assert any(finding.severity == "WARNING" for finding in advisory_report.findings)
    assert any(finding.severity == "INFO" for finding in advisory_report.findings)


def test_canonical_control_id_is_stable_across_row_id_changes() -> None:
    first_session = _make_session(tables=[ControlRegistry.__table__])
    first_session.add(
        ControlRegistry(
            id="ctl-row-1",
            tenant_id=TENANT_A,
            schema_version="1.0",
            control_id="control-external-access",
            title="External Access Review",
            description="Quarterly review of third-party access.",
            control_type="administrative",
            criticality="high",
            owner="secops",
            owner_email="secops@example.com",
            business_unit="Security",
            effectiveness_rating="effective",
            verification_status="verified",
            control_status="active",
            review_frequency_days=90,
            next_review_at="2026-09-30T00:00:00Z",
            last_review_at="2026-07-01T00:00:00Z",
            last_verified_at="2026-07-02T00:00:00Z",
            created_at="2026-07-01T02:00:00Z",
            updated_at="2026-07-02T02:00:00Z",
        )
    )
    first_session.commit()

    second_session = _make_session(tables=[ControlRegistry.__table__])
    second_session.add(
        ControlRegistry(
            id="ctl-row-99",
            tenant_id=TENANT_A,
            schema_version="1.0",
            control_id="control-external-access",
            title="External Access Review",
            description="Quarterly review of third-party access.",
            control_type="administrative",
            criticality="high",
            owner="secops",
            owner_email="secops@example.com",
            business_unit="Security",
            effectiveness_rating="effective",
            verification_status="verified",
            control_status="active",
            review_frequency_days=90,
            next_review_at="2026-09-30T00:00:00Z",
            last_review_at="2026-07-01T00:00:00Z",
            last_verified_at="2026-07-02T00:00:00Z",
            created_at="2026-07-01T02:00:00Z",
            updated_at="2026-07-02T02:00:00Z",
        )
    )
    second_session.commit()

    first_snapshot = build_governance_digital_twin_snapshot(first_session, TENANT_A)
    second_snapshot = build_governance_digital_twin_snapshot(second_session, TENANT_A)

    first_control = _find_entity(first_snapshot, "control", "External Access Review")
    second_control = _find_entity(second_snapshot, "control", "External Access Review")

    assert first_control.id == second_control.id
    assert first_control.canonical_entity_id == second_control.canonical_entity_id
    assert first_control.source_ref != second_control.source_ref


def test_entity_provenance_and_validator_rejects_orphans() -> None:
    session = _make_session()
    _seed_full_state(session)
    snapshot = build_governance_digital_twin_snapshot(session, TENANT_A)

    policy = _find_entity(snapshot, "policy", "Vendor Access Governance")
    assert policy.canonical_entity_id == policy.id
    assert policy.provenance.origin_authority == "governance_orchestration"
    assert policy.provenance.source_table == "fa_gov_orch_policy"
    assert policy.provenance.capture_method == "orm_select"
    assert policy.provenance.deterministic_extractor.endswith("policy_entity_v1")
    assert policy.confidence_provenance.authority == "governance_orchestration"
    assert policy.confidence_provenance.coverage_percent == 100

    broken_relationship = replace(
        snapshot.relationships[0], to_entity_id="missing-entity"
    )
    broken_snapshot = replace(
        snapshot,
        relationships=(broken_relationship,) + snapshot.relationships[1:],
        replay_safe_export={},
        validation_report=None,
    )
    report = validate_governance_digital_twin_snapshot(
        broken_snapshot,
        require_replay_integrity=False,
    )

    assert report.valid is False
    assert any("orphan_relationship:" in violation for violation in report.violations)
    assert any("tenant_isolation" not in violation for violation in report.violations)
