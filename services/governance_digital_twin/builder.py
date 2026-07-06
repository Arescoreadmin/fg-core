"""Deterministic Governance Digital Twin snapshot builder."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

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
from services.governance_digital_twin.exporter import export_replay_safe_snapshot
from services.governance_digital_twin.fingerprint import (
    compute_metadata_hash,
    compute_snapshot_fingerprint,
)
from services.governance_digital_twin.immutability import deep_freeze
from services.governance_digital_twin.manifest import build_snapshot_manifest
from services.governance_digital_twin.models import (
    GOVERNANCE_DIGITAL_TWIN_BUILDER_VERSION,
    GOVERNANCE_DIGITAL_TWIN_EPOCH,
    GOVERNANCE_DIGITAL_TWIN_GOVERNANCE_MODEL_VERSION,
    GOVERNANCE_DIGITAL_TWIN_GRAPH_SCHEMA_VERSION,
    GOVERNANCE_DIGITAL_TWIN_SNAPSHOT_VERSION,
    GOVERNANCE_DIGITAL_TWIN_TWIN_VERSION,
    GovernanceDigitalTwinAuthorityEdge,
    GovernanceDigitalTwinAuthorityGraph,
    GovernanceDigitalTwinAuthorityNode,
    GovernanceDigitalTwinBaselineReference,
    GovernanceDigitalTwinConfidenceProvenance,
    GovernanceDigitalTwinEntity,
    GovernanceDigitalTwinEntityProvenance,
    GovernanceDigitalTwinEntityType,
    GovernanceDigitalTwinFutureReferences,
    GovernanceDigitalTwinStateExtensions,
    GovernanceDigitalTwinRelationship,
    GovernanceDigitalTwinRelationshipType,
    GovernanceDigitalTwinSnapshot,
    GovernanceDigitalTwinSnapshotCategory,
    GovernanceDigitalTwinSourceAuthority,
    GovernanceDigitalTwinTwinIdentity,
)
from services.governance_digital_twin.redaction import FORBIDDEN_FIELD_KEYS
from services.governance_digital_twin.relationship_registry import (
    RELATIONSHIP_REGISTRY,
)
from services.governance_digital_twin.validator import (
    validate_governance_digital_twin_snapshot,
)


class GovernanceDigitalTwinBuildError(RuntimeError):
    """Raised when the Governance Digital Twin snapshot cannot be built safely."""


_REDUCTION_PROFILE_REPLAY_SAFE = "replay_safe"
_ID_KEY_RE = re.compile(r"^[a-z0-9_]+(?:_id|_ids|_ref|_refs)$")


class _AuthorityDefinition:
    def __init__(
        self,
        *,
        ownership: str,
        source_tables: tuple[str, ...],
        source_routes: tuple[str, ...],
        capabilities: tuple[str, ...],
    ) -> None:
        self.ownership = ownership
        self.source_tables = source_tables
        self.source_routes = source_routes
        self.capabilities = capabilities


_AUTHORITY_DEFINITIONS: dict[str, _AuthorityDefinition] = {
    "governance_orchestration": _AuthorityDefinition(
        ownership="control_plane",
        source_tables=(
            "fa_gov_orch_policy",
            "fa_gov_orch_workflow",
            "fa_gov_orch_simulation",
        ),
        source_routes=("/governance-orchestration",),
        capabilities=("policy_authoring", "workflow_coordination", "impact_simulation"),
    ),
    "control_registry": _AuthorityDefinition(
        ownership="control_plane",
        source_tables=("control_registry",),
        source_routes=("/control-registry",),
        capabilities=("control_registry", "control_ownership"),
    ),
    "evidence_authority": _AuthorityDefinition(
        ownership="control_plane",
        source_tables=(
            "fa_evidence",
            "fa_evidence_control_links",
            "fa_evidence_risk_links",
        ),
        source_routes=("/evidence",),
        capabilities=("canonical_evidence", "verification_state"),
    ),
    "field_assessment": _AuthorityDefinition(
        ownership="assessment_plane",
        source_tables=(
            "fa_engagements",
            "fa_normalized_findings",
            "fa_evidence_report_links",
        ),
        source_routes=("/field-assessment",),
        capabilities=("assessment_state", "finding_normalization"),
    ),
    "remediation": _AuthorityDefinition(
        ownership="control_plane",
        source_tables=("remediation_tasks",),
        source_routes=("/remediation/tasks",),
        capabilities=("remediation_tracking",),
    ),
    "report_authority": _AuthorityDefinition(
        ownership="delivery_plane",
        source_tables=("fa_report",),
        source_routes=("/report-authority",),
        capabilities=("canonical_reporting",),
    ),
    "governance_decision": _AuthorityDefinition(
        ownership="control_plane",
        source_tables=("fa_governance_decisions",),
        source_routes=("/governance-decisions",),
        capabilities=("immutable_decision_ledger",),
    ),
    "framework_authority": _AuthorityDefinition(
        ownership="control_plane",
        source_tables=("fa_frameworks", "control_framework_mappings"),
        source_routes=("/framework",),
        capabilities=("framework_mapping",),
    ),
    "governance_workflows": _AuthorityDefinition(
        ownership="assessment_plane",
        source_tables=("governance_workflows",),
        source_routes=("/governance-workflows",),
        capabilities=("workflow_execution",),
    ),
    "readiness_simulation": _AuthorityDefinition(
        ownership="analysis_plane",
        source_tables=("readiness_simulation_runs",),
        source_routes=("/readiness-simulation",),
        capabilities=("deterministic_simulation_record",),
    ),
    "portal_grant": _AuthorityDefinition(
        ownership="delivery_plane",
        source_tables=("portal_grants",),
        source_routes=("/portal",),
        capabilities=("customer_delivery",),
    ),
}


_ENTITY_SOURCE_TABLES: dict[tuple[str, str], str] = {
    ("governance_orchestration", "policy"): "fa_gov_orch_policy",
    ("governance_orchestration", "workflow"): "fa_gov_orch_workflow",
    ("governance_orchestration", "simulation"): "fa_gov_orch_simulation",
    ("control_registry", "control"): "control_registry",
    ("evidence_authority", "evidence"): "fa_evidence",
    ("field_assessment", "assessment"): "fa_engagements",
    ("field_assessment", "finding"): "fa_normalized_findings",
    ("field_assessment", "customer"): "fa_engagements",
    ("remediation", "remediation"): "remediation_tasks",
    ("report_authority", "report"): "fa_report",
    ("governance_decision", "decision"): "fa_governance_decisions",
    ("framework_authority", "framework"): "fa_frameworks",
    ("governance_workflows", "workflow"): "governance_workflows",
    ("readiness_simulation", "simulation"): "readiness_simulation_runs",
    ("portal_grant", "customer"): "portal_grants",
    ("field_assessment", "authority"): "__authority_definition__",
    ("evidence_authority", "authority"): "__authority_definition__",
    ("control_registry", "authority"): "__authority_definition__",
    ("governance_orchestration", "authority"): "__authority_definition__",
    ("remediation", "authority"): "__authority_definition__",
    ("report_authority", "authority"): "__authority_definition__",
    ("governance_decision", "authority"): "__authority_definition__",
    ("framework_authority", "authority"): "__authority_definition__",
    ("governance_workflows", "authority"): "__authority_definition__",
    ("readiness_simulation", "authority"): "__authority_definition__",
    ("portal_grant", "authority"): "__authority_definition__",
}


def _canonical_source_ref(authority: str, collection: str, source_id: str) -> str:
    return f"{authority}:{collection}:{source_id}"


def _stable_hash(*parts: str) -> str:
    return compute_metadata_hash({"parts": list(parts)})


def _entity_identifier(
    tenant_id: str,
    entity_type: str,
    authority: str,
    source_ref: str,
) -> str:
    digest = _stable_hash(tenant_id, entity_type, authority, source_ref)
    return f"gdt-{entity_type}-{digest[:24]}"


def _relationship_identifier(
    tenant_id: str,
    relationship_type: str,
    from_entity_id: str,
    to_entity_id: str,
    authority: str,
    evidence_refs: tuple[str, ...],
) -> str:
    digest = _stable_hash(
        tenant_id,
        relationship_type,
        from_entity_id,
        to_entity_id,
        authority,
        ",".join(evidence_refs),
    )
    return f"gdtr-{digest[:24]}"


def _normalize_timestamp(value: Any) -> str:
    if value is None:
        return GOVERNANCE_DIGITAL_TWIN_EPOCH
    if isinstance(value, datetime):
        dt = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        dt = datetime(value.year, value.month, value.day, tzinfo=UTC)
        return dt.isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return GOVERNANCE_DIGITAL_TWIN_EPOCH
        if text.endswith("Z"):
            try:
                datetime.fromisoformat(text.replace("Z", "+00:00"))
                return text
            except ValueError:
                return text
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return text
        dt = dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
        return dt.isoformat().replace("+00:00", "Z")
    return str(value)


def _safe_json_loads(value: Any) -> Any:
    if value is None:
        return {}
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except ValueError:
            return {}
    return {}


def _canonical_identity_ref(
    *,
    entity_type: GovernanceDigitalTwinEntityType,
    authority: str,
    source_ref: str,
    title: str,
    metadata: dict[str, Any],
    canonical_identity_seed: tuple[str, ...] = (),
) -> str:
    normalized_seed = tuple(
        str(part).strip() for part in canonical_identity_seed if str(part).strip()
    )
    if normalized_seed:
        return (
            f"canonical:{entity_type.value}:{authority}:"
            + "|".join(normalized_seed)
        )

    for key in (
        "control_id",
        "evidence_ref",
        "content_hash",
        "findings_hash",
        "remediation_key",
        "report_key",
        "decision_key",
        "workflow_key",
        "simulation_key",
        "framework_key",
        "policy_key",
        "assessment_key",
        "customer_key",
    ):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return f"canonical:{entity_type.value}:{authority}:{value.strip()}"

    normalized_title = title.strip() if isinstance(title, str) else str(title)
    return f"source:{entity_type.value}:{authority}:{source_ref}:{normalized_title}"


def _explicit_id_values(payload: Any, accepted_keys: set[str]) -> tuple[str, ...]:
    collected: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for raw_key, raw_value in node.items():
                key = str(raw_key)
                normalized = key.lower()
                if normalized in accepted_keys or (
                    _ID_KEY_RE.match(normalized) and normalized in accepted_keys
                ):
                    if isinstance(raw_value, str) and raw_value.strip():
                        collected.add(raw_value.strip())
                    elif isinstance(raw_value, list):
                        for item in raw_value:
                            if isinstance(item, str) and item.strip():
                                collected.add(item.strip())
                if isinstance(raw_value, (dict, list)):
                    walk(raw_value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return tuple(sorted(collected))


def _string_list(values: Any) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    normalized = {
        str(value).strip()
        for value in values
        if isinstance(value, (str, int, float)) and str(value).strip()
    }
    return tuple(sorted(normalized))


def _metadata_hash(payload: dict[str, Any]) -> str:
    return compute_metadata_hash(payload)


def _source_table_for(
    authority: str, entity_type: GovernanceDigitalTwinEntityType
) -> str:
    return _ENTITY_SOURCE_TABLES.get((authority, entity_type.value), entity_type.value)


def _confidence_trust_level(confidence: int) -> str:
    if confidence >= 90:
        return "high"
    if confidence >= 70:
        return "moderate"
    if confidence >= 40:
        return "guarded"
    return "low"


def _coverage_percent(metadata: dict[str, Any], fallback_confidence: int) -> int:
    for key in (
        "completeness_score",
        "coverage_percent",
        "coverage_score",
        "verification_score",
    ):
        value = metadata.get(key)
        if isinstance(value, int):
            return max(0, min(100, value))
    return max(0, min(100, fallback_confidence))


def _build_confidence_provenance(
    *,
    authority: str,
    confidence: int,
    freshness_at: str,
    metadata: dict[str, Any],
    trust_level: str | None = None,
    coverage_percent: int | None = None,
    method: str,
) -> GovernanceDigitalTwinConfidenceProvenance:
    normalized_confidence = max(0, min(100, int(confidence)))
    return GovernanceDigitalTwinConfidenceProvenance(
        authority=authority,
        confidence_weight=normalized_confidence,
        coverage_percent=(
            _coverage_percent(metadata, normalized_confidence)
            if coverage_percent is None
            else max(0, min(100, int(coverage_percent)))
        ),
        freshness_at=freshness_at,
        trust_level=trust_level or _confidence_trust_level(normalized_confidence),
        method=method,
    )


def _build_entity(
    *,
    tenant_id: str,
    entity_type: GovernanceDigitalTwinEntityType,
    authority: str,
    source_ref: str,
    title: str,
    status: str,
    created_at: Any,
    updated_at: Any,
    confidence: int,
    metadata: dict[str, Any],
    redaction_state: str = "metadata_hashed",
    source_table: str | None = None,
    source_object: str | None = None,
    capture_method: str = "orm_select",
    deterministic_extractor: str | None = None,
    created_from: tuple[str, ...] = (),
    coverage_percent: int | None = None,
    trust_level: str | None = None,
    tenant_scope: str | None = None,
    canonical_identity_seed: tuple[str, ...] = (),
) -> GovernanceDigitalTwinEntity:
    normalized_created = _normalize_timestamp(created_at)
    normalized_updated = _normalize_timestamp(updated_at)
    normalized_confidence = max(0, min(100, int(confidence)))
    canonical_identity_ref = _canonical_identity_ref(
        entity_type=entity_type,
        authority=authority,
        source_ref=source_ref,
        title=title,
        metadata=metadata,
        canonical_identity_seed=canonical_identity_seed,
    )
    entity_id = _entity_identifier(
        tenant_id, entity_type.value, authority, canonical_identity_ref
    )
    resolved_source_object = source_object or source_ref.rsplit(":", 1)[-1]
    return GovernanceDigitalTwinEntity(
        id=entity_id,
        canonical_entity_id=entity_id,
        type=entity_type.value,
        authority=authority,
        source_ref=source_ref,
        title=title,
        status=status,
        created_at=normalized_created,
        updated_at=normalized_updated,
        confidence=normalized_confidence,
        confidence_provenance=_build_confidence_provenance(
            authority=authority,
            confidence=normalized_confidence,
            freshness_at=normalized_updated,
            metadata=metadata,
            trust_level=trust_level,
            coverage_percent=coverage_percent,
            method="deterministic_authority_record",
        ),
        tenant_scope=tenant_scope or tenant_id,
        replay_safe=True,
        redaction_state=redaction_state,
        metadata_hash=_metadata_hash(metadata),
        provenance=GovernanceDigitalTwinEntityProvenance(
            origin_authority=authority,
            source_table=source_table or _source_table_for(authority, entity_type),
            source_object=resolved_source_object,
            capture_method=capture_method,
            deterministic_extractor=(
                deterministic_extractor
                or f"governance_digital_twin.{entity_type.value}_entity_v1"
            ),
            created_from=tuple(sorted(set(created_from))),
        ),
    )


def _build_relationship(
    *,
    tenant_id: str,
    relationship_type: GovernanceDigitalTwinRelationshipType,
    from_entity_id: str,
    to_entity_id: str,
    authority: str,
    confidence: int,
    evidence_refs: tuple[str, ...],
    created_at: Any,
    metadata: dict[str, Any],
    trust_level: str | None = None,
    coverage_percent: int | None = None,
) -> GovernanceDigitalTwinRelationship:
    normalized_evidence_refs = tuple(sorted(set(evidence_refs)))
    normalized_created = _normalize_timestamp(created_at)
    normalized_confidence = max(0, min(100, int(confidence)))
    relationship_id = _relationship_identifier(
        tenant_id,
        relationship_type.value,
        from_entity_id,
        to_entity_id,
        authority,
        normalized_evidence_refs,
    )
    return GovernanceDigitalTwinRelationship(
        id=relationship_id,
        canonical_relationship_id=relationship_id,
        type=relationship_type.value,
        from_entity_id=from_entity_id,
        to_entity_id=to_entity_id,
        authority=authority,
        confidence=normalized_confidence,
        confidence_provenance=_build_confidence_provenance(
            authority=authority,
            confidence=normalized_confidence,
            freshness_at=normalized_created,
            metadata=metadata,
            trust_level=trust_level,
            coverage_percent=coverage_percent,
            method="deterministic_relationship_record",
        ),
        evidence_refs=normalized_evidence_refs,
        created_at=normalized_created,
        replay_safe=True,
        metadata_hash=_metadata_hash(metadata),
    )


def _sorted_entities(
    entities: list[GovernanceDigitalTwinEntity],
) -> tuple[GovernanceDigitalTwinEntity, ...]:
    return tuple(
        sorted(
            entities,
            key=lambda entity: (
                entity.type,
                entity.authority,
                entity.title,
                entity.id,
            ),
        )
    )


def _sorted_relationships(
    relationships: list[GovernanceDigitalTwinRelationship],
) -> tuple[GovernanceDigitalTwinRelationship, ...]:
    deduped = {relationship.id: relationship for relationship in relationships}
    return tuple(
        sorted(
            deduped.values(),
            key=lambda relationship: (
                relationship.type,
                relationship.from_entity_id,
                relationship.to_entity_id,
                relationship.id,
            ),
        )
    )


def _entity_timestamp(entity: GovernanceDigitalTwinEntity) -> str:
    return max(entity.created_at, entity.updated_at)


def _record_warning(messages: list[str], message: str) -> None:
    if message not in messages:
        messages.append(message)


def _record_limitation(messages: list[str], message: str) -> None:
    if message not in messages:
        messages.append(message)


def _scan_for_forbidden_keys(payload: Any, *, warnings: list[str], origin: str) -> None:
    if isinstance(payload, dict):
        for raw_key, raw_value in payload.items():
            key = str(raw_key).strip().lower()
            if key in FORBIDDEN_FIELD_KEYS:
                _record_warning(
                    warnings,
                    f"{origin} contained forbidden sensitive fields that were excluded from snapshot metadata",
                )
            _scan_for_forbidden_keys(raw_value, warnings=warnings, origin=origin)
    elif isinstance(payload, list):
        for item in payload:
            _scan_for_forbidden_keys(item, warnings=warnings, origin=origin)


def _query_rows(
    db: Session,
    stmt: Any,
    *,
    authority: str,
    availability: dict[str, list[bool]],
    warnings: list[str],
    limitations: list[str],
    required: bool = False,
) -> list[Any]:
    try:
        availability[authority].append(True)
        return list(db.execute(stmt).scalars().all())
    except SQLAlchemyError as exc:
        availability[authority].append(False)
        _record_warning(warnings, f"{authority} unavailable: {exc.__class__.__name__}")
        _record_limitation(
            limitations,
            f"{authority} source unavailable during snapshot build",
        )
        if required:
            raise GovernanceDigitalTwinBuildError(
                f"required authority unavailable: {authority}"
            ) from exc
        return []


def _build_authority_entities(
    tenant_id: str,
    authorities: list[str],
    generated_at: str,
) -> list[GovernanceDigitalTwinEntity]:
    entities: list[GovernanceDigitalTwinEntity] = []
    for authority in sorted(authorities):
        definition = _AUTHORITY_DEFINITIONS[authority]
        source_ref = _canonical_source_ref(authority, "authority", authority)
        entity = _build_entity(
            tenant_id=tenant_id,
            entity_type=GovernanceDigitalTwinEntityType.authority,
            authority=authority,
            source_ref=source_ref,
            title=authority.replace("_", " ").title(),
            status="available",
            created_at=GOVERNANCE_DIGITAL_TWIN_EPOCH,
            updated_at=generated_at,
            confidence=100,
            metadata={
                "capabilities": list(definition.capabilities),
                "source_tables": list(definition.source_tables),
                "source_routes": list(definition.source_routes),
            },
            canonical_identity_seed=(authority,),
        )
        entities.append(entity)
    return entities


def build_governance_digital_twin_snapshot(
    db: Session,
    tenant_id: str,
    *,
    baseline_ref: str | None = None,
    redaction_profile: str = _REDUCTION_PROFILE_REPLAY_SAFE,
    parent_snapshot_id: str | None = None,
    previous_fingerprint: str | None = None,
    generation: int | None = None,
    lineage_id: str | None = None,
    snapshot_category: GovernanceDigitalTwinSnapshotCategory
    | str = GovernanceDigitalTwinSnapshotCategory.operational.value,
    created_by: str = "system:governance_digital_twin_builder",
    twin_id: str | None = None,
    memory_reference: str | None = None,
    memory_sequence: int | None = None,
    timeline_anchor: str | None = None,
) -> GovernanceDigitalTwinSnapshot:
    if not tenant_id or not tenant_id.strip():
        raise GovernanceDigitalTwinBuildError("tenant_id is required")
    if redaction_profile != _REDUCTION_PROFILE_REPLAY_SAFE:
        raise GovernanceDigitalTwinBuildError(
            f"unsupported redaction profile: {redaction_profile!r}"
        )

    warnings: list[str] = []
    limitations: list[str] = []
    authority_availability: dict[str, list[bool]] = defaultdict(list)
    tenant_id = tenant_id.strip()
    normalized_category = (
        snapshot_category.value
        if isinstance(snapshot_category, GovernanceDigitalTwinSnapshotCategory)
        else str(snapshot_category).strip()
    )
    if normalized_category not in {
        category.value for category in GovernanceDigitalTwinSnapshotCategory
    }:
        raise GovernanceDigitalTwinBuildError(
            f"unsupported snapshot category: {snapshot_category!r}"
        )
    normalized_generation = (
        0
        if generation is None and parent_snapshot_id is None
        else (1 if generation is None else int(generation))
    )
    if normalized_generation < 0:
        raise GovernanceDigitalTwinBuildError("generation must be >= 0")
    resolved_lineage_id = (
        lineage_id or f"gdtl-{_stable_hash(tenant_id, 'governance_digital_twin')[:24]}"
    )
    resolved_twin_id = (
        twin_id or f"gdtwin-{_stable_hash(tenant_id, resolved_lineage_id)[:24]}"
    )
    twin_identity = GovernanceDigitalTwinTwinIdentity(
        twin_id=resolved_twin_id,
        twin_version=GOVERNANCE_DIGITAL_TWIN_TWIN_VERSION,
        twin_class="governance_digital_twin",
        tenant_id=tenant_id,
        created_by=created_by,
        governance_model_version=GOVERNANCE_DIGITAL_TWIN_GOVERNANCE_MODEL_VERSION,
    )
    state_extensions = GovernanceDigitalTwinStateExtensions(
        memory_reference=memory_reference,
        memory_sequence=memory_sequence,
        timeline_anchor=timeline_anchor or resolved_lineage_id,
    )
    future_references = GovernanceDigitalTwinFutureReferences(
        simulation_overlay=None,
        prediction_reference=None,
        execution_reference=None,
        learning_reference=None,
        optimization_reference=None,
    )

    policy_rows = _query_rows(
        db,
        select(GovOrchPolicy)
        .where(GovOrchPolicy.tenant_id == tenant_id)
        .order_by(GovOrchPolicy.id.asc()),
        authority="governance_orchestration",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    control_rows = _query_rows(
        db,
        select(ControlRegistry)
        .where(ControlRegistry.tenant_id == tenant_id)
        .order_by(ControlRegistry.id.asc()),
        authority="control_registry",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    evidence_rows = _query_rows(
        db,
        select(FaEvidence)
        .where(FaEvidence.tenant_id == tenant_id)
        .order_by(FaEvidence.id.asc()),
        authority="evidence_authority",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    evidence_control_rows = _query_rows(
        db,
        select(FaEvidenceControlLink)
        .where(FaEvidenceControlLink.tenant_id == tenant_id)
        .order_by(FaEvidenceControlLink.id.asc()),
        authority="evidence_authority",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    evidence_risk_rows = _query_rows(
        db,
        select(FaEvidenceRiskLink)
        .where(FaEvidenceRiskLink.tenant_id == tenant_id)
        .order_by(FaEvidenceRiskLink.id.asc()),
        authority="evidence_authority",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    assessment_rows = _query_rows(
        db,
        select(FaEngagement)
        .where(FaEngagement.tenant_id == tenant_id)
        .order_by(FaEngagement.id.asc()),
        authority="field_assessment",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    finding_rows = _query_rows(
        db,
        select(FaNormalizedFinding)
        .where(FaNormalizedFinding.tenant_id == tenant_id)
        .order_by(FaNormalizedFinding.id.asc()),
        authority="field_assessment",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    evidence_report_rows = _query_rows(
        db,
        select(FaEvidenceReportLink)
        .where(FaEvidenceReportLink.tenant_id == tenant_id)
        .order_by(FaEvidenceReportLink.id.asc()),
        authority="field_assessment",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    remediation_rows = _query_rows(
        db,
        select(RemediationTask)
        .where(RemediationTask.tenant_id == tenant_id)
        .order_by(RemediationTask.id.asc()),
        authority="remediation",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    report_rows = _query_rows(
        db,
        select(FaReport)
        .where(FaReport.tenant_id == tenant_id)
        .order_by(FaReport.id.asc()),
        authority="report_authority",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    decision_rows = _query_rows(
        db,
        select(FaGovernanceDecision)
        .where(FaGovernanceDecision.tenant_id == tenant_id)
        .order_by(FaGovernanceDecision.id.asc()),
        authority="governance_decision",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    workflow_rows = _query_rows(
        db,
        select(GovernanceWorkflow)
        .where(GovernanceWorkflow.tenant_id == tenant_id)
        .order_by(GovernanceWorkflow.id.asc()),
        authority="governance_workflows",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    orch_workflow_rows = _query_rows(
        db,
        select(GovOrchWorkflow)
        .where(GovOrchWorkflow.tenant_id == tenant_id)
        .order_by(GovOrchWorkflow.id.asc()),
        authority="governance_orchestration",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    simulation_rows = _query_rows(
        db,
        select(GovOrchSimulation)
        .where(GovOrchSimulation.tenant_id == tenant_id)
        .order_by(GovOrchSimulation.id.asc()),
        authority="governance_orchestration",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    simulation_run_rows = _query_rows(
        db,
        select(SimulationRunModel)
        .where(SimulationRunModel.tenant_id == tenant_id)
        .order_by(SimulationRunModel.run_id.asc()),
        authority="readiness_simulation",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    framework_mapping_rows = _query_rows(
        db,
        select(ControlFrameworkMappingRecord)
        .where(ControlFrameworkMappingRecord.tenant_id == tenant_id)
        .order_by(ControlFrameworkMappingRecord.id.asc()),
        authority="framework_authority",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )
    portal_rows = _query_rows(
        db,
        select(PortalGrant)
        .where(PortalGrant.tenant_id == tenant_id)
        .order_by(PortalGrant.id.asc()),
        authority="portal_grant",
        availability=authority_availability,
        warnings=warnings,
        limitations=limitations,
    )

    framework_ids = tuple(
        sorted(
            {
                str(row.framework_id)
                for row in framework_mapping_rows
                if row.framework_id
            }
        )
    )
    framework_rows = (
        _query_rows(
            db,
            select(FrameworkAuthorityFrameworkRecord)
            .where(FrameworkAuthorityFrameworkRecord.id.in_(framework_ids))
            .order_by(FrameworkAuthorityFrameworkRecord.id.asc()),
            authority="framework_authority",
            availability=authority_availability,
            warnings=warnings,
            limitations=limitations,
        )
        if framework_ids
        else []
    )

    entities: list[GovernanceDigitalTwinEntity] = []
    entity_by_key: dict[tuple[str, str], GovernanceDigitalTwinEntity] = {}
    customer_by_engagement_id: dict[str, GovernanceDigitalTwinEntity] = {}

    def add_entity(
        entity: GovernanceDigitalTwinEntity, source_key: tuple[str, str]
    ) -> None:
        entity_by_key[source_key] = entity
        entities.append(entity)

    for row in policy_rows:
        payload = _safe_json_loads(row.policy_data)
        _scan_for_forbidden_keys(
            payload,
            warnings=warnings,
            origin=f"governance_orchestration.policy:{row.id}",
        )
        source_ref = _canonical_source_ref("governance_orchestration", "policy", row.id)
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.policy,
                authority="governance_orchestration",
                source_ref=source_ref,
                title=row.name,
                status="active" if bool(row.active) else "inactive",
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=100,
                metadata={
                    "risk_level": row.risk_level,
                    "version": row.version,
                    "policy_keys": sorted(payload.keys())
                    if isinstance(payload, dict)
                    else [],
                    "policy_key": row.name,
                },
                canonical_identity_seed=(str(row.name or ""), str(row.version or "")),
            ),
            ("policy", row.id),
        )

    for row in control_rows:
        source_ref = _canonical_source_ref("control_registry", "control", row.id)
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.control,
                authority="control_registry",
                source_ref=source_ref,
                title=row.title,
                status=row.control_status,
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=100,
                metadata={
                    "control_id": row.control_id,
                    "control_type": row.control_type,
                    "criticality": row.criticality,
                    "verification_status": row.verification_status,
                    "effectiveness_rating": row.effectiveness_rating,
                },
                canonical_identity_seed=(str(row.control_id or ""),),
            ),
            ("control", row.id),
        )

    for row in evidence_rows:
        source_ref = _canonical_source_ref("evidence_authority", "evidence", row.id)
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.evidence,
                authority="evidence_authority",
                source_ref=source_ref,
                title=row.title,
                status=row.lifecycle_state,
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=row.trust_score or 0,
                metadata={
                    "evidence_ref": row.evidence_ref,
                    "trust_state": row.trust_state,
                    "classification": row.classification,
                    "engagement_id": row.engagement_id,
                    "source_type": row.source_type,
                    "source_system": row.source_system,
                    "content_hash": row.content_hash,
                },
                canonical_identity_seed=(
                    str(row.evidence_ref or ""),
                    str(row.content_hash or ""),
                ),
            ),
            ("evidence", row.id),
        )

    for row in assessment_rows:
        source_ref = _canonical_source_ref("field_assessment", "assessment", row.id)
        assessment_entity = _build_entity(
            tenant_id=tenant_id,
            entity_type=GovernanceDigitalTwinEntityType.assessment,
            authority="field_assessment",
            source_ref=source_ref,
            title=f"{row.client_name} {row.assessment_type}",
            status=row.status,
            created_at=row.created_at,
            updated_at=row.updated_at,
            confidence=100,
            metadata={
                "assessment_type": row.assessment_type,
                "assessor_id": row.assessor_id,
                "client_domain": row.client_domain,
                "scheduled_date": row.scheduled_date,
                "assessment_key": (
                    f"{row.client_name}:{row.assessment_type}:"
                    f"{row.client_domain or ''}:{row.scheduled_date or ''}"
                ),
            },
            canonical_identity_seed=(
                str(row.client_name or ""),
                str(row.assessment_type or ""),
                str(row.client_domain or ""),
                str(row.scheduled_date or ""),
            ),
        )
        add_entity(assessment_entity, ("assessment", row.id))

        customer_source_ref = _canonical_source_ref(
            "field_assessment",
            "customer",
            f"{row.client_name}:{row.client_domain or ''}",
        )
        customer_entity = entity_by_key.get(("customer", customer_source_ref))
        if customer_entity is None:
            customer_entity = _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.customer,
                authority="field_assessment",
                source_ref=customer_source_ref,
                title=row.client_name,
                status="active",
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=100,
                metadata={
                    "client_domain": row.client_domain or "",
                    "customer_key": f"{row.client_name}:{row.client_domain or ''}",
                },
                canonical_identity_seed=(
                    str(row.client_name or ""),
                    str(row.client_domain or ""),
                ),
            )
            add_entity(customer_entity, ("customer", customer_source_ref))
        customer_by_engagement_id[row.id] = customer_entity

    for row in finding_rows:
        source_ref = _canonical_source_ref("field_assessment", "finding", row.id)
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.finding,
                authority="field_assessment",
                source_ref=source_ref,
                title=row.title,
                status=row.status,
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=row.confidence_score,
                metadata={
                    "finding_type": row.finding_type,
                    "severity": row.severity,
                    "engagement_id": row.engagement_id,
                    "framework_mappings": _string_list(row.framework_mappings),
                    "evidence_ref_ids": _string_list(row.evidence_ref_ids),
                    "findings_hash": row.findings_hash,
                },
                canonical_identity_seed=(
                    str(row.findings_hash or ""),
                    str(row.engagement_id or ""),
                    str(row.title or ""),
                ),
            ),
            ("finding", row.id),
        )

    for row in remediation_rows:
        _scan_for_forbidden_keys(
            row.task_metadata,
            warnings=warnings,
            origin=f"remediation.task:{row.id}",
        )
        source_ref = _canonical_source_ref("remediation", "task", row.id)
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.remediation,
                authority="remediation",
                source_ref=source_ref,
                title=row.title,
                status=row.status,
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=100,
                metadata={
                    "finding_id": row.finding_id,
                    "assessment_id": row.assessment_id,
                    "priority": row.priority,
                    "assigned_to": row.assigned_to,
                    "remediation_key": f"{row.finding_id}:{row.title}",
                },
                canonical_identity_seed=(
                    str(row.finding_id or ""),
                    str(row.assessment_id or ""),
                    str(row.title or ""),
                ),
            ),
            ("remediation", row.id),
        )

    for row in report_rows:
        source_ref = _canonical_source_ref("report_authority", "report", row.id)
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.report,
                authority="report_authority",
                source_ref=source_ref,
                title=row.title,
                status=row.lifecycle_state,
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=int(round((row.confidence_score or 0.0) * 100)),
                metadata={
                    "assessment_id": row.assessment_id,
                    "report_type": row.report_type,
                    "report_ref": row.report_ref,
                    "quality_grade": row.quality_grade,
                    "report_version": row.report_version,
                    "report_key": row.report_ref or f"{row.assessment_id}:{row.report_version}",
                },
                canonical_identity_seed=(
                    str(row.report_ref or ""),
                    str(row.assessment_id or ""),
                    str(row.report_version or ""),
                ),
            ),
            ("report", row.id),
        )

    for row in decision_rows:
        _scan_for_forbidden_keys(
            _safe_json_loads(row.decision_metadata),
            warnings=warnings,
            origin=f"governance_decision:{row.id}",
        )
        source_ref = _canonical_source_ref("governance_decision", "decision", row.id)
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.decision,
                authority="governance_decision",
                source_ref=source_ref,
                title=f"{row.decision_type}:{row.entity_type}:{row.entity_id}",
                status=row.status,
                created_at=row.decision_at,
                updated_at=row.decision_at,
                confidence=100,
                metadata={
                    "entity_type": row.entity_type,
                    "entity_id": row.entity_id,
                    "engagement_id": row.engagement_id,
                    "actor_id": row.actor_id,
                    "transaction_id": row.transaction_id,
                    "decision_key": row.transaction_id
                    or f"{row.decision_type}:{row.entity_type}:{row.entity_id}:{row.decision_at}",
                },
                canonical_identity_seed=(
                    str(row.transaction_id or ""),
                    str(row.entity_type or ""),
                    str(row.entity_id or ""),
                    str(row.decision_at or ""),
                ),
            ),
            ("decision", row.id),
        )

    for row in workflow_rows:
        _scan_for_forbidden_keys(
            row.metadata_,
            warnings=warnings,
            origin=f"governance_workflows:{row.id}",
        )
        source_ref = _canonical_source_ref("governance_workflows", "workflow", row.id)
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.workflow,
                authority="governance_workflows",
                source_ref=source_ref,
                title=row.title,
                status=row.state,
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=100,
                metadata={
                    "template_name": row.template_name,
                    "context_ref_type": row.context_ref_type,
                    "context_ref_id": row.context_ref_id,
                    "workflow_key": f"{row.template_name}:{row.context_ref_type}:{row.context_ref_id}",
                    "finding_id": row.finding_id,
                },
                canonical_identity_seed=(
                    str(row.template_name or ""),
                    str(row.context_ref_type or ""),
                    str(row.context_ref_id or ""),
                    str(row.finding_id or ""),
                ),
            ),
            ("workflow", row.id),
        )

    for row in orch_workflow_rows:
        context = _safe_json_loads(row.context)
        _scan_for_forbidden_keys(
            context,
            warnings=warnings,
            origin=f"governance_orchestration.workflow:{row.id}",
        )
        source_ref = _canonical_source_ref(
            "governance_orchestration",
            "workflow",
            row.id,
        )
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.workflow,
                authority="governance_orchestration",
                source_ref=source_ref,
                title=row.name,
                status=row.workflow_state,
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=100,
                metadata={
                    "playbook_id": row.playbook_id,
                    "trigger_id": row.trigger_id,
                    "context_keys": sorted(context.keys())
                    if isinstance(context, dict)
                    else [],
                    "workflow_key": row.name,
                },
                canonical_identity_seed=(
                    str(row.name or ""),
                    str(context.get("decision_id") if isinstance(context, dict) else ""),
                    str(row.playbook_id or ""),
                    str(row.trigger_id or ""),
                ),
            ),
            ("workflow", f"orch:{row.id}"),
        )

    for row in simulation_rows:
        change_data = _safe_json_loads(row.change_data)
        result = _safe_json_loads(row.result)
        _scan_for_forbidden_keys(
            change_data,
            warnings=warnings,
            origin=f"governance_orchestration.simulation:{row.id}:change_data",
        )
        _scan_for_forbidden_keys(
            result,
            warnings=warnings,
            origin=f"governance_orchestration.simulation:{row.id}:result",
        )
        source_ref = _canonical_source_ref(
            "governance_orchestration",
            "simulation",
            row.id,
        )
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.simulation,
                authority="governance_orchestration",
                source_ref=source_ref,
                title=row.name,
                status=row.simulation_state,
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=100,
                metadata={
                    "change_type": row.change_type,
                    "change_keys": sorted(change_data.keys())
                    if isinstance(change_data, dict)
                    else [],
                    "result_keys": sorted(result.keys())
                    if isinstance(result, dict)
                    else [],
                    "simulation_key": f"{row.name}:{row.change_type}",
                },
                canonical_identity_seed=(
                    str(row.name or ""),
                    str(row.change_type or ""),
                ),
            ),
            ("simulation", row.id),
        )

    for row in simulation_run_rows:
        projection = _safe_json_loads(row.projection_json)
        _scan_for_forbidden_keys(
            projection,
            warnings=warnings,
            origin=f"readiness_simulation:{row.run_id}",
        )
        source_ref = _canonical_source_ref(
            "readiness_simulation", "simulation", row.run_id
        )
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.simulation,
                authority="readiness_simulation",
                source_ref=source_ref,
                title=row.scenario_type,
                status="complete" if row.completed else "failed",
                created_at=row.created_at,
                updated_at=row.simulated_at_iso,
                confidence=100,
                metadata={
                    "assessment_id": row.assessment_id,
                    "framework_id": row.framework_id,
                    "snapshot_id": row.snapshot_id,
                    "scenario_type": row.scenario_type,
                    "simulation_key": f"{row.snapshot_id}:{row.scenario_type}",
                },
                canonical_identity_seed=(
                    str(row.snapshot_id or ""),
                    str(row.scenario_type or ""),
                    str(row.assessment_id or ""),
                ),
            ),
            ("simulation", f"run:{row.run_id}"),
        )

    for row in framework_rows:
        source_ref = _canonical_source_ref("framework_authority", "framework", row.id)
        tenant_scope = tenant_id if row.tenant_id is None else str(row.tenant_id)
        add_entity(
            _build_entity(
                tenant_id=tenant_id,
                entity_type=GovernanceDigitalTwinEntityType.framework,
                authority="framework_authority",
                source_ref=source_ref,
                title=row.name,
                status=row.status,
                created_at=row.created_at,
                updated_at=row.updated_at,
                confidence=100,
                tenant_scope=tenant_scope,
                metadata={
                    "framework_key": row.framework_key,
                    "version": row.version,
                    "category": row.category,
                    "publisher": row.publisher,
                    "scope_type": row.scope_type,
                },
                canonical_identity_seed=(
                    str(row.framework_key or ""),
                    str(row.version or ""),
                ),
            ),
            ("framework", row.id),
        )

    relationships: list[GovernanceDigitalTwinRelationship] = []
    evidence_links_by_evidence = defaultdict(list)
    for row in evidence_control_rows:
        evidence_links_by_evidence[row.evidence_id].append(row.control_id)
    risk_links_by_evidence = defaultdict(list)
    for row in evidence_risk_rows:
        risk_links_by_evidence[row.evidence_id].append(
            (row.link_type, row.linked_resource_id)
        )

    for row in assessment_rows:
        assessment_link_entity = entity_by_key.get(("assessment", row.id))
        customer_entity = customer_by_engagement_id.get(row.id)
        if assessment_link_entity and customer_entity:
            relationships.append(
                _build_relationship(
                    tenant_id=tenant_id,
                    relationship_type=GovernanceDigitalTwinRelationshipType.owned_by,
                    from_entity_id=assessment_link_entity.id,
                    to_entity_id=customer_entity.id,
                    authority="field_assessment",
                    confidence=100,
                    evidence_refs=(),
                    created_at=row.created_at,
                    metadata={"engagement_id": row.id},
                )
            )

    explicit_policy_control_links = 0
    for row in policy_rows:
        policy_entity = entity_by_key.get(("policy", row.id))
        payload = _safe_json_loads(row.policy_data)
        control_ids = _explicit_id_values(
            payload,
            {
                "control_id",
                "control_ids",
                "related_control_ids",
                "affected_control_ids",
            },
        )
        for control_id in control_ids:
            control_entity = entity_by_key.get(("control", control_id))
            if policy_entity and control_entity:
                explicit_policy_control_links += 1
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.governs,
                        from_entity_id=policy_entity.id,
                        to_entity_id=control_entity.id,
                        authority="governance_orchestration",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.updated_at,
                        metadata={"policy_id": row.id, "control_id": control_id},
                    )
                )
    if policy_rows and explicit_policy_control_links == 0:
        _record_limitation(
            limitations,
            "No explicit policy-to-control references were present in governance policy_data",
        )

    for row in framework_mapping_rows:
        control_entity = entity_by_key.get(("control", str(row.control_id)))
        framework_entity = entity_by_key.get(("framework", str(row.framework_id)))
        if control_entity and framework_entity:
            relationships.append(
                _build_relationship(
                    tenant_id=tenant_id,
                    relationship_type=GovernanceDigitalTwinRelationshipType.maps_to,
                    from_entity_id=control_entity.id,
                    to_entity_id=framework_entity.id,
                    authority="framework_authority",
                    confidence=int(row.confidence),
                    evidence_refs=(),
                    created_at=row.created_at,
                    metadata={
                        "mapping_type": row.mapping_type,
                        "coverage_level": row.coverage_level,
                        "status": row.status,
                    },
                )
            )

    for row in finding_rows:
        finding_entity = entity_by_key.get(("finding", row.id))
        assessment_link_entity = entity_by_key.get(("assessment", row.engagement_id))
        evidence_ids = _string_list(row.evidence_ref_ids)
        if finding_entity and assessment_link_entity:
            relationships.append(
                _build_relationship(
                    tenant_id=tenant_id,
                    relationship_type=GovernanceDigitalTwinRelationshipType.derived_from,
                    from_entity_id=finding_entity.id,
                    to_entity_id=assessment_link_entity.id,
                    authority="field_assessment",
                    confidence=row.confidence_score,
                    evidence_refs=evidence_ids,
                    created_at=row.created_at,
                    metadata={"engagement_id": row.engagement_id},
                )
            )
        for evidence_id in evidence_ids:
            evidence_entity = entity_by_key.get(("evidence", evidence_id))
            if finding_entity and evidence_entity:
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.generated_from,
                        from_entity_id=finding_entity.id,
                        to_entity_id=evidence_entity.id,
                        authority="field_assessment",
                        confidence=row.confidence_score,
                        evidence_refs=(evidence_id,),
                        created_at=row.created_at,
                        metadata={"evidence_id": evidence_id},
                    )
                )
            for control_id in sorted(
                set(evidence_links_by_evidence.get(evidence_id, []))
            ):
                control_entity = entity_by_key.get(("control", control_id))
                if finding_entity and control_entity:
                    relationships.append(
                        _build_relationship(
                            tenant_id=tenant_id,
                            relationship_type=GovernanceDigitalTwinRelationshipType.affects,
                            from_entity_id=finding_entity.id,
                            to_entity_id=control_entity.id,
                            authority="evidence_authority",
                            confidence=row.confidence_score,
                            evidence_refs=(evidence_id,),
                            created_at=row.updated_at,
                            metadata={
                                "finding_id": row.id,
                                "control_id": control_id,
                                "via_evidence_id": evidence_id,
                            },
                        )
                    )

    for row in remediation_rows:
        remediation_entity = entity_by_key.get(("remediation", row.id))
        finding_entity = entity_by_key.get(("finding", row.finding_id))
        if remediation_entity and finding_entity:
            relationships.append(
                _build_relationship(
                    tenant_id=tenant_id,
                    relationship_type=GovernanceDigitalTwinRelationshipType.affects,
                    from_entity_id=finding_entity.id,
                    to_entity_id=remediation_entity.id,
                    authority="remediation",
                    confidence=100,
                    evidence_refs=(),
                    created_at=row.created_at,
                    metadata={"finding_id": row.finding_id, "task_id": row.id},
                )
            )
            relationships.append(
                _build_relationship(
                    tenant_id=tenant_id,
                    relationship_type=GovernanceDigitalTwinRelationshipType.remediates,
                    from_entity_id=remediation_entity.id,
                    to_entity_id=finding_entity.id,
                    authority="remediation",
                    confidence=100,
                    evidence_refs=(),
                    created_at=row.created_at,
                    metadata={"finding_id": row.finding_id, "task_id": row.id},
                )
            )

    for row in report_rows:
        report_entity = entity_by_key.get(("report", row.id))
        if row.assessment_id:
            assessment_link_entity = entity_by_key.get(
                ("assessment", row.assessment_id)
            )
            if report_entity and assessment_link_entity:
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.derived_from,
                        from_entity_id=report_entity.id,
                        to_entity_id=assessment_link_entity.id,
                        authority="report_authority",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.created_at,
                        metadata={"assessment_id": row.assessment_id},
                    )
                )
            customer_entity = customer_by_engagement_id.get(row.assessment_id)
            if report_entity and customer_entity:
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.published_to,
                        from_entity_id=report_entity.id,
                        to_entity_id=customer_entity.id,
                        authority="report_authority",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.published_at or row.created_at,
                        metadata={"assessment_id": row.assessment_id},
                    )
                )

    for row in evidence_report_rows:
        report_entity = entity_by_key.get(("report", row.report_id))
        evidence_entity = entity_by_key.get(("evidence", row.evidence_id))
        if report_entity and evidence_entity:
            relationships.append(
                _build_relationship(
                    tenant_id=tenant_id,
                    relationship_type=GovernanceDigitalTwinRelationshipType.generated_from,
                    from_entity_id=report_entity.id,
                    to_entity_id=evidence_entity.id,
                    authority="field_assessment",
                    confidence=100,
                    evidence_refs=(row.evidence_id,),
                    created_at=row.linked_at,
                    metadata={
                        "report_id": row.report_id,
                        "evidence_id": row.evidence_id,
                    },
                )
            )

    for row in decision_rows:
        decision_entity = entity_by_key.get(("decision", row.id))
        decision_metadata = _safe_json_loads(row.decision_metadata)
        if row.entity_type == "policy":
            policy_entity = entity_by_key.get(("policy", row.entity_id))
            if decision_entity and policy_entity:
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.affects,
                        from_entity_id=decision_entity.id,
                        to_entity_id=policy_entity.id,
                        authority="governance_decision",
                        confidence=100,
                        evidence_refs=_string_list(_safe_json_loads(row.evidence_refs)),
                        created_at=row.decision_at,
                        metadata={
                            "entity_type": row.entity_type,
                            "entity_id": row.entity_id,
                        },
                    )
                )
        if row.entity_type in {"remediation", "remediation_task"}:
            remediation_entity = entity_by_key.get(("remediation", row.entity_id))
            if decision_entity and remediation_entity:
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.affects,
                        from_entity_id=decision_entity.id,
                        to_entity_id=remediation_entity.id,
                        authority="governance_decision",
                        confidence=100,
                        evidence_refs=_string_list(_safe_json_loads(row.evidence_refs)),
                        created_at=row.decision_at,
                        metadata={
                            "entity_type": row.entity_type,
                            "entity_id": row.entity_id,
                        },
                    )
                )
        explicit_remediations = _explicit_id_values(
            decision_metadata,
            {
                "remediation_id",
                "remediation_ids",
                "remediation_task_id",
                "remediation_task_ids",
            },
        )
        for remediation_id in explicit_remediations:
            remediation_entity = entity_by_key.get(("remediation", remediation_id))
            if decision_entity and remediation_entity:
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.affects,
                        from_entity_id=decision_entity.id,
                        to_entity_id=remediation_entity.id,
                        authority="governance_decision",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.decision_at,
                        metadata={"remediation_id": remediation_id},
                    )
                )

    for row in workflow_rows:
        workflow_entity = entity_by_key.get(("workflow", row.id))
        if row.context_ref_type.lower().startswith("decision"):
            decision_entity = entity_by_key.get(("decision", row.context_ref_id))
            if workflow_entity and decision_entity:
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.depends_on,
                        from_entity_id=workflow_entity.id,
                        to_entity_id=decision_entity.id,
                        authority="governance_workflows",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.created_at,
                        metadata={"context_ref_type": row.context_ref_type},
                    )
                )
        if row.finding_id:
            finding_entity = entity_by_key.get(("finding", row.finding_id))
            if workflow_entity and finding_entity:
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.depends_on,
                        from_entity_id=workflow_entity.id,
                        to_entity_id=finding_entity.id,
                        authority="governance_workflows",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.created_at,
                        metadata={"finding_id": row.finding_id},
                    )
                )

    for row in orch_workflow_rows:
        workflow_entity = entity_by_key.get(("workflow", f"orch:{row.id}"))
        context = _safe_json_loads(row.context)
        decision_ids = _explicit_id_values(context, {"decision_id", "decision_ids"})
        for decision_id in decision_ids:
            decision_entity = entity_by_key.get(("decision", decision_id))
            if workflow_entity and decision_entity:
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.depends_on,
                        from_entity_id=workflow_entity.id,
                        to_entity_id=decision_entity.id,
                        authority="governance_orchestration",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.created_at,
                        metadata={"decision_id": decision_id},
                    )
                )

    simulation_links = 0
    for row in simulation_rows:
        simulation_entity = entity_by_key.get(("simulation", row.id))
        payload = {
            "change_data": _safe_json_loads(row.change_data),
            "result": _safe_json_loads(row.result),
        }
        policy_ids = _explicit_id_values(payload, {"policy_id", "policy_ids"})
        control_ids = _explicit_id_values(
            payload,
            {"control_id", "control_ids", "affected_control_ids"},
        )
        finding_ids = _explicit_id_values(payload, {"finding_id", "finding_ids"})
        for policy_id in policy_ids:
            policy_entity = entity_by_key.get(("policy", policy_id))
            if simulation_entity and policy_entity:
                simulation_links += 1
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.affects,
                        from_entity_id=simulation_entity.id,
                        to_entity_id=policy_entity.id,
                        authority="governance_orchestration",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.updated_at,
                        metadata={"policy_id": policy_id},
                    )
                )
        for control_id in control_ids:
            control_entity = entity_by_key.get(("control", control_id))
            if simulation_entity and control_entity:
                simulation_links += 1
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.affects,
                        from_entity_id=simulation_entity.id,
                        to_entity_id=control_entity.id,
                        authority="governance_orchestration",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.updated_at,
                        metadata={"control_id": control_id},
                    )
                )
        for finding_id in finding_ids:
            finding_entity = entity_by_key.get(("finding", finding_id))
            if simulation_entity and finding_entity:
                simulation_links += 1
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.affects,
                        from_entity_id=simulation_entity.id,
                        to_entity_id=finding_entity.id,
                        authority="governance_orchestration",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.updated_at,
                        metadata={"finding_id": finding_id},
                    )
                )

    for row in simulation_run_rows:
        simulation_entity = entity_by_key.get(("simulation", f"run:{row.run_id}"))
        projection = _safe_json_loads(row.projection_json)
        control_ids = _explicit_id_values(
            projection,
            {"control_id", "control_ids", "affected_control_ids"},
        )
        for control_id in control_ids:
            control_entity = entity_by_key.get(("control", control_id))
            if simulation_entity and control_entity:
                simulation_links += 1
                relationships.append(
                    _build_relationship(
                        tenant_id=tenant_id,
                        relationship_type=GovernanceDigitalTwinRelationshipType.affects,
                        from_entity_id=simulation_entity.id,
                        to_entity_id=control_entity.id,
                        authority="readiness_simulation",
                        confidence=100,
                        evidence_refs=(),
                        created_at=row.simulated_at_iso,
                        metadata={"control_id": control_id},
                    )
                )
    if (simulation_rows or simulation_run_rows) and simulation_links == 0:
        _record_limitation(
            limitations,
            "Simulation records lacked explicit policy/control/finding references",
        )

    baselines: tuple[GovernanceDigitalTwinBaselineReference, ...]
    if baseline_ref:
        baselines = (
            GovernanceDigitalTwinBaselineReference(
                baseline_id=baseline_ref,
                label="requested-baseline",
                fingerprint=None,
                purpose="comparison_preparation",
                available=False,
            ),
        )
        _record_limitation(
            limitations,
            "Baseline lookup storage is deferred in PR 18.8.1; only baseline references are captured",
        )
    else:
        baselines = ()

    if portal_rows:
        _record_limitation(
            limitations,
            "Portal grant records are authority inputs only; no standalone portal entity type is exported in 18.8.1",
        )
    if not portal_rows:
        _record_limitation(
            limitations,
            "No portal grant records were available for customer delivery linkage",
        )

    _record_limitation(
        limitations,
        "Replay entities are deferred until a persisted replay authority exists; replay-safe snapshot export is available now",
    )

    entity_timestamps = [_entity_timestamp(entity) for entity in entities]
    relationship_timestamps = [
        relationship.created_at for relationship in relationships
    ]
    generated_at = max(
        entity_timestamps + relationship_timestamps,
        default=GOVERNANCE_DIGITAL_TWIN_EPOCH,
    )

    available_authorities = sorted(
        authority
        for authority, outcomes in authority_availability.items()
        if outcomes and any(outcomes)
    )
    participating_authorities = sorted(
        set(available_authorities)
        | {entity.authority for entity in entities}
        | {relationship.authority for relationship in relationships}
    )

    authority_entities = _build_authority_entities(
        tenant_id,
        participating_authorities,
        generated_at,
    )
    entities.extend(authority_entities)
    sorted_entities = _sorted_entities(entities)
    sorted_relationships = _sorted_relationships(relationships)

    source_authority_entities = Counter(
        entity.authority
        for entity in sorted_entities
        if entity.type != GovernanceDigitalTwinEntityType.authority.value
    )
    source_authority_relationships = Counter(
        relationship.authority for relationship in sorted_relationships
    )
    authority_confidence_weight: dict[str, int] = {}
    authority_coverage_percent: dict[str, int] = {}
    authority_freshness_at: dict[str, str] = {}
    authority_trust_level: dict[str, str] = {}
    for authority in participating_authorities:
        authority_entities = [
            entity
            for entity in sorted_entities
            if entity.authority == authority
            and entity.type != GovernanceDigitalTwinEntityType.authority.value
        ]
        authority_relationships = [
            relationship
            for relationship in sorted_relationships
            if relationship.authority == authority
        ]
        confidence_values = [entity.confidence for entity in authority_entities] + [
            relationship.confidence for relationship in authority_relationships
        ]
        authority_confidence_weight[authority] = (
            int(round(sum(confidence_values) / len(confidence_values)))
            if confidence_values
            else 100
        )
        authority_coverage_percent[authority] = (
            100 if authority in available_authorities else 0
        )
        freshness_candidates = [entity.updated_at for entity in authority_entities] + [
            relationship.created_at for relationship in authority_relationships
        ]
        authority_freshness_at[authority] = max(
            freshness_candidates, default=generated_at
        )
        authority_trust_level[authority] = _confidence_trust_level(
            authority_confidence_weight[authority]
        )

    source_authorities = tuple(
        GovernanceDigitalTwinSourceAuthority(
            authority=authority,
            available=True,
            entity_count=source_authority_entities.get(authority, 0),
            relationship_count=source_authority_relationships.get(authority, 0),
            source_tables=_AUTHORITY_DEFINITIONS[authority].source_tables,
            source_routes=_AUTHORITY_DEFINITIONS[authority].source_routes,
            produced_entity_types=tuple(
                sorted(
                    {
                        entity.type
                        for entity in sorted_entities
                        if entity.authority == authority
                        and entity.type
                        != GovernanceDigitalTwinEntityType.authority.value
                    }
                )
            ),
            confidence_weight=authority_confidence_weight[authority],
            coverage_percent=authority_coverage_percent[authority],
            freshness_at=authority_freshness_at[authority],
            trust_level=authority_trust_level[authority],
        )
        for authority in participating_authorities
    )

    authority_dependencies: set[tuple[str, str, str]] = set()
    consumed_types_by_authority: dict[str, set[str]] = defaultdict(set)
    downstream_by_authority: dict[str, set[str]] = defaultdict(set)
    entity_by_id = {entity.id: entity for entity in sorted_entities}
    for relationship in sorted_relationships:
        spec = RELATIONSHIP_REGISTRY.get(relationship.type)
        if spec is None or not spec.participates_in_authority_dependencies:
            continue
        source_entity = entity_by_id.get(relationship.from_entity_id)
        target_entity = entity_by_id.get(relationship.to_entity_id)
        if source_entity is None or target_entity is None:
            continue
        if source_entity.authority == target_entity.authority:
            continue
        authority_dependencies.add(
            (
                source_entity.authority,
                target_entity.authority,
                relationship.type,
            )
        )
        consumed_types_by_authority[source_entity.authority].add(target_entity.type)
        downstream_by_authority[source_entity.authority].add(target_entity.authority)

    authority_graph = GovernanceDigitalTwinAuthorityGraph(
        authorities=tuple(
            GovernanceDigitalTwinAuthorityNode(
                authority=authority,
                available=True,
                ownership=_AUTHORITY_DEFINITIONS[authority].ownership,
                source_tables=_AUTHORITY_DEFINITIONS[authority].source_tables,
                source_routes=_AUTHORITY_DEFINITIONS[authority].source_routes,
                capabilities=_AUTHORITY_DEFINITIONS[authority].capabilities,
                produced_entity_types=tuple(
                    sorted(
                        {
                            entity.type
                            for entity in sorted_entities
                            if entity.authority == authority
                            and entity.type
                            != GovernanceDigitalTwinEntityType.authority.value
                        }
                    )
                ),
                consumed_entity_types=tuple(
                    sorted(consumed_types_by_authority.get(authority, set()))
                ),
                downstream_dependencies=tuple(
                    sorted(downstream_by_authority.get(authority, set()))
                ),
                confidence_weight=authority_confidence_weight[authority],
                coverage_percent=authority_coverage_percent[authority],
                freshness_at=authority_freshness_at[authority],
                trust_level=authority_trust_level[authority],
            )
            for authority in participating_authorities
        ),
        dependencies=tuple(
            GovernanceDigitalTwinAuthorityEdge(
                authority=source,
                downstream_authority=target,
                relationship_type=relationship_type,
            )
            for source, target, relationship_type in sorted(authority_dependencies)
        ),
    )

    expected_core_authorities = (
        "field_assessment",
        "evidence_authority",
        "control_registry",
        "governance_orchestration",
        "remediation",
        "report_authority",
        "governance_decision",
        "framework_authority",
    )
    available_core_authorities = tuple(
        authority
        for authority in expected_core_authorities
        if authority in available_authorities
    )
    missing_authorities = tuple(
        authority
        for authority in expected_core_authorities
        if authority not in available_core_authorities
    )
    unavailable_sources = tuple(
        sorted(
            authority
            for authority, outcomes in authority_availability.items()
            if outcomes and not any(outcomes)
        )
    )
    completeness_score = int(
        round((len(available_core_authorities) / len(expected_core_authorities)) * 100)
    )
    completeness = deep_freeze({
        "score": completeness_score,
        "method": "available_core_authorities_ratio_v2",
        "coverage": {
            "expected_core_authority_count": len(expected_core_authorities),
            "available_core_authority_count": len(available_core_authorities),
            "entity_count": len(sorted_entities),
            "relationship_count": len(sorted_relationships),
        },
        "expected_core_authorities": list(expected_core_authorities),
        "available_core_authorities": list(available_core_authorities),
        "missing_authorities": list(missing_authorities),
        "missing_sources": list(unavailable_sources),
        "partial_state": bool(
            missing_authorities or unavailable_sources or limitations
        ),
        "unavailable_sources": list(unavailable_sources),
        "confidence_in_completeness": max(
            0, completeness_score - (10 * len(unavailable_sources))
        ),
    })

    preliminary_snapshot = GovernanceDigitalTwinSnapshot(
        snapshot_id="",
        canonical_snapshot_id="",
        tenant_id=tenant_id,
        generated_at=generated_at,
        snapshot_version=GOVERNANCE_DIGITAL_TWIN_SNAPSHOT_VERSION,
        graph_schema_version=GOVERNANCE_DIGITAL_TWIN_GRAPH_SCHEMA_VERSION,
        builder_version=GOVERNANCE_DIGITAL_TWIN_BUILDER_VERSION,
        category=normalized_category,
        parent_snapshot_id=parent_snapshot_id,
        previous_fingerprint=previous_fingerprint,
        generation=normalized_generation,
        lineage_id=resolved_lineage_id,
        twin_identity=twin_identity,
        source_authorities=source_authorities,
        authority_graph=authority_graph,
        entities=sorted_entities,
        relationships=sorted_relationships,
        baselines=baselines,
        manifest=None,
        replay_safe_export=deep_freeze({}),
        fingerprint="",
        redaction_profile=redaction_profile,
        completeness=completeness,
        validation_report=None,
        state_extensions=state_extensions,
        future_references=future_references,
        warnings=tuple(sorted(set(warnings))),
        limitations=tuple(sorted(set(limitations))),
    )
    structural_validation = validate_governance_digital_twin_snapshot(
        preliminary_snapshot,
        require_replay_integrity=False,
    )
    if not structural_validation.valid:
        raise GovernanceDigitalTwinBuildError(
            "snapshot validation failed: " + ", ".join(structural_validation.violations)
        )
    fingerprint = compute_snapshot_fingerprint(preliminary_snapshot)
    snapshot_id = f"gdts-{compute_metadata_hash({'tenant_id': tenant_id, 'fingerprint': fingerprint})[:24]}"
    snapshot = replace(
        preliminary_snapshot,
        snapshot_id=snapshot_id,
        canonical_snapshot_id=snapshot_id,
        fingerprint=fingerprint,
    )
    manifest = build_snapshot_manifest(snapshot)
    snapshot = replace(snapshot, manifest=manifest)
    provisional_export = deep_freeze(export_replay_safe_snapshot(snapshot))
    snapshot = replace(snapshot, replay_safe_export=provisional_export)
    final_validation = validate_governance_digital_twin_snapshot(
        snapshot,
        require_replay_integrity=True,
    )
    if not final_validation.valid:
        raise GovernanceDigitalTwinBuildError(
            "snapshot validation failed: " + ", ".join(final_validation.violations)
        )
    snapshot = replace(snapshot, validation_report=final_validation)
    export = deep_freeze(export_replay_safe_snapshot(snapshot))
    return replace(snapshot, replay_safe_export=export)
