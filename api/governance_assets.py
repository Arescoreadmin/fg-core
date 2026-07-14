"""Governance Asset Registry API.

Tenant-scoped, cryptographically audited CRUD for AI systems, vendors, models,
OAuth apps, agents, copilots, automations, data flows, and their relationships.

All tenant resolution is auth-context-only — never from request body.
All mutations emit tamper-evident chained audit events.

Scopes:
  governance:read   — list, get, versions, owners, attestations, risk, blast-radius
  governance:write  — create, update, decommission, assign/remove owners,
                      attest, relationships, policy bindings, risk recompute
  governance:admin  — audit chain verification
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes.resolution import require_scopes
from api.db_models_governance_assets import GaAssetOwner
from api.deps import auth_ctx_db_session
from services.governance_asset_registry import registry
from services.governance_asset_registry.audit import verify_asset_audit_chain
from services.governance_asset_registry.continuity import (
    attestation_health,
    continuity_gaps,
)
from services.governance_asset_registry.graph import blast_radius
from services.governance_asset_registry.shadow_detector import detect_shadow_assets

log = logging.getLogger("frostgate.api.governance_assets")

router = APIRouter(
    prefix="/governance/assets",
    tags=["governance-assets"],
)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _resolve_caller_tenant(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tid = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )
    if not tid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )
    return str(tid)


def _actor(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    return (
        getattr(auth, "subject", None) or getattr(auth, "key_prefix", None) or "system"
    )


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------


class CreateAssetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_type: str = Field(
        description="ai_system|ai_vendor|model|oauth_app|agent|copilot|automation|data_flow"
    )
    name: str = Field(min_length=1, max_length=512)
    description: str | None = None
    external_id: str | None = None
    discovery_source: str = Field(
        default="declared", description="declared|discovered|inferred"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateAssetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    description: str | None = None
    external_id: str | None = None
    status: str | None = None
    metadata: dict[str, Any] | None = None


class DecommissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1)


class AssignOwnerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner_email: str = Field(min_length=1, max_length=512)
    owner_role: str = Field(default="primary", description="primary|secondary|delegate")


class SubmitAttestationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner_email: str = Field(min_length=1, max_length=512)
    attestation_type: str = Field(
        description="ownership|accuracy|risk_review|access_review"
    )
    statement: str = Field(min_length=1)
    notes: str | None = None


class CreateRelationshipRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_asset_id: str
    relationship_type: str = Field(
        description="data_flow|depends_on|manages|monitors|delegates_to|trained_on"
    )
    data_classification: str = Field(
        default="unknown",
        description="pii|phi|financial|confidential|internal|public|unknown",
    )
    transfer_volume_tier: str = Field(
        default="unknown", description="high|medium|low|unknown"
    )
    is_declared: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class BindPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_type: str
    policy_ref: str
    policy_version_hash: str
    effective_from: str | None = None
    effective_until: str | None = None


class AssetResponse(BaseModel):
    asset_id: str
    tenant_id: str
    asset_type: str
    asset_name: str  # portal canonical name field
    name: str
    description: str | None
    status: str
    risk_tier: str
    risk_score: int
    discovery_source: str
    external_id: str | None
    metadata: dict[str, Any]
    current_version_hash: str | None
    schema_version: str
    created_at: str
    updated_at: str
    created_by_email: str
    # Owner fields — populated by list_assets; null when asset has no owner
    last_attested_at: str | None = None
    next_attestation_due: str | None = None
    owner_email: str | None = None


class AssetVersionResponse(BaseModel):
    version_id: str
    asset_id: str
    tenant_id: str
    version_seq: int
    version_hash: str
    parent_hash: str | None
    version_payload: dict[str, Any]
    created_at: str
    created_by_email: str
    chain_signature: str | None
    key_id: str | None


class OwnerResponse(BaseModel):
    ownership_id: str
    asset_id: str
    tenant_id: str
    owner_email: str
    owner_role: str
    attestation_interval_days: int
    last_attested_at: str | None
    next_attestation_due_at: str | None
    assigned_at: str
    assigned_by_email: str


class AttestationResponse(BaseModel):
    attestation_id: str
    asset_id: str
    tenant_id: str
    owner_email: str
    attestation_type: str
    attested_version_hash: str
    statement: str
    attestation_hash: str
    chain_signature: str | None
    status: str
    due_at: str | None
    completed_at: str | None
    notes: str | None
    schema_version: str
    created_at: str


class RelationshipResponse(BaseModel):
    relationship_id: str
    tenant_id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    data_classification: str
    transfer_volume_tier: str
    is_declared: bool
    metadata: dict[str, Any]
    created_at: str
    created_by_email: str


class RiskScoreResponse(BaseModel):
    score_id: str
    asset_id: str
    tenant_id: str
    score: int
    tier: str
    factors: dict[str, Any]
    trigger_event: str
    is_current: bool
    computed_at: str


class PolicyBindingResponse(BaseModel):
    binding_id: str
    asset_id: str
    tenant_id: str
    policy_type: str
    policy_ref: str
    policy_version_hash: str
    status: str
    bound_at: str
    bound_by_email: str
    effective_from: str | None
    effective_until: str | None


class AttestationHealthResponse(BaseModel):
    compliant: int
    due_soon: int
    overdue: int
    never_attested: int
    total: int
    health_pct: float


class ContinuityGapResponse(BaseModel):
    asset_id: str
    asset_type: str
    asset_name: str
    risk_tier: str
    days_overdue: int
    staleness_index: int
    last_attested_at: str | None


class ContinuityGapsResponse(BaseModel):
    items: list[ContinuityGapResponse]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Serialisers
# ---------------------------------------------------------------------------


def _asset_out(a: Any, owner: GaAssetOwner | None = None) -> AssetResponse:
    return AssetResponse(
        asset_id=a.asset_id,
        tenant_id=a.tenant_id,
        asset_type=a.asset_type,
        asset_name=a.name,
        name=a.name,
        description=a.description,
        status=a.status,
        risk_tier=a.risk_tier,
        risk_score=a.risk_score,
        discovery_source=a.discovery_source,
        external_id=a.external_id,
        metadata=a.metadata_json or {},
        current_version_hash=a.current_version_hash,
        schema_version=a.schema_version,
        created_at=a.created_at,
        updated_at=a.updated_at,
        created_by_email=a.created_by_email,
        last_attested_at=owner.last_attested_at if owner else None,
        next_attestation_due=owner.next_attestation_due_at if owner else None,
        owner_email=owner.owner_email if owner else None,
    )


def _version_out(v: Any) -> AssetVersionResponse:
    return AssetVersionResponse(
        version_id=v.version_id,
        asset_id=v.asset_id,
        tenant_id=v.tenant_id,
        version_seq=v.version_seq,
        version_hash=v.version_hash,
        parent_hash=v.parent_hash,
        version_payload=v.version_payload_json or {},
        created_at=v.created_at,
        created_by_email=v.created_by_email,
        chain_signature=v.chain_signature,
        key_id=v.key_id,
    )


def _owner_out(o: Any) -> OwnerResponse:
    return OwnerResponse(
        ownership_id=o.ownership_id,
        asset_id=o.asset_id,
        tenant_id=o.tenant_id,
        owner_email=o.owner_email,
        owner_role=o.owner_role,
        attestation_interval_days=o.attestation_interval_days,
        last_attested_at=o.last_attested_at,
        next_attestation_due_at=o.next_attestation_due_at,
        assigned_at=o.assigned_at,
        assigned_by_email=o.assigned_by_email,
    )


def _attestation_out(a: Any) -> AttestationResponse:
    return AttestationResponse(
        attestation_id=a.attestation_id,
        asset_id=a.asset_id,
        tenant_id=a.tenant_id,
        owner_email=a.owner_email,
        attestation_type=a.attestation_type,
        attested_version_hash=a.attested_version_hash,
        statement=a.statement,
        attestation_hash=a.attestation_hash,
        chain_signature=a.chain_signature,
        status=a.status,
        due_at=a.due_at,
        completed_at=a.completed_at,
        notes=a.notes,
        schema_version=a.schema_version,
        created_at=a.created_at,
    )


def _rel_out(r: Any) -> RelationshipResponse:
    return RelationshipResponse(
        relationship_id=r.relationship_id,
        tenant_id=r.tenant_id,
        source_asset_id=r.source_asset_id,
        target_asset_id=r.target_asset_id,
        relationship_type=r.relationship_type,
        data_classification=r.data_classification,
        transfer_volume_tier=r.transfer_volume_tier,
        is_declared=r.is_declared,
        metadata=r.metadata_json or {},
        created_at=r.created_at,
        created_by_email=r.created_by_email,
    )


def _risk_out(s: Any) -> RiskScoreResponse:
    return RiskScoreResponse(
        score_id=s.score_id,
        asset_id=s.asset_id,
        tenant_id=s.tenant_id,
        score=s.score,
        tier=s.tier,
        factors=s.factors_json or {},
        trigger_event=s.trigger_event,
        is_current=s.is_current,
        computed_at=s.computed_at,
    )


def _policy_out(b: Any) -> PolicyBindingResponse:
    return PolicyBindingResponse(
        binding_id=b.binding_id,
        asset_id=b.asset_id,
        tenant_id=b.tenant_id,
        policy_type=b.policy_type,
        policy_ref=b.policy_ref,
        policy_version_hash=b.policy_version_hash,
        status=b.status,
        bound_at=b.bound_at,
        bound_by_email=b.bound_by_email,
        effective_from=b.effective_from,
        effective_until=b.effective_until,
    )


# ---------------------------------------------------------------------------
# Routes — summary and shadow (must precede /{asset_id} to avoid route clash)
# ---------------------------------------------------------------------------


@router.get(
    "/summary",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_registry_summary(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _resolve_caller_tenant(request)
    return registry.registry_summary(db, tenant_id=tenant_id)


@router.get(
    "/shadow",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_shadow_assets(
    request: Request,
    limit: int = Query(100, ge=1, le=200),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _resolve_caller_tenant(request)
    candidates = detect_shadow_assets(db, tenant_id=tenant_id, limit=limit)
    return {
        "tenant_id": tenant_id,
        "shadow_asset_count": len(candidates),
        "items": candidates,
    }


@router.get(
    "/attestation-health",
    response_model=AttestationHealthResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_attestation_health(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AttestationHealthResponse:
    tenant_id = _resolve_caller_tenant(request)
    report = attestation_health(db, tenant_id=tenant_id)
    return AttestationHealthResponse(
        compliant=report.compliant,
        due_soon=report.due_soon,
        overdue=report.overdue,
        never_attested=report.never_attested,
        total=report.total,
        health_pct=report.health_pct,
    )


@router.get(
    "/continuity-gaps",
    response_model=ContinuityGapsResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_continuity_gaps(
    request: Request,
    risk_tier: str | None = Query(default=None),
    days_overdue_min: int = Query(default=0, ge=0),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(auth_ctx_db_session),
) -> ContinuityGapsResponse:
    tenant_id = _resolve_caller_tenant(request)
    all_gaps = continuity_gaps(
        db,
        tenant_id=tenant_id,
        risk_tier=risk_tier,
        days_overdue_min=days_overdue_min,
    )
    total = len(all_gaps)
    offset = (page - 1) * page_size
    page_items = all_gaps[offset : offset + page_size]
    return ContinuityGapsResponse(
        items=[
            ContinuityGapResponse(
                asset_id=g.asset_id,
                asset_type=g.asset_type,
                asset_name=g.asset_name,
                risk_tier=g.risk_tier,
                days_overdue=g.days_overdue,
                staleness_index=g.staleness_index,
                last_attested_at=g.last_attested_at,
            )
            for g in page_items
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# Routes — Asset CRUD
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_asset(
    request: Request,
    body: CreateAssetRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> AssetResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)
    try:
        asset = registry.create_asset(
            db,
            tenant_id=tenant_id,
            asset_type=body.asset_type,
            name=body.name,
            description=body.description,
            external_id=body.external_id,
            metadata=body.metadata,
            discovery_source=body.discovery_source,
            actor_email=actor,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _asset_out(asset)


@router.get(
    "",
    response_model=list[AssetResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_assets(
    request: Request,
    asset_type: str | None = Query(None),
    asset_status: str | None = Query(None, alias="status"),
    risk_tier: str | None = Query(None),
    discovery_source: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[AssetResponse]:
    tenant_id = _resolve_caller_tenant(request)
    assets = registry.list_assets(
        db,
        tenant_id=tenant_id,
        asset_type=asset_type,
        status=asset_status,
        risk_tier=risk_tier,
        discovery_source=discovery_source,
        limit=limit,
        offset=offset,
    )
    # Batch-fetch the most-overdue owner per asset for portal attestation state.
    # Order by next_attestation_due_at ASC NULLS FIRST so that a never-attested or
    # overdue owner always wins over a recently-attested co-owner — ensuring the
    # asset appears in the portal due list whenever any owner is overdue.
    owners: dict[str, GaAssetOwner] = {}
    if assets:
        rows = (
            db.execute(
                select(GaAssetOwner)
                .where(
                    GaAssetOwner.tenant_id == tenant_id,
                    GaAssetOwner.asset_id.in_([a.asset_id for a in assets]),
                )
                .order_by(GaAssetOwner.next_attestation_due_at.asc().nullsfirst())
            )
            .scalars()
            .all()
        )
        for o in rows:
            owners.setdefault(o.asset_id, o)
    return [_asset_out(a, owners.get(a.asset_id)) for a in assets]


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_asset(
    asset_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AssetResponse:
    tenant_id = _resolve_caller_tenant(request)
    asset = registry.get_asset(db, tenant_id=tenant_id, asset_id=asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="asset not found"
        )
    return _asset_out(asset)


@router.patch(
    "/{asset_id}",
    response_model=AssetResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def update_asset(
    asset_id: str,
    request: Request,
    body: UpdateAssetRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> AssetResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)
    try:
        asset = registry.update_asset(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            actor_email=actor,
            name=body.name,
            description=body.description,
            external_id=body.external_id,
            metadata=body.metadata,
            status=body.status,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _asset_out(asset)


@router.post(
    "/{asset_id}/decommission",
    response_model=AssetResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def decommission_asset(
    asset_id: str,
    request: Request,
    body: DecommissionRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> AssetResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)
    try:
        asset = registry.decommission_asset(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            actor_email=actor,
            reason=body.reason,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return _asset_out(asset)


# ---------------------------------------------------------------------------
# Routes — Versions (time-travel)
# ---------------------------------------------------------------------------


@router.get(
    "/{asset_id}/versions",
    response_model=list[AssetVersionResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_versions(
    asset_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> list[AssetVersionResponse]:
    tenant_id = _resolve_caller_tenant(request)
    versions = registry.list_versions(db, tenant_id=tenant_id, asset_id=asset_id)
    return [_version_out(v) for v in versions]


@router.get(
    "/{asset_id}/versions/{version_hash}",
    response_model=AssetVersionResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_version(
    asset_id: str,
    version_hash: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AssetVersionResponse:
    tenant_id = _resolve_caller_tenant(request)
    version = registry.get_version_by_hash(
        db, tenant_id=tenant_id, version_hash=version_hash
    )
    if version is None or version.asset_id != asset_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="version not found"
        )
    return _version_out(version)


# ---------------------------------------------------------------------------
# Routes — Ownership
# ---------------------------------------------------------------------------


@router.post(
    "/{asset_id}/owners",
    response_model=OwnerResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def assign_owner(
    asset_id: str,
    request: Request,
    body: AssignOwnerRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> OwnerResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)
    try:
        owner = registry.assign_owner(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            owner_email=body.owner_email,
            owner_role=body.owner_role,
            assigned_by_email=actor,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _owner_out(owner)


@router.delete(
    "/{asset_id}/owners/{ownership_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def remove_owner(
    asset_id: str,
    ownership_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> None:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)
    try:
        registry.remove_owner(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            ownership_id=ownership_id,
            actor_email=actor,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@router.get(
    "/{asset_id}/owners",
    response_model=list[OwnerResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_owners(
    asset_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> list[OwnerResponse]:
    tenant_id = _resolve_caller_tenant(request)
    owners = registry.list_owners(db, tenant_id=tenant_id, asset_id=asset_id)
    return [_owner_out(o) for o in owners]


# ---------------------------------------------------------------------------
# Routes — Attestations
# ---------------------------------------------------------------------------


@router.post(
    "/{asset_id}/attestations",
    response_model=AttestationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def submit_attestation(
    asset_id: str,
    request: Request,
    body: SubmitAttestationRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> AttestationResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)
    try:
        attestation = registry.submit_attestation(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            owner_email=body.owner_email,
            attestation_type=body.attestation_type,
            statement=body.statement,
            notes=body.notes,
            actor_email=actor,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _attestation_out(attestation)


@router.get(
    "/{asset_id}/attestations",
    response_model=list[AttestationResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_attestations(
    asset_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> list[AttestationResponse]:
    tenant_id = _resolve_caller_tenant(request)
    attestations = registry.list_attestations(
        db, tenant_id=tenant_id, asset_id=asset_id
    )
    return [_attestation_out(a) for a in attestations]


# ---------------------------------------------------------------------------
# Routes — Relationships
# ---------------------------------------------------------------------------


@router.post(
    "/{asset_id}/relationships",
    response_model=RelationshipResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_relationship(
    asset_id: str,
    request: Request,
    body: CreateRelationshipRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> RelationshipResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)
    try:
        rel = registry.create_relationship(
            db,
            tenant_id=tenant_id,
            source_asset_id=asset_id,
            target_asset_id=body.target_asset_id,
            relationship_type=body.relationship_type,
            data_classification=body.data_classification,
            transfer_volume_tier=body.transfer_volume_tier,
            is_declared=body.is_declared,
            metadata=body.metadata,
            actor_email=actor,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _rel_out(rel)


@router.get(
    "/{asset_id}/relationships",
    response_model=list[RelationshipResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_relationships(
    asset_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> list[RelationshipResponse]:
    tenant_id = _resolve_caller_tenant(request)
    rels = registry.list_relationships(db, tenant_id=tenant_id, asset_id=asset_id)
    return [_rel_out(r) for r in rels]


# ---------------------------------------------------------------------------
# Routes — Risk scoring
# ---------------------------------------------------------------------------


@router.get(
    "/{asset_id}/risk",
    response_model=RiskScoreResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_risk_score(
    asset_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> RiskScoreResponse:
    tenant_id = _resolve_caller_tenant(request)
    score = registry.get_current_risk_score(db, tenant_id=tenant_id, asset_id=asset_id)
    if score is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="risk score not found"
        )
    return _risk_out(score)


@router.post(
    "/{asset_id}/risk/recompute",
    response_model=RiskScoreResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def recompute_risk(
    asset_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> RiskScoreResponse:
    tenant_id = _resolve_caller_tenant(request)
    asset = registry.get_asset(db, tenant_id=tenant_id, asset_id=asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="asset not found"
        )
    # pylint: disable=protected-access
    score = registry._recompute_and_store_risk(
        db, asset=asset, trigger_event="risk.manual_recompute"
    )
    db.commit()
    return _risk_out(score)


# ---------------------------------------------------------------------------
# Routes — Policy bindings
# ---------------------------------------------------------------------------


@router.post(
    "/{asset_id}/policies",
    response_model=PolicyBindingResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def bind_policy(
    asset_id: str,
    request: Request,
    body: BindPolicyRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> PolicyBindingResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)
    try:
        binding = registry.bind_policy(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            policy_type=body.policy_type,
            policy_ref=body.policy_ref,
            policy_version_hash=body.policy_version_hash,
            actor_email=actor,
            effective_from=body.effective_from,
            effective_until=body.effective_until,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _policy_out(binding)


@router.get(
    "/{asset_id}/policies",
    response_model=list[PolicyBindingResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_policy_bindings(
    asset_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> list[PolicyBindingResponse]:
    tenant_id = _resolve_caller_tenant(request)
    bindings = registry.list_policy_bindings(db, tenant_id=tenant_id, asset_id=asset_id)
    return [_policy_out(b) for b in bindings]


# ---------------------------------------------------------------------------
# Routes — Blast radius
# ---------------------------------------------------------------------------


@router.get(
    "/{asset_id}/blast-radius",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_blast_radius(
    asset_id: str,
    request: Request,
    max_depth: int = Query(3, ge=1, le=6),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _resolve_caller_tenant(request)
    if registry.get_asset(db, tenant_id=tenant_id, asset_id=asset_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="asset not found"
        )
    return blast_radius(db, tenant_id=tenant_id, asset_id=asset_id, max_depth=max_depth)


# ---------------------------------------------------------------------------
# Routes — Audit chain (separate prefix, admin scope)
# ---------------------------------------------------------------------------

audit_router = APIRouter(
    prefix="/governance/audit",
    tags=["governance-audit"],
)


@audit_router.get(
    "/chain/verify",
    dependencies=[Depends(require_scopes("governance:admin"))],
)
def verify_audit_chain(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _resolve_caller_tenant(request)
    return verify_asset_audit_chain(db, tenant_id=tenant_id)
