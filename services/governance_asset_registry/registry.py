"""Governance Asset Registry — core CRUD, versioning, and scoring logic.

All public functions take an explicit db Session and tenant_id.
They never resolve tenant from request context — callers own that boundary.

Versioning contract:
  Every create and update produces an immutable GaAssetVersion snapshot.
  asset.current_version_hash always points to the latest version_hash.
  The version chain (parent_hash → version_hash) is signed with Ed25519.

Risk score contract:
  _recompute_and_store_risk is called after every mutation that could change
  the score.  It marks the previous is_current=False and inserts a new row.
  The full factor breakdown is preserved for reproducibility.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.db_models_governance_assets import (
    GaAsset,
    GaAssetAttestation,
    GaAssetAuditEvent,
    GaAssetOwner,
    GaAssetPolicyBinding,
    GaAssetRelationship,
    GaAssetRiskScore,
    GaAssetVersion,
)
from api.signed_artifacts import (
    canonical_hash,
    sign_hash,
    signing_key_id,
)
from services.canonical import utc_iso8601_z_now
from services.governance_asset_registry.attestation import (
    compute_next_due_at,
    days_overdue,
    interval_days_for_tier,
)
from services.governance_asset_registry.audit import emit_asset_audit_event
from services.governance_asset_registry.models import (
    AssetStatus,
    AttestationStatus,
    DataClassification,
    DiscoverySource,
    PolicyBindingStatus,
    RiskTier,
)
from services.governance_asset_registry.risk_engine import (
    build_factors,
    compute_risk_score,
)

log = logging.getLogger("frostgate.governance_assets.registry")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _new_id() -> str:
    return uuid.uuid4().hex


def _version_payload(asset: GaAsset) -> dict[str, Any]:
    return {
        "asset_id": asset.asset_id,
        "tenant_id": asset.tenant_id,
        "asset_type": asset.asset_type,
        "name": asset.name,
        "description": asset.description,
        "status": asset.status,
        "risk_tier": asset.risk_tier,
        "risk_score": asset.risk_score,
        "discovery_source": asset.discovery_source,
        "external_id": asset.external_id,
        "metadata_json": asset.metadata_json,
        "schema_version": asset.schema_version,
        "snapshotted_at": utc_iso8601_z_now(),
    }


def _create_version(
    db: Session,
    *,
    asset: GaAsset,
    actor_email: str,
) -> GaAssetVersion:
    """Append an immutable signed version snapshot. Never called externally."""
    payload = _version_payload(asset)
    version_hash = canonical_hash(payload)

    # Determine parent_hash from previous version (if any)
    stmt = (
        select(GaAssetVersion)
        .where(
            GaAssetVersion.asset_id == asset.asset_id,
            GaAssetVersion.tenant_id == asset.tenant_id,
        )
        .order_by(GaAssetVersion.version_seq.desc())
        .limit(1)
    )
    prev = db.execute(stmt).scalar_one_or_none()
    parent_hash = prev.version_hash if prev else None
    seq = (prev.version_seq + 1) if prev else 1

    sig: str | None = None
    key_id: str | None = None
    try:
        key_id = signing_key_id()
        sig = sign_hash(version_hash)
    except Exception as exc:
        log.warning("ga_registry: version signing unavailable — %s", exc)

    version = GaAssetVersion(
        version_id=_new_id(),
        asset_id=asset.asset_id,
        tenant_id=asset.tenant_id,
        version_seq=seq,
        version_hash=version_hash,
        parent_hash=parent_hash,
        version_payload_json=payload,
        created_at=utc_iso8601_z_now(),
        created_by_email=actor_email,
        chain_signature=sig,
        key_id=key_id,
    )
    db.add(version)
    db.flush()

    asset.current_version_hash = version_hash
    db.flush()
    return version


def _recompute_and_store_risk(
    db: Session,
    *,
    asset: GaAsset,
    trigger_event: str,
) -> GaAssetRiskScore:
    """Atomically retire old current score and insert new one."""
    # Determine worst data classification across relationships
    stmt = (
        select(GaAssetRelationship.data_classification)
        .where(
            GaAssetRelationship.tenant_id == asset.tenant_id,
            GaAssetRelationship.source_asset_id == asset.asset_id,
        )
    )
    data_classes = [r for (r,) in db.execute(stmt).all()]
    cls_severity = {
        "phi": 7, "pii": 6, "financial": 5, "confidential": 4,
        "internal": 3, "unknown": 2, "public": 1,
    }
    worst_cls = max(
        data_classes,
        key=lambda c: cls_severity.get(c, 0),
        default=DataClassification.unknown,
    )

    # Find worst overdue owner
    owners_stmt = select(GaAssetOwner).where(
        GaAssetOwner.asset_id == asset.asset_id,
        GaAssetOwner.tenant_id == asset.tenant_id,
    )
    owners = db.execute(owners_stmt).scalars().all()
    worst_overdue = max(
        (days_overdue(o.next_attestation_due_at) for o in owners), default=0
    )

    factors = build_factors(
        asset_type=asset.asset_type,
        discovery_source=asset.discovery_source,
        days_attestation_overdue=worst_overdue,
        max_data_classification=worst_cls,
    )
    result = compute_risk_score(factors)

    # Retire previous current scores
    db.execute(
        update(GaAssetRiskScore)
        .where(
            GaAssetRiskScore.asset_id == asset.asset_id,
            GaAssetRiskScore.tenant_id == asset.tenant_id,
            GaAssetRiskScore.is_current.is_(True),
        )
        .values(is_current=False)
    )

    score_row = GaAssetRiskScore(
        score_id=_new_id(),
        asset_id=asset.asset_id,
        tenant_id=asset.tenant_id,
        score=result.score,
        tier=result.tier.value,
        factors_json={
            "asset_type_base": result.factors.asset_type_base,
            "vendor_risk": result.factors.vendor_risk,
            "data_sensitivity": result.factors.data_sensitivity,
            "change_velocity": result.factors.change_velocity,
            "open_findings_weight": result.factors.open_findings_weight,
            "attestation_staleness": result.factors.attestation_staleness,
            "discovery_penalty": result.factors.discovery_penalty,
        },
        trigger_event=trigger_event,
        is_current=True,
        computed_at=result.computed_at,
    )
    db.add(score_row)
    db.flush()

    # Update cached values on the asset row
    asset.risk_score = result.score
    asset.risk_tier = result.tier.value
    asset.updated_at = utc_iso8601_z_now()
    db.flush()
    return score_row


# ---------------------------------------------------------------------------
# Asset CRUD
# ---------------------------------------------------------------------------


def create_asset(
    db: Session,
    *,
    tenant_id: str,
    asset_type: str,
    name: str,
    description: str | None,
    external_id: str | None,
    metadata: dict[str, Any],
    discovery_source: str,
    actor_email: str,
) -> GaAsset:
    now = utc_iso8601_z_now()
    asset = GaAsset(
        asset_id=_new_id(),
        tenant_id=tenant_id,
        asset_type=asset_type,
        name=name,
        description=description,
        status=AssetStatus.active.value,
        risk_tier=RiskTier.unclassified.value,
        risk_score=0,
        discovery_source=discovery_source,
        external_id=external_id,
        metadata_json=metadata,
        schema_version="1.0",
        created_at=now,
        updated_at=now,
        created_by_email=actor_email,
    )
    db.add(asset)
    db.flush()

    _create_version(db, asset=asset, actor_email=actor_email)
    _recompute_and_store_risk(db, asset=asset, trigger_event="asset.created")
    emit_asset_audit_event(
        db,
        tenant_id=tenant_id,
        asset_id=asset.asset_id,
        event_type="asset.created",
        actor_email=actor_email,
        payload={
            "asset_type": asset_type,
            "name": name,
            "discovery_source": discovery_source,
            "external_id": external_id,
        },
    )
    return asset


def get_asset(db: Session, *, tenant_id: str, asset_id: str) -> GaAsset | None:
    stmt = select(GaAsset).where(
        GaAsset.asset_id == asset_id,
        GaAsset.tenant_id == tenant_id,
    )
    return db.execute(stmt).scalar_one_or_none()


def list_assets(
    db: Session,
    *,
    tenant_id: str,
    asset_type: str | None = None,
    status: str | None = None,
    risk_tier: str | None = None,
    discovery_source: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[GaAsset]:
    stmt = select(GaAsset).where(GaAsset.tenant_id == tenant_id)
    if asset_type:
        stmt = stmt.where(GaAsset.asset_type == asset_type)
    if status:
        stmt = stmt.where(GaAsset.status == status)
    if risk_tier:
        stmt = stmt.where(GaAsset.risk_tier == risk_tier)
    if discovery_source:
        stmt = stmt.where(GaAsset.discovery_source == discovery_source)
    stmt = stmt.order_by(GaAsset.risk_score.desc(), GaAsset.created_at.desc())
    stmt = stmt.limit(min(limit, 500)).offset(offset)
    return list(db.execute(stmt).scalars().all())


def update_asset(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    actor_email: str,
    name: str | None = None,
    description: str | None = None,
    external_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    status: str | None = None,
) -> GaAsset:
    asset = get_asset(db, tenant_id=tenant_id, asset_id=asset_id)
    if asset is None:
        raise ValueError(f"asset not found: {asset_id}")
    if asset.status == AssetStatus.decommissioned.value:
        raise ValueError("decommissioned assets cannot be updated")

    changed: dict[str, Any] = {}
    if name is not None and name != asset.name:
        asset.name = name
        changed["name"] = name
    if description is not None and description != asset.description:
        asset.description = description
        changed["description"] = description
    if external_id is not None and external_id != asset.external_id:
        asset.external_id = external_id
        changed["external_id"] = external_id
    if metadata is not None:
        asset.metadata_json = metadata
        changed["metadata_updated"] = True
    if status is not None and status != asset.status:
        asset.status = status
        changed["status"] = status

    if not changed:
        return asset  # no-op

    asset.updated_at = utc_iso8601_z_now()
    db.flush()

    _create_version(db, asset=asset, actor_email=actor_email)
    _recompute_and_store_risk(db, asset=asset, trigger_event="asset.updated")
    emit_asset_audit_event(
        db,
        tenant_id=tenant_id,
        asset_id=asset_id,
        event_type="asset.updated",
        actor_email=actor_email,
        payload={"changed_fields": list(changed.keys()), "changes": changed},
    )
    return asset


def decommission_asset(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    actor_email: str,
    reason: str,
) -> GaAsset:
    asset = get_asset(db, tenant_id=tenant_id, asset_id=asset_id)
    if asset is None:
        raise ValueError(f"asset not found: {asset_id}")
    if asset.status == AssetStatus.decommissioned.value:
        return asset  # idempotent

    asset.status = AssetStatus.decommissioned.value
    asset.updated_at = utc_iso8601_z_now()
    db.flush()

    _create_version(db, asset=asset, actor_email=actor_email)
    emit_asset_audit_event(
        db,
        tenant_id=tenant_id,
        asset_id=asset_id,
        event_type="asset.decommissioned",
        actor_email=actor_email,
        payload={"reason": reason},
    )
    return asset


# ---------------------------------------------------------------------------
# Version history
# ---------------------------------------------------------------------------


def list_versions(
    db: Session, *, tenant_id: str, asset_id: str
) -> list[GaAssetVersion]:
    stmt = (
        select(GaAssetVersion)
        .where(
            GaAssetVersion.asset_id == asset_id,
            GaAssetVersion.tenant_id == tenant_id,
        )
        .order_by(GaAssetVersion.version_seq.desc())
    )
    return list(db.execute(stmt).scalars().all())


def get_version_by_hash(
    db: Session, *, tenant_id: str, version_hash: str
) -> GaAssetVersion | None:
    stmt = select(GaAssetVersion).where(
        GaAssetVersion.tenant_id == tenant_id,
        GaAssetVersion.version_hash == version_hash,
    )
    return db.execute(stmt).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------


def assign_owner(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    owner_email: str,
    owner_role: str,
    assigned_by_email: str,
) -> GaAssetOwner:
    asset = get_asset(db, tenant_id=tenant_id, asset_id=asset_id)
    if asset is None:
        raise ValueError(f"asset not found: {asset_id}")

    interval = interval_days_for_tier(asset.risk_tier)
    now = utc_iso8601_z_now()
    owner = GaAssetOwner(
        ownership_id=_new_id(),
        asset_id=asset_id,
        tenant_id=tenant_id,
        owner_email=owner_email,
        owner_role=owner_role,
        attestation_interval_days=interval,
        last_attested_at=None,
        next_attestation_due_at=compute_next_due_at(asset.risk_tier, None),
        assigned_at=now,
        assigned_by_email=assigned_by_email,
    )
    db.add(owner)
    db.flush()

    _recompute_and_store_risk(db, asset=asset, trigger_event="owner.assigned")
    emit_asset_audit_event(
        db,
        tenant_id=tenant_id,
        asset_id=asset_id,
        event_type="owner.assigned",
        actor_email=assigned_by_email,
        payload={"owner_email": owner_email, "owner_role": owner_role},
    )
    return owner


def remove_owner(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    ownership_id: str,
    actor_email: str,
) -> None:
    stmt = select(GaAssetOwner).where(
        GaAssetOwner.ownership_id == ownership_id,
        GaAssetOwner.tenant_id == tenant_id,
        GaAssetOwner.asset_id == asset_id,
    )
    owner = db.execute(stmt).scalar_one_or_none()
    if owner is None:
        raise ValueError(f"ownership not found: {ownership_id}")

    removed_email = owner.owner_email
    db.delete(owner)
    db.flush()

    emit_asset_audit_event(
        db,
        tenant_id=tenant_id,
        asset_id=asset_id,
        event_type="owner.removed",
        actor_email=actor_email,
        payload={"owner_email": removed_email, "ownership_id": ownership_id},
    )


def list_owners(
    db: Session, *, tenant_id: str, asset_id: str
) -> list[GaAssetOwner]:
    stmt = select(GaAssetOwner).where(
        GaAssetOwner.asset_id == asset_id,
        GaAssetOwner.tenant_id == tenant_id,
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Attestations
# ---------------------------------------------------------------------------


def submit_attestation(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    owner_email: str,
    attestation_type: str,
    statement: str,
    notes: str | None = None,
    actor_email: str,
) -> GaAssetAttestation:
    asset = get_asset(db, tenant_id=tenant_id, asset_id=asset_id)
    if asset is None:
        raise ValueError(f"asset not found: {asset_id}")
    if not asset.current_version_hash:
        raise ValueError("asset has no version yet — cannot attest")

    now = utc_iso8601_z_now()
    due_at = compute_next_due_at(asset.risk_tier, None)  # was due before now

    attest_payload = {
        "asset_id": asset_id,
        "owner_email": owner_email,
        "attestation_type": attestation_type,
        "attested_version_hash": asset.current_version_hash,
        "statement": statement,
        "due_at": due_at,
    }
    attest_hash = canonical_hash(attest_payload)

    sig: str | None = None
    key_id: str | None = None
    try:
        key_id = signing_key_id()
        sig = sign_hash(attest_hash)
    except Exception as exc:
        log.warning("ga_registry: attestation signing unavailable — %s", exc)

    attestation = GaAssetAttestation(
        attestation_id=_new_id(),
        asset_id=asset_id,
        tenant_id=tenant_id,
        owner_email=owner_email,
        attestation_type=attestation_type,
        attested_version_hash=asset.current_version_hash,
        statement=statement,
        attestation_hash=attest_hash,
        chain_signature=sig,
        key_id=key_id,
        status=AttestationStatus.completed.value,
        due_at=due_at,
        completed_at=now,
        notes=notes,
        schema_version="1.0",
        created_at=now,
    )
    db.add(attestation)
    db.flush()

    # Update owner's last_attested_at and next_attestation_due_at
    owners_stmt = select(GaAssetOwner).where(
        GaAssetOwner.asset_id == asset_id,
        GaAssetOwner.tenant_id == tenant_id,
        GaAssetOwner.owner_email == owner_email,
    )
    for owner in db.execute(owners_stmt).scalars().all():
        owner.last_attested_at = now
        owner.next_attestation_due_at = compute_next_due_at(asset.risk_tier, now)
    db.flush()

    _recompute_and_store_risk(db, asset=asset, trigger_event="attestation.submitted")
    emit_asset_audit_event(
        db,
        tenant_id=tenant_id,
        asset_id=asset_id,
        event_type="attestation.submitted",
        actor_email=actor_email,
        payload={
            "owner_email": owner_email,
            "attestation_type": attestation_type,
            "attested_version_hash": asset.current_version_hash,
            "attestation_hash": attest_hash,
        },
    )
    return attestation


def list_attestations(
    db: Session, *, tenant_id: str, asset_id: str
) -> list[GaAssetAttestation]:
    stmt = (
        select(GaAssetAttestation)
        .where(
            GaAssetAttestation.asset_id == asset_id,
            GaAssetAttestation.tenant_id == tenant_id,
        )
        .order_by(GaAssetAttestation.created_at.desc())
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------


def create_relationship(
    db: Session,
    *,
    tenant_id: str,
    source_asset_id: str,
    target_asset_id: str,
    relationship_type: str,
    data_classification: str,
    transfer_volume_tier: str,
    is_declared: bool,
    metadata: dict[str, Any],
    actor_email: str,
) -> GaAssetRelationship:
    # Verify both assets exist
    for aid in (source_asset_id, target_asset_id):
        if get_asset(db, tenant_id=tenant_id, asset_id=aid) is None:
            raise ValueError(f"asset not found: {aid}")

    rel = GaAssetRelationship(
        relationship_id=_new_id(),
        tenant_id=tenant_id,
        source_asset_id=source_asset_id,
        target_asset_id=target_asset_id,
        relationship_type=relationship_type,
        data_classification=data_classification,
        transfer_volume_tier=transfer_volume_tier,
        is_declared=is_declared,
        metadata_json=metadata,
        created_at=utc_iso8601_z_now(),
        created_by_email=actor_email,
    )
    db.add(rel)
    db.flush()

    # Recompute risk for the source (data classification may have changed)
    source = get_asset(db, tenant_id=tenant_id, asset_id=source_asset_id)
    if source:
        _recompute_and_store_risk(
            db, asset=source, trigger_event="relationship.created"
        )

    emit_asset_audit_event(
        db,
        tenant_id=tenant_id,
        asset_id=source_asset_id,
        event_type="relationship.created",
        actor_email=actor_email,
        payload={
            "target_asset_id": target_asset_id,
            "relationship_type": relationship_type,
            "data_classification": data_classification,
            "is_declared": is_declared,
        },
    )
    return rel


def list_relationships(
    db: Session, *, tenant_id: str, asset_id: str
) -> list[GaAssetRelationship]:
    stmt = select(GaAssetRelationship).where(
        GaAssetRelationship.tenant_id == tenant_id,
        (GaAssetRelationship.source_asset_id == asset_id)
        | (GaAssetRelationship.target_asset_id == asset_id),
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Risk score history
# ---------------------------------------------------------------------------


def get_current_risk_score(
    db: Session, *, tenant_id: str, asset_id: str
) -> GaAssetRiskScore | None:
    stmt = select(GaAssetRiskScore).where(
        GaAssetRiskScore.asset_id == asset_id,
        GaAssetRiskScore.tenant_id == tenant_id,
        GaAssetRiskScore.is_current.is_(True),
    )
    return db.execute(stmt).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Policy bindings
# ---------------------------------------------------------------------------


def bind_policy(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    policy_type: str,
    policy_ref: str,
    policy_version_hash: str,
    actor_email: str,
    effective_from: str | None = None,
    effective_until: str | None = None,
) -> GaAssetPolicyBinding:
    if get_asset(db, tenant_id=tenant_id, asset_id=asset_id) is None:
        raise ValueError(f"asset not found: {asset_id}")

    # Supersede any existing active binding for this policy_type
    db.execute(
        update(GaAssetPolicyBinding)
        .where(
            GaAssetPolicyBinding.asset_id == asset_id,
            GaAssetPolicyBinding.tenant_id == tenant_id,
            GaAssetPolicyBinding.policy_type == policy_type,
            GaAssetPolicyBinding.status == PolicyBindingStatus.active.value,
        )
        .values(status=PolicyBindingStatus.superseded.value)
    )

    binding = GaAssetPolicyBinding(
        binding_id=_new_id(),
        asset_id=asset_id,
        tenant_id=tenant_id,
        policy_type=policy_type,
        policy_ref=policy_ref,
        policy_version_hash=policy_version_hash,
        status=PolicyBindingStatus.active.value,
        bound_at=utc_iso8601_z_now(),
        bound_by_email=actor_email,
        effective_from=effective_from,
        effective_until=effective_until,
    )
    db.add(binding)
    db.flush()

    emit_asset_audit_event(
        db,
        tenant_id=tenant_id,
        asset_id=asset_id,
        event_type="policy.bound",
        actor_email=actor_email,
        payload={
            "policy_type": policy_type,
            "policy_ref": policy_ref,
            "policy_version_hash": policy_version_hash,
        },
    )
    return binding


def list_policy_bindings(
    db: Session, *, tenant_id: str, asset_id: str
) -> list[GaAssetPolicyBinding]:
    stmt = select(GaAssetPolicyBinding).where(
        GaAssetPolicyBinding.asset_id == asset_id,
        GaAssetPolicyBinding.tenant_id == tenant_id,
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Registry summary
# ---------------------------------------------------------------------------


def registry_summary(db: Session, *, tenant_id: str) -> dict[str, Any]:
    """Return tenant-level inventory statistics."""
    assets = list_assets(db, tenant_id=tenant_id, limit=5000)
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    shadow_count = 0

    for a in assets:
        by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
        by_status[a.status] = by_status.get(a.status, 0) + 1
        by_tier[a.risk_tier] = by_tier.get(a.risk_tier, 0) + 1
        if a.discovery_source != DiscoverySource.declared.value:
            shadow_count += 1

    return {
        "total_assets": len(assets),
        "by_type": by_type,
        "by_status": by_status,
        "by_risk_tier": by_tier,
        "shadow_asset_count": shadow_count,
    }
