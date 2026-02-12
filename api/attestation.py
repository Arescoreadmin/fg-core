from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from collections.abc import Iterator

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from api.db import get_sessionmaker, set_tenant_context
from api.db_models import ApprovalLog, EvidenceBundle, ModuleRegistry
from api.signed_artifacts import (
    GENESIS_CHAIN_HASH,
    canonical_hash,
    chain_hash,
    sign_hash,
    signing_key_id,
    verify_hash_signature,
)

router = APIRouter(tags=["attestation"])


def _attestation_db(request: Request) -> Iterator[Session]:
    session_local = get_sessionmaker()
    db = session_local()

    auth_ctx = getattr(getattr(request, "state", None), "auth", None)
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth_ctx, "tenant_id", None
    )
    if tenant_id:
        set_tenant_context(db, tenant_id)

    request.state.db_session = db
    try:
        yield db
    finally:
        db.close()


class ArtifactMeta(BaseModel):
    name: str
    uri: str
    sha256: str = Field(min_length=64, max_length=64)


class EvidenceBundleCreateRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    subject_type: str = Field(min_length=1, max_length=64)
    subject_id: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]
    artifacts: list[ArtifactMeta] = Field(default_factory=list)


class EvidenceBundleCreateResponse(BaseModel):
    bundle_id: str
    bundle_hash: str
    signature: str
    key_id: str
    created_at: datetime


class EvidenceVerifyRequest(BaseModel):
    bundle: dict[str, Any]
    bundle_hash: str = Field(min_length=64, max_length=64)
    signature: str
    key_id: str


class EvidenceVerifyResponse(BaseModel):
    verified: bool
    reason: str | None = None


@router.post("/evidence/bundles", response_model=EvidenceBundleCreateResponse)
def create_evidence_bundle(
    req: EvidenceBundleCreateRequest, db: Session = Depends(_attestation_db)
) -> EvidenceBundleCreateResponse:
    created_at = datetime.now(UTC)
    bundle = {
        "tenant_id": req.tenant_id,
        "subject_type": req.subject_type,
        "subject_id": req.subject_id,
        "payload": req.payload,
        "artifacts": [artifact.model_dump() for artifact in req.artifacts],
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    bundle_hash = canonical_hash(bundle)
    key_id = signing_key_id()
    signature = sign_hash(bundle_hash)
    bundle_id = canonical_hash(
        {
            "tenant_id": req.tenant_id,
            "subject_type": req.subject_type,
            "subject_id": req.subject_id,
            "bundle_hash": bundle_hash,
        }
    )

    row = EvidenceBundle(
        id=bundle_id,
        tenant_id=req.tenant_id,
        subject_type=req.subject_type,
        subject_id=req.subject_id,
        bundle_json=bundle,
        bundle_hash=bundle_hash,
        signature=signature,
        key_id=key_id,
        created_at=created_at,
    )
    db.add(row)
    db.commit()

    return EvidenceBundleCreateResponse(
        bundle_id=bundle_id,
        bundle_hash=bundle_hash,
        signature=signature,
        key_id=key_id,
        created_at=created_at,
    )


@router.get("/evidence/bundles/{bundle_id}")
def get_evidence_bundle(
    bundle_id: str, db: Session = Depends(_attestation_db)
) -> dict[str, Any]:
    row = db.query(EvidenceBundle).filter(EvidenceBundle.id == bundle_id).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="bundle_not_found")
    return {
        "bundle_id": row.id,
        "bundle": row.bundle_json,
        "bundle_hash": row.bundle_hash,
        "signature": row.signature,
        "key_id": row.key_id,
        "created_at": row.created_at,
    }


@router.post("/evidence/verify", response_model=EvidenceVerifyResponse)
def verify_evidence(req: EvidenceVerifyRequest) -> EvidenceVerifyResponse:
    computed_hash = canonical_hash(req.bundle)
    if computed_hash != req.bundle_hash:
        return EvidenceVerifyResponse(verified=False, reason="bundle_hash_mismatch")

    ok, reason = verify_hash_signature(req.bundle_hash, req.signature, req.key_id)
    return EvidenceVerifyResponse(verified=ok, reason=reason)


class ApprovalCreateRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    subject_type: str = Field(min_length=1, max_length=64)
    subject_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=64)
    approver: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=1024)
    bundle_id: str | None = None


class ApprovalVerifyRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    subject_type: str = Field(min_length=1, max_length=64)
    subject_id: str = Field(min_length=1, max_length=128)


@router.post("/approvals")
def create_approval(
    req: ApprovalCreateRequest, db: Session = Depends(_attestation_db)
) -> dict[str, Any]:
    max_seq = (
        db.query(func.max(ApprovalLog.seq))
        .filter(
            and_(
                ApprovalLog.tenant_id == req.tenant_id,
                ApprovalLog.subject_type == req.subject_type,
                ApprovalLog.subject_id == req.subject_id,
            )
        )
        .scalar()
    )
    seq = (max_seq or 0) + 1

    prev_row = (
        db.query(ApprovalLog)
        .filter(
            and_(
                ApprovalLog.tenant_id == req.tenant_id,
                ApprovalLog.subject_type == req.subject_type,
                ApprovalLog.subject_id == req.subject_id,
            )
        )
        .order_by(ApprovalLog.seq.desc())
        .first()
    )
    prev_chain = prev_row.chain_hash if prev_row else GENESIS_CHAIN_HASH

    entry = {
        "tenant_id": req.tenant_id,
        "subject_type": req.subject_type,
        "subject_id": req.subject_id,
        "seq": seq,
        "action": req.action,
        "approver": req.approver,
        "reason": req.reason,
        "bundle_id": req.bundle_id,
    }
    entry_hash = canonical_hash(entry)
    computed_chain_hash = chain_hash(prev_chain, entry_hash)
    key_id = signing_key_id()
    signature = sign_hash(computed_chain_hash)

    row = ApprovalLog(
        tenant_id=req.tenant_id,
        subject_type=req.subject_type,
        subject_id=req.subject_id,
        seq=seq,
        entry_json=entry,
        entry_hash=entry_hash,
        prev_chain_hash=prev_chain,
        chain_hash=computed_chain_hash,
        signature=signature,
        key_id=key_id,
    )
    db.add(row)
    db.commit()

    return {
        **entry,
        "entry_hash": entry_hash,
        "prev_chain_hash": prev_chain,
        "chain_hash": computed_chain_hash,
        "signature": signature,
        "key_id": key_id,
        "created_at": row.created_at,
    }


@router.get("/approvals/{subject_type}/{subject_id}")
def list_approvals(
    subject_type: str,
    subject_id: str,
    tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: Session = Depends(_attestation_db),
) -> list[dict[str, Any]]:
    rows = (
        db.query(ApprovalLog)
        .filter(
            and_(
                ApprovalLog.tenant_id == tenant_id,
                ApprovalLog.subject_type == subject_type,
                ApprovalLog.subject_id == subject_id,
            )
        )
        .order_by(ApprovalLog.seq.asc())
        .all()
    )
    return [
        {
            "seq": row.seq,
            "entry": row.entry_json,
            "entry_hash": row.entry_hash,
            "prev_chain_hash": row.prev_chain_hash,
            "chain_hash": row.chain_hash,
            "signature": row.signature,
            "key_id": row.key_id,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.post("/approvals/verify")
def verify_approvals(
    req: ApprovalVerifyRequest, db: Session = Depends(_attestation_db)
) -> dict[str, Any]:
    rows = (
        db.query(ApprovalLog)
        .filter(
            and_(
                ApprovalLog.tenant_id == req.tenant_id,
                ApprovalLog.subject_type == req.subject_type,
                ApprovalLog.subject_id == req.subject_id,
            )
        )
        .order_by(ApprovalLog.seq.asc())
        .all()
    )

    expected_seq = 1
    prev_chain = GENESIS_CHAIN_HASH
    for row in rows:
        if row.seq != expected_seq:
            return {"verified": False, "reason": "seq_not_monotonic"}
        expected_seq += 1

        computed_entry_hash = canonical_hash(row.entry_json)
        if computed_entry_hash != row.entry_hash:
            return {"verified": False, "reason": "entry_hash_mismatch", "seq": row.seq}

        computed_chain_hash = chain_hash(prev_chain, row.entry_hash)
        if computed_chain_hash != row.chain_hash:
            return {"verified": False, "reason": "chain_hash_mismatch", "seq": row.seq}

        ok, reason = verify_hash_signature(row.chain_hash, row.signature, row.key_id)
        if not ok:
            return {
                "verified": False,
                "reason": reason or "signature_invalid",
                "seq": row.seq,
            }

        prev_chain = row.chain_hash

    return {"verified": True, "count": len(rows)}


_SEMVER_PATTERN = r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$"


class ModuleRegistrationRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    module_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    capabilities: list[str] = Field(min_length=1)
    required_scopes: list[str] = Field(default_factory=list)
    git_sha: str = Field(min_length=7, max_length=64)
    build_id: str = Field(min_length=1, max_length=128)
    sbom_ref: str | None = None
    evidence_bundle_id: str | None = None

    @field_validator("version")
    @classmethod
    def validate_semver(cls, value: str) -> str:
        import re

        if not re.match(_SEMVER_PATTERN, value):
            raise ValueError("version must be semver")
        return value


@router.post("/modules/register")
def register_module(
    req: ModuleRegistrationRequest, db: Session = Depends(_attestation_db)
) -> dict[str, Any]:
    registered_at = datetime.now(UTC)
    record = {
        **req.model_dump(),
        "registered_at": registered_at.isoformat().replace("+00:00", "Z"),
    }
    registration_hash = canonical_hash(record)
    key_id = signing_key_id()
    signature = sign_hash(registration_hash)

    row = ModuleRegistry(
        module_id=req.module_id,
        version=req.version,
        record_json=record,
        registration_hash=registration_hash,
        signature=signature,
        key_id=key_id,
        registered_at=registered_at,
    )
    db.add(row)
    db.commit()

    return {
        **record,
        "registration_hash": registration_hash,
        "signature": signature,
        "key_id": key_id,
    }


@router.get("/modules/{module_id}")
def get_module(
    module_id: str, db: Session = Depends(_attestation_db)
) -> list[dict[str, Any]]:
    rows = (
        db.query(ModuleRegistry)
        .filter(ModuleRegistry.module_id == module_id)
        .order_by(ModuleRegistry.registered_at.desc())
        .all()
    )
    return [
        {
            **row.record_json,
            "registration_hash": row.registration_hash,
            "signature": row.signature,
            "key_id": row.key_id,
        }
        for row in rows
    ]


@router.get("/modules")
def list_modules(
    module_id: str | None = None, db: Session = Depends(_attestation_db)
) -> list[dict[str, Any]]:
    q = db.query(ModuleRegistry)
    if module_id:
        q = q.filter(ModuleRegistry.module_id == module_id)
    rows = q.order_by(ModuleRegistry.registered_at.desc()).all()
    return [
        {
            **row.record_json,
            "registration_hash": row.registration_hash,
            "signature": row.signature,
            "key_id": row.key_id,
        }
        for row in rows
    ]


@router.get("/modules/enforce/{module_id}")
def enforce_module(
    module_id: str,
    version: str,
    tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: Session = Depends(_attestation_db),
) -> dict[str, Any]:
    row = (
        db.query(ModuleRegistry)
        .filter(
            and_(
                ModuleRegistry.module_id == module_id,
                ModuleRegistry.version == version,
            )
        )
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=403, detail="module_not_registered")

    if row.record_json.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=403, detail="module_tenant_mismatch")

    recomputed_hash = canonical_hash(row.record_json)
    if recomputed_hash != row.registration_hash:
        raise HTTPException(status_code=403, detail="module_registration_hash_invalid")

    ok, _ = verify_hash_signature(row.registration_hash, row.signature, row.key_id)
    if not ok:
        raise HTTPException(status_code=403, detail="module_signature_invalid")

    return {"allowed": True, "module_id": module_id, "version": version}
