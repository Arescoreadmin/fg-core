# api/cgin_transparency.py
"""CGIN Transparency Authority API — PR 17.7D.

All routes are tenant-scoped. All routes require governance:read.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.auth_scopes import require_bound_tenant, require_scopes
from services.cgin.transparency import (
    ACTIVE_TRANSPARENCY_LEDGER,
    TRANSPARENCY_VERSION,
)

router = APIRouter(tags=["cgin-transparency"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class TransparencyEntryResponse(BaseModel):
    entry_id: str
    entry_type: str
    authority_name: str
    authority_version: str
    artifact_digest: str
    parent_digest: str | None
    sequence_number: int
    generated_at: str
    tenant_fingerprint: str
    signature_algorithm: str
    signature_provider: str
    schema_version: str
    transparency_version: str


class TransparencyRootResponse(BaseModel):
    root_id: str
    root_digest: str
    entry_count: int
    generation_timestamp: str
    tree_height: int
    algorithm: str
    authority_version: str
    schema_version: str
    transparency_version: str
    signature: str
    signing_algorithm: str
    provider_name: str


class MembershipProofResponse(BaseModel):
    entry_id: str
    entry_index: int
    leaf_hash: str
    proof_path: list[dict]  # [{"side": "left"|"right", "hash": "hex..."}]
    root_digest: str
    root_id: str
    algorithm: str
    transparency_version: str


class TransparencyVerifyRequest(BaseModel):
    entry_id: str
    artifact_digest: str
    root_id: str | None = None


class TransparencyVerificationResponse(BaseModel):
    valid: bool
    entry_found: bool
    digest_match: bool
    proof_valid: bool
    root_signature_valid: bool
    errors: list[str]


class IntegrityStatisticsResponse(BaseModel):
    entry_count: int
    root_count: int
    tree_height: int
    average_proof_length: float
    algorithm: str
    transparency_version: str
    generated_at: str


class TransparencyHealthResponse(BaseModel):
    status: str  # "healthy" | "degraded" | "unavailable"
    entry_count: int
    root_count: int
    transparency_version: str
    generated_at: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/cgin/transparency/root/latest",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TransparencyRootResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "No root available yet"},
    },
)
def get_latest_root(request: Request) -> TransparencyRootResponse:
    """Return the most recently built Merkle root."""
    require_bound_tenant(request)
    root = ACTIVE_TRANSPARENCY_LEDGER._store.get_latest_root()
    if root is None:
        raise HTTPException(
            status_code=404, detail="No transparency root has been built yet"
        )
    return TransparencyRootResponse(
        root_id=root.root_id,
        root_digest=root.root_digest,
        entry_count=root.entry_count,
        generation_timestamp=root.generation_timestamp,
        tree_height=root.tree_height,
        algorithm=root.algorithm,
        authority_version=root.authority_version,
        schema_version=root.schema_version,
        transparency_version=root.transparency_version,
        signature=root.signature,
        signing_algorithm=root.signing_algorithm,
        provider_name=root.provider_name,
    )


@router.get(
    "/cgin/transparency/root/{root_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TransparencyRootResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Root not found"},
    },
)
def get_root(root_id: str, request: Request) -> TransparencyRootResponse:
    """Return a specific transparency root by ID."""
    require_bound_tenant(request)
    root = ACTIVE_TRANSPARENCY_LEDGER._store.get_root(root_id)
    if root is None:
        raise HTTPException(status_code=404, detail=f"Root {root_id!r} not found")
    return TransparencyRootResponse(
        root_id=root.root_id,
        root_digest=root.root_digest,
        entry_count=root.entry_count,
        generation_timestamp=root.generation_timestamp,
        tree_height=root.tree_height,
        algorithm=root.algorithm,
        authority_version=root.authority_version,
        schema_version=root.schema_version,
        transparency_version=root.transparency_version,
        signature=root.signature,
        signing_algorithm=root.signing_algorithm,
        provider_name=root.provider_name,
    )


@router.get(
    "/cgin/transparency/entries/{entry_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TransparencyEntryResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Entry not found"},
    },
)
def get_entry(entry_id: str, request: Request) -> TransparencyEntryResponse:
    """Return a specific transparency entry by ID."""
    require_bound_tenant(request)
    entry = ACTIVE_TRANSPARENCY_LEDGER._store.get_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Entry {entry_id!r} not found")
    return TransparencyEntryResponse(
        entry_id=entry.entry_id,
        entry_type=entry.entry_type,
        authority_name=entry.authority_name,
        authority_version=entry.authority_version,
        artifact_digest=entry.artifact_digest,
        parent_digest=entry.parent_digest,
        sequence_number=entry.sequence_number,
        generated_at=entry.generated_at,
        tenant_fingerprint=entry.tenant_fingerprint,
        signature_algorithm=entry.signature_algorithm,
        signature_provider=entry.signature_provider,
        schema_version=entry.schema_version,
        transparency_version=entry.transparency_version,
    )


@router.get(
    "/cgin/transparency/proof/{entry_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=MembershipProofResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Entry not found"},
        409: {"description": "No root built yet"},
    },
)
def get_proof(entry_id: str, request: Request) -> MembershipProofResponse:
    """Return a Merkle membership proof for the given entry_id."""
    require_bound_tenant(request)
    try:
        proof = ACTIVE_TRANSPARENCY_LEDGER.membership_proof(entry_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Entry {entry_id!r} not found")
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return MembershipProofResponse(
        entry_id=proof.entry_id,
        entry_index=proof.entry_index,
        leaf_hash=proof.leaf_hash,
        proof_path=[{"side": s, "hash": h} for s, h in proof.proof_path],
        root_digest=proof.root_digest,
        root_id=proof.root_id,
        algorithm=proof.algorithm,
        transparency_version=proof.transparency_version,
    )


@router.post(
    "/cgin/transparency/verify",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TransparencyVerificationResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        422: {"description": "Validation error"},
    },
)
def verify_entry(
    body: TransparencyVerifyRequest, request: Request
) -> TransparencyVerificationResponse:
    """Verify an entry's existence, digest match, and Merkle membership."""
    require_bound_tenant(request)
    result = ACTIVE_TRANSPARENCY_LEDGER.verify_entry(
        body.entry_id,
        body.artifact_digest,
        root_id=body.root_id,
    )
    return TransparencyVerificationResponse(
        valid=result.valid,
        entry_found=result.entry_found,
        digest_match=result.digest_match,
        proof_valid=result.proof_valid,
        root_signature_valid=result.root_signature_valid,
        errors=result.errors,
    )


@router.get(
    "/cgin/transparency/statistics",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=IntegrityStatisticsResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_statistics(request: Request) -> IntegrityStatisticsResponse:
    """Return current integrity statistics for the transparency ledger."""
    require_bound_tenant(request)
    stats = ACTIVE_TRANSPARENCY_LEDGER.statistics()
    return IntegrityStatisticsResponse(
        entry_count=stats.entry_count,
        root_count=stats.root_count,
        tree_height=stats.tree_height,
        average_proof_length=stats.average_proof_length,
        algorithm=stats.algorithm,
        transparency_version=stats.transparency_version,
        generated_at=stats.generated_at,
    )


@router.get(
    "/cgin/transparency/health",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TransparencyHealthResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_health(request: Request) -> TransparencyHealthResponse:
    """Return health status of the transparency ledger."""
    require_bound_tenant(request)
    try:
        entry_count = ACTIVE_TRANSPARENCY_LEDGER._store.entry_count()
        root_count = ACTIVE_TRANSPARENCY_LEDGER._store.root_count()
        status = "healthy"
    except Exception:
        entry_count = 0
        root_count = 0
        status = "unavailable"

    return TransparencyHealthResponse(
        status=status,
        entry_count=entry_count,
        root_count=root_count,
        transparency_version=TRANSPARENCY_VERSION,
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
    )
