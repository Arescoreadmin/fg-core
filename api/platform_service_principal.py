# api/platform_service_principal.py
"""Canonical platform service principal.

PR #586 adds the machine identity layer on top of PR #585's internal platform
authority. A platform service principal is the canonical non-human, non-customer,
non-portal, non-interactive machine identity used by FrostGate platform workloads
acting through the canonical internal platform authority.

The trust chain is:
    human actor or platform workload
        → platform service principal
        → canonical internal platform authority (PR #585 / frostgate-internal)
        → requested operation against target tenant
        → RBAC + policy + target-tenant authorization + RLS

This module owns:
- PSP domain model and lifecycle
- Idempotent deterministic bootstrap (created / reused / conflict / invalid_authority)
- Authority binding validation (internal_platform only; customer/demo/validation fail closed)
- Credential lifecycle delegation to CredentialAuthority
- Append-only audit event emission (platform_service_principal_events; mutation-protected by DB trigger)
- Authentication (credential + lifecycle check)
- Authorization (explicit permission check; target-tenant enforcement; never a global superuser)
- Request context fields for PR #587 actor attribution

PR #587 extends actor/service/target-tenant attribution.
PR #588 adds cryptographic provenance attestation.

Identity continuity model:
    The canonical PSP uses a single stable_key ("frostgate-platform-service") that is
    globally unique across all lifecycle states.  uq_psp_stable_key is a non-partial
    index, so a revoked PSP is permanently terminal — the identity slot is exhausted.
    Revocation cannot be undone by bootstrapping a replacement with the same stable_key.
    Recovery from revocation requires explicit operator intervention to insert a new row
    under a different stable_key, which the application bootstrap code does not support
    by design.  This prevents silent identity resurrection.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from api.credential_authority import (
    CredentialStateError,
    issue_credential,
    revoke_credential,
    rotate_credential,
)
from api.tenant_authority import policy_for_tenant_kind
from api.tenant_repository import TenantRepository, TenantRow

# ── Constants ────────────────────────────────────────────────────────────────

CANONICAL_PSP_STABLE_KEY = "frostgate-platform-service"
CANONICAL_PSP_DISPLAY_NAME = "FrostGate Platform Service"
PSP_PRINCIPAL_KIND = "platform_service"
PSP_CREDENTIAL_TYPE = "tenant_api_key"
PSP_CREDENTIAL_SLOT = "platform-service-principal:v1"
PSP_CREDENTIAL_SCOPES: tuple[str, ...] = (
    "platform.authority.verify",
    "platform.tenants.read",
    "platform.tenants.operate",
    "platform.credentials.rotate",
    "platform.audit.write",
)
PSP_CREDENTIAL_IDEMPOTENCY_KEY = "platform-service-principal:v1:bootstrap"
PSP_AUTHORITY_VERSION = 1
PSP_SERVICE = "frostgate-core"
PSP_ACTOR = "system:platform-service-principal"

# Default permission set granted to the canonical PSP at issuance.
# These are explicit — the PSP is never a global superuser.
PLATFORM_SERVICE_DEFAULT_PERMISSIONS: frozenset[str] = frozenset(PSP_CREDENTIAL_SCOPES)

ServicePrincipalEventType = Literal[
    "bootstrap_created",
    "bootstrap_reused",
    "bootstrap_conflict",
    "activation",
    "authentication_success",
    "authentication_failure",
    "authorization_allowed",
    "authorization_denied",
    "credential_issued",
    "credential_rotated",
    "credential_revoked",
    "principal_suspended",
    "principal_resumed",
    "principal_revoked",
    "invalid_authority_binding",
]

ServicePrincipalBootstrapStatus = Literal[
    "created", "reused", "conflict", "invalid_authority", "failed"
]

# ── Errors ───────────────────────────────────────────────────────────────────


class PlatformServicePrincipalError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


# ── Domain model ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PlatformServicePrincipalRow:
    id: str
    stable_key: str
    display_name: str
    authority_tenant_id: str
    principal_kind: str
    lifecycle_state: str
    authority_version: int
    credential_slot: str
    credential_type: str
    granted_permissions: list[str]
    created_at: Any
    updated_at: Any
    activated_at: Any
    suspended_at: Any
    revoked_at: Any
    metadata: dict[str, Any]


@dataclass(frozen=True)
class ServicePrincipalBootstrapResult:
    status: ServicePrincipalBootstrapStatus
    principal_id: Optional[str]
    stable_key: Optional[str]
    authority_tenant_id: Optional[str]
    lifecycle_state: Optional[str]
    credential_id: Optional[str]
    credential_issued: bool
    error_code: Optional[str] = None
    error_message: Optional[str] = None


@dataclass(frozen=True)
class RotationResult:
    """Returned by rotate_service_principal_credential."""

    status: "PlatformServicePrincipalStatus"
    plaintext_secret: Optional[str]


@dataclass(frozen=True)
class PlatformServicePrincipalStatus:
    """Safe, secret-free status snapshot for API responses and logging."""

    exists: bool
    id: Optional[str]
    stable_key: Optional[str]
    display_name: Optional[str]
    principal_kind: Optional[str]
    lifecycle_state: Optional[str]
    authority_tenant_id: Optional[str]
    authority_version: Optional[int]
    credential_type: Optional[str]
    credential_slot: Optional[str]
    credential_id: Optional[str]
    credential_status: Optional[str]
    credential_generation: int
    last_rotated_at: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]
    granted_permissions: list[str] = field(default_factory=list)

    def safe_dict(self) -> dict[str, Any]:
        return {
            "exists": self.exists,
            "id": self.id,
            "stable_key": self.stable_key,
            "display_name": self.display_name,
            "principal_kind": self.principal_kind,
            "lifecycle_state": self.lifecycle_state,
            "authority_tenant_id": self.authority_tenant_id,
            "authority_version": self.authority_version,
            "credential_type": self.credential_type,
            "credential_slot": self.credential_slot,
            "credential_id": self.credential_id,
            "credential_status": self.credential_status,
            "credential_generation": self.credential_generation,
            "last_rotated_at": self.last_rotated_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "granted_permissions": self.granted_permissions,
        }


# ── Helpers ──────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encode_meta(metadata: dict[str, Any] | None) -> str:
    return json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))


def _decode_permissions(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(p) for p in raw]
    try:
        decoded = json.loads(str(raw))
        if isinstance(decoded, list):
            return [str(p) for p in decoded]
    except (ValueError, TypeError):
        pass
    return []


def _row_from_db(row: Any) -> PlatformServicePrincipalRow:
    return PlatformServicePrincipalRow(
        id=str(row[0]),
        stable_key=str(row[1]),
        display_name=str(row[2]),
        authority_tenant_id=str(row[3]),
        principal_kind=str(row[4]),
        lifecycle_state=str(row[5]),
        authority_version=int(row[6] or PSP_AUTHORITY_VERSION),
        credential_slot=str(row[7]),
        credential_type=str(row[8]),
        granted_permissions=_decode_permissions(row[9]),
        created_at=row[10],
        updated_at=row[11],
        activated_at=row[12],
        suspended_at=row[13],
        revoked_at=row[14],
        metadata=json.loads(row[15]) if isinstance(row[15], str) else (row[15] or {}),
    )


_SELECT_PSP = """
SELECT id, stable_key, display_name, authority_tenant_id,
       principal_kind, lifecycle_state, authority_version,
       credential_slot, credential_type, granted_permissions,
       created_at, updated_at, activated_at, suspended_at, revoked_at, metadata
FROM platform_service_principals
"""


def _fetch_by_stable_key(
    conn: Connection, stable_key: str
) -> Optional[PlatformServicePrincipalRow]:
    row = conn.execute(
        text(f"{_SELECT_PSP} WHERE stable_key = :sk"),
        {"sk": stable_key},
    ).fetchone()
    return _row_from_db(row) if row is not None else None


def _fetch_credential_row(
    conn: Connection, tenant_id: str, credential_type: str, credential_slot: str
) -> Any:
    return conn.execute(
        text(
            """
            SELECT tc.credential_id, tc.status, tc.generation,
                   tc.rotated_at, cs.current_generation
            FROM credential_slots cs
            LEFT JOIN tenant_credentials tc
              ON tc.tenant_id = cs.tenant_id
             AND tc.credential_type = cs.credential_type
             AND tc.credential_slot = cs.credential_slot
             AND tc.generation = cs.current_generation
            WHERE cs.tenant_id = :tenant_id
              AND cs.credential_type = :credential_type
              AND cs.credential_slot = :credential_slot
            """
        ),
        {
            "tenant_id": tenant_id,
            "credential_type": credential_type,
            "credential_slot": credential_slot,
        },
    ).fetchone()


def _status_from_psp_row(
    engine: Engine,
    psp: Optional[PlatformServicePrincipalRow],
) -> PlatformServicePrincipalStatus:
    if psp is None:
        return PlatformServicePrincipalStatus(
            exists=False,
            id=None,
            stable_key=None,
            display_name=None,
            principal_kind=None,
            lifecycle_state=None,
            authority_tenant_id=None,
            authority_version=None,
            credential_type=None,
            credential_slot=None,
            credential_id=None,
            credential_status=None,
            credential_generation=0,
            last_rotated_at=None,
            created_at=None,
            updated_at=None,
        )

    with engine.connect() as conn:
        cred = _fetch_credential_row(
            conn, psp.authority_tenant_id, psp.credential_type, psp.credential_slot
        )

    credential_id = str(cred[0]) if cred and cred[0] else None
    credential_status = str(cred[1]) if cred and cred[1] else None
    credential_generation = int(cred[4] or cred[2] or 0) if cred else 0
    last_rotated_at = str(cred[3]) if cred and cred[3] else None
    created_at = str(psp.created_at) if psp.created_at else None
    updated_at = str(psp.updated_at) if psp.updated_at else None

    return PlatformServicePrincipalStatus(
        exists=True,
        id=psp.id,
        stable_key=psp.stable_key,
        display_name=psp.display_name,
        principal_kind=psp.principal_kind,
        lifecycle_state=psp.lifecycle_state,
        authority_tenant_id=psp.authority_tenant_id,
        authority_version=psp.authority_version,
        credential_type=psp.credential_type,
        credential_slot=psp.credential_slot,
        credential_id=credential_id,
        credential_status=credential_status,
        credential_generation=credential_generation,
        last_rotated_at=last_rotated_at,
        created_at=created_at,
        updated_at=updated_at,
        granted_permissions=psp.granted_permissions,
    )


# ── Audit events ─────────────────────────────────────────────────────────────


def emit_service_principal_event(
    conn: Connection,
    *,
    event_type: ServicePrincipalEventType,
    actor_id: str,
    service_id: str,
    authority_tenant_id: Optional[str],
    service_principal_id: Optional[str] = None,
    stable_key: Optional[str] = None,
    target_tenant_id: Optional[str] = None,
    credential_id: Optional[str] = None,
    credential_type: Optional[str] = None,
    credential_slot: Optional[str] = None,
    generation: Optional[int] = None,
    request_id: Optional[str] = None,
    permission: Optional[str] = None,
    outcome: str = "success",
    failure_reason: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """Append an audit event to platform_service_principal_events.

    The table is append-only and mutation-protected by a database trigger
    (pspe_prevent_mutation raises restrict_violation on UPDATE or DELETE).
    Cryptographic provenance (hash chaining, signatures) is deferred to PR #588.

    No credential material (secrets, hashes) is ever stored here.
    actor/service/target-tenant attribution extended in PR #588.
    """
    if authority_tenant_id and conn.dialect.name == "postgresql":
        conn.execute(
            text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
            {"tid": authority_tenant_id},
        )

    conn.execute(
        text(
            """
            INSERT INTO platform_service_principal_events (
                event_id, event_type,
                service_principal_id, stable_key,
                actor_id, service_id,
                authority_tenant_id, target_tenant_id,
                credential_id, credential_type, credential_slot, generation,
                request_id, permission,
                outcome, failure_reason, occurred_at, metadata, schema_version
            ) VALUES (
                :event_id, :event_type,
                :spid, :stable_key,
                :actor_id, :service_id,
                :authority_tenant_id, :target_tenant_id,
                :credential_id, :credential_type, :credential_slot, :generation,
                :request_id, :permission,
                :outcome, :failure_reason, :occurred_at, :metadata, 1
            )
            """
        ),
        {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "spid": service_principal_id,
            "stable_key": stable_key or CANONICAL_PSP_STABLE_KEY,
            "actor_id": actor_id,
            "service_id": service_id,
            "authority_tenant_id": authority_tenant_id,
            "target_tenant_id": target_tenant_id,
            "credential_id": credential_id,
            "credential_type": credential_type,
            "credential_slot": credential_slot,
            "generation": generation,
            "request_id": request_id,
            "permission": permission,
            "outcome": outcome,
            "failure_reason": failure_reason,
            "occurred_at": _now_iso(),
            "metadata": _encode_meta(metadata),
        },
    )


# ── Authority binding validation ─────────────────────────────────────────────


def _validate_authority_tenant(record: TenantRow) -> None:
    """Fail closed for any tenant that is not an active internal_platform authority.

    Customer, demo, validation, and unknown tenant kinds are all rejected.
    Missing or archived tenants are rejected.
    """
    policy = policy_for_tenant_kind(record.tenant_kind)
    if record.lifecycle_state != "active" or not policy.operator_authority_allowed:
        raise PlatformServicePrincipalError(
            "AUTHORITY_TENANT_NOT_ELIGIBLE",
            f"tenant {record.tenant_id!r} (kind={record.tenant_kind!r}, "
            f"state={record.lifecycle_state!r}) is not eligible as a "
            "platform service principal authority",
        )


def _find_canonical_internal_authority(engine: Engine) -> TenantRow:
    """Return the single active internal_platform tenant.

    Fails closed for: missing, multiple candidates, non-active, non-internal.
    """
    repo = TenantRepository(engine)
    rows = repo.list_by_kind("internal_platform", include_archived=False)

    if not rows:
        raise PlatformServicePrincipalError(
            "INTERNAL_AUTHORITY_MISSING",
            "no active internal_platform tenant exists; "
            "run bootstrap_internal_platform_authority first",
        )
    if len(rows) > 1:
        raise PlatformServicePrincipalError(
            "INTERNAL_AUTHORITY_AMBIGUOUS",
            f"multiple internal_platform tenants exist ({[r.tenant_id for r in rows]}); "
            "exactly one is required for deterministic bootstrap",
        )

    record = rows[0]
    _validate_authority_tenant(record)
    return record


# ── Bootstrap ────────────────────────────────────────────────────────────────


def bootstrap_platform_service_principal(
    engine: Engine,
    *,
    actor_id: str = PSP_ACTOR,
    service_id: str = PSP_SERVICE,
    request_id: Optional[str] = None,
) -> ServicePrincipalBootstrapResult:
    """Idempotent, deterministic bootstrap of the canonical platform service principal.

    Returns a ServicePrincipalBootstrapResult with status:
      created           — PSP was created now
      reused            — PSP already existed; returned as-is
      conflict          — a PSP with conflicting stable_key or authority exists
      invalid_authority — the bound authority tenant is ineligible
      failed            — unexpected error during creation

    Concurrent calls are safe: a unique index on stable_key + a partial unique
    index on (authority_tenant_id, principal_kind) WHERE state != 'revoked'
    serialize concurrent inserts at the DB level.
    """
    try:
        authority = _find_canonical_internal_authority(engine)
    except PlatformServicePrincipalError as exc:
        with engine.begin() as conn:
            emit_service_principal_event(
                conn,
                event_type="invalid_authority_binding",
                actor_id=actor_id,
                service_id=service_id,
                authority_tenant_id=None,
                request_id=request_id,
                outcome="failure",
                failure_reason=exc.code,
                metadata={"error_code": exc.code},
            )
        return ServicePrincipalBootstrapResult(
            status="invalid_authority",
            principal_id=None,
            stable_key=None,
            authority_tenant_id=None,
            lifecycle_state=None,
            credential_id=None,
            credential_issued=False,
            error_code=exc.code,
            error_message=str(exc),
        )

    # Check for existing PSP record
    with engine.connect() as conn:
        psp = _fetch_by_stable_key(conn, CANONICAL_PSP_STABLE_KEY)

    if psp is not None:
        # Validate binding still matches
        if psp.authority_tenant_id != authority.tenant_id:
            with engine.begin() as conn:
                emit_service_principal_event(
                    conn,
                    event_type="bootstrap_conflict",
                    actor_id=actor_id,
                    service_id=service_id,
                    authority_tenant_id=authority.tenant_id,
                    service_principal_id=psp.id,
                    stable_key=psp.stable_key,
                    request_id=request_id,
                    outcome="failure",
                    failure_reason="authority_tenant_id_mismatch",
                    metadata={
                        "existing_authority": psp.authority_tenant_id,
                        "expected_authority": authority.tenant_id,
                    },
                )
            return ServicePrincipalBootstrapResult(
                status="conflict",
                principal_id=psp.id,
                stable_key=psp.stable_key,
                authority_tenant_id=psp.authority_tenant_id,
                lifecycle_state=psp.lifecycle_state,
                credential_id=None,
                credential_issued=False,
                error_code="AUTHORITY_BINDING_MISMATCH",
                error_message=(
                    f"existing PSP is bound to {psp.authority_tenant_id!r} "
                    f"but canonical authority is {authority.tenant_id!r}"
                ),
            )

        with engine.begin() as conn:
            emit_service_principal_event(
                conn,
                event_type="bootstrap_reused",
                actor_id=actor_id,
                service_id=service_id,
                authority_tenant_id=authority.tenant_id,
                service_principal_id=psp.id,
                stable_key=psp.stable_key,
                request_id=request_id,
                metadata={"authority_version": psp.authority_version},
            )

        with engine.connect() as conn:
            cred_row = _fetch_credential_row(
                conn, authority.tenant_id, PSP_CREDENTIAL_TYPE, PSP_CREDENTIAL_SLOT
            )
        credential_id = str(cred_row[0]) if cred_row and cred_row[0] else None

        return ServicePrincipalBootstrapResult(
            status="reused",
            principal_id=psp.id,
            stable_key=psp.stable_key,
            authority_tenant_id=psp.authority_tenant_id,
            lifecycle_state=psp.lifecycle_state,
            credential_id=credential_id,
            credential_issued=False,
        )

    # Create new PSP record
    new_id = str(uuid.uuid4())
    now = _now_iso()
    permissions_json = json.dumps(sorted(PLATFORM_SERVICE_DEFAULT_PERMISSIONS))
    meta = {
        "authority": "internal_platform",
        "authority_version": PSP_AUTHORITY_VERSION,
        "managed_by": "frostgate-core",
        "customer_visible": False,
        "portal_enabled": False,
        "billing_eligible": False,
        "created_by_pr": "586",
    }

    try:
        with engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                conn.execute(
                    text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
                    {"tid": authority.tenant_id},
                )
            conn.execute(
                text(
                    """
                    INSERT INTO platform_service_principals (
                        id, stable_key, display_name, authority_tenant_id,
                        principal_kind, lifecycle_state, authority_version,
                        credential_slot, credential_type, granted_permissions,
                        created_at, updated_at, activated_at,
                        metadata, schema_version
                    ) VALUES (
                        :id, :stable_key, :display_name, :authority_tenant_id,
                        :principal_kind, :lifecycle_state, :authority_version,
                        :credential_slot, :credential_type, :granted_permissions,
                        :now, :now, :now,
                        :metadata, 1
                    )
                    """
                ),
                {
                    "id": new_id,
                    "stable_key": CANONICAL_PSP_STABLE_KEY,
                    "display_name": CANONICAL_PSP_DISPLAY_NAME,
                    "authority_tenant_id": authority.tenant_id,
                    "principal_kind": PSP_PRINCIPAL_KIND,
                    "lifecycle_state": "active",
                    "authority_version": PSP_AUTHORITY_VERSION,
                    "credential_slot": PSP_CREDENTIAL_SLOT,
                    "credential_type": PSP_CREDENTIAL_TYPE,
                    "granted_permissions": permissions_json,
                    "now": now,
                    "metadata": _encode_meta(meta),
                },
            )
            emit_service_principal_event(
                conn,
                event_type="bootstrap_created",
                actor_id=actor_id,
                service_id=service_id,
                authority_tenant_id=authority.tenant_id,
                service_principal_id=new_id,
                stable_key=CANONICAL_PSP_STABLE_KEY,
                request_id=request_id,
                metadata={"authority_version": PSP_AUTHORITY_VERSION},
            )
    except IntegrityError:
        # Concurrent bootstrap: another request won the INSERT race.
        # Reload to distinguish a legitimate concurrent bootstrap (same authority →
        # return "reused") from a genuine conflict (different authority → "conflict").
        with engine.connect() as conn:
            concurrent_psp = _fetch_by_stable_key(conn, CANONICAL_PSP_STABLE_KEY)

        if (
            concurrent_psp is not None
            and concurrent_psp.authority_tenant_id == authority.tenant_id
        ):
            # Legitimate race: the other bootstrapper created the exact same identity.
            with engine.begin() as conn:
                emit_service_principal_event(
                    conn,
                    event_type="bootstrap_reused",
                    actor_id=actor_id,
                    service_id=service_id,
                    authority_tenant_id=authority.tenant_id,
                    service_principal_id=concurrent_psp.id,
                    stable_key=concurrent_psp.stable_key,
                    request_id=request_id,
                    metadata={"authority_version": concurrent_psp.authority_version},
                )
            with engine.connect() as conn:
                cred_row = _fetch_credential_row(
                    conn,
                    authority.tenant_id,
                    PSP_CREDENTIAL_TYPE,
                    PSP_CREDENTIAL_SLOT,
                )
            return ServicePrincipalBootstrapResult(
                status="reused",
                principal_id=concurrent_psp.id,
                stable_key=concurrent_psp.stable_key,
                authority_tenant_id=concurrent_psp.authority_tenant_id,
                lifecycle_state=concurrent_psp.lifecycle_state,
                credential_id=str(cred_row[0]) if cred_row and cred_row[0] else None,
                credential_issued=False,
            )

        # Genuine conflict: PSP was created concurrently for a different authority.
        with engine.begin() as conn:
            emit_service_principal_event(
                conn,
                event_type="bootstrap_conflict",
                actor_id=actor_id,
                service_id=service_id,
                authority_tenant_id=authority.tenant_id,
                request_id=request_id,
                outcome="failure",
                failure_reason="integrity_conflict_different_authority",
                metadata={
                    "existing_authority": (
                        concurrent_psp.authority_tenant_id if concurrent_psp else None
                    )
                },
            )
        return ServicePrincipalBootstrapResult(
            status="conflict",
            principal_id=concurrent_psp.id if concurrent_psp else None,
            stable_key=CANONICAL_PSP_STABLE_KEY,
            authority_tenant_id=authority.tenant_id,
            lifecycle_state=concurrent_psp.lifecycle_state if concurrent_psp else None,
            credential_id=None,
            credential_issued=False,
            error_code="BOOTSTRAP_INTEGRITY_CONFLICT",
            error_message=(
                "concurrent bootstrap created a PSP bound to a different authority"
            ),
        )

    # Issue credential
    credential_issued = False
    credential_id = None
    try:
        issued = issue_credential(
            engine,
            tenant_id=authority.tenant_id,
            credential_type=PSP_CREDENTIAL_TYPE,
            credential_slot=PSP_CREDENTIAL_SLOT,
            scopes=list(PSP_CREDENTIAL_SCOPES),
            actor_id=actor_id,
            request_id=request_id,
            idempotency_key=PSP_CREDENTIAL_IDEMPOTENCY_KEY,
            metadata={
                "authority": "internal_platform",
                "service_principal_id": new_id,
                "stable_key": CANONICAL_PSP_STABLE_KEY,
                "authority_version": PSP_AUTHORITY_VERSION,
                "service": service_id,
                "raw_secret_exposed": False,
            },
        )
        credential_id = issued.record.credential_id
        credential_issued = issued.plaintext_secret is not None
        with engine.begin() as conn:
            emit_service_principal_event(
                conn,
                event_type="credential_issued",
                actor_id=actor_id,
                service_id=service_id,
                authority_tenant_id=authority.tenant_id,
                service_principal_id=new_id,
                stable_key=CANONICAL_PSP_STABLE_KEY,
                credential_id=issued.record.credential_id,
                credential_type=issued.record.credential_type,
                credential_slot=issued.record.credential_slot,
                generation=issued.record.generation,
                request_id=request_id,
                metadata={"plaintext_exposed": False},
            )
    except CredentialStateError:
        credential_issued = False

    return ServicePrincipalBootstrapResult(
        status="created",
        principal_id=new_id,
        stable_key=CANONICAL_PSP_STABLE_KEY,
        authority_tenant_id=authority.tenant_id,
        lifecycle_state="active",
        credential_id=credential_id,
        credential_issued=credential_issued,
    )


# ── Status read ──────────────────────────────────────────────────────────────


def read_service_principal_status(engine: Engine) -> PlatformServicePrincipalStatus:
    """Return safe, secret-free status of the canonical PSP."""
    with engine.connect() as conn:
        psp = _fetch_by_stable_key(conn, CANONICAL_PSP_STABLE_KEY)
    return _status_from_psp_row(engine, psp)


# ── Lifecycle mutations ──────────────────────────────────────────────────────


def _fetch_active_psp(engine: Engine) -> PlatformServicePrincipalRow:
    """Load the canonical PSP; raise if it does not exist."""
    with engine.connect() as conn:
        psp = _fetch_by_stable_key(conn, CANONICAL_PSP_STABLE_KEY)
    if psp is None:
        raise PlatformServicePrincipalError(
            "SERVICE_PRINCIPAL_NOT_FOUND",
            "canonical platform service principal has not been bootstrapped",
        )
    return psp


def rotate_service_principal_credential(
    engine: Engine,
    *,
    actor_id: str,
    request_id: Optional[str] = None,
) -> RotationResult:
    """Rotate the PSP credential via CredentialAuthority.

    Revoked or missing PSPs fail closed.
    Returns a RotationResult with the updated status and the new plaintext secret.
    """
    psp = _fetch_active_psp(engine)

    if psp.lifecycle_state == "revoked":
        raise PlatformServicePrincipalError(
            "SERVICE_PRINCIPAL_REVOKED",
            "revoked platform service principals cannot rotate their credential",
        )

    rotated = rotate_credential(
        engine,
        tenant_id=psp.authority_tenant_id,
        credential_type=PSP_CREDENTIAL_TYPE,
        credential_slot=PSP_CREDENTIAL_SLOT,
        actor_id=actor_id,
        request_id=request_id,
    )
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(
                text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
                {"tid": psp.authority_tenant_id},
            )
        conn.execute(
            text(
                "UPDATE platform_service_principals "
                "SET updated_at = :now WHERE id = :psp_id"
            ),
            {"now": _now_iso(), "psp_id": psp.id},
        )
        emit_service_principal_event(
            conn,
            event_type="credential_rotated",
            actor_id=actor_id,
            service_id=PSP_SERVICE,
            authority_tenant_id=psp.authority_tenant_id,
            service_principal_id=psp.id,
            stable_key=psp.stable_key,
            credential_id=rotated.record.credential_id,
            credential_type=rotated.record.credential_type,
            credential_slot=rotated.record.credential_slot,
            generation=rotated.record.generation,
            request_id=request_id,
        )

    return RotationResult(
        status=read_service_principal_status(engine),
        plaintext_secret=rotated.plaintext_secret,
    )


def suspend_service_principal(
    engine: Engine,
    *,
    actor_id: str,
    reason: Optional[str] = None,
    request_id: Optional[str] = None,
) -> PlatformServicePrincipalStatus:
    """Suspend the canonical PSP.

    Suspended principals cannot authenticate until resumed.
    Revoked principals cannot be suspended.
    """
    psp = _fetch_active_psp(engine)

    if psp.lifecycle_state == "revoked":
        raise PlatformServicePrincipalError(
            "SERVICE_PRINCIPAL_REVOKED",
            "revoked platform service principals cannot be suspended",
        )
    if psp.lifecycle_state == "suspended":
        raise PlatformServicePrincipalError(
            "SERVICE_PRINCIPAL_ALREADY_SUSPENDED",
            "platform service principal is already suspended",
        )

    now = _now_iso()
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(
                text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
                {"tid": psp.authority_tenant_id},
            )
        result_proxy = conn.execute(
            text(
                "UPDATE platform_service_principals "
                "SET lifecycle_state = 'suspended', suspended_at = :now, "
                "updated_at = :now WHERE id = :psp_id AND lifecycle_state = 'active'"
            ),
            {"now": now, "psp_id": psp.id},
        )
        if result_proxy.rowcount == 0:
            raise PlatformServicePrincipalError(
                "SERVICE_PRINCIPAL_CONCURRENT_TRANSITION",
                "lifecycle state changed concurrently; re-read and retry",
            )
        emit_service_principal_event(
            conn,
            event_type="principal_suspended",
            actor_id=actor_id,
            service_id=PSP_SERVICE,
            authority_tenant_id=psp.authority_tenant_id,
            service_principal_id=psp.id,
            stable_key=psp.stable_key,
            request_id=request_id,
            metadata={"reason": reason},
        )

    return read_service_principal_status(engine)


def resume_service_principal(
    engine: Engine,
    *,
    actor_id: str,
    request_id: Optional[str] = None,
) -> PlatformServicePrincipalStatus:
    """Resume a suspended PSP.

    Revoked PSPs cannot be resumed (irreversible).
    Active PSPs are returned as-is without error.
    """
    psp = _fetch_active_psp(engine)

    if psp.lifecycle_state == "revoked":
        raise PlatformServicePrincipalError(
            "SERVICE_PRINCIPAL_REVOKED",
            "revoked platform service principals cannot be resumed",
        )
    if psp.lifecycle_state == "active":
        return read_service_principal_status(engine)

    now = _now_iso()
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(
                text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
                {"tid": psp.authority_tenant_id},
            )
        result_proxy = conn.execute(
            text(
                "UPDATE platform_service_principals "
                "SET lifecycle_state = 'active', suspended_at = NULL, "
                "activated_at = :now, updated_at = :now "
                "WHERE id = :psp_id AND lifecycle_state = 'suspended'"
            ),
            {"now": now, "psp_id": psp.id},
        )
        if result_proxy.rowcount == 0:
            raise PlatformServicePrincipalError(
                "SERVICE_PRINCIPAL_CONCURRENT_TRANSITION",
                "lifecycle state changed concurrently; re-read and retry",
            )
        emit_service_principal_event(
            conn,
            event_type="principal_resumed",
            actor_id=actor_id,
            service_id=PSP_SERVICE,
            authority_tenant_id=psp.authority_tenant_id,
            service_principal_id=psp.id,
            stable_key=psp.stable_key,
            request_id=request_id,
        )

    return read_service_principal_status(engine)


def revoke_service_principal(
    engine: Engine,
    *,
    actor_id: str,
    reason: Optional[str] = None,
    request_id: Optional[str] = None,
) -> PlatformServicePrincipalStatus:
    """Permanently revoke the canonical PSP.

    Revocation is irreversible. The credential is also revoked through
    CredentialAuthority. A new PSP must be bootstrapped to recover.
    """
    psp = _fetch_active_psp(engine)

    if psp.lifecycle_state == "revoked":
        raise PlatformServicePrincipalError(
            "SERVICE_PRINCIPAL_ALREADY_REVOKED",
            "platform service principal is already revoked",
        )

    # Revoke the credential first
    with engine.connect() as conn:
        cred_row = _fetch_credential_row(
            conn, psp.authority_tenant_id, PSP_CREDENTIAL_TYPE, PSP_CREDENTIAL_SLOT
        )
    revoked_cred = None
    if cred_row and cred_row[0] and str(cred_row[1]) == "active":
        try:
            revoked_cred = revoke_credential(
                engine,
                credential_id=str(cred_row[0]),
                tenant_id=psp.authority_tenant_id,
                actor_id=actor_id,
                reason=reason or "service_principal_revoked",
                request_id=request_id,
            )
        except CredentialStateError:
            pass

    now = _now_iso()
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(
                text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
                {"tid": psp.authority_tenant_id},
            )
        conn.execute(
            text(
                "UPDATE platform_service_principals "
                "SET lifecycle_state = 'revoked', revoked_at = :now, "
                "updated_at = :now WHERE id = :psp_id"
            ),
            {"now": now, "psp_id": psp.id},
        )
        emit_service_principal_event(
            conn,
            event_type="credential_revoked",
            actor_id=actor_id,
            service_id=PSP_SERVICE,
            authority_tenant_id=psp.authority_tenant_id,
            service_principal_id=psp.id,
            stable_key=psp.stable_key,
            credential_id=revoked_cred.credential_id if revoked_cred else None,
            credential_type=revoked_cred.credential_type if revoked_cred else None,
            credential_slot=revoked_cred.credential_slot if revoked_cred else None,
            generation=revoked_cred.generation if revoked_cred else None,
            request_id=request_id,
            metadata={"reason": reason},
        )
        emit_service_principal_event(
            conn,
            event_type="principal_revoked",
            actor_id=actor_id,
            service_id=PSP_SERVICE,
            authority_tenant_id=psp.authority_tenant_id,
            service_principal_id=psp.id,
            stable_key=psp.stable_key,
            request_id=request_id,
            metadata={"reason": reason},
        )

    return read_service_principal_status(engine)


# ── Authentication and authorization ─────────────────────────────────────────


@dataclass(frozen=True)
class ServicePrincipalAuthResult:
    """Result of authenticate_service_principal()."""

    authenticated: bool
    principal_id: Optional[str]
    authority_tenant_id: Optional[str]
    lifecycle_state: Optional[str]
    denial_code: Optional[str] = None


def authenticate_service_principal(
    engine: Engine,
    *,
    actor_id: str,
    service_id: str = PSP_SERVICE,
    request_id: Optional[str] = None,
) -> ServicePrincipalAuthResult:
    """Verify the canonical PSP exists, is active, and its credential is active.

    This is not a secret-based auth check (that lives in CredentialAuthority).
    This verifies the machine identity state for platform operations.
    Emits authentication_success or authentication_failure audit events.
    """
    try:
        with engine.connect() as conn:
            psp = _fetch_by_stable_key(conn, CANONICAL_PSP_STABLE_KEY)
    except (OperationalError, ProgrammingError):
        return ServicePrincipalAuthResult(
            authenticated=False,
            principal_id=None,
            authority_tenant_id=None,
            lifecycle_state=None,
            denial_code="SERVICE_PRINCIPAL_DB_UNAVAILABLE",
        )

    def _deny(
        code: str, psp_id: Optional[str], auth_tid: Optional[str], state: Optional[str]
    ) -> ServicePrincipalAuthResult:
        try:
            with engine.begin() as conn:
                emit_service_principal_event(
                    conn,
                    event_type="authentication_failure",
                    actor_id=actor_id,
                    service_id=service_id,
                    authority_tenant_id=auth_tid,
                    service_principal_id=psp_id,
                    request_id=request_id,
                    outcome="denied",
                    failure_reason=code,
                )
        except Exception:  # noqa: BLE001 — best-effort audit
            pass
        return ServicePrincipalAuthResult(
            authenticated=False,
            principal_id=psp_id,
            authority_tenant_id=auth_tid,
            lifecycle_state=state,
            denial_code=code,
        )

    if psp is None:
        return _deny("SERVICE_PRINCIPAL_NOT_FOUND", None, None, None)

    if psp.lifecycle_state != "active":
        return _deny(
            "SERVICE_PRINCIPAL_" + psp.lifecycle_state.upper(),
            psp.id,
            psp.authority_tenant_id,
            psp.lifecycle_state,
        )

    with engine.connect() as conn:
        cred_row = _fetch_credential_row(
            conn, psp.authority_tenant_id, PSP_CREDENTIAL_TYPE, PSP_CREDENTIAL_SLOT
        )

    if not cred_row or not cred_row[0]:
        return _deny(
            "SERVICE_PRINCIPAL_NO_CREDENTIAL",
            psp.id,
            psp.authority_tenant_id,
            psp.lifecycle_state,
        )

    if str(cred_row[1]) != "active":
        return _deny(
            "SERVICE_PRINCIPAL_CREDENTIAL_" + str(cred_row[1]).upper(),
            psp.id,
            psp.authority_tenant_id,
            psp.lifecycle_state,
        )

    with engine.begin() as conn:
        emit_service_principal_event(
            conn,
            event_type="authentication_success",
            actor_id=actor_id,
            service_id=service_id,
            authority_tenant_id=psp.authority_tenant_id,
            service_principal_id=psp.id,
            stable_key=psp.stable_key,
            credential_id=str(cred_row[0]),
            credential_type=PSP_CREDENTIAL_TYPE,
            credential_slot=PSP_CREDENTIAL_SLOT,
            generation=int(cred_row[4] or cred_row[2] or 0),
            request_id=request_id,
        )

    return ServicePrincipalAuthResult(
        authenticated=True,
        principal_id=psp.id,
        authority_tenant_id=psp.authority_tenant_id,
        lifecycle_state=psp.lifecycle_state,
    )


@dataclass(frozen=True)
class ServicePrincipalAuthzResult:
    """Result of authorize_service_principal()."""

    allowed: bool
    principal_id: Optional[str]
    authority_tenant_id: Optional[str]
    permission: Optional[str]
    target_tenant_id: Optional[str]
    denial_code: Optional[str] = None


def authorize_service_principal(
    engine: Engine,
    *,
    actor_id: str,
    permission: str,
    target_tenant_id: Optional[str],
    service_id: str = PSP_SERVICE,
    request_id: Optional[str] = None,
) -> ServicePrincipalAuthzResult:
    """Check that the canonical PSP is authenticated and has the requested permission.

    This function is a complete authorization gate — it enforces:
    1. PSP existence and active lifecycle (authentication)
    2. Explicit permission in granted_permissions (RBAC)
    3. target_tenant_id is non-None, non-empty, and not the authority tenant
    4. Target tenant exists and is active (tenant lifecycle gate)

    Passing this gate does NOT bypass further route-level policy checks
    (e.g. RLS must still be set to the target tenant's context on each query).

    Emits authorization_allowed or authorization_denied audit events.
    """
    # Gate 1: target_tenant_id must be explicit and non-empty.
    if not target_tenant_id or not target_tenant_id.strip():
        return ServicePrincipalAuthzResult(
            allowed=False,
            principal_id=None,
            authority_tenant_id=None,
            permission=permission,
            target_tenant_id=target_tenant_id,
            denial_code="TARGET_TENANT_REQUIRED",
        )

    auth = authenticate_service_principal(
        engine,
        actor_id=actor_id,
        service_id=service_id,
        request_id=request_id,
    )

    if not auth.authenticated:
        return ServicePrincipalAuthzResult(
            allowed=False,
            principal_id=auth.principal_id,
            authority_tenant_id=auth.authority_tenant_id,
            permission=permission,
            target_tenant_id=target_tenant_id,
            denial_code=auth.denial_code,
        )

    # Gate 2: authority tenant must not silently become the target tenant.
    if auth.authority_tenant_id and target_tenant_id == auth.authority_tenant_id:
        try:
            with engine.begin() as conn:
                emit_service_principal_event(
                    conn,
                    event_type="authorization_denied",
                    actor_id=actor_id,
                    service_id=service_id,
                    authority_tenant_id=auth.authority_tenant_id,
                    service_principal_id=auth.principal_id,
                    target_tenant_id=target_tenant_id,
                    permission=permission,
                    request_id=request_id,
                    outcome="denied",
                    failure_reason="AUTHORITY_TENANT_CANNOT_BE_TARGET",
                )
        except Exception:  # noqa: BLE001
            pass
        return ServicePrincipalAuthzResult(
            allowed=False,
            principal_id=auth.principal_id,
            authority_tenant_id=auth.authority_tenant_id,
            permission=permission,
            target_tenant_id=target_tenant_id,
            denial_code="AUTHORITY_TENANT_CANNOT_BE_TARGET",
        )

    # Gate 3: target tenant must exist and be active.
    try:
        target_record = TenantRepository(engine).get(target_tenant_id)
    except Exception:  # noqa: BLE001
        target_record = None

    if target_record is None:
        try:
            with engine.begin() as conn:
                emit_service_principal_event(
                    conn,
                    event_type="authorization_denied",
                    actor_id=actor_id,
                    service_id=service_id,
                    authority_tenant_id=auth.authority_tenant_id,
                    service_principal_id=auth.principal_id,
                    target_tenant_id=target_tenant_id,
                    permission=permission,
                    request_id=request_id,
                    outcome="denied",
                    failure_reason="TARGET_TENANT_NOT_FOUND",
                )
        except Exception:  # noqa: BLE001
            pass
        return ServicePrincipalAuthzResult(
            allowed=False,
            principal_id=auth.principal_id,
            authority_tenant_id=auth.authority_tenant_id,
            permission=permission,
            target_tenant_id=target_tenant_id,
            denial_code="TARGET_TENANT_NOT_FOUND",
        )

    if target_record.lifecycle_state not in ("active",):
        try:
            with engine.begin() as conn:
                emit_service_principal_event(
                    conn,
                    event_type="authorization_denied",
                    actor_id=actor_id,
                    service_id=service_id,
                    authority_tenant_id=auth.authority_tenant_id,
                    service_principal_id=auth.principal_id,
                    target_tenant_id=target_tenant_id,
                    permission=permission,
                    request_id=request_id,
                    outcome="denied",
                    failure_reason=f"TARGET_TENANT_{target_record.lifecycle_state.upper()}",
                )
        except Exception:  # noqa: BLE001
            pass
        return ServicePrincipalAuthzResult(
            allowed=False,
            principal_id=auth.principal_id,
            authority_tenant_id=auth.authority_tenant_id,
            permission=permission,
            target_tenant_id=target_tenant_id,
            denial_code=f"TARGET_TENANT_{target_record.lifecycle_state.upper()}",
        )

    with engine.connect() as conn:
        psp = _fetch_by_stable_key(conn, CANONICAL_PSP_STABLE_KEY)

    if psp is None:
        return ServicePrincipalAuthzResult(
            allowed=False,
            principal_id=auth.principal_id,
            authority_tenant_id=auth.authority_tenant_id,
            permission=permission,
            target_tenant_id=target_tenant_id,
            denial_code="SERVICE_PRINCIPAL_NOT_FOUND",
        )

    granted = set(psp.granted_permissions)
    allowed = permission in granted

    def _record(
        event_type: ServicePrincipalEventType,
        outcome: str,
        failure_reason: Optional[str],
    ) -> None:
        try:
            with engine.begin() as conn:
                emit_service_principal_event(
                    conn,
                    event_type=event_type,
                    actor_id=actor_id,
                    service_id=service_id,
                    authority_tenant_id=psp.authority_tenant_id,
                    service_principal_id=psp.id,
                    stable_key=psp.stable_key,
                    target_tenant_id=target_tenant_id,
                    permission=permission,
                    request_id=request_id,
                    outcome=outcome,
                    failure_reason=failure_reason,
                )
        except Exception:  # noqa: BLE001 — best-effort audit
            pass

    if allowed:
        _record("authorization_allowed", "success", None)
    else:
        _record(
            "authorization_denied", "denied", f"permission {permission!r} not granted"
        )

    return ServicePrincipalAuthzResult(
        allowed=allowed,
        principal_id=psp.id,
        authority_tenant_id=psp.authority_tenant_id,
        permission=permission,
        target_tenant_id=target_tenant_id,
        denial_code=None if allowed else "PERMISSION_NOT_GRANTED",
    )
