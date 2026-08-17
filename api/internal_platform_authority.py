# api/internal_platform_authority.py
"""Canonical internal platform authority bootstrap.

PR #585 keeps the near-term Console operator bridge tenant-bound while making
that authority explicit, idempotent, and independently auditable. This is not a
service-principal implementation; PR #586 owns that separation.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, NoReturn

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import OperationalError, ProgrammingError

from api.credential_authority import (
    CredentialStateError,
    issue_credential,
)
from api.tenant_authority import policy_for_tenant_kind
from api.tenant_repository import TenantRepository, TenantRow

CANONICAL_INTERNAL_TENANT_ID = "frostgate-internal"
CANONICAL_INTERNAL_DISPLAY_NAME = "FrostGate Internal Platform"
INTERNAL_AUTHORITY_VERSION = 1
INTERNAL_AUTHORITY_SERVICE = "frostgate-core"
INTERNAL_AUTHORITY_ACTOR = "system:internal-platform-authority"
OPERATOR_CREDENTIAL_TYPE = "tenant_api_key"
OPERATOR_CREDENTIAL_SLOT = "console-bff-key"
OPERATOR_CREDENTIAL_SCOPES: tuple[str, ...] = (
    "admin:read",
    "admin:write",
    "audit:read",
    "audit:export",
    "keys:admin",
    "keys:read",
    "keys:write",
)
OPERATOR_CREDENTIAL_IDEMPOTENCY_KEY = "internal-platform-authority:console-bff-key:v1"
TENANT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")

InternalAuthorityEventType = Literal[
    "bootstrap_created",
    "bootstrap_reused",
    "credential_issued",
    "credential_reused",
    "credential_rotated",
    "credential_revoked",
    "authority_validated",
    "authority_denied",
]


@dataclass(frozen=True)
class InternalPlatformAuthorityStatus:
    authority_exists: bool
    tenant_id: str | None
    tenant_kind: str | None
    lifecycle_state: str | None
    authority_version: int | None
    bootstrap_status: str
    credential_type: str
    credential_slot: str
    credential_current_generation: int
    credential_status: str | None
    credential_id: str | None
    credential_issued: bool = False

    def safe_dict(self) -> dict[str, Any]:
        return {
            "authority_exists": self.authority_exists,
            "tenant_id": self.tenant_id,
            "tenant_kind": self.tenant_kind,
            "lifecycle_state": self.lifecycle_state,
            "authority_version": self.authority_version,
            "bootstrap_status": self.bootstrap_status,
            "credential_type": self.credential_type,
            "credential_slot": self.credential_slot,
            "credential_current_generation": self.credential_current_generation,
            "credential_status": self.credential_status,
            "credential_id": self.credential_id,
            "credential_issued": self.credential_issued,
        }


class InternalPlatformAuthorityError(RuntimeError):
    def __init__(
        self, code: str, message: str, *, tenant_id: str | None = None
    ) -> None:
        self.code = code
        self.tenant_id = tenant_id
        super().__init__(message)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _metadata() -> dict[str, Any]:
    return {
        "authority": "internal_platform",
        "authority_version": INTERNAL_AUTHORITY_VERSION,
        "managed_by": "frostgate-core",
        "customer_visible": False,
        "portal_enabled": False,
        "billing_eligible": False,
        "service_principal": False,
        "created_by_pr": "585",
    }


def _authority_version(record: TenantRow | None) -> int | None:
    if record is None:
        return None
    raw = (record.metadata or {}).get("authority_version")
    try:
        return int(str(raw))
    except (TypeError, ValueError):
        return (
            INTERNAL_AUTHORITY_VERSION
            if record.tenant_kind == "internal_platform"
            else None
        )


def _event_metadata(metadata: dict[str, Any] | None) -> str:
    return json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))


def emit_internal_authority_event(
    conn: Connection,
    *,
    event_type: InternalAuthorityEventType,
    actor_id: str,
    service_id: str,
    target_tenant_id: str,
    authority_tenant_id: str | None,
    request_id: str | None,
    outcome: str = "success",
    credential_id: str | None = None,
    credential_type: str | None = None,
    credential_slot: str | None = None,
    generation: int | None = None,
    failure_reason: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Append an internal authority audit event.

    The table is created by migration 0167. The event is intentionally separate
    from tenant_credential_events so actor/service/target tenant remain explicit
    for PR #587 without changing CredentialAuthority's canonical lifecycle log.
    """

    if authority_tenant_id and conn.dialect.name == "postgresql":
        conn.execute(
            text("SELECT pg_catalog.set_config('app.tenant_id', :tenant_id, true)"),
            {"tenant_id": authority_tenant_id},
        )

    conn.execute(
        text(
            """
            INSERT INTO internal_platform_authority_events (
                event_id, event_type, actor_id, service_id,
                target_tenant_id, authority_tenant_id,
                credential_id, credential_type, credential_slot, generation,
                request_id, occurred_at, outcome, failure_reason, metadata,
                schema_version
            ) VALUES (
                :event_id, :event_type, :actor_id, :service_id,
                :target_tenant_id, :authority_tenant_id,
                :credential_id, :credential_type, :credential_slot, :generation,
                :request_id, :occurred_at, :outcome, :failure_reason, :metadata,
                1
            )
            """
        ),
        {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "actor_id": actor_id,
            "service_id": service_id,
            "target_tenant_id": target_tenant_id,
            "authority_tenant_id": authority_tenant_id,
            "credential_id": credential_id,
            "credential_type": credential_type,
            "credential_slot": credential_slot,
            "generation": generation,
            "request_id": request_id,
            "occurred_at": _now_iso(),
            "outcome": outcome,
            "failure_reason": failure_reason,
            "metadata": _event_metadata(metadata),
        },
    )


def _list_internal_platform_rows(repo: TenantRepository) -> list[TenantRow]:
    return repo.list_by_kind("internal_platform", include_archived=True)


def _operator_credential_row(conn: Connection, tenant_id: str) -> Any | None:
    if conn.dialect.name == "postgresql":
        conn.execute(
            text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
            {"tid": tenant_id},
        )
    return conn.execute(
        text(
            """
            SELECT
                tc.credential_id, tc.status, tc.generation,
                cs.current_generation
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
            "credential_type": OPERATOR_CREDENTIAL_TYPE,
            "credential_slot": OPERATOR_CREDENTIAL_SLOT,
        },
    ).fetchone()


def _status_from_record(
    engine: Engine,
    record: TenantRow | None,
    *,
    bootstrap_status: str,
    credential_issued: bool = False,
) -> InternalPlatformAuthorityStatus:
    credential_id = None
    credential_status = None
    current_generation = 0
    if record is not None:
        with engine.connect() as conn:
            row = _operator_credential_row(conn, record.tenant_id)
        if row is not None:
            credential_id = row[0]
            credential_status = row[1]
            current_generation = int(row[3] or row[2] or 0)

    return InternalPlatformAuthorityStatus(
        authority_exists=record is not None,
        tenant_id=record.tenant_id if record else None,
        tenant_kind=record.tenant_kind if record else None,
        lifecycle_state=record.lifecycle_state if record else None,
        authority_version=_authority_version(record),
        bootstrap_status=bootstrap_status,
        credential_type=OPERATOR_CREDENTIAL_TYPE,
        credential_slot=OPERATOR_CREDENTIAL_SLOT,
        credential_current_generation=current_generation,
        credential_status=credential_status,
        credential_id=credential_id,
        credential_issued=credential_issued,
    )


def read_internal_platform_authority_status(
    engine: Engine,
) -> InternalPlatformAuthorityStatus:
    repo = TenantRepository(engine)
    rows = _list_internal_platform_rows(repo)
    if not rows:
        return _status_from_record(engine, None, bootstrap_status="missing")
    if len(rows) > 1:
        raise InternalPlatformAuthorityError(
            "INTERNAL_PLATFORM_AUTHORITY_DUPLICATE",
            "multiple internal_platform tenants exist",
        )
    return _status_from_record(engine, rows[0], bootstrap_status="reused")


def validate_operator_authority_record(record: TenantRow) -> None:
    policy = policy_for_tenant_kind(record.tenant_kind)
    if record.lifecycle_state != "active" or not policy.operator_authority_allowed:
        raise InternalPlatformAuthorityError(
            "OPERATOR_TENANT_NOT_ALLOWED",
            "tenant is not allowed to act as internal operator authority",
            tenant_id=record.tenant_id,
        )


def validate_configured_core_tenant_id(
    engine: Engine,
    *,
    actor_id: str = INTERNAL_AUTHORITY_ACTOR,
    service_id: str = INTERNAL_AUTHORITY_SERVICE,
    request_id: str | None = None,
) -> TenantRow:
    raw = (os.getenv("CORE_TENANT_ID") or "").strip()
    target = raw or "missing"

    def _deny(code: str, reason: str) -> NoReturn:
        with engine.begin() as conn:
            emit_internal_authority_event(
                conn,
                event_type="authority_denied",
                actor_id=actor_id,
                service_id=service_id,
                target_tenant_id=target,
                authority_tenant_id=None,
                request_id=request_id,
                outcome="denied",
                failure_reason=reason,
                metadata={"code": code},
            )
        raise InternalPlatformAuthorityError(code, reason, tenant_id=raw or None)

    if not raw:
        _deny("CORE_TENANT_ID_MISSING", "CORE_TENANT_ID is required")
    if raw.lower() == "default" or not TENANT_ID_RE.fullmatch(raw):
        _deny(
            "CORE_TENANT_ID_INVALID", "CORE_TENANT_ID is not a valid operator authority"
        )

    repo = TenantRepository(engine)
    record = repo.get(raw)
    if record is None:
        _deny("OPERATOR_TENANT_NOT_FOUND", "configured operator tenant does not exist")

    try:
        validate_operator_authority_record(record)
    except InternalPlatformAuthorityError as exc:
        with engine.begin() as conn:
            emit_internal_authority_event(
                conn,
                event_type="authority_denied",
                actor_id=actor_id,
                service_id=service_id,
                target_tenant_id=raw,
                authority_tenant_id=record.tenant_id,
                request_id=request_id,
                outcome="denied",
                failure_reason=exc.code,
                metadata={
                    "tenant_kind": record.tenant_kind,
                    "lifecycle_state": record.lifecycle_state,
                },
            )
        raise

    with engine.begin() as conn:
        emit_internal_authority_event(
            conn,
            event_type="authority_validated",
            actor_id=actor_id,
            service_id=service_id,
            target_tenant_id=record.tenant_id,
            authority_tenant_id=record.tenant_id,
            request_id=request_id,
            metadata={
                "tenant_kind": record.tenant_kind,
                "authority_version": _authority_version(record),
            },
        )
    return record


def bootstrap_internal_platform_authority(
    engine: Engine,
    *,
    actor_id: str = INTERNAL_AUTHORITY_ACTOR,
    service_id: str = INTERNAL_AUTHORITY_SERVICE,
    request_id: str | None = None,
) -> InternalPlatformAuthorityStatus:
    repo = TenantRepository(engine)
    rows = _list_internal_platform_rows(repo)
    if len(rows) > 1:
        raise InternalPlatformAuthorityError(
            "INTERNAL_PLATFORM_AUTHORITY_DUPLICATE",
            "multiple internal_platform tenants exist",
        )

    credential_issued = False
    if rows:
        record = rows[0]
        with engine.begin() as conn:
            emit_internal_authority_event(
                conn,
                event_type="bootstrap_reused",
                actor_id=actor_id,
                service_id=service_id,
                target_tenant_id=record.tenant_id,
                authority_tenant_id=record.tenant_id,
                request_id=request_id,
                metadata={"authority_version": _authority_version(record)},
            )
    else:
        existing = repo.get(CANONICAL_INTERNAL_TENANT_ID)
        if existing is not None:
            raise InternalPlatformAuthorityError(
                "CANONICAL_INTERNAL_AUTHORITY_CONFLICT",
                "canonical internal authority tenant_id exists with a non-internal kind",
                tenant_id=CANONICAL_INTERNAL_TENANT_ID,
            )
        record = repo.create(
            CANONICAL_INTERNAL_TENANT_ID,
            CANONICAL_INTERNAL_DISPLAY_NAME,
            tenant_kind="internal_platform",
            allow_internal_platform=True,
            created_by=actor_id,
            migration_source="internal_platform_bootstrap",
            migration_version="0167",
            metadata=_metadata(),
        )
        with engine.begin() as conn:
            emit_internal_authority_event(
                conn,
                event_type="bootstrap_created",
                actor_id=actor_id,
                service_id=service_id,
                target_tenant_id=record.tenant_id,
                authority_tenant_id=record.tenant_id,
                request_id=request_id,
                metadata={"authority_version": _authority_version(record)},
            )

    validate_operator_authority_record(record)

    with engine.connect() as conn:
        credential_row = _operator_credential_row(conn, record.tenant_id)

    if credential_row is None or int(credential_row[3] or 0) == 0:
        try:
            issued = issue_credential(
                engine,
                tenant_id=record.tenant_id,
                credential_type=OPERATOR_CREDENTIAL_TYPE,
                credential_slot=OPERATOR_CREDENTIAL_SLOT,
                scopes=list(OPERATOR_CREDENTIAL_SCOPES),
                actor_id=actor_id,
                request_id=request_id,
                idempotency_key=OPERATOR_CREDENTIAL_IDEMPOTENCY_KEY,
                metadata={
                    "authority": "internal_platform",
                    "authority_version": _authority_version(record),
                    "service": service_id,
                    "raw_secret_exposed": False,
                },
            )
            credential_issued = issued.plaintext_secret is not None
            with engine.begin() as conn:
                emit_internal_authority_event(
                    conn,
                    event_type="credential_issued",
                    actor_id=actor_id,
                    service_id=service_id,
                    target_tenant_id=record.tenant_id,
                    authority_tenant_id=record.tenant_id,
                    credential_id=issued.record.credential_id,
                    credential_type=issued.record.credential_type,
                    credential_slot=issued.record.credential_slot,
                    generation=issued.record.generation,
                    request_id=request_id,
                    metadata={"plaintext_exposed": False},
                )
        except CredentialStateError:
            credential_issued = False
    else:
        with engine.begin() as conn:
            emit_internal_authority_event(
                conn,
                event_type="credential_reused",
                actor_id=actor_id,
                service_id=service_id,
                target_tenant_id=record.tenant_id,
                authority_tenant_id=record.tenant_id,
                credential_id=str(credential_row[0]) if credential_row[0] else None,
                credential_type=OPERATOR_CREDENTIAL_TYPE,
                credential_slot=OPERATOR_CREDENTIAL_SLOT,
                generation=int(credential_row[2] or credential_row[3] or 0),
                request_id=request_id,
                metadata={"status": credential_row[1]},
            )

    return _status_from_record(
        engine,
        record,
        bootstrap_status="created" if not rows else "reused",
        credential_issued=credential_issued,
    )


def emit_internal_credential_event_if_applicable(
    engine: Engine,
    *,
    tenant_id: str,
    event_type: Literal[
        "credential_issued", "credential_rotated", "credential_revoked"
    ],
    actor_id: str,
    service_id: str = INTERNAL_AUTHORITY_SERVICE,
    request_id: str | None = None,
    credential_id: str | None = None,
    credential_type: str | None = None,
    credential_slot: str | None = None,
    generation: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    repo = TenantRepository(engine)
    try:
        record = repo.get(tenant_id)
    except (OperationalError, ProgrammingError):
        return
    if record is None:
        return
    policy = policy_for_tenant_kind(record.tenant_kind)
    if not policy.operator_authority_allowed:
        return
    with engine.begin() as conn:
        emit_internal_authority_event(
            conn,
            event_type=event_type,
            actor_id=actor_id,
            service_id=service_id,
            target_tenant_id=tenant_id,
            authority_tenant_id=tenant_id,
            credential_id=credential_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
            generation=generation,
            request_id=request_id,
            metadata=metadata,
        )
