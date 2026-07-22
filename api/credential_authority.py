# api/credential_authority.py
"""
R4 — Credential Authority.

Single authority for all tenant credential lifecycle operations.
No other module may INSERT or UPDATE tenant_credentials or credential_slots
outside of migration files.

Tenant lifecycle integration (R4.4):
  Tenant existence and lifecycle state are resolved through TenantRepository —
  the canonical source of truth established by R7 (persistence) and R3
  (transition authority).  This ensures credential operations observe the same
  tenant state abstraction used everywhere else in the platform, including the
  JSON fallback during the R7 transition window.

  validate_credential is the sole exception: it uses a single JOIN query to
  read credential + tenant lifecycle atomically in one round-trip.  Replacing
  the JOIN with TenantRepository.get() would introduce a race window (two
  separate reads) and double the DB round-trips on the hot validation path.
  The JOIN is documented as intentional and guarded by the CI gate.

Non-negotiable invariants:
  - Plaintext secret returned exactly once at issuance; never stored.
  - lookup_fingerprint (HMAC-SHA256) for indexed lookup.
  - secret_hash (Argon2id) for constant-time verification.
  - Tenant lifecycle enforced synchronously — via JOIN at validation time,
    via TenantRepository at issuance/rotation/revocation time.
  - No caching: lifecycle state is always read fresh from Postgres.
  - Slot-level serialization via SELECT FOR UPDATE on credential_slots.
  - Rotation is atomic: new generation inserted before old is marked rotated.
  - Revocation is idempotent; terminal statuses never reactivate.
  - Expiration enforced lazily at validation; normalised by scheduled sweep.
  - Idempotency replay never re-exposes original plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional, cast

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine, Row

from api.tenant_repository import TenantRepository

log = logging.getLogger("frostgate.credential_authority")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_CREDENTIAL_TYPES: frozenset[str] = frozenset({"tenant_api_key", "portal_access"})
TERMINAL_STATUSES: frozenset[str] = frozenset({"rotated", "revoked", "expired"})
CREDENTIAL_SCOPE: str = "credential:use"
DEFAULT_CREDENTIAL_TTL_SECONDS: int = 365 * 24 * 3600
DEFAULT_PORTAL_CREDENTIAL_TTL_SECONDS: int = 14 * 24 * 3600  # 14-day grant window
SCHEMA_VERSION: int = 1

# ---------------------------------------------------------------------------
# Per-type metadata schemas
# ---------------------------------------------------------------------------

_MAX_CLIENT_ID_LEN = 255
_MAX_ENGAGEMENT_ID_LEN = 64
_MAX_GRANT_ID_LEN = 64


class PortalAccessMetadata(BaseModel):
    """Validated metadata stored in tenant_credentials for portal_access type.

    client_id and engagement_id are the stable binding for this credential slot.
    portal_grant_id links to the originating portal_grants row when set
    (populated for legacy-migrated rows; None for new canonical credentials).
    """

    client_id: str
    engagement_id: str
    portal_grant_id: str | None = None

    @field_validator("client_id")
    @classmethod
    def _check_client_id(cls, v: str) -> str:
        if not v or not v.strip() or len(v) > _MAX_CLIENT_ID_LEN:
            raise ValueError(
                f"client_id must be 1–{_MAX_CLIENT_ID_LEN} non-whitespace chars"
            )
        return v

    @field_validator("engagement_id")
    @classmethod
    def _check_engagement_id(cls, v: str) -> str:
        if not v or not v.strip() or len(v) > _MAX_ENGAGEMENT_ID_LEN:
            raise ValueError(
                f"engagement_id must be 1–{_MAX_ENGAGEMENT_ID_LEN} non-whitespace chars"
            )
        return v


# Module-level hasher — tests may monkeypatch with lower parameters to keep
# the suite fast without changing the production hash parameters.
_HASHER: PasswordHasher = PasswordHasher()

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CredentialNotFoundError(KeyError):
    """Raised when a credential does not exist or authentication fails.

    We do not distinguish "not found" from "wrong secret" at the API boundary
    to avoid timing and enumeration attacks.

    absent=True means the credential was not found in the canonical store (safe
    to fall through to the legacy path during dual-read migration).
    absent=False (default) means the credential was found but authentication
    failed — callers MUST NOT fall through to any legacy path.
    """

    def __init__(self, *args: object, absent: bool = False, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.absent = absent


class CredentialTypeError(ValueError):
    """Raised when credential_type is not a recognised class."""


class CredentialStateError(ValueError):
    """Raised when the requested operation is invalid for the current status."""


class TenantLifecycleError(PermissionError):
    """Raised when tenant lifecycle state does not permit the operation."""


class TenantNotFoundError(KeyError):
    """Raised when tenant_id does not exist."""


class CredentialConflictError(RuntimeError):
    """Raised when a concurrent rotation wins the slot lock. Caller may retry."""


class CredentialSlotNotFoundError(KeyError):
    """Raised when attempting to rotate a slot that has never been issued."""


# ---------------------------------------------------------------------------
# Lifecycle policy
# ---------------------------------------------------------------------------

_LIFECYCLE_POLICY: dict[str, dict[str, bool]] = {
    "active": {"validate": True, "issue": True, "rotate": True, "revoke": True},
    "suspended": {"validate": False, "issue": False, "rotate": False, "revoke": True},
    "archived": {"validate": False, "issue": False, "rotate": False, "revoke": True},
    "deleted": {"validate": False, "issue": False, "rotate": False, "revoke": True},
}


def _enforce_lifecycle(lifecycle_state: str, operation: str, tenant_id: str) -> None:
    permitted = _LIFECYCLE_POLICY.get(lifecycle_state, {}).get(operation, False)
    if not permitted:
        raise TenantLifecycleError(
            f"Tenant {tenant_id!r} in state {lifecycle_state!r} "
            f"does not permit {operation!r}."
        )


def _get_tenant_lifecycle_state(conn: Connection, tenant_id: str) -> str:
    """Read tenant lifecycle_state on the caller's existing connection.

    Uses TenantRepository.get_lifecycle_state_on_conn() so no second pool slot
    is consumed — issue_credential/rotate_credential already hold engine.begin().
    Raises TenantNotFoundError if the tenant does not exist.
    """
    state = TenantRepository.get_lifecycle_state_on_conn(conn, tenant_id)
    if state is None:
        raise TenantNotFoundError(f"Tenant not found: {tenant_id!r}")
    return state


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_EVENT_INSERT = """
INSERT INTO tenant_credential_events (
    event_id, tenant_id, credential_id, credential_type,
    credential_slot, generation, event_type, actor_id, request_id,
    occurred_at, outcome, failure_reason, metadata, schema_version
) VALUES (
    :eid, :tid, :cid, :ctype,
    :slot, :gen, :etype, :actor, :req,
    :occurred_at, :outcome, :reason, :meta, 1
)
"""


def _insert_event(
    conn: Connection,
    *,
    tenant_id: str,
    event_type: str,
    outcome: str = "success",
    credential_id: Optional[str] = None,
    credential_type: Optional[str] = None,
    credential_slot: Optional[str] = None,
    generation: Optional[int] = None,
    actor_id: Optional[str] = None,
    request_id: Optional[str] = None,
    failure_reason: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> str:
    """Insert a credential audit event on the caller's connection. Returns event_id."""
    event_id = str(uuid.uuid4())
    conn.execute(
        text(_EVENT_INSERT),
        {
            "eid": event_id,
            "tid": tenant_id,
            "cid": credential_id,
            "ctype": credential_type,
            "slot": credential_slot,
            "gen": generation,
            "etype": event_type,
            "actor": actor_id,
            "req": request_id,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "outcome": outcome,
            "reason": failure_reason,
            "meta": json.dumps(metadata) if metadata else None,
        },
    )
    return event_id


def _emit_event_best_effort(
    engine: Engine,
    *,
    tenant_id: str,
    event_type: str,
    outcome: str = "success",
    credential_id: Optional[str] = None,
    credential_type: Optional[str] = None,
    credential_slot: Optional[str] = None,
    generation: Optional[int] = None,
    actor_id: Optional[str] = None,
    request_id: Optional[str] = None,
    failure_reason: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """Emit an audit event on a fresh connection; swallow all exceptions.

    Used for validation telemetry — emission failure must never block the
    validation response.  Lifecycle events (issue/rotate/revoke/expire) use
    _insert_event directly on the credential write connection instead.
    """
    try:
        with engine.begin() as conn:
            # Set the tenant context so RLS on tenant_credential_events accepts
            # the INSERT.  SET LOCAL is transaction-scoped and is lost when the
            # previous (validation) transaction closed, so each fresh connection
            # must re-establish it.  Postgres-only: SQLite has no set_config().
            if conn.dialect.name == "postgresql":
                conn.execute(
                    text("SELECT set_config('app.tenant_id', :tid, true)"),
                    {"tid": tenant_id},
                )
            _insert_event(
                conn,
                tenant_id=tenant_id,
                event_type=event_type,
                outcome=outcome,
                credential_id=credential_id,
                credential_type=credential_type,
                credential_slot=credential_slot,
                generation=generation,
                actor_id=actor_id,
                request_id=request_id,
                failure_reason=failure_reason,
                metadata=metadata,
            )
    except Exception:
        log.debug("credential event emission failed (best-effort)", exc_info=True)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CredentialPrincipal:
    """Typed result of a successful validation. Never contains secret material."""

    tenant_id: str
    credential_id: str
    credential_type: str
    credential_slot: str
    generation: int
    scopes: frozenset[str]
    issued_at: datetime
    authentication_method: str = "api_key"
    metadata: Optional[dict] = None

    def __repr__(self) -> str:
        return (
            f"CredentialPrincipal(tenant_id={self.tenant_id!r}, "
            f"credential_id={self.credential_id!r}, "
            f"credential_type={self.credential_type!r})"
        )


@dataclass
class CredentialRecord:
    """Metadata representation of a credential. Never contains secret material."""

    credential_id: str
    tenant_id: str
    credential_type: str
    credential_slot: str
    generation: int
    status: str
    expires_at: Optional[datetime]
    issued_at: datetime
    activated_at: Optional[datetime]
    rotated_at: Optional[datetime]
    revoked_at: Optional[datetime]
    replaced_by_credential_id: Optional[str]
    created_by_actor_id: Optional[str]
    request_id: Optional[str]
    idempotency_key: Optional[str]
    last_used_at: Optional[datetime]
    approximate_use_count: int
    scopes_csv: Optional[str]
    schema_version: int
    record_hash: Optional[str]
    metadata: Optional[dict] = None

    def __repr__(self) -> str:
        return (
            f"CredentialRecord(credential_id={self.credential_id!r}, "
            f"tenant_id={self.tenant_id!r}, "
            f"status={self.status!r}, "
            f"generation={self.generation!r})"
        )


@dataclass
class IssuanceResult:
    """Returned by issue_credential and rotate_credential.

    plaintext_secret is set exactly once at initial issuance.
    On idempotency replay it is None — the original secret is not recoverable.
    """

    record: CredentialRecord
    plaintext_secret: Optional[str]

    def __repr__(self) -> str:
        return (
            f"IssuanceResult(record={self.record!r}, "
            f"plaintext_secret={'<present>' if self.plaintext_secret is not None else 'None'})"
        )


@dataclass(frozen=True)
class CredentialEventRecord:
    """Single entry in the credential audit log."""

    event_id: str
    tenant_id: str
    credential_id: Optional[str]
    credential_type: Optional[str]
    credential_slot: Optional[str]
    generation: Optional[int]
    event_type: str
    actor_id: Optional[str]
    request_id: Optional[str]
    occurred_at: datetime
    outcome: str
    failure_reason: Optional[str]
    metadata: Optional[dict]
    schema_version: int


# ---------------------------------------------------------------------------
# Helpers — crypto and key generation
# ---------------------------------------------------------------------------


def _get_pepper() -> str:
    pepper = os.environ.get("FG_KEY_PEPPER", "")
    if not pepper:
        raise RuntimeError(
            "FG_KEY_PEPPER not configured; cannot issue or validate credentials."
        )
    return pepper


def _compute_lookup_fingerprint(secret_part: str, pepper: str) -> str:
    """HMAC-SHA256(secret_part, pepper) — deterministic, indexed, non-secret."""
    return _hmac.new(
        key=pepper.encode("utf-8"),
        msg=secret_part.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def _compute_record_hash(
    *,
    credential_id: str,
    tenant_id: str,
    credential_type: str,
    credential_slot: str,
    generation: int,
    issued_at: str,
) -> str:
    """SHA-256 of immutable issuance facts. Same pattern as R3 transition_hash."""
    payload = "\n".join(
        [
            credential_id,
            tenant_id,
            credential_type,
            credential_slot,
            str(generation),
            issued_at,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _generate_key(
    tenant_id: str,
    expires_at: Optional[datetime],
) -> tuple[str, str, str, str]:
    """Generate a new credential key.

    Returns (raw_key, secret_part, secret_prefix, lookup_fingerprint).
    raw_key is the one-time plaintext. Never store it after returning.
    """
    secret_part = secrets.token_urlsafe(32)

    payload_data: dict[str, object] = {"t": tenant_id}
    if expires_at is not None:
        payload_data["exp"] = int(expires_at.timestamp())
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(payload_data, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )

    raw_key = f"fgk.{payload}.{secret_part}"
    pepper = _get_pepper()
    fp = _compute_lookup_fingerprint(secret_part, pepper)
    secret_prefix = fp[:8]

    return raw_key, secret_part, secret_prefix, fp


def _parse_key(raw_key: str) -> tuple[str, str]:
    """Parse raw_key → (tenant_id_hint, secret_part).

    Raises CredentialNotFoundError on any malformed input so that
    parse failures are indistinguishable from authentication failures.
    """
    parts = raw_key.split(".")
    if len(parts) < 3 or parts[0] != "fgk":
        raise CredentialNotFoundError("credential authentication failed", absent=True)
    try:
        padding = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
        tenant_id_hint: str = payload.get("t", "")
    except Exception:
        raise CredentialNotFoundError("credential authentication failed", absent=True)
    return tenant_id_hint, parts[-1]


# Portal secret bounds — token_urlsafe(32) produces 43 chars; accept a generous
# range to allow for future entropy changes without breaking the validator.
_PORTAL_SECRET_MIN_LEN = 20
_PORTAL_SECRET_MAX_LEN = 128


def _generate_portal_key(pepper: str) -> tuple[str, str, str, str]:
    """Generate a portal_access credential key.

    Returns (raw_key, secret_part, secret_prefix, fp).
    raw_key == secret_part — no fgk. prefix, no encoded payload.
    The entire token is the secret input for fingerprint derivation.
    """
    secret_part = secrets.token_urlsafe(32)
    fp = _compute_lookup_fingerprint(secret_part, pepper)
    secret_prefix = fp[:8]
    return secret_part, secret_part, secret_prefix, fp


def _parse_portal_key(raw_key: str) -> str:
    """Validate and return the secret_part for a portal_access token.

    Raises CredentialNotFoundError(absent=True) on: empty, whitespace-only,
    out-of-range length, fgk. prefix (caller confused the key type), or
    any encoding that cannot plausibly be a raw opaque bearer token.
    """
    if not raw_key:
        raise CredentialNotFoundError("credential authentication failed", absent=True)
    stripped = raw_key.strip()
    if not stripped:
        raise CredentialNotFoundError("credential authentication failed", absent=True)
    if stripped.startswith("fgk."):
        # Caller passed a tenant_api_key where a portal secret is expected.
        raise CredentialNotFoundError("credential authentication failed", absent=True)
    if len(stripped) < _PORTAL_SECRET_MIN_LEN or len(stripped) > _PORTAL_SECRET_MAX_LEN:
        raise CredentialNotFoundError("credential authentication failed", absent=True)
    return stripped


def _hash_secret(secret_part: str) -> tuple[str, dict]:
    """Argon2id hash of secret_part. Returns (phc_string, params_dict)."""
    phc = _HASHER.hash(secret_part)
    params = {
        "time_cost": _HASHER.time_cost,
        "memory_cost": _HASHER.memory_cost,
        "parallelism": _HASHER.parallelism,
        "hash_len": _HASHER.hash_len,
        "salt_len": _HASHER.salt_len,
    }
    return phc, params


def _verify_secret(secret_part: str, stored_hash: str) -> bool:
    """Constant-time Argon2id verification."""
    try:
        _HASHER.verify(stored_hash, secret_part)
        return True
    except VerifyMismatchError:
        return False


# ---------------------------------------------------------------------------
# Internal — row mapping
# ---------------------------------------------------------------------------


def _parse_dt(val: object) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(val)).replace(tzinfo=timezone.utc)


def _parse_json(val: object) -> object:
    if val is None or isinstance(val, dict):
        return val
    return json.loads(str(val))


_RECORD_SELECT = (
    "credential_id, tenant_id, credential_type, credential_slot, generation, "
    "status, expires_at, issued_at, activated_at, rotated_at, revoked_at, "
    "replaced_by_credential_id, created_by_actor_id, request_id, idempotency_key, "
    "last_used_at, approximate_use_count, scopes_csv, metadata, schema_version, record_hash"
)

# Same columns with tc. prefix for queries that JOIN another table with overlapping names.
_RECORD_SELECT_TC = ", ".join(f"tc.{c.strip()}" for c in _RECORD_SELECT.split(","))


def _row_to_record(row: Row[Any]) -> CredentialRecord:
    r = row
    return CredentialRecord(
        credential_id=r[0],
        tenant_id=r[1],
        credential_type=r[2],
        credential_slot=r[3],
        generation=r[4],
        status=r[5],
        expires_at=_parse_dt(r[6]),
        issued_at=_parse_dt(r[7]),  # type: ignore[arg-type]
        activated_at=_parse_dt(r[8]),
        rotated_at=_parse_dt(r[9]),
        revoked_at=_parse_dt(r[10]),
        replaced_by_credential_id=r[11],
        created_by_actor_id=r[12],
        request_id=r[13],
        idempotency_key=r[14],
        last_used_at=_parse_dt(r[15]),
        approximate_use_count=r[16] or 0,
        scopes_csv=r[17],
        metadata=_parse_json(r[18]),  # type: ignore[arg-type]
        schema_version=r[19] or SCHEMA_VERSION,
        record_hash=r[20],
    )


# ---------------------------------------------------------------------------
# Internal — slot helpers
# ---------------------------------------------------------------------------


def _select_slot_sql(is_postgres: bool) -> str:
    q = (
        "SELECT current_generation, rotation_policy, max_overlap_count "
        "FROM credential_slots "
        "WHERE tenant_id = :tid AND credential_type = :ctype AND credential_slot = :slot"
    )
    return q + " FOR UPDATE" if is_postgres else q


def _upsert_slot(
    conn: Connection,
    *,
    tenant_id: str,
    credential_type: str,
    credential_slot: str,
) -> None:
    conn.execute(
        text(
            "INSERT INTO credential_slots "
            "(tenant_id, credential_type, credential_slot) "
            "VALUES (:tid, :ctype, :slot) "
            "ON CONFLICT (tenant_id, credential_type, credential_slot) DO NOTHING"
        ),
        {"tid": tenant_id, "ctype": credential_type, "slot": credential_slot},
    )


def _advance_slot_generation(
    conn: Connection,
    *,
    tenant_id: str,
    credential_type: str,
    credential_slot: str,
    expected_generation: int,
    new_generation: int,
    now_iso: str,
) -> None:
    result = conn.execute(
        text(
            "UPDATE credential_slots "
            "SET current_generation = :new_gen, updated_at = :now "
            "WHERE tenant_id = :tid AND credential_type = :ctype "
            "  AND credential_slot = :slot "
            "  AND current_generation = :expected_gen"
        ),
        {
            "new_gen": new_generation,
            "now": now_iso,
            "tid": tenant_id,
            "ctype": credential_type,
            "slot": credential_slot,
            "expected_gen": expected_generation,
        },
    )
    if result.rowcount == 0:
        raise CredentialConflictError(
            f"Concurrent modification to slot {credential_slot!r} for tenant "
            f"{tenant_id!r}; retry the operation."
        )


# ---------------------------------------------------------------------------
# Internal — credential insert
# ---------------------------------------------------------------------------


def _insert_credential(
    conn: Connection,
    *,
    credential_id: str,
    tenant_id: str,
    credential_type: str,
    credential_slot: str,
    generation: int,
    lookup_fingerprint: str,
    secret_prefix: str,
    secret_hash: str,
    hash_params: dict,
    status: str,
    expires_at: Optional[str],
    issued_at: str,
    actor_id: Optional[str],
    request_id: Optional[str],
    idempotency_key: Optional[str],
    scopes_csv: str,
    metadata: Optional[dict],
    record_hash: str,
) -> None:
    conn.execute(
        text(
            """
            INSERT INTO tenant_credentials (
                credential_id, tenant_id, credential_type, credential_slot,
                generation, lookup_fingerprint, lookup_key_version, secret_prefix,
                secret_hash, hash_algorithm, hash_params, status, expires_at,
                issued_at, activated_at, created_by_actor_id, request_id,
                idempotency_key, scopes_csv, metadata, schema_version, record_hash
            ) VALUES (
                :cid, :tid, :ctype, :slot,
                :gen, :fp, 1, :prefix,
                :shash, 'argon2id', :hparams, :status, :expires,
                :issued, :issued, :actor, :reqid,
                :ikey, :scopes, :meta, :sv, :rhash
            )
            """
        ),
        {
            "cid": credential_id,
            "tid": tenant_id,
            "ctype": credential_type,
            "slot": credential_slot,
            "gen": generation,
            "fp": lookup_fingerprint,
            "prefix": secret_prefix,
            "shash": secret_hash,
            "hparams": json.dumps(hash_params),
            "status": status,
            "expires": expires_at,
            "issued": issued_at,
            "actor": actor_id,
            "reqid": request_id,
            "ikey": idempotency_key,
            "scopes": scopes_csv,
            "meta": json.dumps(metadata) if metadata else None,
            "sv": SCHEMA_VERSION,
            "rhash": record_hash,
        },
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def issue_credential(
    engine: Engine,
    *,
    tenant_id: str,
    credential_type: str,
    credential_slot: str,
    scopes: Optional[list[str]] = None,
    metadata: Optional[dict] = None,
    expires_in_seconds: Optional[int] = None,
    actor_id: Optional[str] = None,
    request_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> IssuanceResult:
    """Issue a new credential for a tenant slot.

    Returns IssuanceResult with plaintext_secret set exactly once.
    On idempotency replay, plaintext_secret is None.

    Raises:
        CredentialTypeError:    credential_type not recognised.
        TenantNotFoundError:    tenant_id does not exist.
        TenantLifecycleError:   tenant state does not permit issuance.
        CredentialConflictError: concurrent issuance; caller may retry.
    """
    if credential_type not in VALID_CREDENTIAL_TYPES:
        raise CredentialTypeError(f"Unknown credential type: {credential_type!r}")

    is_postgres = engine.dialect.name == "postgresql"

    with engine.begin() as conn:
        # Idempotency: scoped to tenant so cross-tenant replay is impossible.
        if idempotency_key:
            existing = conn.execute(
                text(
                    f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                    "WHERE tenant_id = :tid AND idempotency_key = :key"
                ),
                {"tid": tenant_id, "key": idempotency_key},
            ).fetchone()
            if existing is not None:
                return IssuanceResult(
                    record=_row_to_record(existing), plaintext_secret=None
                )

        # Tenant existence and lifecycle — via TenantRepository on existing conn.
        lifecycle_state = _get_tenant_lifecycle_state(conn, tenant_id)
        _enforce_lifecycle(lifecycle_state, "issue", tenant_id)

        # Ensure slot row exists; lock it.
        _upsert_slot(
            conn,
            tenant_id=tenant_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
        )
        slot_row = conn.execute(
            text(_select_slot_sql(is_postgres)),
            {"tid": tenant_id, "ctype": credential_type, "slot": credential_slot},
        ).fetchone()
        current_gen: int = slot_row[0] if slot_row else 0

        # Occupied-slot guard: a slot with an existing generation must go
        # through rotate_credential, not issue_credential.  Without this
        # check every call to issue_credential would insert another active
        # row on the same slot, violating the max_overlap_count=1 invariant
        # and leaving multiple usable secrets for the same slot.
        if current_gen > 0:
            raise CredentialStateError(
                f"Slot {credential_slot!r} already has a credential at "
                f"generation {current_gen}. "
                "Use rotate_credential() to issue a successor."
            )

        new_gen = current_gen + 1

        # Key material — generated inside the transaction so any rollback
        # discards it before it can be returned.
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        default_ttl = (
            DEFAULT_PORTAL_CREDENTIAL_TTL_SECONDS
            if credential_type == "portal_access"
            else DEFAULT_CREDENTIAL_TTL_SECONDS
        )
        ttl = expires_in_seconds if expires_in_seconds is not None else default_ttl
        expires_dt = (
            None
            if ttl == 0
            else datetime.fromtimestamp(now.timestamp() + ttl, tz=timezone.utc)
        )
        expires_iso = expires_dt.isoformat() if expires_dt else None

        if credential_type == "portal_access":
            raw_key, secret_part, secret_prefix, fp = _generate_portal_key(
                _get_pepper()
            )
        else:
            raw_key, secret_part, secret_prefix, fp = _generate_key(
                tenant_id, expires_dt
            )
        phc, hash_params = _hash_secret(secret_part)

        cred_id = str(uuid.uuid4())
        rec_hash = _compute_record_hash(
            credential_id=cred_id,
            tenant_id=tenant_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
            generation=new_gen,
            issued_at=now_iso,
        )

        effective_scopes = scopes or [CREDENTIAL_SCOPE]
        scopes_csv = ",".join(sorted(effective_scopes))

        _insert_credential(
            conn,
            credential_id=cred_id,
            tenant_id=tenant_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
            generation=new_gen,
            lookup_fingerprint=fp,
            secret_prefix=secret_prefix,
            secret_hash=phc,
            hash_params=hash_params,
            status="active",
            expires_at=expires_iso,
            issued_at=now_iso,
            actor_id=actor_id,
            request_id=request_id,
            idempotency_key=idempotency_key,
            scopes_csv=scopes_csv,
            metadata=metadata,
            record_hash=rec_hash,
        )

        _advance_slot_generation(
            conn,
            tenant_id=tenant_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
            expected_generation=current_gen,
            new_generation=new_gen,
            now_iso=now_iso,
        )

        record = conn.execute(
            text(
                f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                "WHERE credential_id = :cid"
            ),
            {"cid": cred_id},
        ).fetchone()

        _insert_event(
            conn,
            tenant_id=tenant_id,
            credential_id=cred_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
            generation=new_gen,
            event_type="issued",
            actor_id=actor_id,
            request_id=request_id,
        )

    assert record is not None, "credential insert did not return a row"
    return IssuanceResult(record=_row_to_record(record), plaintext_secret=raw_key)


def validate_credential(
    engine: Engine,
    raw_key: str,
    *,
    credential_type: str = "tenant_api_key",
) -> CredentialPrincipal:
    """Validate a raw credential string and return a typed principal.

    Raises:
        CredentialNotFoundError: credential does not exist, hash mismatch,
            expired, revoked, rotated, or tenant lifecycle does not permit.
    """
    if credential_type == "portal_access":
        secret_part = _parse_portal_key(raw_key)
        tenant_id_hint = ""
    else:
        tenant_id_hint, secret_part = _parse_key(raw_key)
    fp = _compute_lookup_fingerprint(secret_part, _get_pepper())

    is_postgres = engine.dialect.name == "postgresql"

    with engine.begin() as conn:
        if is_postgres and tenant_id_hint:
            conn.execute(
                text("SET LOCAL app.tenant_id = :tid"),
                {"tid": tenant_id_hint},
            )

        # AUTHORIZED-DIRECT-TENANT-SQL: validate_credential JOIN.
        # This is the only place in the authority that queries tenants directly.
        # A JOIN is used instead of TenantRepository.get() because:
        #   (a) credential status and tenant lifecycle state must be read
        #       atomically in a single round-trip — two separate reads would
        #       introduce a race window on the hot validation path, and
        #   (b) it eliminates one DB connection acquisition per validation call.
        # Any other direct tenant SQL in this module is a regression.
        row = conn.execute(
            text(
                f"SELECT {_RECORD_SELECT_TC}, tc.secret_hash, t.lifecycle_state "
                "FROM tenant_credentials tc "
                "JOIN tenants t ON t.tenant_id = tc.tenant_id "
                "WHERE tc.lookup_fingerprint = :fp "
                "  AND tc.credential_type = :ctype"
            ),
            {"fp": fp, "ctype": credential_type},
        ).fetchone()

    # All checks happen outside the connection block (connection already closed).
    # Emit validation telemetry best-effort after each decision point.
    if row is None:
        _emit_event_best_effort(
            engine,
            tenant_id=tenant_id_hint or "unknown",
            event_type="validation_failed",
            credential_type=credential_type,
            outcome="failure",
            failure_reason="not_found",
        )
        raise CredentialNotFoundError("credential authentication failed", absent=True)

    stored_hash: str = row[21]
    lifecycle_state: str = row[22]

    if not _verify_secret(secret_part, stored_hash):
        rec = _row_to_record(cast(Row[Any], row))
        _emit_event_best_effort(
            engine,
            tenant_id=rec.tenant_id,
            credential_id=rec.credential_id,
            credential_type=rec.credential_type,
            credential_slot=rec.credential_slot,
            generation=rec.generation,
            event_type="validation_failed",
            outcome="failure",
            failure_reason="hash_mismatch",
        )
        raise CredentialNotFoundError("credential authentication failed")

    rec = _row_to_record(cast(Row[Any], row))

    # Lazy expiration enforcement — status field may still read 'active'
    # if the sweep hasn't run yet; enforce at validation time regardless.
    if rec.status != "active":
        _emit_event_best_effort(
            engine,
            tenant_id=rec.tenant_id,
            credential_id=rec.credential_id,
            credential_type=rec.credential_type,
            credential_slot=rec.credential_slot,
            generation=rec.generation,
            event_type="validation_failed",
            outcome="failure",
            failure_reason=f"status_{rec.status}",
        )
        raise CredentialNotFoundError(
            f"credential is {rec.status} and cannot be used for authentication"
        )
    if rec.expires_at is not None and rec.expires_at <= datetime.now(timezone.utc):
        _emit_event_best_effort(
            engine,
            tenant_id=rec.tenant_id,
            credential_id=rec.credential_id,
            credential_type=rec.credential_type,
            credential_slot=rec.credential_slot,
            generation=rec.generation,
            event_type="validation_failed",
            outcome="failure",
            failure_reason="expired",
        )
        raise CredentialNotFoundError("credential has expired")

    try:
        _enforce_lifecycle(lifecycle_state, "validate", rec.tenant_id)
    except TenantLifecycleError:
        _emit_event_best_effort(
            engine,
            tenant_id=rec.tenant_id,
            credential_id=rec.credential_id,
            credential_type=rec.credential_type,
            credential_slot=rec.credential_slot,
            generation=rec.generation,
            event_type="denied_tenant_state",
            outcome="denied",
        )
        raise

    _emit_event_best_effort(
        engine,
        tenant_id=rec.tenant_id,
        credential_id=rec.credential_id,
        credential_type=rec.credential_type,
        credential_slot=rec.credential_slot,
        generation=rec.generation,
        event_type="validated",
        outcome="success",
    )

    scopes = frozenset(rec.scopes_csv.split(",")) if rec.scopes_csv else frozenset()
    return CredentialPrincipal(
        tenant_id=rec.tenant_id,
        credential_id=rec.credential_id,
        credential_type=rec.credential_type,
        credential_slot=rec.credential_slot,
        generation=rec.generation,
        scopes=scopes,
        issued_at=rec.issued_at,
        metadata=rec.metadata,
    )


def rotate_credential(
    engine: Engine,
    *,
    tenant_id: str,
    credential_type: str,
    credential_slot: str,
    actor_id: Optional[str] = None,
    request_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    expires_in_seconds: Optional[int] = None,
) -> IssuanceResult:
    """Rotate the active credential for a slot.

    Atomic: new generation is inserted and committed before the old is marked
    rotated. Concurrent rotations serialize via slot-level FOR UPDATE.

    Raises:
        TenantNotFoundError:         tenant_id does not exist.
        TenantLifecycleError:        tenant state does not permit rotation.
        CredentialSlotNotFoundError: slot has never been issued.
        CredentialConflictError:     concurrent rotation; caller may retry.
    """
    is_postgres = engine.dialect.name == "postgresql"

    with engine.begin() as conn:
        # Idempotency.
        if idempotency_key:
            existing = conn.execute(
                text(
                    f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                    "WHERE tenant_id = :tid AND idempotency_key = :key"
                ),
                {"tid": tenant_id, "key": idempotency_key},
            ).fetchone()
            if existing is not None:
                return IssuanceResult(
                    record=_row_to_record(existing), plaintext_secret=None
                )

        # Tenant existence and lifecycle — via TenantRepository on existing conn.
        lifecycle_state = _get_tenant_lifecycle_state(conn, tenant_id)
        _enforce_lifecycle(lifecycle_state, "rotate", tenant_id)

        # Lock slot.
        slot_row = conn.execute(
            text(_select_slot_sql(is_postgres)),
            {"tid": tenant_id, "ctype": credential_type, "slot": credential_slot},
        ).fetchone()
        if slot_row is None or slot_row[0] == 0:
            raise CredentialSlotNotFoundError(
                f"Slot {credential_slot!r} has no issued credentials to rotate."
            )
        current_gen: int = slot_row[0]
        new_gen = current_gen + 1

        # Fetch the current active credential.
        old_row = conn.execute(
            text(
                f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                "WHERE tenant_id = :tid AND credential_type = :ctype "
                "  AND credential_slot = :slot AND generation = :gen"
            ),
            {
                "tid": tenant_id,
                "ctype": credential_type,
                "slot": credential_slot,
                "gen": current_gen,
            },
        ).fetchone()
        if old_row is None:
            raise CredentialSlotNotFoundError(
                f"Active credential at generation {current_gen} not found."
            )
        old_record = _row_to_record(old_row)
        if old_record.status != "active":
            raise CredentialStateError(
                f"Cannot rotate generation {current_gen}: "
                f"status is {old_record.status!r}. "
                "Only active credentials may be rotated."
            )

        # New key material.
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        default_ttl = (
            DEFAULT_PORTAL_CREDENTIAL_TTL_SECONDS
            if credential_type == "portal_access"
            else DEFAULT_CREDENTIAL_TTL_SECONDS
        )
        ttl = expires_in_seconds if expires_in_seconds is not None else default_ttl
        expires_dt = (
            None
            if ttl == 0
            else datetime.fromtimestamp(now.timestamp() + ttl, tz=timezone.utc)
        )
        expires_iso = expires_dt.isoformat() if expires_dt else None

        if credential_type == "portal_access":
            raw_key, secret_part, secret_prefix, fp = _generate_portal_key(
                _get_pepper()
            )
        else:
            raw_key, secret_part, secret_prefix, fp = _generate_key(
                tenant_id, expires_dt
            )
        phc, hash_params = _hash_secret(secret_part)

        new_cred_id = str(uuid.uuid4())
        rec_hash = _compute_record_hash(
            credential_id=new_cred_id,
            tenant_id=tenant_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
            generation=new_gen,
            issued_at=now_iso,
        )
        scopes_csv = old_record.scopes_csv or CREDENTIAL_SCOPE

        # For portal_access, carry binding metadata into the new generation.
        new_metadata = (
            old_record.metadata if credential_type == "portal_access" else None
        )

        # Insert new generation first — never invalidate old before new is safe.
        _insert_credential(
            conn,
            credential_id=new_cred_id,
            tenant_id=tenant_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
            generation=new_gen,
            lookup_fingerprint=fp,
            secret_prefix=secret_prefix,
            secret_hash=phc,
            hash_params=hash_params,
            status="active",
            expires_at=expires_iso,
            issued_at=now_iso,
            actor_id=actor_id,
            request_id=request_id,
            idempotency_key=idempotency_key,
            scopes_csv=scopes_csv,
            metadata=new_metadata,
            record_hash=rec_hash,
        )

        # Mark old generation rotated (immediate cutover default).
        conn.execute(
            text(
                "UPDATE tenant_credentials "
                "SET status = 'rotated', rotated_at = :now, "
                "    replaced_by_credential_id = :new_id "
                "WHERE credential_id = :old_id AND tenant_id = :tid"
            ),
            {
                "now": now_iso,
                "new_id": new_cred_id,
                "old_id": old_record.credential_id,
                "tid": tenant_id,
            },
        )

        # Advance slot — rowcount=0 means concurrent rotation won the lock.
        _advance_slot_generation(
            conn,
            tenant_id=tenant_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
            expected_generation=current_gen,
            new_generation=new_gen,
            now_iso=now_iso,
        )

        new_row = conn.execute(
            text(
                f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                "WHERE credential_id = :cid"
            ),
            {"cid": new_cred_id},
        ).fetchone()

        _insert_event(
            conn,
            tenant_id=tenant_id,
            credential_id=new_cred_id,
            credential_type=credential_type,
            credential_slot=credential_slot,
            generation=new_gen,
            event_type="rotated",
            actor_id=actor_id,
            request_id=request_id,
            metadata={"replaced_credential_id": old_record.credential_id},
        )

    assert new_row is not None, "credential rotation did not return a row"
    return IssuanceResult(record=_row_to_record(new_row), plaintext_secret=raw_key)


def revoke_credential(
    engine: Engine,
    *,
    credential_id: str,
    tenant_id: str,
    actor_id: str,
    reason: str,
    request_id: Optional[str] = None,
) -> CredentialRecord:
    """Revoke a specific credential. Idempotent — revoking an already-revoked
    credential returns the current record without error.

    Raises:
        CredentialNotFoundError: credential does not exist or belongs to a
            different tenant.
        CredentialStateError:    credential is rotated or expired (not revokable
            by this path; those are terminal for different reasons).
    """
    with engine.begin() as conn:
        row = conn.execute(
            text(
                f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                "WHERE credential_id = :cid AND tenant_id = :tid"
            ),
            {"cid": credential_id, "tid": tenant_id},
        ).fetchone()
        if row is None:
            raise CredentialNotFoundError(
                f"Credential {credential_id!r} not found for tenant {tenant_id!r}."
            )
        rec = _row_to_record(cast(Row[Any], row))

        if rec.status == "revoked":
            return rec  # idempotent

        if rec.status in ("rotated", "expired"):
            raise CredentialStateError(
                f"Credential {credential_id!r} is {rec.status!r} and cannot be revoked."
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            text(
                "UPDATE tenant_credentials "
                "SET status = 'revoked', revoked_at = :now "
                "WHERE credential_id = :cid AND tenant_id = :tid "
                "  AND status NOT IN ('rotated', 'expired', 'revoked')"
            ),
            {"now": now_iso, "cid": credential_id, "tid": tenant_id},
        )

        updated = conn.execute(
            text(
                f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                "WHERE credential_id = :cid"
            ),
            {"cid": credential_id},
        ).fetchone()

        _insert_event(
            conn,
            tenant_id=tenant_id,
            credential_id=credential_id,
            credential_type=rec.credential_type,
            credential_slot=rec.credential_slot,
            generation=rec.generation,
            event_type="revoked",
            actor_id=actor_id,
            request_id=request_id,
            metadata={"reason": reason},
        )

    assert updated is not None, "credential revocation did not return a row"
    return _row_to_record(updated)


def expire_credentials(
    engine: Engine,
    *,
    tenant_id: Optional[str] = None,
    batch_size: int = 100,
) -> int:
    """Normalise stale active/pending rows to expired status.

    This is for audit completeness only — expiration is enforced lazily
    at validation time regardless of whether this sweep has run.
    Idempotent: safe to call multiple times.

    Returns the number of rows updated.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    params: dict = {"now": now_iso, "batch": batch_size}
    tenant_clause = ""
    if tenant_id is not None:
        tenant_clause = " AND tenant_id = :tid"
        params["tid"] = tenant_id

    with engine.begin() as conn:
        # Fetch targets first so we can emit per-credential audit events.
        targets = conn.execute(
            text(
                "SELECT credential_id, tenant_id, credential_type, "
                "  credential_slot, generation "
                "FROM tenant_credentials "
                "WHERE status IN ('pending', 'active') "
                "  AND expires_at IS NOT NULL "
                "  AND expires_at <= :now" + tenant_clause + " LIMIT :batch"
            ),
            params,
        ).fetchall()

        if not targets:
            return 0

        # UPDATE using an IN list built from the pre-selected IDs so that
        # the same WHERE guard protects against concurrent status changes.
        # RETURNING credential_id limits event emission to rows this UPDATE
        # actually changed — concurrent revoke/rotate/expire on a pre-selected
        # row re-checks status IN ('pending','active') and skips that row.
        cid_params = {f"cid_{i}": r[0] for i, r in enumerate(targets)}
        in_clause = ", ".join(f":cid_{i}" for i in range(len(targets)))
        updated_ids = {
            row[0]
            for row in conn.execute(
                text(
                    "UPDATE tenant_credentials SET status = 'expired' "
                    f"WHERE credential_id IN ({in_clause}) "
                    "  AND status IN ('pending', 'active') "
                    "  AND expires_at IS NOT NULL AND expires_at <= :now "
                    "RETURNING credential_id"
                ),
                {"now": now_iso, **cid_params},
            ).fetchall()
        }

        for cid, tid, ctype, slot, gen in targets:
            if cid not in updated_ids:
                continue
            _insert_event(
                conn,
                tenant_id=tid,
                credential_id=cid,
                credential_type=ctype,
                credential_slot=slot,
                generation=gen,
                event_type="expired",
            )

    return len(updated_ids)


def get_credential(
    engine: Engine,
    credential_id: str,
    tenant_id: str,
) -> CredentialRecord:
    """Fetch a single credential record by ID.

    Raises:
        CredentialNotFoundError: not found or belongs to a different tenant.
    """
    with engine.connect() as conn:
        row = conn.execute(
            text(
                f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                "WHERE credential_id = :cid AND tenant_id = :tid"
            ),
            {"cid": credential_id, "tid": tenant_id},
        ).fetchone()
    if row is None:
        raise CredentialNotFoundError(
            f"Credential {credential_id!r} not found for tenant {tenant_id!r}."
        )
    return _row_to_record(cast(Row[Any], row))


def list_credentials(
    engine: Engine,
    tenant_id: str,
    *,
    credential_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> list[CredentialRecord]:
    """List credentials for a tenant, newest first."""
    clauses = ["tenant_id = :tid"]
    params: dict = {"tid": tenant_id, "limit": limit}
    if credential_type is not None:
        clauses.append("credential_type = :ctype")
        params["ctype"] = credential_type
    if status is not None:
        clauses.append("status = :status")
        params["status"] = status

    where = " AND ".join(clauses)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                f"WHERE {where} "
                "ORDER BY issued_at DESC "
                "LIMIT :limit"
            ),
            params,
        ).fetchall()
    return [_row_to_record(r) for r in rows]


def get_credential_history(
    engine: Engine,
    tenant_id: str,
    credential_slot: str,
    *,
    credential_type: str = "tenant_api_key",
    limit: int = 50,
) -> list[CredentialRecord]:
    """Return all generations for a slot, newest first. Shows the rotation chain."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                f"SELECT {_RECORD_SELECT} FROM tenant_credentials "
                "WHERE tenant_id = :tid "
                "  AND credential_type = :ctype "
                "  AND credential_slot = :slot "
                "ORDER BY generation DESC "
                "LIMIT :limit"
            ),
            {
                "tid": tenant_id,
                "ctype": credential_type,
                "slot": credential_slot,
                "limit": limit,
            },
        ).fetchall()
    return [_row_to_record(r) for r in rows]


_EVENT_SELECT = (
    "event_id, tenant_id, credential_id, credential_type, credential_slot, "
    "generation, event_type, actor_id, request_id, occurred_at, outcome, "
    "failure_reason, metadata, schema_version"
)


def _row_to_event(row) -> CredentialEventRecord:
    (
        event_id,
        tenant_id,
        credential_id,
        credential_type,
        credential_slot,
        generation,
        event_type,
        actor_id,
        request_id,
        occurred_at,
        outcome,
        failure_reason,
        metadata_raw,
        schema_version,
    ) = row[:14]
    occurred_dt = (
        datetime.fromisoformat(occurred_at)
        if isinstance(occurred_at, str)
        else occurred_at
    )
    meta = json.loads(metadata_raw) if metadata_raw else None
    return CredentialEventRecord(
        event_id=event_id,
        tenant_id=tenant_id,
        credential_id=credential_id,
        credential_type=credential_type,
        credential_slot=credential_slot,
        generation=generation,
        event_type=event_type,
        actor_id=actor_id,
        request_id=request_id,
        occurred_at=occurred_dt,
        outcome=outcome,
        failure_reason=failure_reason,
        metadata=meta,
        schema_version=schema_version,
    )


def list_credential_events(
    engine: Engine,
    tenant_id: str,
    *,
    credential_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
) -> List[CredentialEventRecord]:
    """Return audit events for a tenant, newest first.

    Optionally filter by credential_id or event_type.
    """
    clauses = ["tenant_id = :tid"]
    params: dict = {"tid": tenant_id, "limit": limit}
    if credential_id is not None:
        clauses.append("credential_id = :cid")
        params["cid"] = credential_id
    if event_type is not None:
        clauses.append("event_type = :etype")
        params["etype"] = event_type

    where = " AND ".join(clauses)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                f"SELECT {_EVENT_SELECT} FROM tenant_credential_events "
                f"WHERE {where} "
                "ORDER BY occurred_at DESC "
                "LIMIT :limit"
            ),
            params,
        ).fetchall()
    return [_row_to_event(r) for r in rows]
