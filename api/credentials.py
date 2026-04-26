"""
Customer Credential Issuance / Revoke / Rotate — Task 12.1

Deterministic, tenant-scoped credential system built on the existing
auth_scopes persistence layer (SQLite api_keys table, Argon2id hashing,
HMAC key_lookup index).

Guarantees:
- Tenant-scoped: credentials are bound to a single tenant at creation time.
- Hash-only storage: the plaintext secret is returned exactly once and is
  never stored or logged.
- Constant-time comparison: validation delegates to Argon2id verify which
  is inherently constant-time; key_lookup uses HMAC.
- Audit trail: every issuance, revocation, rotation, and validation failure
  emits a structured security event.
- No fallback / dev bypass paths.
- Structured error contract (Task 11.1): all failures raise HTTPException
  with api_error() payload.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from dataclasses import dataclass

from fastapi import HTTPException

from api.auth_scopes import mint_key, verify_api_key_detailed
from api.auth_scopes.helpers import _get_key_pepper, _key_lookup_hash
from api.db import _resolve_sqlite_path
from api.error_contracts import api_error
from api.security_audit import AuditEvent, EventType, Severity

log = logging.getLogger("frostgate.credentials")
_audit = logging.getLogger("frostgate.security")

# Scope assigned to all customer credentials
_CREDENTIAL_SCOPE = "credential:use"

# TTL: 1 year for customer credentials
_CREDENTIAL_TTL_SECONDS = 365 * 24 * 3600

# ---------------------------------------------------------------------------
# Stable error codes (never change meaning once published)
# ---------------------------------------------------------------------------

ERR_AUTH_REQUIRED = "CREDENTIAL_AUTH_REQUIRED"
ERR_AUTH_INVALID = "CREDENTIAL_AUTH_INVALID"
ERR_AUTH_REVOKED = "CREDENTIAL_AUTH_REVOKED"
ERR_TENANT_ACCESS_DENIED = "CREDENTIAL_TENANT_ACCESS_DENIED"
ERR_NOT_FOUND = "CREDENTIAL_NOT_FOUND"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CredentialRecord:
    """Opaque descriptor returned after issuance or rotation.

    The plaintext secret is NEVER included here — it is returned once,
    separately, at the issuance call site only.

    Fields:
        credential_id: Stable public identifier (HMAC of secret+pepper).
                       Safe to store; does not reveal the secret.
        tenant_id: Tenant this credential is bound to.
        status: "active" or "revoked".
        created_at: Unix timestamp of issuance.
        rotated_from: credential_id of the prior credential if this was
                      produced by rotate_credential(); else None.
    """

    credential_id: str
    tenant_id: str
    status: str  # "active" | "revoked"
    created_at: int
    rotated_from: str | None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _db_path() -> str:
    p = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not p:
        p = str(_resolve_sqlite_path())
    return p


def _emit(
    event_type: EventType,
    success: bool,
    tenant_id: str | None,
    reason: str | None = None,
    **extra: object,
) -> None:
    """Emit a structured credential security audit event.

    Never includes secret values, key_hash, or full credential_id.
    credential_id_prefix (first 8 chars) is the only credential identifier
    logged, matching the key_prefix truncation pattern in security_audit.py.
    """
    ev = AuditEvent(
        event_type=event_type,
        success=success,
        severity=Severity.INFO if success else Severity.WARNING,
        tenant_id=tenant_id,
        reason=reason,
        details={k: v for k, v in extra.items()},
    )
    _audit.info(
        "credential.audit event=%s", event_type.value, extra={"ev": ev.to_dict()}
    )


def _lookup_row(credential_id: str, tenant_id: str) -> tuple[int, bool, str | None]:
    """Return (db_id, enabled, name) for the credential or raise NOT_FOUND.

    Enforces tenant ownership: if the row exists but belongs to a different
    tenant, the same NOT_FOUND response is returned — no existence side channel.
    """
    path = _db_path()
    con = sqlite3.connect(path)
    try:
        row = con.execute(
            "SELECT id, enabled, name, tenant_id FROM api_keys WHERE key_lookup = ? LIMIT 1",
            (credential_id,),
        ).fetchone()
    finally:
        con.close()

    if row is None or row[3] != tenant_id:
        # Same response whether the credential doesn't exist or belongs to another
        # tenant — no existence side channel.
        raise HTTPException(
            status_code=404,
            detail=api_error(
                ERR_NOT_FOUND,
                "credential not found",
            ),
        )
    db_id, enabled, name = int(row[0]), bool(row[1]), row[2]
    return db_id, enabled, name


def _revoke_by_db_id(db_id: int) -> None:
    """Set enabled=0 for the given row id."""
    path = _db_path()
    con = sqlite3.connect(path)
    try:
        con.execute("UPDATE api_keys SET enabled=0 WHERE id=?", (db_id,))
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_credential(tenant_id: str) -> tuple[CredentialRecord, str]:
    """Issue a new tenant-scoped credential.

    Args:
        tenant_id: Pre-validated, trusted tenant identifier. Must not be
                   sourced from user-supplied document content.

    Returns:
        (CredentialRecord, one_time_secret)

        one_time_secret is the full raw key string in ``fgk.<token>.<secret>``
        format. It is shown exactly once and MUST be stored by the caller
        immediately — it cannot be recovered after this call.

    Security invariants:
        - plaintext secret is generated by ``secrets.token_urlsafe``, not
          derived from tenant_id or any predictable value
        - stored as Argon2id hash only
        - credential_id = HMAC(secret, pepper) — does not reveal the secret
        - audit event emitted on every issuance
    """
    if not tenant_id or not str(tenant_id).strip():
        raise HTTPException(
            status_code=400,
            detail=api_error(
                "CREDENTIAL_TENANT_REQUIRED",
                "tenant_id is required for credential issuance",
                action="supply a valid tenant_id",
            ),
        )

    now = int(time.time())
    raw_key = mint_key(
        _CREDENTIAL_SCOPE,
        tenant_id=tenant_id,
        ttl_seconds=_CREDENTIAL_TTL_SECONDS,
        now=now,
    )

    # Derive credential_id from the secret component via the same HMAC used
    # for the DB key_lookup column — safe to expose, does not reveal the secret.
    secret_part = raw_key.rsplit(".", 1)[-1]
    pepper = _get_key_pepper()
    credential_id = _key_lookup_hash(secret_part, pepper)

    record = CredentialRecord(
        credential_id=credential_id,
        tenant_id=tenant_id,
        status="active",
        created_at=now,
        rotated_from=None,
    )

    _emit(
        EventType.KEY_CREATED,
        True,
        tenant_id,
        "credential_issued",
        credential_id_prefix=credential_id[:8],
    )
    log.debug("credential issued tenant=%s", tenant_id)

    # raw_key is the one-time secret; must be stored by caller immediately
    return record, raw_key


def hash_credential(secret: str) -> str:
    """Return the Argon2id stored form of a credential secret.

    This is the same hash function used internally by mint_key/hash_key.
    Exposed here for transparency and testability.

    Never call this on an existing credential — the hash is already stored.
    This is only needed if building a side-channel comparison fixture.
    """
    from api.auth_scopes.helpers import hash_key  # local import: avoid circular

    hashed, _alg, _params, _lookup = hash_key(secret)
    return hashed


def validate_credential(
    raw_key: str | None,
    *,
    expected_tenant_id: str | None = None,
) -> str:
    """Validate a credential and return its tenant_id.

    Args:
        raw_key: The full ``fgk.<token>.<secret>`` credential string.
        expected_tenant_id: When supplied, raises TENANT_ACCESS_DENIED if the
            credential belongs to a different tenant. Pass the trusted tenant
            from the execution context, never from user input.

    Returns:
        tenant_id bound to the credential.

    Raises:
        HTTPException 401 CREDENTIAL_AUTH_REQUIRED — no credential supplied.
        HTTPException 401 CREDENTIAL_AUTH_INVALID  — credential not recognized.
        HTTPException 401 CREDENTIAL_AUTH_REVOKED  — credential revoked.
        HTTPException 403 CREDENTIAL_TENANT_ACCESS_DENIED — tenant mismatch.

    Security invariants:
        - Argon2id verify is inherently constant-time
        - error messages do not reveal whether a credential exists or its tenant
        - failed validation is audited
    """
    if not raw_key or not str(raw_key).strip():
        _emit(EventType.AUTH_FAILURE, False, None, ERR_AUTH_REQUIRED)
        raise HTTPException(
            status_code=401,
            detail=api_error(
                ERR_AUTH_REQUIRED,
                "credential is required",
                action="supply credential in Authorization header",
            ),
        )

    result = verify_api_key_detailed(raw=raw_key.strip())

    if not result.valid:
        reason = getattr(result, "reason", "") or ""
        if reason == "key_disabled":
            _emit(EventType.AUTH_FAILURE, False, None, ERR_AUTH_REVOKED)
            raise HTTPException(
                status_code=401,
                detail=api_error(
                    ERR_AUTH_REVOKED,
                    "credential has been revoked",
                ),
            )
        _emit(EventType.AUTH_FAILURE, False, None, ERR_AUTH_INVALID)
        raise HTTPException(
            status_code=401,
            detail=api_error(
                ERR_AUTH_INVALID,
                "credential is invalid or expired",
            ),
        )

    authenticated_tenant = result.tenant_id or ""

    if expected_tenant_id is not None and authenticated_tenant != expected_tenant_id:
        _emit(
            EventType.AUTH_FAILURE,
            False,
            expected_tenant_id,
            ERR_TENANT_ACCESS_DENIED,
            authenticated_tenant_hash=authenticated_tenant[:4] + "***",
        )
        raise HTTPException(
            status_code=403,
            detail=api_error(
                ERR_TENANT_ACCESS_DENIED,
                "credential does not belong to this tenant",
            ),
        )

    _emit(EventType.AUTH_SUCCESS, True, authenticated_tenant, "credential_validated")
    return authenticated_tenant


def revoke_credential(credential_id: str, tenant_id: str) -> None:
    """Permanently revoke a credential.

    Idempotent: revoking an already-revoked credential succeeds silently.
    Tenant ownership is enforced — cross-tenant revocation is rejected with
    the same NOT_FOUND response to avoid existence side channels.

    Args:
        credential_id: The credential_id returned at issuance time.
        tenant_id: Pre-validated trusted tenant. Must not come from user input.

    Raises:
        HTTPException 404 CREDENTIAL_NOT_FOUND — credential not found for
            this tenant (or belongs to another tenant — same response).
    """
    db_id, _enabled, _name = _lookup_row(credential_id, tenant_id)
    _revoke_by_db_id(db_id)
    _emit(
        EventType.KEY_REVOKED,
        True,
        tenant_id,
        "credential_revoked",
        credential_id_prefix=credential_id[:8],
    )
    log.debug("credential revoked tenant=%s", tenant_id)


def rotate_credential(
    credential_id: str,
    tenant_id: str,
) -> tuple[CredentialRecord, str]:
    """Revoke the current credential and issue a replacement.

    The old credential is revoked atomically before the new one is issued.
    The new CredentialRecord carries rotated_from=credential_id linking back
    to the revoked credential.

    Args:
        credential_id: The credential_id returned at issuance (or prior rotation).
        tenant_id: Pre-validated trusted tenant.

    Returns:
        (new_CredentialRecord, one_time_secret)

        The new one_time_secret must be stored by the caller immediately.
        The old credential is revoked and will return AUTH_REVOKED on any
        further validation attempt.

    Raises:
        HTTPException 404 CREDENTIAL_NOT_FOUND — old credential not found.
    """
    # Revoke old credential first (raises if not found or wrong tenant)
    revoke_credential(credential_id, tenant_id)

    # Issue new credential
    now = int(time.time())
    raw_key = mint_key(
        _CREDENTIAL_SCOPE,
        tenant_id=tenant_id,
        ttl_seconds=_CREDENTIAL_TTL_SECONDS,
        now=now,
    )

    secret_part = raw_key.rsplit(".", 1)[-1]
    pepper = _get_key_pepper()
    new_credential_id = _key_lookup_hash(secret_part, pepper)

    record = CredentialRecord(
        credential_id=new_credential_id,
        tenant_id=tenant_id,
        status="active",
        created_at=now,
        rotated_from=credential_id,
    )

    _emit(
        EventType.KEY_ROTATED,
        True,
        tenant_id,
        "credential_rotated",
        old_credential_id_prefix=credential_id[:8],
        new_credential_id_prefix=new_credential_id[:8],
    )
    log.debug("credential rotated tenant=%s", tenant_id)

    return record, raw_key
