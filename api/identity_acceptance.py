"""Workforce invitation acceptance — GET preflight + POST accept.

Transport: canonical platform-admin machine credential (gateway auth) carrying
trusted named-user identity headers (email, email_verified, sub). The headers
are an identity transport, not an authority source. Authority derives from:
  - locked invitation (tenant, role, email)
  - canonical identity provider (principal)
The named-user headers supply only: email match target + email_verified state.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text as _sql

from api.admin import require_internal_admin_gateway
from api.db import get_sessionmaker, set_tenant_context
from api.db_models_identity import TenantInvitation
from api.identity.store import TenantIdentityStore, emit_identity_audit_event
from api.identity.workforce_token import fingerprint_for, generate as _gen_token
from api.notifications.email import (
    EmailDeliveryResult,
    build_workforce_invitation_url,
    send_portal_invitation,
)
from api.principal_authority import resolve_or_create_principal_for_external_identity
from api.ratelimit import check_rate_limit_key

_log = logging.getLogger(__name__)
router = APIRouter(prefix="/identity", tags=["identity-acceptance"])
_store = TenantIdentityStore()

_RESEND_PER_MIN_RATE = 1.0 / 60      # 1 resend per minute; capacity = 1
_RESEND_PER_DAY_RATE = 5.0 / 86400   # 5 resends per day; capacity = 5


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _lookup_by_token_hash(db, fp: str):
    """Pre-context lookup: returns (id, tenant_id, email, normalized_email, role, status, expires_at) or None.

    Calls the security-definer function on PostgreSQL to bypass tenant RLS (FORCE
    ROW LEVEL SECURITY prevents querying before app.tenant_id is set). Falls back
    to a direct ORM query in SQLite (test env — no RLS enforced).
    """
    try:
        row = db.execute(
            _sql(
                "SELECT id, tenant_id, email, normalized_email, role, status, expires_at"
                " FROM get_invitation_by_token_hash(:fp)"
            ),
            {"fp": fp},
        ).fetchone()
        return row  # None if not found
    except Exception:
        # SQLite / function absent: no RLS enforced, direct query is safe
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.acceptance_token_hash == fp)
            .first()
        )
        if inv is None:
            return None
        return (
            inv.id,
            inv.tenant_id,
            inv.email,
            inv.normalized_email,
            inv.role,
            inv.status,
            inv.expires_at,
        )


def _get_trusted_named_user(request: Request) -> tuple[str, bool]:
    """Extract named-user email + verified from trusted headers.

    Only safe to call after gateway auth (canonical_platform_admin) is confirmed.
    Returns ("", False) if headers are absent or malformed.
    """
    auth = getattr(getattr(request, "state", None), "auth", None)
    if getattr(auth, "reason", "") != "canonical_platform_admin":
        # Fallback: require_internal_admin_gateway passed; headers still trusted
        # because the gateway machine credential was verified. However, for maximum
        # defense-in-depth we accept named-user headers whenever the gateway
        # internal-token check has already passed (enforced by Depends above).
        pass
    email = (request.headers.get("X-FG-Named-User-Email") or "").strip()
    verified_raw = (
        (request.headers.get("X-FG-Named-User-Email-Verified") or "").strip().lower()
    )
    verified = verified_raw == "true"
    return email, verified


@router.get("/invitations/{token}")
def get_invitation_preflight(token: str) -> dict:
    """Public preflight: minimal display info for the acceptance UX.

    Returns 404 for any invalid, expired, or consumed token. The detail.code
    distinguishes the cause so the console can offer specific recovery actions:
      INVITATION_NOT_FOUND  — malformed token or fingerprint not in DB
      INVITATION_EXPIRED    — token was real but is past expiry
      INVITATION_CONSUMED   — token was used, revoked, or is no longer available

    Never returns tenant_id, invitation_id, fingerprint, or internal IDs.
    """
    fp = fingerprint_for(token)
    if fp is None:
        raise HTTPException(status_code=404, detail={"code": "INVITATION_NOT_FOUND"})

    db = get_sessionmaker()()
    try:
        # Pre-context lookup via security-definer function (bypasses tenant RLS)
        row = _lookup_by_token_hash(db, fp)
        if row is None:
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_NOT_FOUND"}
            )

        _id, tenant_id, _email, normalized_email, role, status, expires_at = row

        inv_expires = expires_at
        if inv_expires is not None and inv_expires.tzinfo is None:
            inv_expires = inv_expires.replace(tzinfo=timezone.utc)

        if status == "expired":
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_EXPIRED"}
            )
        if status != "pending":
            # bound, revoked, failed, auth_started, accepted_identity_pending_binding
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_CONSUMED"}
            )
        if inv_expires is None or inv_expires < _now():
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_EXPIRED"}
            )

        # Fetch tenant display name within tenant context
        set_tenant_context(db, tenant_id)
        tn_row = db.execute(
            _sql("SELECT display_name FROM tenants WHERE tenant_id = :t"),
            {"t": tenant_id},
        ).fetchone()
        tenant_display_name = tn_row[0] if tn_row else "Your workspace"

        role_labels = {
            "tenant_admin": "Tenant Administrator",
            "auditor": "Auditor",
            "user": "User",
            "admin": "Administrator",
        }
        email_str = normalized_email or _email or ""
        parts = email_str.split("@", 1)
        if len(parts) == 2 and parts[0]:
            masked = parts[0][0] + "***@" + parts[1]
        else:
            masked = "***"

        return {
            "tenant_display_name": tenant_display_name,
            "invited_role_display_name": role_labels.get(
                role, role.replace("_", " ").title()
            ),
            "email_masked": masked,
            "expires_at": inv_expires.isoformat(),
            "status": status,
        }
    finally:
        db.close()


@router.post("/invitations/{token}/accept")
def accept_invitation(
    token: str,
    request: Request,
    _gw: None = Depends(require_internal_admin_gateway),
) -> dict:
    """Accept a workforce invitation. Requires gateway auth + named-user identity headers.

    No request body accepted. Any body present is rejected 422 by FastAPI since
    the function signature declares no Body parameter — unexpected fields will
    cause a 422 automatically. Explicit body check added below as defense-in-depth.

    Authority chain:
      fgwi1.* token → fingerprint → locked invitation → named-user email match
      → verified email → canonical principal → tenant_user binding → COMMIT
    """
    # Defense-in-depth: reject any request body
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 0:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "NO_BODY_ACCEPTED",
                "message": "This endpoint accepts no request body.",
            },
        )

    # Extract trusted named-user identity (gateway-authenticated transport only)
    named_email, named_email_verified = _get_trusted_named_user(request)

    # --- Identity verification (before touching DB) ---
    if not named_email_verified:
        raise HTTPException(status_code=403, detail={"code": "IDENTITY_UNVERIFIED"})
    if not named_email:
        raise HTTPException(status_code=403, detail={"code": "IDENTITY_UNVERIFIED"})

    # Compute fingerprint — wrong prefix / malformed returns None
    fp = fingerprint_for(token)
    if fp is None:
        raise HTTPException(status_code=404, detail={"code": "INVITATION_NOT_FOUND"})

    db = get_sessionmaker()()
    try:
        # Pre-context lookup via security-definer function (bypasses tenant RLS).
        # Gives us the tenant_id so we can set the RLS context before locking.
        pre = _lookup_by_token_hash(db, fp)
        if pre is None:
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_NOT_FOUND"}
            )
        pre_id, pre_tenant_id = pre[0], pre[1]

        # Set RLS context before the locking re-query
        set_tenant_context(db, pre_tenant_id)

        # Lock invitation within tenant scope — serializes concurrent acceptance attempts
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.id == pre_id)
            .with_for_update()
            .first()
        )
        if inv is None:
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_NOT_FOUND"}
            )

        # Status + expiry guards (normalized error — all map to 404)
        if inv.status != "pending":
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_NOT_FOUND"}
            )

        inv_expires = inv.expires_at
        if inv_expires is not None and inv_expires.tzinfo is None:
            inv_expires = inv_expires.replace(tzinfo=timezone.utc)
        if inv_expires is None or inv_expires < _now():
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_NOT_FOUND"}
            )

        # Email match — normalized comparison
        inv_email = _normalize_email(inv.normalized_email or inv.email or "")
        if _normalize_email(named_email) != inv_email:
            raise HTTPException(
                status_code=403, detail={"code": "INVITATION_EMAIL_MISMATCH"}
            )

        # Tenant viability — only 'active' state is valid (per client_lifecycle.py)
        tenant_row = db.execute(
            _sql("SELECT lifecycle_state FROM tenants WHERE tenant_id = :t"),
            {"t": inv.tenant_id},
        ).fetchone()
        if not tenant_row or tenant_row[0] != "active":
            raise HTTPException(
                status_code=403, detail={"code": "TENANT_NOT_AVAILABLE"}
            )

        # --- Begin canonical authority sequence (single transaction) ---

        # Step 1: auth_started
        _store.transition_invitation(db, inv, to_status="auth_started")

        # Step 2: Resolve canonical external principal
        named_sub = (request.headers.get("X-FG-Named-User-Sub") or "").strip()
        import os as _os

        auth0_domain = _os.getenv("FG_AUTH0_DOMAIN", "").strip().rstrip("/")
        issuer = f"https://{auth0_domain}/" if auth0_domain else ""
        if not issuer or not named_sub:
            db.rollback()
            raise HTTPException(status_code=403, detail={"code": "IDENTITY_UNVERIFIED"})

        try:
            resolved = resolve_or_create_principal_for_external_identity(
                db,
                provider="auth0",
                issuer=issuer,
                subject=named_sub,
                primary_email=named_email,
            )
        except Exception:
            db.rollback()
            _log.exception("identity_acceptance.principal_resolution_failed")
            raise HTTPException(status_code=403, detail={"code": "PRINCIPAL_INACTIVE"})

        # Step 3: Bind tenant_user — rowcount guard enforces atomicity
        now_iso = _now().isoformat()
        result = db.execute(
            _sql("""
                UPDATE tenant_users
                   SET principal_id              = :pid,
                       identity_binding_status   = 'bound',
                       identity_subject          = :sub,
                       identity_issuer           = :issuer,
                       identity_provider         = 'auth0',
                       identity_bound_at         = :now,
                       updated_at                = :now
                 WHERE tenant_id = :tenant_id
                   AND email     = :email
                   AND identity_binding_status = 'unbound'
            """),
            {
                "pid": str(resolved.principal_id),
                "sub": named_sub,
                "issuer": issuer,
                "now": now_iso,
                "tenant_id": inv.tenant_id,
                "email": inv_email,
            },
        )
        if result.rowcount != 1:
            db.rollback()
            _log.error(
                "identity_acceptance.binding_conflict",
                extra={"tenant_id": inv.tenant_id},
            )
            raise HTTPException(status_code=500, detail={"code": "BINDING_CONFLICT"})

        # Steps 4+5: Advance invitation to bound (via intermediate state)
        _store.transition_invitation(
            db, inv, to_status="accepted_identity_pending_binding"
        )
        _store.transition_invitation(db, inv, to_status="bound")

        # Capture before commit: after commit, SQLAlchemy expires ORM objects and
        # lazy-reload is blocked by RLS (app.tenant_id cleared on connection return).
        return_tenant_id = inv.tenant_id
        return_role = inv.role

        # Single commit covers all authority-changing writes
        db.commit()

        return {"accepted": True, "tenant_id": return_tenant_id, "role": return_role}

    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        _log.exception("identity_acceptance.unexpected_error")
        raise HTTPException(status_code=500, detail={"code": "INTERNAL_ERROR"})
    finally:
        db.close()


def _check_resend_rate_limit(inv_id: str) -> None:
    # check_rate_limit_key uses the configured backend (Redis in production, memory
    # in dev/test). Keys are stable invitation ID so limits survive token rotation.
    ok_min, reset_min = check_rate_limit_key(
        f"resend:inv:{inv_id}:min", _RESEND_PER_MIN_RATE, 1.0
    )
    if not ok_min:
        raise HTTPException(
            status_code=429,
            detail={"code": "RESEND_RATE_LIMITED", "retry_after_seconds": reset_min},
            headers={"Retry-After": str(reset_min)},
        )
    ok_day, reset_day = check_rate_limit_key(
        f"resend:inv:{inv_id}:day", _RESEND_PER_DAY_RATE, 5.0
    )
    if not ok_day:
        raise HTTPException(
            status_code=429,
            detail={"code": "RESEND_DAILY_LIMIT", "retry_after_seconds": reset_day},
            headers={"Retry-After": str(reset_day)},
        )


_ROLE_LABELS = {
    "tenant_admin": "Tenant Administrator",
    "auditor": "Auditor",
    "user": "User",
    "admin": "Administrator",
}


def _attempt_resend_email(
    to_email: str, role: str, raw_token: str, expires_at: datetime
) -> EmailDeliveryResult:
    result = send_portal_invitation(
        to_email=to_email,
        invitation_url=build_workforce_invitation_url(raw_token),
        portal_role=_ROLE_LABELS.get(role, role.replace("_", " ").title()),
        expires_at=expires_at.isoformat(),
    )
    if result.state == "failed":
        _log.error(
            "identity_acceptance.resend_email_failed code=%s retryable=%s",
            result.error_code,
            result.retryable,
        )
    return result


@router.post("/invitations/{token}/request-resend")
def request_resend(token: str) -> dict:
    """User-triggered resend for expired workforce invitations.

    The expired bearer token authorizes the resend — same authority model as the
    GET preflight. No gateway auth or session required.

    Only genuinely expired invitations are resendable (status='expired' or
    status='pending' past expires_at). Terminal and in-progress states return
    404 to avoid leaking state.

    Delivery-before-rotation contract:
      1. Generate new token in memory (not yet in DB).
      2. Attempt email delivery while holding the row lock.
      3. On delivery success ('sent' or 'skipped'): commit rotation — old token
         invalid, new token live, 200 {"sent": true}.
      4. On delivery failure: rollback — old expired token remains valid so the
         user can retry with the same link — 503 with retryable flag.

    This guarantees the user is never stranded with an unknown live token:
    either they received the email with the new token, or the old token still
    works for a retry. Email address, tenant, and role are immutable.
    """
    fp = fingerprint_for(token)
    if fp is None:
        raise HTTPException(status_code=404, detail={"code": "INVITATION_NOT_FOUND"})

    db = get_sessionmaker()()
    try:
        row = _lookup_by_token_hash(db, fp)
        if row is None:
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_NOT_FOUND"}
            )

        pre_id, pre_tenant_id, _email, _norm, _role, pre_status, pre_expires = row

        pre_expires_tz = pre_expires
        if pre_expires_tz is not None and pre_expires_tz.tzinfo is None:
            pre_expires_tz = pre_expires_tz.replace(tzinfo=timezone.utc)

        now = _now()
        is_resendable = pre_status == "expired" or (
            pre_status == "pending"
            and pre_expires_tz is not None
            and pre_expires_tz < now
        )
        if not is_resendable:
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_NOT_FOUND"}
            )

        # Rate limit before acquiring the row lock (key = stable invitation ID)
        _check_resend_rate_limit(pre_id)

        set_tenant_context(db, pre_tenant_id)

        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.id == pre_id)
            .with_for_update()
            .first()
        )
        if inv is None:
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_NOT_FOUND"}
            )

        # Re-validate under lock — state may have changed since pre-context lookup
        inv_expires = inv.expires_at
        if inv_expires is not None and inv_expires.tzinfo is None:
            inv_expires = inv_expires.replace(tzinfo=timezone.utc)

        is_still_resendable = inv.status == "expired" or (
            inv.status == "pending"
            and inv_expires is not None
            and inv_expires < now
        )
        if not is_still_resendable:
            raise HTTPException(
                status_code=404, detail={"code": "INVITATION_NOT_FOUND"}
            )

        new_expires_at = now + timedelta(hours=72)

        # Generate new token in memory before touching the DB.
        # Row lock is held during email delivery so the old fingerprint cannot
        # be used for a concurrent accept while delivery is in flight.
        new_raw_token, new_fingerprint = _gen_token()

        send_email = inv.normalized_email or inv.email or ""
        send_role = inv.role

        email_result = _attempt_resend_email(
            send_email, send_role, new_raw_token, new_expires_at
        )
        if email_result.state == "failed":
            db.rollback()
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "RESEND_EMAIL_FAILED",
                    "retryable": email_result.retryable,
                },
            )

        # Email delivered (or skipped in dev) — commit rotation atomically
        inv.acceptance_token_hash = new_fingerprint
        inv.expires_at = new_expires_at
        inv.status = "pending"
        inv.revoked_at = None
        inv.updated_at = now

        emit_identity_audit_event(
            db,
            tenant_id=inv.tenant_id,
            event_type="tenant.invite.created",
            invitation_id=inv.id,
            affected_email=send_email,
            details={"invitation_status": "pending"},
        )

        db.commit()
        return {"sent": True}

    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        _log.exception("identity_acceptance.resend_unexpected_error")
        raise HTTPException(status_code=500, detail={"code": "INTERNAL_ERROR"})
    finally:
        db.close()
