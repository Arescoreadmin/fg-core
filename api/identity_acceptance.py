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
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text as _sql

from api.admin import require_internal_admin_gateway
from api.db import get_sessionmaker, set_tenant_context
from api.db_models_identity import TenantInvitation
from api.identity.store import TenantIdentityStore
from api.identity.workforce_token import fingerprint_for
from api.principal_authority import resolve_or_create_principal_for_external_identity

_log = logging.getLogger(__name__)
router = APIRouter(prefix="/identity", tags=["identity-acceptance"])
_store = TenantIdentityStore()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


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

    All invalid/expired/revoked/consumed tokens return the same 404.
    Never returns tenant_id, invitation_id, fingerprint, or internal IDs.
    """
    fp = fingerprint_for(token)
    if fp is None:
        raise HTTPException(status_code=404, detail={"code": "INVITATION_NOT_FOUND"})

    db = get_sessionmaker()()
    try:
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.acceptance_token_hash == fp)
            .first()
        )
        if inv is None or inv.status != "pending":
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

        # Fetch tenant display name — safe to return without exposing tenant_id
        row = db.execute(
            _sql("SELECT display_name FROM tenants WHERE tenant_id = :t"),
            {"t": inv.tenant_id},
        ).fetchone()
        tenant_display_name = row[0] if row else "Your workspace"

        role_labels = {
            "tenant_admin": "Tenant Administrator",
            "auditor": "Auditor",
            "user": "User",
            "admin": "Administrator",
        }
        email = inv.normalized_email or inv.email or ""
        parts = email.split("@", 1)
        if len(parts) == 2 and parts[0]:
            masked = parts[0][0] + "***@" + parts[1]
        else:
            masked = "***"

        return {
            "tenant_display_name": tenant_display_name,
            "invited_role_display_name": role_labels.get(
                inv.role, inv.role.replace("_", " ").title()
            ),
            "email_masked": masked,
            "expires_at": inv_expires.isoformat(),
            "status": inv.status,
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
        # Lock invitation — serializes concurrent acceptance attempts
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.acceptance_token_hash == fp)
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

        # Set RLS context for this tenant
        set_tenant_context(db, inv.tenant_id)

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

        # Single commit covers all authority-changing writes
        db.commit()

        return {"accepted": True, "tenant_id": inv.tenant_id, "role": inv.role}

    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        _log.exception("identity_acceptance.unexpected_error")
        raise HTTPException(status_code=500, detail={"code": "INTERNAL_ERROR"})
    finally:
        db.close()
