"""
workforce.py — Workforce Intelligence API (PR 36)

Endpoints for per-user AI activity monitoring and risk profiling.
All endpoints require admin:write scope and tenant isolation.

Not standalone: requires tenant_users + ai_query_log tables (migrations 0068–0069),
auth layer, and Postgres substrate.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from api.errors import http_error

router = APIRouter(prefix="/workforce", tags=["workforce"])

_INVITE_TTL_HOURS = 72
_RISK_WINDOW_DAYS = 30

# ─── Pydantic models ──────────────────────────────────────────────────────────

class InviteUserPayload(BaseModel):
    email: str
    display_name: str
    role: str = "user"

    @field_validator("role")
    @classmethod
    def _valid_role(cls, v: str) -> str:
        if v not in {"user", "admin", "auditor"}:
            raise ValueError("role must be user | admin | auditor")
        return v


class UpdateUserPayload(BaseModel):
    active: bool | None = None
    role: str | None = None
    display_name: str | None = None

    @field_validator("role")
    @classmethod
    def _valid_role(cls, v: str | None) -> str | None:
        if v is not None and v not in {"user", "admin", "auditor"}:
            raise ValueError("role must be user | admin | auditor")
        return v


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _risk_band(score: float) -> str:
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def _compute_risk_profile(db: Session, tenant_id: str, user_id: str) -> dict[str, Any]:
    """Compute a risk score for a user from their last 30 days of query logs."""
    since = (_now() - timedelta(days=_RISK_WINDOW_DAYS)).isoformat()

    rows = db.execute(
        text("""
            SELECT
                COUNT(*)                                                          AS total_queries,
                SUM(CASE WHEN policy_decision != 'allow' THEN 1 ELSE 0 END)      AS policy_violations,
                SUM(CASE WHEN work_relevance = 'personal' THEN 1 ELSE 0 END)     AS personal_queries,
                SUM(CASE WHEN sensitivity_flags @> '["contains_pii"]' THEN 1 ELSE 0 END) AS pii_queries,
                SUM(CASE WHEN sensitivity_flags @> '["competitor_mention"]' THEN 1 ELSE 0 END) AS competitor_queries,
                SUM(CASE WHEN subject_category IN ('hr','legal') THEN 1 ELSE 0 END) AS sensitive_topic_queries,
                COUNT(DISTINCT DATE(created_at))                                  AS active_days
            FROM ai_query_log
            WHERE tenant_id = :tenant_id AND user_id = :user_id
              AND created_at >= :since
        """),
        {"tenant_id": tenant_id, "user_id": user_id, "since": since},
    ).fetchone()

    if not rows or rows.total_queries == 0:
        return {
            "risk_score": 0.0,
            "risk_band": "low",
            "total_queries": 0,
            "policy_violations": 0,
            "personal_ratio": 0.0,
            "sensitive_topic_count": 0,
            "pii_query_count": 0,
            "competitor_query_count": 0,
            "active_days": 0,
            "period_days": _RISK_WINDOW_DAYS,
        }

    total = rows.total_queries
    violations = rows.policy_violations or 0
    personal = rows.personal_queries or 0
    pii = rows.pii_queries or 0
    competitor = rows.competitor_queries or 0
    sensitive = rows.sensitive_topic_queries or 0
    personal_ratio = personal / total if total else 0.0

    raw = (
        min(violations * 15, 30)
        + (personal_ratio * 25)
        + min(sensitive * 5, 20)
        + min(pii * 8, 16)
        + min(competitor * 6, 12)
    )
    score = min(round(raw, 1), 100.0)

    return {
        "risk_score": score,
        "risk_band": _risk_band(score),
        "total_queries": total,
        "policy_violations": violations,
        "personal_ratio": round(personal_ratio, 3),
        "sensitive_topic_count": sensitive,
        "pii_query_count": pii,
        "competitor_query_count": competitor,
        "active_days": rows.active_days or 0,
        "period_days": _RISK_WINDOW_DAYS,
    }


# ─── User management ──────────────────────────────────────────────────────────

@router.post("/users", dependencies=[Depends(require_scopes("admin:write"))])
def invite_user(
    payload: InviteUserPayload,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)

    existing = db.execute(
        text("SELECT id FROM tenant_users WHERE tenant_id=:t AND email=:e"),
        {"t": tenant_id, "e": payload.email.lower()},
    ).fetchone()
    if existing:
        raise http_error(409, "USER_ALREADY_EXISTS", "A user with that email already exists.")

    user_id = str(uuid.uuid4())
    invite_token = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(hours=_INVITE_TTL_HOURS)

    db.execute(
        text("""
            INSERT INTO tenant_users
                (id, tenant_id, email, display_name, role, invite_token, invite_expires_at, active, created_at, updated_at)
            VALUES
                (:id, :tenant_id, :email, :display_name, :role, :invite_token, :expires_at, TRUE, NOW(), NOW())
        """),
        {
            "id": user_id,
            "tenant_id": tenant_id,
            "email": payload.email.lower(),
            "display_name": payload.display_name,
            "role": payload.role,
            "invite_token": invite_token,
            "expires_at": expires_at,
        },
    )
    db.commit()

    return {
        "user_id": user_id,
        "email": payload.email.lower(),
        "display_name": payload.display_name,
        "role": payload.role,
        "invite_token": invite_token,
        "invite_expires_at": expires_at.isoformat(),
        "invite_url_hint": f"/accept-invite?token={invite_token}",
    }


@router.get("/users", dependencies=[Depends(require_scopes("admin:write"))])
def list_users(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    rows = db.execute(
        text("""
            SELECT id, email, display_name, role, active, last_active_at, created_at,
                   (invite_token IS NOT NULL AND invite_expires_at > NOW()) AS invite_pending
            FROM tenant_users
            WHERE tenant_id = :tenant_id
            ORDER BY created_at DESC
        """),
        {"tenant_id": tenant_id},
    ).fetchall()

    return {
        "items": [
            {
                "user_id": r.id,
                "email": r.email,
                "display_name": r.display_name,
                "role": r.role,
                "active": r.active,
                "invite_pending": bool(r.invite_pending),
                "last_active_at": r.last_active_at.isoformat() if r.last_active_at else None,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
        "total": len(rows),
    }


@router.patch("/users/{user_id}", dependencies=[Depends(require_scopes("admin:write"))])
def update_user(
    user_id: str,
    payload: UpdateUserPayload,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)

    row = db.execute(
        text("SELECT id FROM tenant_users WHERE tenant_id=:t AND id=:u"),
        {"t": tenant_id, "u": user_id},
    ).fetchone()
    if not row:
        raise http_error(404, "USER_NOT_FOUND", "User not found.")

    updates: list[str] = ["updated_at = NOW()"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "user_id": user_id}

    if payload.active is not None:
        updates.append("active = :active")
        params["active"] = payload.active
    if payload.role is not None:
        updates.append("role = :role")
        params["role"] = payload.role
    if payload.display_name is not None:
        updates.append("display_name = :display_name")
        params["display_name"] = payload.display_name

    db.execute(
        text(f"UPDATE tenant_users SET {', '.join(updates)} WHERE tenant_id=:tenant_id AND id=:user_id"),
        params,
    )
    db.commit()
    return {"ok": True, "user_id": user_id}


# ─── Risk profiles ────────────────────────────────────────────────────────────

@router.get("/risk-profiles", dependencies=[Depends(require_scopes("admin:write"))])
def list_risk_profiles(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)

    users = db.execute(
        text("""
            SELECT id, email, display_name, role, active, last_active_at
            FROM tenant_users
            WHERE tenant_id = :tenant_id AND active = TRUE
            ORDER BY display_name
        """),
        {"tenant_id": tenant_id},
    ).fetchall()

    profiles = []
    for u in users:
        profile = _compute_risk_profile(db, tenant_id, u.id)
        profiles.append({
            "user_id": u.id,
            "email": u.email,
            "display_name": u.display_name,
            "role": u.role,
            "last_active_at": u.last_active_at.isoformat() if u.last_active_at else None,
            **profile,
        })

    profiles.sort(key=lambda p: p["risk_score"], reverse=True)
    return {"items": profiles, "total": len(profiles), "period_days": _RISK_WINDOW_DAYS}


@router.get("/users/{user_id}/activity", dependencies=[Depends(require_scopes("admin:write"))])
def get_user_activity(
    user_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)

    user = db.execute(
        text("SELECT id, email, display_name, role FROM tenant_users WHERE tenant_id=:t AND id=:u"),
        {"t": tenant_id, "u": user_id},
    ).fetchone()
    if not user:
        raise http_error(404, "USER_NOT_FOUND", "User not found.")

    queries = db.execute(
        text("""
            SELECT id, session_id, query_text, response_text, provider, model,
                   prompt_tokens, completion_tokens, policy_decision,
                   subject_category, work_relevance, sensitivity_flags,
                   classified_at, created_at
            FROM ai_query_log
            WHERE tenant_id = :tenant_id AND user_id = :user_id
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {"tenant_id": tenant_id, "user_id": user_id, "limit": limit, "offset": offset},
    ).fetchall()

    total = db.execute(
        text("SELECT COUNT(*) FROM ai_query_log WHERE tenant_id=:t AND user_id=:u"),
        {"t": tenant_id, "u": user_id},
    ).scalar() or 0

    risk = _compute_risk_profile(db, tenant_id, user_id)

    return {
        "user": {
            "user_id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
        },
        "risk_profile": risk,
        "queries": [
            {
                "id": q.id,
                "session_id": q.session_id,
                "query_text": q.query_text,
                "response_text": q.response_text,
                "provider": q.provider,
                "model": q.model,
                "prompt_tokens": q.prompt_tokens,
                "completion_tokens": q.completion_tokens,
                "policy_decision": q.policy_decision,
                "subject_category": q.subject_category,
                "work_relevance": q.work_relevance,
                "sensitivity_flags": q.sensitivity_flags or [],
                "classified_at": q.classified_at.isoformat() if q.classified_at else None,
                "created_at": q.created_at.isoformat(),
            }
            for q in queries
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ─── Accept invite (portal login) ────────────────────────────────────────────

class _AcceptInviteBody(BaseModel):
    invite_token: str


@router.post("/users/accept-invite")
def accept_invite(
    body: _AcceptInviteBody,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    """Validate an invite token and return user identity for session creation.
    Called by the portal BFF, not exposed directly to clients.
    """
    token = body.invite_token.strip()
    if not token:
        raise http_error(400, "INVITE_TOKEN_REQUIRED", "invite_token is required.")

    row = db.execute(
        text("""
            SELECT id, tenant_id, email, display_name, role, invite_expires_at, active
            FROM tenant_users
            WHERE invite_token = :token
        """),
        {"token": token},
    ).fetchone()

    if not row:
        raise http_error(401, "INVITE_INVALID", "Invalid or expired invite token.")
    if not row.active:
        raise http_error(403, "USER_INACTIVE", "This user account is deactivated.")
    if row.invite_expires_at and row.invite_expires_at < _now():
        raise http_error(401, "INVITE_EXPIRED", "This invite link has expired.")

    # Clear the invite token (one-time use) and record last_active_at
    db.execute(
        text("""
            UPDATE tenant_users
            SET invite_token = NULL, invite_expires_at = NULL, last_active_at = NOW(), updated_at = NOW()
            WHERE id = :user_id
        """),
        {"user_id": row.id},
    )
    db.commit()

    return {
        "user_id": row.id,
        "tenant_id": row.tenant_id,
        "email": row.email,
        "display_name": row.display_name,
        "role": row.role,
    }
