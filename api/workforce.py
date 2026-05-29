"""
workforce.py — Workforce Intelligence API (PR 36)

Endpoints for per-user AI activity monitoring and risk profiling.
All endpoints require admin:write scope and tenant isolation.

Not standalone: requires tenant_users + ai_query_log tables (migrations 0068–0069),
auth layer, and Postgres substrate.
"""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from api.error_contracts import api_error

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
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "USER_ALREADY_EXISTS", "A user with that email already exists."
            ),
        )

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
                "last_active_at": r.last_active_at.isoformat()
                if r.last_active_at
                else None,
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
        raise HTTPException(
            status_code=404, detail=api_error("USER_NOT_FOUND", "User not found.")
        )

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
        text(
            f"UPDATE tenant_users SET {', '.join(updates)} WHERE tenant_id=:tenant_id AND id=:user_id"
        ),
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
        profiles.append(
            {
                "user_id": u.id,
                "email": u.email,
                "display_name": u.display_name,
                "role": u.role,
                "last_active_at": u.last_active_at.isoformat()
                if u.last_active_at
                else None,
                **profile,
            }
        )

    profiles.sort(key=lambda p: p["risk_score"], reverse=True)

    # Organic snapshot capture: one upsert per user per day on leaderboard load
    for profile in profiles:
        _upsert_snapshot(db, tenant_id, profile["user_id"], profile)

    # Fire threshold-based alerts (cooldown enforced inside helper)
    _fire_alerts(db, tenant_id, profiles)

    return {"items": profiles, "total": len(profiles), "period_days": _RISK_WINDOW_DAYS}


@router.get(
    "/users/{user_id}/activity", dependencies=[Depends(require_scopes("admin:write"))]
)
def get_user_activity(
    user_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)

    user = db.execute(
        text(
            "SELECT id, email, display_name, role FROM tenant_users WHERE tenant_id=:t AND id=:u"
        ),
        {"t": tenant_id, "u": user_id},
    ).fetchone()
    if not user:
        raise HTTPException(
            status_code=404, detail=api_error("USER_NOT_FOUND", "User not found.")
        )

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

    total = (
        db.execute(
            text("SELECT COUNT(*) FROM ai_query_log WHERE tenant_id=:t AND user_id=:u"),
            {"t": tenant_id, "u": user_id},
        ).scalar()
        or 0
    )

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
                "classified_at": q.classified_at.isoformat()
                if q.classified_at
                else None,
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
        raise HTTPException(
            status_code=400,
            detail=api_error("INVITE_TOKEN_REQUIRED", "invite_token is required."),
        )

    row = db.execute(
        text("""
            SELECT id, tenant_id, email, display_name, role, invite_expires_at, active
            FROM tenant_users
            WHERE invite_token = :token
        """),
        {"token": token},
    ).fetchone()

    if not row:
        raise HTTPException(
            status_code=401,
            detail=api_error("INVITE_INVALID", "Invalid or expired invite token."),
        )
    if not row.active:
        raise HTTPException(
            status_code=403,
            detail=api_error("USER_INACTIVE", "This user account is deactivated."),
        )
    if row.invite_expires_at and row.invite_expires_at < _now():
        raise HTTPException(
            status_code=401,
            detail=api_error("INVITE_EXPIRED", "This invite link has expired."),
        )

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


# ─── PR 37 additions: risk history · keywords · alerts ───────────────────────

# ── Pydantic models ────────────────────────────────────────────────────────────


class KeywordPayload(BaseModel):
    keyword: str
    match_type: str = "contains"
    case_sensitive: bool = False
    flag_value: str
    flag_type: str = "sensitivity"
    action: str = "flag"
    description: str | None = None

    @field_validator("match_type")
    @classmethod
    def _valid_match_type(cls, v: str) -> str:
        if v not in {"contains", "exact", "word_boundary", "prefix", "regex"}:
            raise ValueError(
                "match_type must be contains|exact|word_boundary|prefix|regex"
            )
        return v

    @field_validator("action")
    @classmethod
    def _valid_action(cls, v: str) -> str:
        if v not in {"flag", "block", "escalate"}:
            raise ValueError("action must be flag|block|escalate")
        return v

    @field_validator("keyword")
    @classmethod
    def _not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("keyword must not be empty")
        return v.strip()


class AlertRulePayload(BaseModel):
    name: str
    threshold_score: float | None = None
    threshold_band: str | None = None
    cooldown_hours: int = 24
    active: bool = True

    @field_validator("name")
    @classmethod
    def _not_empty_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be empty")
        return v.strip()


# ── Snapshot helper ────────────────────────────────────────────────────────────


def _upsert_snapshot(
    db: Session, tenant_id: str, user_id: str, profile: dict[str, Any]
) -> None:
    """Upsert one risk_score_snapshots row for today (UTC). Non-fatal on error."""
    today_str = _now().strftime("%Y-%m-%d")
    try:
        existing = db.execute(
            text("""
                SELECT id FROM risk_score_snapshots
                WHERE tenant_id = :t AND user_id = :u
                  AND DATE(captured_at AT TIME ZONE 'UTC') = :today
            """),
            {"t": tenant_id, "u": user_id, "today": today_str},
        ).fetchone()

        if existing:
            db.execute(
                text("""
                    UPDATE risk_score_snapshots
                    SET risk_score = :risk_score, risk_band = :risk_band,
                        total_queries = :total_queries, policy_violations = :policy_violations,
                        personal_ratio = :personal_ratio,
                        sensitive_topic_count = :sensitive_topic_count,
                        pii_query_count = :pii_query_count,
                        competitor_query_count = :competitor_query_count,
                        active_days = :active_days, captured_at = NOW()
                    WHERE id = :id
                """),
                {
                    "id": existing.id,
                    "risk_score": profile["risk_score"],
                    "risk_band": profile["risk_band"],
                    "total_queries": profile["total_queries"],
                    "policy_violations": profile["policy_violations"],
                    "personal_ratio": profile["personal_ratio"],
                    "sensitive_topic_count": profile["sensitive_topic_count"],
                    "pii_query_count": profile["pii_query_count"],
                    "competitor_query_count": profile["competitor_query_count"],
                    "active_days": profile["active_days"],
                },
            )
        else:
            db.execute(
                text("""
                    INSERT INTO risk_score_snapshots
                        (id, tenant_id, user_id, risk_score, risk_band,
                         total_queries, policy_violations, personal_ratio,
                         sensitive_topic_count, pii_query_count, competitor_query_count,
                         active_days, period_days, captured_at)
                    VALUES
                        (:id, :tenant_id, :user_id, :risk_score, :risk_band,
                         :total_queries, :policy_violations, :personal_ratio,
                         :sensitive_topic_count, :pii_query_count, :competitor_query_count,
                         :active_days, :period_days, NOW())
                """),
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "risk_score": profile["risk_score"],
                    "risk_band": profile["risk_band"],
                    "total_queries": profile["total_queries"],
                    "policy_violations": profile["policy_violations"],
                    "personal_ratio": profile["personal_ratio"],
                    "sensitive_topic_count": profile["sensitive_topic_count"],
                    "pii_query_count": profile["pii_query_count"],
                    "competitor_query_count": profile["competitor_query_count"],
                    "active_days": profile["active_days"],
                    "period_days": profile["period_days"],
                },
            )
        db.commit()
    except Exception:
        db.rollback()


# ── Alert fire helper ──────────────────────────────────────────────────────────


def _fire_alerts(db: Session, tenant_id: str, profiles: list[dict[str, Any]]) -> None:
    """Check active alert rules and fire for matching users (respects cooldown)."""
    rules = db.execute(
        text("""
            SELECT id, threshold_score, threshold_band, cooldown_hours
            FROM risk_alert_rules
            WHERE tenant_id = :t AND active = TRUE
        """),
        {"t": tenant_id},
    ).fetchall()

    if not rules:
        return

    for rule in rules:
        bands = (
            {b.strip() for b in rule.threshold_band.split(",")}
            if rule.threshold_band
            else set()
        )
        for p in profiles:
            score_hit = rule.threshold_score is not None and p["risk_score"] >= float(
                rule.threshold_score
            )
            band_hit = bool(bands) and p["risk_band"] in bands
            if not (score_hit or band_hit):
                continue

            # Cooldown check: last firing for this rule+user within cooldown window
            last = db.execute(
                text("""
                    SELECT fired_at FROM risk_alerts_fired
                    WHERE rule_id = :rule_id AND user_id = :user_id
                    ORDER BY fired_at DESC LIMIT 1
                """),
                {"rule_id": rule.id, "user_id": p["user_id"]},
            ).fetchone()

            if last:
                cooldown_delta = timedelta(hours=rule.cooldown_hours)
                if (
                    _now() - last.fired_at.replace(tzinfo=timezone.utc)
                ) < cooldown_delta:
                    continue

            try:
                db.execute(
                    text("""
                        INSERT INTO risk_alerts_fired
                            (id, tenant_id, rule_id, user_id, user_email,
                             risk_score, risk_band, fired_at)
                        VALUES
                            (:id, :tenant_id, :rule_id, :user_id, :user_email,
                             :risk_score, :risk_band, NOW())
                    """),
                    {
                        "id": str(uuid.uuid4()),
                        "tenant_id": tenant_id,
                        "rule_id": rule.id,
                        "user_id": p["user_id"],
                        "user_email": p.get("email"),
                        "risk_score": p["risk_score"],
                        "risk_band": p["risk_band"],
                    },
                )
                db.commit()
            except Exception:
                db.rollback()


# ── Risk history endpoint ──────────────────────────────────────────────────────


@router.get(
    "/users/{user_id}/risk-history",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def get_risk_history(
    user_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
    days: int = 30,
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    since = (_now() - timedelta(days=max(1, min(days, 365)))).isoformat()

    rows = db.execute(
        text("""
            SELECT risk_score, risk_band, total_queries, policy_violations,
                   personal_ratio, captured_at
            FROM risk_score_snapshots
            WHERE tenant_id = :t AND user_id = :u AND captured_at >= :since
            ORDER BY captured_at ASC
        """),
        {"t": tenant_id, "u": user_id, "since": since},
    ).fetchall()

    return {
        "user_id": user_id,
        "history": [
            {
                "date": r.captured_at.strftime("%Y-%m-%d"),
                "risk_score": float(r.risk_score),
                "risk_band": r.risk_band,
                "total_queries": r.total_queries,
                "policy_violations": r.policy_violations,
                "personal_ratio": float(r.personal_ratio),
            }
            for r in rows
        ],
        "period_days": days,
    }


# ── Keyword CRUD ───────────────────────────────────────────────────────────────


@router.get("/keywords", dependencies=[Depends(require_scopes("admin:write"))])
def list_keywords(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    rows = db.execute(
        text("""
            SELECT id, keyword, match_type, case_sensitive, flag_value, flag_type,
                   action, description, created_by, active, created_at
            FROM tenant_keywords
            WHERE tenant_id = :t AND active = TRUE
            ORDER BY created_at DESC
        """),
        {"t": tenant_id},
    ).fetchall()

    return {
        "items": [
            {
                "id": r.id,
                "keyword": r.keyword,
                "match_type": r.match_type,
                "case_sensitive": r.case_sensitive,
                "flag_value": r.flag_value,
                "flag_type": r.flag_type,
                "action": r.action,
                "description": r.description,
                "created_by": r.created_by,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
        "total": len(rows),
    }


@router.post("/keywords", dependencies=[Depends(require_scopes("admin:write"))])
def create_keyword(
    payload: KeywordPayload,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)

    # Validate regex at creation time so we don't store broken patterns
    if payload.match_type == "regex":
        try:
            re.compile(payload.keyword)
        except re.error as exc:
            raise HTTPException(
                status_code=422,
                detail=api_error("INVALID_REGEX", f"Invalid regex: {exc}"),
            ) from exc

    kw_id = str(uuid.uuid4())
    db.execute(
        text("""
            INSERT INTO tenant_keywords
                (id, tenant_id, keyword, match_type, case_sensitive,
                 flag_value, flag_type, action, description, created_by,
                 active, created_at, updated_at)
            VALUES
                (:id, :tenant_id, :keyword, :match_type, :case_sensitive,
                 :flag_value, :flag_type, :action, :description, :created_by,
                 TRUE, NOW(), NOW())
            ON CONFLICT (tenant_id, keyword, flag_value) WHERE active = TRUE DO NOTHING
        """),
        {
            "id": kw_id,
            "tenant_id": tenant_id,
            "keyword": payload.keyword,
            "match_type": payload.match_type,
            "case_sensitive": payload.case_sensitive,
            "flag_value": payload.flag_value,
            "flag_type": payload.flag_type,
            "action": payload.action,
            "description": payload.description,
            "created_by": getattr(request.state, "user_email", None),
        },
    )
    db.commit()
    return {"id": kw_id, "ok": True}


@router.delete(
    "/keywords/{keyword_id}", dependencies=[Depends(require_scopes("admin:write"))]
)
def delete_keyword(
    keyword_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    db.execute(
        text("""
            UPDATE tenant_keywords SET active = FALSE, updated_at = NOW()
            WHERE tenant_id = :t AND id = :id
        """),
        {"t": tenant_id, "id": keyword_id},
    )
    db.commit()
    return {"ok": True}


# ── Keyword preview/backtest ───────────────────────────────────────────────────


class _BacktestPayload(BaseModel):
    keyword: str
    match_type: str = "contains"
    case_sensitive: bool = False
    limit: int = 100


@router.post("/keywords/preview", dependencies=[Depends(require_scopes("admin:write"))])
def preview_keyword(
    payload: _BacktestPayload,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    """Return matching queries from the last `limit` rows for this tenant."""
    tenant_id = require_bound_tenant(request)
    limit = max(1, min(payload.limit, 500))

    rows = db.execute(
        text("""
            SELECT id, query_text, user_id, created_at
            FROM ai_query_log
            WHERE tenant_id = :t
            ORDER BY created_at DESC
            LIMIT :limit
        """),
        {"t": tenant_id, "limit": limit},
    ).fetchall()

    kw = payload.keyword
    flags = re.IGNORECASE if not payload.case_sensitive else 0

    def _matches(text_val: str) -> bool:
        t = text_val if payload.case_sensitive else text_val.lower()
        k = kw if payload.case_sensitive else kw.lower()
        if payload.match_type == "contains":
            return k in t
        if payload.match_type == "exact":
            return t == k
        if payload.match_type == "word_boundary":
            try:
                return bool(re.search(rf"\b{re.escape(kw)}\b", text_val, flags))
            except re.error:
                return False
        if payload.match_type == "prefix":
            return t.startswith(k)
        if payload.match_type == "regex":
            try:
                return bool(re.search(kw, text_val, flags))
            except re.error:
                return False
        return False

    matches = [
        {
            "query_id": r.id,
            "query_text": r.query_text[:200],
            "user_id": r.user_id,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
        if _matches(r.query_text)
    ]

    return {
        "matched": len(matches),
        "scanned": len(rows),
        "matches": matches[:50],
    }


# ── Alert rule CRUD ────────────────────────────────────────────────────────────


@router.get("/alert-rules", dependencies=[Depends(require_scopes("admin:write"))])
def list_alert_rules(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    rows = db.execute(
        text("""
            SELECT id, name, threshold_score, threshold_band,
                   cooldown_hours, active, created_at
            FROM risk_alert_rules
            WHERE tenant_id = :t
            ORDER BY created_at DESC
        """),
        {"t": tenant_id},
    ).fetchall()

    return {
        "items": [
            {
                "id": r.id,
                "name": r.name,
                "threshold_score": float(r.threshold_score)
                if r.threshold_score is not None
                else None,
                "threshold_band": r.threshold_band,
                "cooldown_hours": r.cooldown_hours,
                "active": r.active,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
        "total": len(rows),
    }


@router.post("/alert-rules", dependencies=[Depends(require_scopes("admin:write"))])
def create_alert_rule(
    payload: AlertRulePayload,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    if payload.threshold_score is None and not payload.threshold_band:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "RULE_NEEDS_CONDITION",
                "At least one of threshold_score or threshold_band must be set.",
            ),
        )
    rule_id = str(uuid.uuid4())
    db.execute(
        text("""
            INSERT INTO risk_alert_rules
                (id, tenant_id, name, threshold_score, threshold_band,
                 cooldown_hours, active, created_at, updated_at)
            VALUES
                (:id, :tenant_id, :name, :threshold_score, :threshold_band,
                 :cooldown_hours, :active, NOW(), NOW())
        """),
        {
            "id": rule_id,
            "tenant_id": tenant_id,
            "name": payload.name,
            "threshold_score": payload.threshold_score,
            "threshold_band": payload.threshold_band,
            "cooldown_hours": payload.cooldown_hours,
            "active": payload.active,
        },
    )
    db.commit()
    return {"id": rule_id, "ok": True}


@router.patch(
    "/alert-rules/{rule_id}", dependencies=[Depends(require_scopes("admin:write"))]
)
def update_alert_rule(
    rule_id: str,
    payload: AlertRulePayload,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    db.execute(
        text("""
            UPDATE risk_alert_rules
            SET name = :name, threshold_score = :threshold_score,
                threshold_band = :threshold_band, cooldown_hours = :cooldown_hours,
                active = :active, updated_at = NOW()
            WHERE tenant_id = :t AND id = :id
        """),
        {
            "t": tenant_id,
            "id": rule_id,
            "name": payload.name,
            "threshold_score": payload.threshold_score,
            "threshold_band": payload.threshold_band,
            "cooldown_hours": payload.cooldown_hours,
            "active": payload.active,
        },
    )
    db.commit()
    return {"ok": True}


@router.delete(
    "/alert-rules/{rule_id}", dependencies=[Depends(require_scopes("admin:write"))]
)
def delete_alert_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    db.execute(
        text("DELETE FROM risk_alert_rules WHERE tenant_id = :t AND id = :id"),
        {"t": tenant_id, "id": rule_id},
    )
    db.commit()
    return {"ok": True}


# ── Fired alerts ───────────────────────────────────────────────────────────────


@router.get("/alerts", dependencies=[Depends(require_scopes("admin:write"))])
def list_alerts(
    request: Request,
    db: Session = Depends(tenant_db_required),
    dismissed: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    rows = db.execute(
        text("""
            SELECT f.id, f.rule_id, r.name AS rule_name,
                   f.user_id, f.user_email, f.risk_score, f.risk_band,
                   f.dismissed, f.dismissed_at, f.fired_at
            FROM risk_alerts_fired f
            JOIN risk_alert_rules r ON r.id = f.rule_id
            WHERE f.tenant_id = :t AND f.dismissed = :dismissed
            ORDER BY f.fired_at DESC
            LIMIT :limit
        """),
        {"t": tenant_id, "dismissed": dismissed, "limit": min(limit, 200)},
    ).fetchall()

    return {
        "items": [
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "user_id": r.user_id,
                "user_email": r.user_email,
                "risk_score": float(r.risk_score),
                "risk_band": r.risk_band,
                "dismissed": r.dismissed,
                "dismissed_at": r.dismissed_at.isoformat() if r.dismissed_at else None,
                "fired_at": r.fired_at.isoformat(),
            }
            for r in rows
        ],
        "total": len(rows),
    }


@router.post(
    "/alerts/{alert_id}/dismiss", dependencies=[Depends(require_scopes("admin:write"))]
)
def dismiss_alert(
    alert_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    db.execute(
        text("""
            UPDATE risk_alerts_fired
            SET dismissed = TRUE, dismissed_at = NOW()
            WHERE tenant_id = :t AND id = :id
        """),
        {"t": tenant_id, "id": alert_id},
    )
    db.commit()
    return {"ok": True}
