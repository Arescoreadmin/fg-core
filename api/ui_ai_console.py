from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_bound_tenant, require_scopes
from api.config.env import is_production_env
from api.config_versioning import canonicalize_config, hash_config
from api.deps import tenant_db_required
from api.security_audit import AuditEvent, EventType, Severity, get_auditor
from services.ai_plane_extension.orchestration import deterministic_simulated_response
from services.schema_validation import validate_payload_against_schema

router = APIRouter(prefix="/ui", tags=["ui-ai"])
admin_router = APIRouter(prefix="/admin", tags=["ui-ai-admin"])

DEVICE_COOKIE = "fg_device_id"
CONTRACTS_ROOT = Path("contracts/ai")


class AIChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)
    requested_tenant_id: str | None = None
    persona: str | None = Field(default="default", max_length=64)
    device_id: str | None = None
    provider: str | None = None
    model: str | None = None


class DeviceStateRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=512)
    ticket: str | None = Field(default=None, max_length=128)


KNOWN_PROVIDERS = {"simulated"}
PROVIDER_MAX_TOKENS = {"simulated": 4096}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _prod_like() -> bool:
    return (os.getenv("FG_ENV") or "").strip().lower() in {
        "prod",
        "production",
        "staging",
    }


def _error(status_code: int, code: str, message: str, **extra: Any) -> HTTPException:
    payload: dict[str, Any] = {"error_code": code, "message": message}
    if extra:
        payload["details"] = extra
    return HTTPException(status_code=status_code, detail=payload)


def _hash_payload(payload: dict[str, Any]) -> str:
    return hash_config(canonicalize_config(payload))


def _day_bucket() -> str:
    return _utc_now().strftime("%Y-%m-%d")


def _estimate_tokens(text_value: str) -> int:
    return max(1, len((text_value or "").split()))


def _ip_prefix(request: Request) -> str | None:
    host = request.client.host if request.client else ""
    if not host:
        return None
    if ":" in host:
        return ":".join(host.split(":")[:3])
    parts = host.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return host


def _global_allowed_providers() -> set[str]:
    raw_env = os.getenv("FG_AI_ALLOWED_PROVIDERS")
    raw = "simulated" if raw_env is None else raw_env.strip()
    return {item.strip() for item in raw.split(",") if item.strip()}


def _provider_env_allowed(provider: str) -> bool:
    flags = {
        "simulated": (
            os.getenv("FG_AI_ENABLE_SIMULATED") or "1" if not _prod_like() else "0"
        )
        .strip()
        .lower()
        in {"1", "true", "yes", "on"}
    }
    return bool(flags.get(provider, False))


def _signature_hook_enabled() -> bool:
    return (os.getenv("FG_AI_DEVICE_SIGNATURE_ENABLED") or "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _validate_device_signature_stub(
    request: Request, tenant_id: str, device_id: str, request_hash: str
) -> None:
    ts_h = (request.headers.get("x-fg-ts") or "").strip()
    nonce = (request.headers.get("x-fg-nonce") or "").strip()
    sig = (request.headers.get("x-fg-sig") or "").strip()

    if not _signature_hook_enabled():
        return
    if not ts_h or not nonce or not sig:
        raise _error(401, "AI_DEVICE_SIG_REQUIRED", "device signature headers required")

    try:
        ts_i = int(ts_h)
    except ValueError as exc:
        raise _error(
            401, "AI_DEVICE_SIG_INVALID", "invalid signature timestamp"
        ) from exc

    if abs(int(time.time()) - ts_i) > 300:
        raise _error(401, "AI_DEVICE_SIG_EXPIRED", "signature timestamp expired")

    secret = (os.getenv("FG_AI_DEVICE_SIG_SECRET") or "").strip()
    if not secret:
        if _prod_like():
            raise _error(
                503, "AI_DEVICE_SIG_CONFIG_INVALID", "signature secret missing"
            )
        return

    signed = f"{tenant_id}|{device_id}|{ts_h}|{nonce}|{request_hash}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise _error(401, "AI_DEVICE_SIG_INVALID", "invalid signature")


def _known_provider_or_fail(provider: str) -> None:
    if provider not in KNOWN_PROVIDERS:
        raise _error(400, "AI_PROVIDER_UNKNOWN", "unknown provider", provider=provider)


def _load_schema(name: str) -> dict[str, Any]:
    schema_path = CONTRACTS_ROOT / "schema" / f"{name}.schema.json"
    if not schema_path.exists():
        raise _error(
            503,
            "AI_CONTRACT_SCHEMA_MISSING",
            "contract schema missing",
            schema=str(schema_path),
        )
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _load_contract_dir(name: str, schema: dict[str, Any]) -> list[dict[str, Any]]:
    folder = CONTRACTS_ROOT / name
    if not folder.exists():
        if _prod_like():
            raise _error(
                503,
                "AI_CONTRACTS_MISSING",
                "contracts missing",
                folder=str(folder),
            )
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(folder.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        validate_payload_against_schema(raw, schema)
        records.append(raw)
    return records


def _contracts_bundle() -> dict[str, list[dict[str, Any]]]:
    exp_schema = _load_schema("experience")
    pol_schema = _load_schema("policy")
    theme_schema = _load_schema("theme")
    experiences = _load_contract_dir("experiences", exp_schema)
    policies = _load_contract_dir("policies", pol_schema)
    themes = _load_contract_dir("themes", theme_schema)

    policy_ids = {p["id"] for p in policies}
    theme_ids = {t["id"] for t in themes}
    for exp in experiences:
        if exp["policy_id"] not in policy_ids or exp["theme_id"] not in theme_ids:
            raise _error(
                503,
                "AI_CONTRACT_REFERENCE_INVALID",
                "experience references unknown policy/theme",
                experience_id=exp["id"],
            )
    return {"experiences": experiences, "policies": policies, "themes": themes}


def _resolve_experience(
    tenant_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    bundle = _contracts_bundle()
    experiences = bundle["experiences"]
    experience = next((e for e in experiences if e.get("tenant_id") == tenant_id), None)
    if not experience:
        if _prod_like():
            raise _error(
                503,
                "AI_EXPERIENCE_MISSING",
                "tenant experience missing",
                tenant_id=tenant_id,
            )
        experience = next((e for e in experiences if e.get("is_default") is True), None)
    if not experience:
        raise _error(503, "AI_EXPERIENCE_MISSING", "no AI experience configured")

    policy = next(p for p in bundle["policies"] if p["id"] == experience["policy_id"])
    theme = next(t for t in bundle["themes"] if t["id"] == experience["theme_id"])
    return experience, policy, theme


def _extract_persona(request: Request, requested: str | None) -> str:
    auth = getattr(request.state, "auth", None)
    scopes = getattr(auth, "scopes", set()) or set()
    if "ai:admin" in scopes:
        return (requested or "admin").strip() or "admin"
    if "ai:chat" in scopes:
        return (requested or "default").strip() or "default"
    raise _error(403, "AI_SCOPE_DENIED", "missing ai scope")


def _device_id(request: Request, payload_device_id: str | None) -> str | None:
    value = (
        payload_device_id
        or request.headers.get("x-fg-device-id")
        or request.cookies.get(DEVICE_COOKIE)
        or ""
    ).strip()
    return value or None


def _ensure_device_record(
    db: Session, tenant_id: str, device_id: str, request: Request
) -> dict[str, Any]:
    row = (
        db.execute(
            text(
                "SELECT tenant_id, device_id, enabled FROM ai_device_registry WHERE tenant_id=:tenant_id AND device_id=:device_id"
            ),
            {"tenant_id": tenant_id, "device_id": device_id},
        )
        .mappings()
        .first()
    )
    if row:
        return dict(row)

    db.execute(
        text(
            """
            INSERT INTO ai_device_registry(tenant_id, device_id, enabled, registered_at, last_seen_at, telemetry_json)
            VALUES (:tenant_id, :device_id, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, :telemetry_json)
            """
        ),
        {
            "tenant_id": tenant_id,
            "device_id": device_id,
            "telemetry_json": json.dumps(
                {
                    "user_agent": (request.headers.get("user-agent") or "")[:200],
                    "ip_prefix": _ip_prefix(request),
                }
            ),
        },
    )
    db.commit()
    return {"tenant_id": tenant_id, "device_id": device_id, "enabled": 0}


def _enforce_device_enabled(
    db: Session, tenant_id: str, device_id: str, request: Request
) -> None:
    row = _ensure_device_record(db, tenant_id, device_id, request)
    if str(row.get("tenant_id")) != tenant_id:
        raise _error(403, "AI_DEVICE_TENANT_MISMATCH", "device tenant mismatch")
    if int(row.get("enabled") or 0) != 1:
        raise _error(403, "AI_DEVICE_DISABLED", "device is disabled")
    db.execute(
        text(
            "UPDATE ai_device_registry SET last_seen_at=CURRENT_TIMESTAMP WHERE tenant_id=:tenant_id AND device_id=:device_id"
        ),
        {"tenant_id": tenant_id, "device_id": device_id},
    )
    db.commit()


def _normalize_scope_component(value: str) -> str:
    return "".join(
        ch for ch in str(value).strip().lower() if ch.isalnum() or ch in {"-", "_", ":"}
    )


def _max_tokens_per_request(policy: dict[str, Any], provider: str) -> int:
    configured = int(policy.get("max_tokens_per_request") or 0)
    env_default = int((os.getenv("FG_AI_MAX_TOKENS_PER_REQUEST") or "4096").strip())
    provider_limit = int(PROVIDER_MAX_TOKENS.get(provider, env_default))
    base = configured if configured > 0 else env_default
    return max(1, min(base, provider_limit))


def _quota_scope(kind: str, tenant_id: str, device_id: str | None = None) -> str:
    tenant_component = _normalize_scope_component(tenant_id)
    if kind == "tenant":
        return f"tenant:{tenant_component}"
    device_component = _normalize_scope_component(device_id or "")
    return f"device:{tenant_component}:{device_component}"


def _consume_quota_atomic(
    db: Session,
    *,
    tenant_id: str,
    device_id: str,
    usage_day: str,
    total_tokens: int,
    tenant_limit: int,
    device_limit: int,
) -> None:
    if total_tokens <= 0:
        return

    if tenant_limit <= 0 and device_limit <= 0:
        return

    tenant_scope = _quota_scope("tenant", tenant_id)
    device_scope = _quota_scope("device", tenant_id, device_id)

    try:
        if tenant_limit > 0:
            t_row = db.execute(
                text(
                    """
                    INSERT INTO ai_quota_daily(quota_scope, tenant_id, device_id, usage_day, token_limit, used_tokens, updated_at)
                    VALUES(:scope, :tenant_id, NULL, :usage_day, :token_limit, :delta, CURRENT_TIMESTAMP)
                    ON CONFLICT(quota_scope, usage_day)
                    DO UPDATE SET
                        used_tokens = ai_quota_daily.used_tokens + excluded.used_tokens,
                        token_limit = excluded.token_limit,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE ai_quota_daily.used_tokens + excluded.used_tokens <= ai_quota_daily.token_limit
                    RETURNING used_tokens
                    """
                ),
                {
                    "scope": tenant_scope,
                    "tenant_id": tenant_id,
                    "usage_day": usage_day,
                    "token_limit": tenant_limit,
                    "delta": total_tokens,
                },
            ).first()
            if t_row is None:
                raise _error(
                    429, "AI_QUOTA_TENANT_EXCEEDED", "tenant token quota exceeded"
                )

        if device_limit > 0:
            d_row = db.execute(
                text(
                    """
                    INSERT INTO ai_quota_daily(quota_scope, tenant_id, device_id, usage_day, token_limit, used_tokens, updated_at)
                    VALUES(:scope, :tenant_id, :device_id, :usage_day, :token_limit, :delta, CURRENT_TIMESTAMP)
                    ON CONFLICT(quota_scope, usage_day)
                    DO UPDATE SET
                        used_tokens = ai_quota_daily.used_tokens + excluded.used_tokens,
                        token_limit = excluded.token_limit,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE ai_quota_daily.used_tokens + excluded.used_tokens <= ai_quota_daily.token_limit
                    RETURNING used_tokens
                    """
                ),
                {
                    "scope": device_scope,
                    "tenant_id": tenant_id,
                    "device_id": device_id,
                    "usage_day": usage_day,
                    "token_limit": device_limit,
                    "delta": total_tokens,
                },
            ).first()
            if d_row is None:
                raise _error(
                    429, "AI_QUOTA_DEVICE_EXCEEDED", "device token quota exceeded"
                )

        db.commit()
    except HTTPException:
        db.rollback()
        raise


def _refund_quota_atomic(
    db: Session,
    *,
    tenant_id: str,
    device_id: str,
    usage_day: str,
    total_tokens: int,
    tenant_limit: int,
    device_limit: int,
) -> None:
    if total_tokens <= 0:
        return

    tenant_scope = _quota_scope("tenant", tenant_id)
    device_scope = _quota_scope("device", tenant_id, device_id)

    if tenant_limit > 0:
        db.execute(
            text(
                """
                UPDATE ai_quota_daily
                SET used_tokens = CASE WHEN used_tokens >= :delta THEN used_tokens - :delta ELSE 0 END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE quota_scope=:scope AND usage_day=:usage_day
                """
            ),
            {"scope": tenant_scope, "usage_day": usage_day, "delta": total_tokens},
        )

    if device_limit > 0:
        db.execute(
            text(
                """
                UPDATE ai_quota_daily
                SET used_tokens = CASE WHEN used_tokens >= :delta THEN used_tokens - :delta ELSE 0 END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE quota_scope=:scope AND usage_day=:usage_day
                """
            ),
            {"scope": device_scope, "usage_day": usage_day, "delta": total_tokens},
        )

    db.commit()


def _contains_pii(value: str, deny_terms: list[str]) -> bool:
    low = value.lower()
    if any(term.lower() in low for term in deny_terms if term):
        return True
    if "ssn" in low or "social security" in low:
        return True
    if (
        any(ch.isdigit() for ch in value)
        and len([ch for ch in value if ch.isdigit()]) >= 13
    ):
        return True
    return False


def _audit(
    event_type: EventType,
    *,
    tenant_id: str,
    success: bool,
    reason: str | None,
    details: dict[str, Any],
    request: Request | None = None,
) -> None:
    get_auditor().log_event(
        AuditEvent(
            event_type=event_type,
            success=success,
            severity=Severity.INFO if success else Severity.WARNING,
            tenant_id=tenant_id,
            reason=reason,
            details=details,
            request_id=getattr(getattr(request, "state", None), "request_id", None)
            if request
            else None,
            request_path=str(request.url.path) if request and request.url else None,
            request_method=request.method if request else None,
        )
    )


def _record_usage(
    db: Session,
    *,
    usage_record_id: str,
    tenant_id: str,
    device_id: str,
    user_id: str | None,
    persona: str,
    provider: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    usage_day: str,
    metering_mode: str,
    request_hash: str,
    policy_hash: str,
    experience_hash: str,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO ai_token_usage(
                usage_record_id,
                tenant_id,
                device_id,
                user_id,
                persona,
                provider,
                model,
                prompt_tokens,
                completion_tokens,
                total_tokens,
                usage_day,
                metering_mode,
                estimation_mode,
                request_hash,
                policy_hash,
                experience_hash,
                created_at
            ) VALUES (
                :usage_record_id,
                :tenant_id,
                :device_id,
                :user_id,
                :persona,
                :provider,
                :model,
                :prompt_tokens,
                :completion_tokens,
                :total_tokens,
                :usage_day,
                :metering_mode,
                :estimation_mode,
                :request_hash,
                :policy_hash,
                :experience_hash,
                CURRENT_TIMESTAMP
            )
            """
        ),
        {
            "usage_record_id": usage_record_id,
            "tenant_id": tenant_id,
            "device_id": device_id,
            "user_id": user_id,
            "persona": persona,
            "provider": provider,
            "model": model,
            "prompt_tokens": max(0, int(prompt_tokens)),
            "completion_tokens": max(0, int(completion_tokens)),
            "total_tokens": max(0, int(total_tokens)),
            "usage_day": usage_day,
            "metering_mode": metering_mode,
            "estimation_mode": metering_mode,
            "request_hash": request_hash,
            "policy_hash": policy_hash,
            "experience_hash": experience_hash,
        },
    )
    db.commit()


@router.get("/ai", dependencies=[Depends(require_scopes("ui:read"))])
def ui_ai_page() -> Response:
    html = """
<!doctype html><html><head><meta charset='utf-8'><title>Enterprise AI Console</title></head>
<body>
  <h1>Enterprise AI Console</h1>
  <div id='status'></div>
  <textarea id='message' rows='6' cols='80'></textarea><br/>
  <button id='send'>Send</button>
  <pre id='out'></pre>
  <script>
    async function loadExp(){
      const r=await fetch('/ui/ai/experience');
      const d=await r.json();
      document.getElementById('status').innerText = `device_enabled=${d.device.enabled} tenant=${d.tenant_id}`;
    }
    async function send(){
      const message=document.getElementById('message').value;
      const r=await fetch('/ui/ai/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({message})});
      document.getElementById('out').innerText = await r.text();
    }
    document.getElementById('send').onclick=send;
    loadExp();
  </script>
</body></html>
"""
    return Response(content=html, media_type="text/html")


@router.get("/ai/experience", dependencies=[Depends(require_scopes("ui:read"))])
def ai_experience(
    request: Request,
    response: Response,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    experience, policy, theme = _resolve_experience(tenant_id)

    device_id = _device_id(request, None)
    if not device_id:
        device_id = str(uuid.uuid4())
        response.set_cookie(
            key=DEVICE_COOKIE,
            value=device_id,
            httponly=True,
            samesite="strict",
            secure=is_production_env(),
        )

    device = _ensure_device_record(db, tenant_id, device_id, request)
    return {
        "tenant_id": tenant_id,
        "capabilities": experience.get("capabilities", {}),
        "theme": {
            "id": theme.get("id"),
            "name": theme.get("name"),
            "version": theme.get("version"),
            "colors": theme.get("colors", {}),
        },
        "allowed": {
            "providers": list(policy.get("allowed_providers") or []),
            "models": [policy.get("default_model")],
            "quotas": {
                "tenant_max_tokens_per_day": int(
                    policy.get("tenant_max_tokens_per_day") or 0
                ),
                "device_max_tokens_per_day": int(
                    policy.get("device_max_tokens_per_day") or 0
                ),
            },
        },
        "device": {
            "device_id": device_id,
            "enabled": bool(int(device.get("enabled") or 0)),
        },
    }


@router.get("/ai/usage", dependencies=[Depends(require_scopes("ui:read", "ai:chat"))])
def ai_usage(
    request: Request, db: Session = Depends(tenant_db_required)
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    device_id = _device_id(request, None)
    if not device_id:
        raise _error(400, "AI_DEVICE_REQUIRED", "device identifier missing")
    _enforce_device_enabled(db, tenant_id, device_id, request)
    rows = db.execute(
        text(
            "SELECT usage_record_id, tenant_id, device_id, provider, model, total_tokens, usage_day, metering_mode FROM ai_token_usage WHERE tenant_id=:tenant_id ORDER BY id DESC LIMIT 200"
        ),
        {"tenant_id": tenant_id},
    ).mappings()
    return {"tenant_id": tenant_id, "items": [dict(r) for r in rows]}


@router.post("/ai/chat", dependencies=[Depends(require_scopes("ui:read", "ai:chat"))])
def ai_chat(
    payload: AIChatRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    bound_tenant = require_bound_tenant(request)
    requested = (payload.requested_tenant_id or "").strip() or None
    tenant_id = bind_tenant_id(request, requested, require_explicit_for_unscoped=True)
    if tenant_id != bound_tenant:
        raise _error(403, "AI_TENANT_MISMATCH", "tenant mismatch")

    persona = _extract_persona(request, payload.persona)
    experience, policy, _theme = _resolve_experience(tenant_id)
    device_id = _device_id(request, payload.device_id)
    if not device_id:
        raise _error(400, "AI_DEVICE_REQUIRED", "device identifier missing")

    _enforce_device_enabled(db, tenant_id, device_id, request)

    deny_terms = [str(x) for x in (policy.get("pii_deny_terms") or [])]
    provider = payload.provider or policy.get("default_provider") or "simulated"
    model = payload.model or policy.get("default_model") or "SIMULATED_V1"
    _known_provider_or_fail(provider)

    if provider not in set(policy.get("allowed_providers") or []):
        raise _error(
            400,
            "AI_PROVIDER_DENIED_BY_TENANT_POLICY",
            "provider not allowed by tenant policy",
        )
    if provider not in _global_allowed_providers():
        raise _error(
            400, "AI_PROVIDER_DENIED_BY_SERVER", "provider not allowed by server config"
        )
    if not _provider_env_allowed(provider):
        raise _error(
            400, "AI_PROVIDER_DENIED_BY_ENV", "provider not allowed in this environment"
        )

    request_hash = hashlib.sha256(
        canonicalize_config(payload.model_dump()).encode("utf-8")
    ).hexdigest()
    _validate_device_signature_stub(request, tenant_id, device_id, request_hash)

    policy_hash = _hash_payload(policy)
    experience_hash = _hash_payload(experience)
    request_day = _day_bucket()
    session_id = hashlib.sha256(
        f"{tenant_id}|{device_id}|{request_day}".encode("utf-8")
    ).hexdigest()[:24]
    event_id = hashlib.sha256(
        f"{tenant_id}|{device_id}|{request_hash}|{policy_hash}".encode("utf-8")
    ).hexdigest()[:24]

    output = ""
    metering_mode = "unknown"
    prompt_tokens = _estimate_tokens(payload.message)
    completion_tokens = 0
    total_tokens = prompt_tokens
    usage_record_id = hashlib.sha256(
        f"{tenant_id}|{device_id}|{request_hash}|{session_id}".encode("utf-8")
    ).hexdigest()
    blocked_error: HTTPException | None = None

    denial_error: HTTPException | None = None
    quota_charge_mode = "precharge"
    quota_precharged_tokens = 0
    tenant_limit = int(policy.get("tenant_max_tokens_per_day") or 0)
    device_limit = int(policy.get("device_max_tokens_per_day") or 0)
    try:
        if _contains_pii(payload.message, deny_terms):
            blocked_error = _error(
                400, "AI_INPUT_POLICY_BLOCKED", "input blocked by policy"
            )
            raise blocked_error

        if prompt_tokens > 0:
            _consume_quota_atomic(
                db,
                tenant_id=tenant_id,
                device_id=device_id,
                usage_day=request_day,
                total_tokens=prompt_tokens,
                tenant_limit=tenant_limit,
                device_limit=device_limit,
            )
            quota_precharged_tokens = prompt_tokens

        output = deterministic_simulated_response(payload.message)
        metering_mode = "estimated"

        if _contains_pii(output, deny_terms):
            blocked_error = _error(
                400, "AI_OUTPUT_POLICY_BLOCKED", "output blocked by policy"
            )
            raise blocked_error

        completion_tokens = _estimate_tokens(output)
        total_tokens = prompt_tokens + completion_tokens

        max_tokens = _max_tokens_per_request(policy, provider)
        if total_tokens > max_tokens:
            blocked_error = _error(
                400, "AI_REQUEST_TOKEN_CAP_EXCEEDED", "request token cap exceeded"
            )
            raise blocked_error

        extra_tokens = max(0, total_tokens - quota_precharged_tokens)
        if extra_tokens > 0:
            _consume_quota_atomic(
                db,
                tenant_id=tenant_id,
                device_id=device_id,
                usage_day=request_day,
                total_tokens=extra_tokens,
                tenant_limit=tenant_limit,
                device_limit=device_limit,
            )
    except HTTPException as exc:
        denial_error = exc
    finally:
        usage_day = request_day
        _record_usage(
            db,
            usage_record_id=usage_record_id,
            tenant_id=tenant_id,
            device_id=device_id,
            user_id=getattr(getattr(request.state, "auth", None), "key_prefix", None),
            persona=persona,
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            usage_day=usage_day,
            metering_mode=metering_mode,
            request_hash=request_hash,
            policy_hash=policy_hash,
            experience_hash=experience_hash,
        )

    if blocked_error is not None or denial_error is not None:
        denied = blocked_error or denial_error
        reason_code = "ai_denied"
        if isinstance(getattr(denied, "detail", None), dict):
            reason_code = denied.detail.get("error_code", reason_code)
        if quota_precharged_tokens > 0 and completion_tokens == 0:
            _refund_quota_atomic(
                db,
                tenant_id=tenant_id,
                device_id=device_id,
                usage_day=request_day,
                total_tokens=quota_precharged_tokens,
                tenant_limit=tenant_limit,
                device_limit=device_limit,
            )
            quota_charge_mode = "precharge_refunded"
        _audit(
            EventType.ADMIN_ACTION,
            tenant_id=tenant_id,
            success=False,
            reason=reason_code,
            details={
                "event_id": event_id,
                "session_id": session_id,
                "device_id": device_id,
                "policy_hash": policy_hash,
                "experience_hash": experience_hash,
                "request_hash": request_hash,
                "usage_record_id": usage_record_id,
                "metering_mode": metering_mode,
                "quota_charge_mode": quota_charge_mode,
            },
            request=request,
        )
        raise denied

    if metering_mode == "unknown":
        denied = _error(
            503, "AI_METERING_UNCERTAIN", "unable to determine metering mode"
        )
        _audit(
            EventType.ADMIN_ACTION,
            tenant_id=tenant_id,
            success=False,
            reason="AI_METERING_UNCERTAIN",
            details={
                "event_id": event_id,
                "session_id": session_id,
                "device_id": device_id,
                "policy_hash": policy_hash,
                "experience_hash": experience_hash,
                "request_hash": request_hash,
                "usage_record_id": usage_record_id,
                "metering_mode": metering_mode,
                "quota_charge_mode": quota_charge_mode,
            },
            request=request,
        )
        raise denied

    _audit(
        EventType.ADMIN_ACTION,
        tenant_id=tenant_id,
        success=True,
        reason="ai_chat",
        details={
            "event_id": event_id,
            "session_id": session_id,
            "device_id": device_id,
            "provider": provider,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "policy_hash": policy_hash,
            "experience_hash": experience_hash,
            "request_hash": request_hash,
            "usage_record_id": usage_record_id,
            "metering_mode": metering_mode,
            "quota_charge_mode": quota_charge_mode,
        },
        request=request,
    )

    return {
        "ok": True,
        "correlation_id": event_id,
        "session_id": session_id,
        "tenant_id": tenant_id,
        "device_id": device_id,
        "response": output,
        "usage": {
            "usage_record_id": usage_record_id,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "metering_mode": metering_mode,
            "quota_charge_mode": quota_charge_mode,
        },
        "policy": {
            "decision": "allow",
            "policy_hash": policy_hash,
            "experience_hash": experience_hash,
        },
    }


@admin_router.get("/devices", dependencies=[Depends(require_scopes("admin:write"))])
def list_devices(
    request: Request,
    tenant: str | None = None,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, tenant, require_explicit_for_unscoped=True)
    rows = db.execute(
        text(
            "SELECT tenant_id, device_id, enabled, registered_at, last_seen_at FROM ai_device_registry WHERE tenant_id=:tenant_id ORDER BY last_seen_at DESC"
        ),
        {"tenant_id": tenant_id},
    ).mappings()
    return {"tenant_id": tenant_id, "items": [dict(r) for r in rows]}


def _toggle_device(
    db: Session,
    request: Request,
    tenant_id: str,
    device_id: str,
    enabled: bool,
    reason: str,
    ticket: str | None,
) -> dict[str, Any]:
    row = (
        db.execute(
            text(
                "SELECT enabled FROM ai_device_registry WHERE tenant_id=:tenant_id AND device_id=:device_id"
            ),
            {"tenant_id": tenant_id, "device_id": device_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise _error(404, "AI_DEVICE_UNKNOWN", "device not found")
    before = bool(int(row.get("enabled") or 0))
    db.execute(
        text(
            "UPDATE ai_device_registry SET enabled=:enabled, last_seen_at=CURRENT_TIMESTAMP WHERE tenant_id=:tenant_id AND device_id=:device_id"
        ),
        {
            "enabled": 1 if enabled else 0,
            "tenant_id": tenant_id,
            "device_id": device_id,
        },
    )
    db.commit()

    get_auditor().log_admin_action(
        action="device_toggle",
        tenant_id=tenant_id,
        request=request,
        details={
            "actor": getattr(
                getattr(request.state, "auth", None), "key_prefix", "unknown"
            ),
            "device_id": device_id,
            "reason": reason,
            "ticket": ticket,
            "previous_state": before,
            "new_state": enabled,
        },
    )

    return {
        "tenant_id": tenant_id,
        "device_id": device_id,
        "enabled": enabled,
        "previous_enabled": before,
    }


@admin_router.post(
    "/devices/{device_id}/enable", dependencies=[Depends(require_scopes("admin:write"))]
)
def admin_enable_device(
    device_id: str,
    payload: DeviceStateRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    return _toggle_device(
        db, request, tenant_id, device_id, True, payload.reason, payload.ticket
    )


@admin_router.post(
    "/devices/{device_id}/disable",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def admin_disable_device(
    device_id: str,
    payload: DeviceStateRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    return _toggle_device(
        db,
        request,
        tenant_id,
        device_id,
        False,
        payload.reason,
        payload.ticket,
    )


@router.post(
    "/devices/{device_id}/enable",
    dependencies=[Depends(require_scopes("ui:read", "admin:write"))],
)
def tenant_enable_device(
    device_id: str,
    payload: DeviceStateRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    return _toggle_device(
        db, request, tenant_id, device_id, True, payload.reason, payload.ticket
    )


@router.post(
    "/devices/{device_id}/disable",
    dependencies=[Depends(require_scopes("ui:read", "admin:write"))],
)
def tenant_disable_device(
    device_id: str,
    payload: DeviceStateRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    return _toggle_device(
        db,
        request,
        tenant_id,
        device_id,
        False,
        payload.reason,
        payload.ticket,
    )
