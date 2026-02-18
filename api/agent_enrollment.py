from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from urllib.parse import urlencode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from api.auth_scopes import hash_key
from api.db import get_engine
from api.db_models import AgentDeviceKey, AgentDeviceNonce, AgentDeviceRegistry, AgentEnrollmentToken
from api.security_audit import audit_admin_action

log = logging.getLogger("frostgate.agent")

router = APIRouter(prefix="/agent", tags=["agent"])

_MAX_BODY_BYTES = int(os.getenv("FG_AGENT_MAX_BODY_BYTES", "16384"))
_CLOCK_SKEW_SECONDS = int(os.getenv("FG_AGENT_SIG_SKEW_SECONDS", "120"))
_NONCE_TTL_SECONDS = int(os.getenv("FG_AGENT_NONCE_TTL_SECONDS", "300"))
_NONCE_RETENTION_SECONDS = int(os.getenv("FG_AGENT_NONCE_RETENTION_SECONDS", "600"))
_NONCE_DEVICE_CAP = int(os.getenv("FG_AGENT_NONCE_DEVICE_CAP", "10000"))


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


class _RateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def allow(self, key: str, *, rate_per_sec: float, burst: int) -> bool:
        if (os.getenv("FG_ENV") or "").strip().lower() == "test":
            return True
        now = time.time()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                self._buckets[key] = _Bucket(tokens=float(burst - 1), updated_at=now)
                return True
            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(float(burst), bucket.tokens + elapsed * rate_per_sec)
            bucket.updated_at = now
            if bucket.tokens < 1.0:
                return False
            bucket.tokens -= 1.0
            return True


_HEARTBEAT_LIMITER = _RateLimiter()


@dataclass(frozen=True)
class _KEK:
    version: str
    key: bytes


def _token_pepper() -> str:
    pepper = (os.getenv("FG_AGENT_TOKEN_PEPPER") or os.getenv("FG_KEY_PEPPER") or "").strip()
    if not pepper:
        raise RuntimeError("FG_AGENT_TOKEN_PEPPER or FG_KEY_PEPPER is required")
    return pepper


def _hash_with_pepper(raw: str) -> str:
    return hashlib.sha256(f"{_token_pepper()}:{raw}".encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _load_keks() -> tuple[_KEK, dict[str, bytes]]:
    current_version = (os.getenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION") or "v1").strip()
    prefix = "FG_DEVICE_KEY_KEK_"
    keys: dict[str, bytes] = {}
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        suffix = key[len(prefix) :].strip()
        if not suffix or suffix in {"CURRENT_VERSION"}:
            continue
        if not value.strip():
            continue
        try:
            raw = base64.urlsafe_b64decode(value.strip())
        except Exception as exc:
            raise RuntimeError(f"invalid base64 for {key}") from exc
        if len(raw) != 32:
            raise RuntimeError(f"{key} must decode to 32 bytes")
        keys[suffix.lower()] = raw

    if not keys:
        raise RuntimeError(
            "no KEKs configured; set FG_DEVICE_KEY_KEK_CURRENT_VERSION and FG_DEVICE_KEY_KEK_<version>"
        )

    current_key = keys.get(current_version.lower())
    if current_key is None:
        raise RuntimeError("current KEK version missing")
    return _KEK(version=current_version.lower(), key=current_key), keys


def _encrypt_secret(secret: str) -> str:
    current, _ = _load_keks()
    nonce = secrets.token_bytes(12)
    aad = f"fg-agent:{current.version}".encode("utf-8")
    aes = AESGCM(current.key)
    ciphertext = aes.encrypt(nonce, secret.encode("utf-8"), aad)
    payload = {
        "v": current.version,
        "n": base64.urlsafe_b64encode(nonce).decode("utf-8"),
        "ct": base64.urlsafe_b64encode(ciphertext).decode("utf-8"),
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _decrypt_secret(blob: str) -> str:
    try:
        payload = json.loads(blob)
    except Exception as exc:
        raise RuntimeError("invalid encrypted secret payload") from exc
    version = str(payload.get("v") or "").strip().lower()
    nonce_b64 = str(payload.get("n") or "")
    ct_b64 = str(payload.get("ct") or "")
    if not version or not nonce_b64 or not ct_b64:
        raise RuntimeError("invalid encrypted secret payload fields")

    _, keys = _load_keks()
    key = keys.get(version)
    if key is None:
        raise RuntimeError("missing KEK version for decryption")

    nonce = base64.urlsafe_b64decode(nonce_b64)
    ciphertext = base64.urlsafe_b64decode(ct_b64)
    aad = f"fg-agent:{version}".encode("utf-8")
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, aad)
    return plaintext.decode("utf-8")


def _mint_device_secret() -> tuple[str, str, str, str, str]:
    secret = secrets.token_urlsafe(32)
    key_prefix = f"fgd_{secrets.token_hex(6)}"
    key_hash, hash_alg, _params, key_lookup = hash_key(secret)
    return secret, key_prefix, key_hash, key_lookup, hash_alg


def _fingerprint_hash(fingerprint: str) -> str:
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


def _body_hash(raw: bytes) -> str:
    try:
        obj = json.loads(raw.decode("utf-8")) if raw else {}
        canonical = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except Exception:
        canonical = raw
    return hashlib.sha256(canonical).hexdigest()


def _canonical_path_with_query(request: Request) -> str:
    path = request.url.path
    query_items = list(request.query_params.multi_items())
    if not query_items:
        return path
    query_items.sort(key=lambda x: (x[0], x[1]))
    return f"{path}?{urlencode(query_items, doseq=True)}"


def _canonical_request(method: str, path_with_query: str, body_hash: str, ts: str, nonce: str) -> str:
    return "\n".join([method.upper(), path_with_query, body_hash, ts, nonce])


def _request_metadata(request: Request, body: AgentHeartbeatRequest | AgentEnrollRequest | None = None) -> dict[str, str]:
    payload = {
        "ip": request.client.host if request.client else "",
        "ua": request.headers.get("user-agent", ""),
        "request_id": request.headers.get("X-Request-Id", ""),
    }
    if body is not None and hasattr(body, "signals"):
        signals = getattr(body, "signals") or {}
        payload["tamper_flags_hash"] = hashlib.sha256(
            str(sorted(signals.items())).encode("utf-8")
        ).hexdigest()
    return payload


def _transition_state(current: str, event: str) -> str:
    transitions = {
        ("active", "tamper"): "suspicious",
        ("suspicious", "tamper"): "quarantined",
        ("quarantined", "tamper"): "quarantined",
        ("active", "revoke"): "revoked",
        ("suspicious", "revoke"): "revoked",
        ("quarantined", "revoke"): "revoked",
        ("revoked", "revoke"): "revoked",
    }
    return transitions.get((current, event), current)


class AgentEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_token: str = Field(min_length=8, max_length=256)
    device_fingerprint: str = Field(min_length=8, max_length=1024)
    device_name: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=64)
    agent_version: str | None = Field(default=None, max_length=64)


class AgentEnrollResponse(BaseModel):
    device_id: str
    device_key: str
    device_key_prefix: str
    expires_at: str | None = None


class AgentHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: str
    agent_version: str = Field(max_length=64)
    os: str = Field(max_length=64)
    hostname: str = Field(max_length=255)
    ip_addrs: list[str] = Field(default_factory=list, max_length=32)
    metrics: dict[str, float] = Field(default_factory=dict)
    signals: dict[str, bool] = Field(default_factory=dict)


class AgentHeartbeatResponse(BaseModel):
    status: str = "ok"
    server_time: str
    required_min_version: str | None = None
    action: str = "none"


class AgentRotateResponse(BaseModel):
    device_key: str
    device_key_prefix: str


class DeviceAuthContext(BaseModel):
    device_id: str
    tenant_id: str
    key_row_id: int


async def _validate_signed_request(request: Request, device_secret: str) -> None:
    ts_raw = (request.headers.get("X-FG-TS") or "").strip()
    nonce = (request.headers.get("X-FG-NONCE") or "").strip()
    provided_sig = (request.headers.get("X-FG-SIG") or "").strip()
    if not ts_raw:
        raise HTTPException(status_code=401, detail="missing X-FG-TS")
    if not nonce:
        raise HTTPException(status_code=401, detail="missing X-FG-NONCE")
    if not provided_sig:
        raise HTTPException(status_code=401, detail="missing X-FG-SIG")
    try:
        ts = int(ts_raw)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid signature timestamp") from exc

    now = int(time.time())
    if ts > now + _CLOCK_SKEW_SECONDS:
        log.warning("agent signature denied: timestamp in future ts=%s now=%s", ts, now)
        raise HTTPException(status_code=401, detail="signature timestamp in future")
    if ts < now - _CLOCK_SKEW_SECONDS:
        log.warning("agent signature denied: timestamp too old ts=%s now=%s", ts, now)
        raise HTTPException(status_code=401, detail="signature timestamp too old")

    raw = await request.body()
    if len(raw) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")
    canonical = _canonical_request(
        request.method,
        _canonical_path_with_query(request),
        _body_hash(raw),
        ts_raw,
        nonce,
    )
    expected = hmac.new(
        device_secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, provided_sig):
        raise HTTPException(status_code=403, detail="invalid signature")


def _prune_nonces(session: Session, device_id: str) -> None:
    cutoff = _utcnow() - timedelta(seconds=_NONCE_RETENTION_SECONDS)
    session.query(AgentDeviceNonce).filter(
        AgentDeviceNonce.device_id == device_id,
        AgentDeviceNonce.created_at < cutoff,
    ).delete()

    current_count = (
        session.query(AgentDeviceNonce)
        .filter(AgentDeviceNonce.device_id == device_id)
        .count()
    )
    if current_count > _NONCE_DEVICE_CAP:
        to_prune = current_count - _NONCE_DEVICE_CAP
        oldest = (
            session.query(AgentDeviceNonce)
            .filter(AgentDeviceNonce.device_id == device_id)
            .order_by(AgentDeviceNonce.created_at.asc())
            .limit(to_prune)
            .all()
        )
        for row in oldest:
            session.delete(row)


async def require_device_signature(request: Request) -> DeviceAuthContext:
    key_id = (request.headers.get("X-FG-DEVICE-KEY") or "").strip()
    if not key_id:
        raise HTTPException(status_code=401, detail="invalid device key id")

    engine = get_engine()
    with Session(engine) as session:
        key_row = session.query(AgentDeviceKey).filter(AgentDeviceKey.key_prefix == key_id).first()
        if key_row is None:
            raise HTTPException(status_code=401, detail="invalid device key id")
        device = (
            session.query(AgentDeviceRegistry)
            .filter(
                AgentDeviceRegistry.device_id == key_row.device_id,
                AgentDeviceRegistry.tenant_id == key_row.tenant_id,
            )
            .first()
        )
        if device is None or device.status == "revoked":
            raise HTTPException(status_code=403, detail="device revoked")
        if not key_row.enabled:
            raise HTTPException(status_code=403, detail="device revoked")

        secret = _decrypt_secret(key_row.hmac_secret_enc)
        await _validate_signed_request(request, secret)

        nonce = (request.headers.get("X-FG-NONCE") or "").strip()
        nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        _prune_nonces(session, device.device_id)
        seen = (
            session.query(AgentDeviceNonce)
            .filter(
                AgentDeviceNonce.device_id == device.device_id,
                AgentDeviceNonce.nonce_hash == nonce_hash,
            )
            .first()
        )
        if seen is not None:
            raise HTTPException(status_code=403, detail="replayed nonce")

        session.add(AgentDeviceNonce(device_id=device.device_id, nonce_hash=nonce_hash))
        session.commit()

        request.state.device_id = device.device_id
        request.state.tenant_id = device.tenant_id
        return DeviceAuthContext(device_id=device.device_id, tenant_id=device.tenant_id, key_row_id=key_row.id)


@router.post(
    "/enroll",
    response_model=AgentEnrollResponse,
    responses={401: {"description": "Unauthorized"}, 429: {"description": "Too Many Requests"}},
)
def enroll_agent(body: AgentEnrollRequest, request: Request) -> AgentEnrollResponse:
    if request.headers.get("content-length") and int(request.headers["content-length"]) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")

    now = _utcnow()
    token_hash = _hash_with_pepper(body.enrollment_token)

    engine = get_engine()
    with Session(engine) as session:
        enrollment = (
            session.query(AgentEnrollmentToken)
            .filter(AgentEnrollmentToken.token_hash == token_hash)
            .first()
        )
        if enrollment is None:
            raise HTTPException(status_code=401, detail="invalid enrollment token")
        exp = enrollment.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        if exp < now:
            raise HTTPException(status_code=401, detail="expired enrollment token")
        if enrollment.used_count >= enrollment.max_uses:
            raise HTTPException(status_code=401, detail="enrollment token already used")

        device_id = f"dev_{secrets.token_hex(16)}"
        device_secret, device_key_prefix, key_hash, key_lookup, hash_alg = _mint_device_secret()

        device = AgentDeviceRegistry(
            device_id=device_id,
            tenant_id=enrollment.tenant_id,
            fingerprint_hash=_fingerprint_hash(body.device_fingerprint),
            status="active",
            last_seen_at=now,
            last_ip=(request.client.host if request.client else None),
            last_version=(body.agent_version or ""),
        )
        session.add(device)

        session.add(
            AgentDeviceKey(
                device_id=device_id,
                tenant_id=enrollment.tenant_id,
                key_prefix=device_key_prefix,
                key_hash=key_hash,
                key_lookup=key_lookup,
                hash_alg=hash_alg,
                hmac_secret_enc=_encrypt_secret(device_secret),
                enabled=True,
            )
        )
        enrollment.used_count += 1
        session.commit()

        details = {
            "actor_id": "system",
            "scope": ["system"],
            "fingerprint_hash": _fingerprint_hash(body.device_fingerprint),
            "device_id": device_id,
            **_request_metadata(request),
        }
        audit_admin_action(
            action=f"agent-enroll:{device_id}",
            tenant_id=enrollment.tenant_id,
            request=request,
            details=details,
        )

        return AgentEnrollResponse(
            device_id=device_id,
            device_key=device_secret,
            device_key_prefix=device_key_prefix,
            expires_at=enrollment.expires_at.isoformat(),
        )


@router.post(
    "/heartbeat",
    response_model=AgentHeartbeatResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        429: {"description": "Too Many Requests"},
    },
)
def agent_heartbeat(
    body: AgentHeartbeatRequest,
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> AgentHeartbeatResponse:
    if not _HEARTBEAT_LIMITER.allow(f"d:{device.device_id}", rate_per_sec=1 / 60.0, burst=3):
        raise HTTPException(status_code=429, detail="device heartbeat rate limited")
    if not _HEARTBEAT_LIMITER.allow(f"t:{device.tenant_id}", rate_per_sec=2.0, burst=60):
        raise HTTPException(status_code=429, detail="tenant heartbeat rate limited")

    if (os.getenv("FG_AGENT_RATE_LIMIT_MODE") or "in-memory").strip().lower() == "in-memory":
        log.debug("agent rate limiting uses local in-memory buckets (single-process scope)")

    now = _utcnow()

    engine = get_engine()
    with Session(engine) as session:
        reg = (
            session.query(AgentDeviceRegistry)
            .filter(
                AgentDeviceRegistry.device_id == device.device_id,
                AgentDeviceRegistry.tenant_id == device.tenant_id,
            )
            .first()
        )
        if reg is None or reg.status == "revoked":
            raise HTTPException(status_code=403, detail="device revoked")

        if body.signals.get("tamper"):
            reg.status = _transition_state(reg.status, "tamper")
            reg.suspicious = reg.status in {"suspicious", "quarantined"}

        reg.last_seen_at = now
        reg.last_ip = request.client.host if request.client else None
        reg.last_version = body.agent_version
        session.commit()

        details = {
            "actor_id": device.device_id,
            "scope": ["device"],
            "device_id": device.device_id,
            "state": reg.status,
            **_request_metadata(request, body=body),
        }
        audit_admin_action(
            action=f"agent-heartbeat:{device.device_id}",
            tenant_id=device.tenant_id,
            request=request,
            details=details,
        )

    min_version = (os.getenv("FG_AGENT_MIN_VERSION") or "").strip()
    if min_version and body.agent_version < min_version:
        return AgentHeartbeatResponse(
            server_time=now.isoformat(),
            required_min_version=min_version,
            action="shutdown",
        )

    return AgentHeartbeatResponse(server_time=now.isoformat())


@router.post(
    "/key/rotate",
    response_model=AgentRotateResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def rotate_device_key(
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> AgentRotateResponse:
    engine = get_engine()
    with Session(engine) as session:
        reg = (
            session.query(AgentDeviceRegistry)
            .filter(
                AgentDeviceRegistry.device_id == device.device_id,
                AgentDeviceRegistry.tenant_id == device.tenant_id,
            )
            .first()
        )
        if reg is None or reg.status in {"revoked", "quarantined"}:
            raise HTTPException(status_code=403, detail="device not eligible for rotation")

        old_key = session.query(AgentDeviceKey).filter(AgentDeviceKey.id == device.key_row_id).first()
        if old_key is None:
            raise HTTPException(status_code=401, detail="invalid device key id")
        old_key.enabled = False

        new_secret, new_prefix, key_hash, key_lookup, hash_alg = _mint_device_secret()
        session.add(
            AgentDeviceKey(
                device_id=device.device_id,
                tenant_id=device.tenant_id,
                key_prefix=new_prefix,
                key_hash=key_hash,
                key_lookup=key_lookup,
                hash_alg=hash_alg,
                hmac_secret_enc=_encrypt_secret(new_secret),
                enabled=True,
            )
        )
        session.commit()

        audit_admin_action(
            action=f"agent-rotate:{device.device_id}",
            tenant_id=device.tenant_id,
            request=request,
            details={
                "actor_id": device.device_id,
                "scope": ["device"],
                "device_id": device.device_id,
                **_request_metadata(request),
            },
        )

        return AgentRotateResponse(device_key=new_secret, device_key_prefix=new_prefix)
