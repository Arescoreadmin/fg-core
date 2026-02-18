from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from api.agent_enrollment import (
    DeviceAuthContext,
    _fingerprint_hash,
    _hash_with_pepper,
    _request_metadata,
    require_device_signature,
)
from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models import (
    AgentCommand,
    AgentDeviceIdentity,
    AgentDeviceRegistry,
    AgentEnrollmentToken,
    AgentLogAnchor,
    AgentPolicyBundle,
    AgentQuarantineEvent,
    AgentRateBudgetCounter,
    AgentUpdateRollout,
)
from api.security_audit import audit_admin_action

router = APIRouter(prefix="/agent", tags=["agent-phase2"])
admin_router = APIRouter(
    prefix="/admin/agent",
    tags=["agent-admin-phase2"],
    dependencies=[Depends(require_scopes("keys:admin"))],
)

_CA_CACHE: tuple[rsa.RSAPrivateKey, x509.Certificate] | None = None


class CertEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_token: str = Field(min_length=8, max_length=256)
    device_fingerprint: str = Field(min_length=8, max_length=1024)
    csr_pem: str
    device_name: str | None = None


class CertEnrollResponse(BaseModel):
    device_id: str
    certificate_pem: str
    certificate_chain_pem: str
    expires_at: str


class CommandAckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: str
    status: str = Field(pattern="^(ok|failed)$")
    result: dict = Field(default_factory=dict)


class CommandIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    command_type: str = Field(
        pattern="^(collect_diagnostics|rotate_identity|flush_cache|run_integrity_check|fetch_inventory)$"
    )
    payload: dict = Field(default_factory=dict, max_length=128)
    ttl_seconds: int = Field(default=300, ge=30, le=86400)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)


class CommandLeaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    controller_id: str = Field(min_length=3, max_length=128)
    lease_seconds: int = Field(default=60, ge=10, le=600)


class RolloutConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canary_percent_per_hour: int = Field(default=10, ge=1, le=100)
    pilot_percent_per_hour: int = Field(default=30, ge=1, le=100)
    broad_percent_per_hour: int = Field(default=100, ge=1, le=100)
    canary_error_budget: int = Field(default=5, ge=1, le=1000)
    paused: bool = False
    kill_switch: bool = False


class CollectDiagnosticsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include_processes: bool = True
    include_network: bool = True


class RotateIdentityParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    force: bool = False


class FlushCacheParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cache_scope: str = Field(default="all", pattern="^(all|policy|commands)$")


class RunIntegrityCheckParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deep_scan: bool = False


class FetchInventoryParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include_software: bool = True
    include_services: bool = True


class UpdateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    status: str
    detail: str | None = None


class LogAnchorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hash: str = Field(pattern="^[a-f0-9]{64}$")


class QuarantineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=2, max_length=512)


class PolicyPublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    policy_json: dict
    signature: str


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _load_or_create_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    global _CA_CACHE
    if _CA_CACHE:
        return _CA_CACHE

    key_pem = os.getenv("FG_AGENT_CA_KEY_PEM", "").strip()
    cert_pem = os.getenv("FG_AGENT_CA_CERT_PEM", "").strip()
    if key_pem and cert_pem:
        key = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        _CA_CACHE = (key, cert)
        return _CA_CACHE

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "FrostGate Agent CA")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_utcnow() - timedelta(minutes=1))
        .not_valid_after(_utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    _CA_CACHE = (key, cert)
    return _CA_CACHE


def _device_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _sign_command(payload: dict) -> str:
    key = (
        os.getenv("FG_AGENT_COMMAND_SIGNING_KEY") or os.getenv("FG_KEY_PEPPER") or ""
    ).encode("utf-8")
    if not key:
        raise RuntimeError("FG_AGENT_COMMAND_SIGNING_KEY or FG_KEY_PEPPER required")
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def _verify_policy_hash(policy: dict, policy_hash: str) -> bool:
    canonical = json.dumps(policy, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return hashlib.sha256(canonical).hexdigest() == policy_hash


def _params_hash(payload: dict | None) -> str:
    canonical = json.dumps(payload or {}, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return hashlib.sha256(canonical).hexdigest()


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code, detail={"code": code, "message": message}
    )


def _require_operational_device(
    session: Session,
    device: DeviceAuthContext,
    *,
    allow_quarantined: bool = False,
) -> AgentDeviceRegistry:
    reg = (
        session.query(AgentDeviceRegistry)
        .filter(
            AgentDeviceRegistry.device_id == device.device_id,
            AgentDeviceRegistry.tenant_id == device.tenant_id,
        )
        .first()
    )
    if reg is None:
        raise _error(403, "DEVICE_NOT_FOUND", "device not found")
    if reg.status == "revoked":
        raise _error(403, "DEVICE_REVOKED", "device revoked")
    if reg.status == "quarantined" and not allow_quarantined:
        raise _error(403, "DEVICE_QUARANTINED", "device quarantined")
    return reg


def _audit_action(
    *,
    action: str,
    tenant_id: str,
    request: Request,
    actor_id: str,
    scope: list[str],
    params: dict | None = None,
    extra: dict | None = None,
) -> None:
    details = {
        "actor_id": actor_id,
        "scope": scope,
        "params_hash": _params_hash(params),
    }
    if extra:
        details.update(extra)
    audit_admin_action(
        action=action, tenant_id=tenant_id, request=request, details=details
    )


def _normalize_dt(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _consume_budget(
    session: Session,
    *,
    tenant_id: str,
    device_id: str | None,
    metric: str,
    limit: int,
    window_seconds: int,
) -> bool:
    now = _utcnow()
    slot = int(now.timestamp() // window_seconds) * window_seconds
    window_start = datetime.fromtimestamp(slot, tz=UTC)
    row = (
        session.query(AgentRateBudgetCounter)
        .filter(
            AgentRateBudgetCounter.tenant_id == tenant_id,
            AgentRateBudgetCounter.device_id == device_id,
            AgentRateBudgetCounter.metric == metric,
            AgentRateBudgetCounter.window_start == window_start,
        )
        .first()
    )
    if row is None:
        row = AgentRateBudgetCounter(
            tenant_id=tenant_id,
            device_id=device_id,
            metric=metric,
            window_start=window_start,
            count=0,
        )
        session.add(row)
        session.flush()
    if row.count >= limit:
        return False
    row.count += 1
    session.commit()
    return True


def _validate_command_payload(command_type: str, payload: dict) -> None:
    validators = {
        "collect_diagnostics": CollectDiagnosticsParams,
        "rotate_identity": RotateIdentityParams,
        "flush_cache": FlushCacheParams,
        "run_integrity_check": RunIntegrityCheckParams,
        "fetch_inventory": FetchInventoryParams,
    }
    model = validators.get(command_type)
    if model is None:
        raise _error(403, "COMMAND_TYPE_DENIED", "unsupported command type")
    try:
        model.model_validate(payload)
    except Exception as exc:
        raise _error(
            403, "COMMAND_PARAMS_INVALID", "invalid command parameters"
        ) from exc


def _load_rollout(session: Session, tenant_id: str) -> AgentUpdateRollout:
    row = (
        session.query(AgentUpdateRollout)
        .filter(AgentUpdateRollout.tenant_id == tenant_id)
        .first()
    )
    if row is None:
        row = AgentUpdateRollout(tenant_id=tenant_id)
        session.add(row)
        session.commit()
        session.refresh(row)
    return row


def _rollout_allowed(
    session: Session, *, tenant_id: str, ring: str
) -> tuple[bool, AgentUpdateRollout]:
    rollout = _load_rollout(session, tenant_id)
    if rollout.kill_switch:
        return False, rollout
    if rollout.paused:
        return False, rollout
    if ring == "canary":
        limit = max(1, int(rollout.canary_percent_per_hour))
    elif ring == "pilot":
        limit = max(1, int(rollout.pilot_percent_per_hour))
    else:
        if int(rollout.canary_error_count) > int(rollout.canary_error_budget):
            return False, rollout
        limit = max(1, int(rollout.broad_percent_per_hour))
    ok = _consume_budget(
        session,
        tenant_id=tenant_id,
        device_id=None,
        metric=f"update_ring_{ring}",
        limit=limit,
        window_seconds=3600,
    )
    return ok, rollout


def _require_valid_device_identity(session: Session, device: DeviceAuthContext) -> None:
    row = (
        session.query(AgentDeviceIdentity)
        .filter(
            AgentDeviceIdentity.device_id == device.device_id,
            AgentDeviceIdentity.tenant_id == device.tenant_id,
        )
        .first()
    )
    if row is None:
        return
    if row.status == "revoked":
        raise _error(403, "CERT_REVOKED", "certificate revoked")
    cert_not_after = row.cert_not_after
    if cert_not_after.tzinfo is None:
        cert_not_after = cert_not_after.replace(tzinfo=UTC)
    if cert_not_after < _utcnow():
        raise _error(403, "CERT_EXPIRED", "certificate expired")


@router.post(
    "/cert/enroll",
    response_model=CertEnrollResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def cert_enroll(body: CertEnrollRequest, request: Request) -> CertEnrollResponse:
    now = _utcnow()
    token_hash = _hash_with_pepper(body.enrollment_token)
    csr = x509.load_pem_x509_csr(body.csr_pem.encode("utf-8"))

    engine = get_engine()
    with Session(engine) as session:
        enrollment = (
            session.query(AgentEnrollmentToken)
            .filter(AgentEnrollmentToken.token_hash == token_hash)
            .first()
        )
        if enrollment is None:
            raise _error(401, "ENROLL_TOKEN_INVALID", "invalid enrollment token")
        if enrollment.expires_at.replace(tzinfo=UTC) < now:
            raise _error(401, "ENROLL_TOKEN_EXPIRED", "expired enrollment token")
        if enrollment.used_count >= enrollment.max_uses:
            raise _error(401, "ENROLL_TOKEN_USED", "enrollment token already used")

        device_id = f"dev_{secrets.token_hex(16)}"
        key, ca_cert = _load_or_create_ca()
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(device_id)]), critical=False
            )
            .sign(private_key=key, algorithm=hashes.SHA256())
        )
        fingerprint = _device_fingerprint(cert)

        session.add(
            AgentDeviceRegistry(
                device_id=device_id,
                tenant_id=enrollment.tenant_id,
                fingerprint_hash=_fingerprint_hash(body.device_fingerprint),
                status="active",
                last_seen_at=now,
                last_ip=request.client.host if request.client else None,
            )
        )
        session.add(
            AgentDeviceIdentity(
                device_id=device_id,
                tenant_id=enrollment.tenant_id,
                cert_fingerprint=fingerprint,
                cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                cert_chain_pem=ca_cert.public_bytes(serialization.Encoding.PEM).decode(
                    "utf-8"
                ),
                cert_not_after=cert.not_valid_after_utc,
                status="active",
                last_seen_at=now,
            )
        )
        enrollment.used_count += 1
        session.commit()

        audit_admin_action(
            action=f"agent-cert-enroll:{device_id}",
            tenant_id=enrollment.tenant_id,
            request=request,
            details={"device_id": device_id, **_request_metadata(request)},
        )
        return CertEnrollResponse(
            device_id=device_id,
            certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode(
                "utf-8"
            ),
            certificate_chain_pem=ca_cert.public_bytes(
                serialization.Encoding.PEM
            ).decode("utf-8"),
            expires_at=cert.not_valid_after_utc.isoformat(),
        )


@router.post(
    "/cert/renew",
    response_model=CertEnrollResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def cert_renew(
    body: dict,
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> CertEnrollResponse:
    csr_pem = str(body.get("csr_pem") or "")
    if not csr_pem:
        raise _error(401, "CSR_REQUIRED", "csr_pem required")
    csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    now = _utcnow()
    key, ca_cert = _load_or_create_ca()
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(device.device_id)]),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    engine = get_engine()
    with Session(engine) as session:
        _require_valid_device_identity(session, device)
        _require_operational_device(session, device)
        row = (
            session.query(AgentDeviceIdentity)
            .filter(
                AgentDeviceIdentity.device_id == device.device_id,
                AgentDeviceIdentity.tenant_id == device.tenant_id,
                AgentDeviceIdentity.status != "revoked",
            )
            .first()
        )
        if row is None:
            raise _error(403, "CERT_REVOKED", "device certificate revoked")
        row.cert_fingerprint = _device_fingerprint(cert)
        row.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        row.cert_chain_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode(
            "utf-8"
        )
        row.cert_not_after = cert.not_valid_after_utc
        row.last_seen_at = now
        session.commit()

    return CertEnrollResponse(
        device_id=device.device_id,
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        certificate_chain_pem=ca_cert.public_bytes(serialization.Encoding.PEM).decode(
            "utf-8"
        ),
        expires_at=cert.not_valid_after_utc.isoformat(),
    )


@router.get(
    "/cert/status",
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def cert_status(
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> dict:
    engine = get_engine()
    with Session(engine) as session:
        row = (
            session.query(AgentDeviceIdentity)
            .filter(
                AgentDeviceIdentity.device_id == device.device_id,
                AgentDeviceIdentity.tenant_id == device.tenant_id,
            )
            .first()
        )
        if row is None or row.status == "revoked":
            raise _error(403, "CERT_REVOKED", "certificate revoked")
        cert_not_after = row.cert_not_after
        if cert_not_after.tzinfo is None:
            cert_not_after = cert_not_after.replace(tzinfo=UTC)
        if cert_not_after < _utcnow():
            raise _error(403, "CERT_EXPIRED", "certificate expired")
        row.last_seen_at = _utcnow()
        session.commit()
        return {
            "status": row.status,
            "fingerprint": row.cert_fingerprint,
            "expires_at": row.cert_not_after.isoformat(),
        }


@router.get(
    "/update/manifest",
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        429: {"description": "Too Many Requests"},
    },
)
@router.post(
    "/update/manifest",
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        429: {"description": "Too Many Requests"},
    },
)
def update_manifest(
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> dict:
    engine = get_engine()
    with Session(engine) as session:
        _require_valid_device_identity(session, device)
        reg = _require_operational_device(session, device)
        if not _consume_budget(
            session,
            tenant_id=device.tenant_id,
            device_id=device.device_id,
            metric="update_checks_per_min",
            limit=int(os.getenv("FG_AGENT_UPDATE_CHECKS_PER_MIN", "6")),
            window_seconds=60,
        ):
            raise _error(429, "RATE_LIMIT_UPDATE_CHECK", "update checks exceeded")
        allowed, rollout = _rollout_allowed(
            session, tenant_id=device.tenant_id, ring=(reg.ring or "broad")
        )
        if not allowed:
            if rollout.kill_switch:
                raise _error(403, "UPDATE_KILL_SWITCH", "updates disabled by tenant")
            if rollout.paused:
                raise _error(403, "UPDATE_ROLLOUT_PAUSED", "rollout paused")
            raise _error(403, "UPDATE_RING_BLOCKED", "ring blocked by rollout budget")

    version = os.getenv("FG_AGENT_LATEST_VERSION", "2.0.0")
    min_supported = os.getenv("FG_AGENT_MIN_SUPPORTED_VERSION", "1.0.0")
    sha256 = os.getenv("FG_AGENT_UPDATE_SHA256", "0" * 64)
    size = int(os.getenv("FG_AGENT_UPDATE_SIZE", "1"))
    url = os.getenv("FG_AGENT_UPDATE_URL", "https://updates.example.invalid/agent.bin")
    payload = {
        "version": version,
        "sha256": sha256,
        "size": size,
        "min_supported_version": min_supported,
        "download_url": url,
    }
    signature = _sign_command(payload)
    return {
        **payload,
        "signature": base64.b64encode(signature.encode("utf-8")).decode("utf-8"),
    }


@router.post(
    "/update/report",
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def report_update_event(
    body: UpdateReportRequest,
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> dict:
    engine = get_engine()
    with Session(engine) as session:
        _require_valid_device_identity(session, device)
        reg = _require_operational_device(session, device, allow_quarantined=True)
        if (
            str(body.status).lower() in {"failed", "verify_failed"}
            and (reg.ring or "broad") == "canary"
        ):
            rollout = _load_rollout(session, device.tenant_id)
            rollout.canary_error_count = int(rollout.canary_error_count) + 1
            if int(rollout.canary_error_count) > int(rollout.canary_error_budget):
                rollout.paused = True
            session.commit()

    _audit_action(
        action=f"agent-update:{device.device_id}",
        tenant_id=device.tenant_id,
        request=request,
        actor_id=device.device_id,
        scope=["device"],
        params=body.model_dump(),
        extra={"status": body.status, "version": body.version, "detail": body.detail},
    )
    return {"ok": True}


@admin_router.post(
    "/commands/issue",
    responses={
        429: {"description": "Too Many Requests"},
        403: {"description": "Forbidden"},
    },
)
def issue_command(body: CommandIssueRequest, request: Request) -> dict:
    tenant_id = require_bound_tenant(request)
    now = _utcnow()
    command_id = f"cmd_{secrets.token_hex(16)}"
    nonce = secrets.token_urlsafe(16)
    command_doc = {
        "command_id": command_id,
        "tenant_id": tenant_id,
        "device_id": body.device_id,
        "command_type": body.command_type,
        "payload": body.payload,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=body.ttl_seconds)).isoformat(),
        "nonce": nonce,
    }
    signature = _sign_command(command_doc)

    _validate_command_payload(body.command_type, body.payload)

    engine = get_engine()
    with Session(engine) as session:
        if not _consume_budget(
            session,
            tenant_id=tenant_id,
            device_id=None,
            metric="commands_per_day_tenant",
            limit=int(os.getenv("FG_AGENT_COMMANDS_PER_DAY_TENANT", "10000")),
            window_seconds=86400,
        ):
            raise _error(
                429, "RATE_LIMIT_TENANT_COMMANDS", "tenant command budget exceeded"
            )
        device = (
            session.query(AgentDeviceRegistry)
            .filter(
                AgentDeviceRegistry.device_id == body.device_id,
                AgentDeviceRegistry.tenant_id == tenant_id,
            )
            .first()
        )
        if device is None:
            raise _error(403, "DEVICE_SCOPE_DENIED", "device not found")
        if device.status == "revoked":
            raise _error(403, "DEVICE_REVOKED", "device revoked")
        if device.status == "quarantined":
            raise _error(403, "DEVICE_QUARANTINED", "device quarantined")
        if not _consume_budget(
            session,
            tenant_id=tenant_id,
            device_id=device.device_id,
            metric="commands_per_day_device",
            limit=int(os.getenv("FG_AGENT_COMMANDS_PER_DAY_DEVICE", "500")),
            window_seconds=86400,
        ):
            raise _error(
                429, "RATE_LIMIT_DEVICE_COMMANDS", "device command budget exceeded"
            )

        if body.idempotency_key:
            existing = (
                session.query(AgentCommand)
                .filter(
                    AgentCommand.tenant_id == tenant_id,
                    AgentCommand.device_id == body.device_id,
                    AgentCommand.idempotency_key == body.idempotency_key,
                )
                .first()
            )
            if existing is not None:
                return {
                    "command_id": existing.command_id,
                    "tenant_id": tenant_id,
                    "device_id": body.device_id,
                    "command_type": existing.command_type,
                    "payload": existing.payload,
                    "issued_at": existing.issued_at.isoformat(),
                    "expires_at": existing.expires_at.isoformat(),
                    "nonce": existing.nonce,
                    "signature": existing.signature,
                    "idempotent_replay": True,
                }

        session.add(
            AgentCommand(
                command_id=command_id,
                tenant_id=tenant_id,
                device_id=body.device_id,
                command_type=body.command_type,
                payload=body.payload,
                issued_by="admin",
                issued_at=now,
                expires_at=now + timedelta(seconds=body.ttl_seconds),
                signature=signature,
                nonce=nonce,
                idempotency_key=body.idempotency_key,
                status="issued",
            )
        )
        session.commit()

    _audit_action(
        action=f"agent-command-issued:{body.device_id}",
        tenant_id=tenant_id,
        request=request,
        actor_id="admin",
        scope=["system"],
        params=body.model_dump(),
        extra={"command_type": body.command_type, "command_id": command_id},
    )
    return {**command_doc, "signature": signature}


@router.post(
    "/commands/poll",
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def poll_commands(
    body: CommandLeaseRequest,
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> dict:
    engine = get_engine()
    with Session(engine) as session:
        _require_valid_device_identity(session, device)
        reg = _require_operational_device(session, device)
        reg = (
            session.query(AgentDeviceRegistry)
            .filter(
                AgentDeviceRegistry.device_id == device.device_id,
                AgentDeviceRegistry.tenant_id == device.tenant_id,
            )
            .first()
        )
        quarantined = bool(reg and reg.status == "quarantined")
        lease_now = _utcnow()
        rows = (
            session.query(AgentCommand)
            .filter(
                AgentCommand.device_id == device.device_id,
                AgentCommand.tenant_id == device.tenant_id,
                AgentCommand.status == "issued",
                AgentCommand.expires_at > lease_now,
            )
            .order_by(AgentCommand.issued_at.asc())
            .limit(20)
            .all()
        )
        commands = []
        for row in rows:
            if row.terminal_state in {"acked", "cancelled", "expired"}:
                continue
            lease_expires = (
                _normalize_dt(row.lease_expires_at) if row.lease_expires_at else None
            )
            if (
                row.lease_owner
                and lease_expires
                and lease_expires > lease_now
                and row.lease_owner != body.controller_id
            ):
                continue
            row.lease_owner = body.controller_id
            row.lease_expires_at = lease_now + timedelta(seconds=body.lease_seconds)
            row.attempt_count = int(row.attempt_count or 0) + 1
            if quarantined:
                continue
            doc = {
                "command_id": row.command_id,
                "command_type": row.command_type,
                "payload": row.payload,
                "issued_at": row.issued_at.isoformat(),
                "expires_at": row.expires_at.isoformat(),
                "nonce": row.nonce,
                "signature": row.signature,
                "lease_owner": row.lease_owner,
                "lease_expires_at": row.lease_expires_at.isoformat()
                if row.lease_expires_at
                else None,
                "attempt_count": row.attempt_count,
            }
            commands.append(doc)
        session.commit()
        return {"commands": commands}


@router.post(
    "/commands/ack",
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def ack_command(
    body: CommandAckRequest,
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> dict:
    engine = get_engine()
    command_status = ""
    command_id = body.command_id
    with Session(engine) as session:
        _require_valid_device_identity(session, device)
        _require_operational_device(session, device)
        row = (
            session.query(AgentCommand)
            .filter(
                AgentCommand.command_id == body.command_id,
                AgentCommand.device_id == device.device_id,
                AgentCommand.tenant_id == device.tenant_id,
            )
            .first()
        )
        if row is None:
            raise _error(403, "COMMAND_SCOPE_DENIED", "command not found")
        if row.terminal_state in {"acked", "cancelled", "expired"} or row.status in {
            "acked",
            "failed",
        }:
            raise _error(403, "COMMAND_REPLAY", "command already acknowledged")
        lease_expires = (
            _normalize_dt(row.lease_expires_at) if row.lease_expires_at else None
        )
        if lease_expires and lease_expires < _utcnow():
            row.terminal_state = "expired"
            row.status = "expired"
            session.commit()
            raise _error(403, "LEASE_EXPIRED", "command lease expired")

        expires_at = row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at < _utcnow():
            row.status = "expired"
            session.commit()
            raise _error(403, "COMMAND_EXPIRED", "command expired")

        row.status = "acked" if body.status == "ok" else "failed"
        row.terminal_state = row.status
        row.acked_at = _utcnow()
        command_status = row.status
        command_id = row.command_id
        session.commit()

    _audit_action(
        action=f"agent-command-{command_status}:{device.device_id}",
        tenant_id=device.tenant_id,
        request=request,
        actor_id=device.device_id,
        scope=["device"],
        params=body.model_dump(),
        extra={"command_id": command_id, "result": body.result},
    )
    return {"ok": True}


@admin_router.post("/quarantine/{device_id}")
def quarantine_device(
    device_id: str, body: QuarantineRequest, request: Request
) -> dict:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as session:
        row = (
            session.query(AgentDeviceRegistry)
            .filter(
                AgentDeviceRegistry.device_id == device_id,
                AgentDeviceRegistry.tenant_id == tenant_id,
            )
            .first()
        )
        if row is None:
            raise _error(403, "DEVICE_SCOPE_DENIED", "device not found")
        row.status = "quarantined"
        row.suspicious = True
        session.add(
            AgentQuarantineEvent(
                tenant_id=tenant_id,
                device_id=device_id,
                action="quarantine_initiated",
                reason=body.reason,
            )
        )
        session.commit()
    _audit_action(
        action=f"agent-quarantine:{device_id}",
        tenant_id=tenant_id,
        request=request,
        actor_id="admin",
        scope=["system"],
        params={"device_id": device_id, "reason": body.reason},
        extra={"state": "quarantine_initiated"},
    )
    return {"quarantined": True}


@admin_router.post("/unquarantine/{device_id}")
def unquarantine_device(
    device_id: str, body: QuarantineRequest, request: Request
) -> dict:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as session:
        row = (
            session.query(AgentDeviceRegistry)
            .filter(
                AgentDeviceRegistry.device_id == device_id,
                AgentDeviceRegistry.tenant_id == tenant_id,
            )
            .first()
        )
        if row is None:
            raise _error(403, "DEVICE_SCOPE_DENIED", "device not found")
        row.status = "active"
        session.add(
            AgentQuarantineEvent(
                tenant_id=tenant_id,
                device_id=device_id,
                action="quarantine_lifted",
                reason=body.reason,
            )
        )
        session.commit()
    _audit_action(
        action=f"agent-unquarantine:{device_id}",
        tenant_id=tenant_id,
        request=request,
        actor_id="admin",
        scope=["system"],
        params={"device_id": device_id, "reason": body.reason},
        extra={"state": "quarantine_lifted"},
    )
    return {"quarantined": False}


@router.get(
    "/policy/fetch",
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def fetch_policy(
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> dict:
    engine = get_engine()
    with Session(engine) as session:
        _require_valid_device_identity(session, device)
        _require_operational_device(session, device)
        row = (
            session.query(AgentPolicyBundle)
            .filter(
                AgentPolicyBundle.tenant_id == device.tenant_id,
                AgentPolicyBundle.revoked.is_(False),
            )
            .order_by(AgentPolicyBundle.created_at.desc())
            .first()
        )
        if row is None:
            raise _error(403, "POLICY_NOT_FOUND", "policy not found")
        if not _verify_policy_hash(row.policy_json, row.policy_hash):
            raise _error(403, "POLICY_CORRUPTED", "corrupted policy")
        payload = {
            "version": row.version,
            "policy_hash": row.policy_hash,
            "policy": row.policy_json,
            "signature": row.signature,
        }
        _audit_action(
            action=f"agent-policy-fetch:{device.device_id}",
            tenant_id=device.tenant_id,
            request=request,
            actor_id=device.device_id,
            scope=["device"],
            params={"requested": "latest"},
            extra={"policy_hash": row.policy_hash},
        )
        return payload


@admin_router.post("/policy/publish")
def publish_policy(body: PolicyPublishRequest, request: Request) -> dict:
    tenant_id = require_bound_tenant(request)
    canonical = json.dumps(
        body.policy_json, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    policy_hash = hashlib.sha256(canonical).hexdigest()
    engine = get_engine()
    with Session(engine) as session:
        if not _consume_budget(
            session,
            tenant_id=tenant_id,
            device_id=None,
            metric="policy_publish_per_day",
            limit=int(os.getenv("FG_AGENT_POLICY_PUBLISH_PER_DAY", "100")),
            window_seconds=86400,
        ):
            raise _error(
                429, "RATE_LIMIT_POLICY_PUBLISH", "policy publish budget exceeded"
            )
        session.add(
            AgentPolicyBundle(
                tenant_id=tenant_id,
                version=body.version,
                policy_hash=policy_hash,
                policy_json=body.policy_json,
                signature=body.signature,
            )
        )
        session.commit()
    _audit_action(
        action="agent-policy-publish",
        tenant_id=tenant_id,
        request=request,
        actor_id="admin",
        scope=["system"],
        params=body.model_dump(),
        extra={"policy_hash": policy_hash},
    )
    return {"ok": True, "policy_hash": policy_hash}


@admin_router.post("/policy/revoke/{policy_hash}")
def revoke_policy(policy_hash: str, request: Request) -> dict:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as session:
        count = (
            session.query(AgentPolicyBundle)
            .filter(
                AgentPolicyBundle.tenant_id == tenant_id,
                AgentPolicyBundle.policy_hash == policy_hash,
            )
            .update({"revoked": True})
        )
        session.commit()
    _audit_action(
        action="agent-policy-revoke",
        tenant_id=tenant_id,
        request=request,
        actor_id="admin",
        scope=["system"],
        params={"policy_hash": policy_hash},
        extra={"revoked": bool(count)},
    )
    return {"revoked": count > 0}


@router.post(
    "/log/anchor",
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def anchor_log_hash(
    body: LogAnchorRequest,
    request: Request,
    device: DeviceAuthContext = Depends(require_device_signature),
) -> dict:
    engine = get_engine()
    with Session(engine) as session:
        _require_valid_device_identity(session, device)
        _require_operational_device(session, device)
        session.add(
            AgentLogAnchor(
                tenant_id=device.tenant_id,
                device_id=device.device_id,
                hash=body.hash,
            )
        )
        session.commit()
    _audit_action(
        action=f"agent-log-anchor:{device.device_id}",
        tenant_id=device.tenant_id,
        request=request,
        actor_id=device.device_id,
        scope=["device"],
        params=body.model_dump(),
    )
    return {"ok": True}


@admin_router.post("/update/rollout")
def configure_update_rollout(body: RolloutConfigRequest, request: Request) -> dict:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as session:
        rollout = _load_rollout(session, tenant_id)
        rollout.canary_percent_per_hour = body.canary_percent_per_hour
        rollout.pilot_percent_per_hour = body.pilot_percent_per_hour
        rollout.broad_percent_per_hour = body.broad_percent_per_hour
        rollout.canary_error_budget = body.canary_error_budget
        rollout.paused = body.paused
        rollout.kill_switch = body.kill_switch
        rollout.updated_at = _utcnow()
        session.commit()
    _audit_action(
        action="agent-update-rollout-config",
        tenant_id=tenant_id,
        request=request,
        actor_id="admin",
        scope=["system"],
        params=body.model_dump(),
    )
    return {"ok": True}


@admin_router.get("/evidence/export/{device_id}")
def export_device_evidence(device_id: str, request: Request) -> dict:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as session:
        cmds = (
            session.query(AgentCommand)
            .filter(
                AgentCommand.tenant_id == tenant_id,
                AgentCommand.device_id == device_id,
            )
            .order_by(AgentCommand.issued_at.asc())
            .all()
        )
        anchors = (
            session.query(AgentLogAnchor)
            .filter(
                AgentLogAnchor.tenant_id == tenant_id,
                AgentLogAnchor.device_id == device_id,
            )
            .order_by(AgentLogAnchor.anchored_at.asc())
            .all()
        )
        policies = (
            session.query(AgentPolicyBundle)
            .filter(
                AgentPolicyBundle.tenant_id == tenant_id,
            )
            .order_by(AgentPolicyBundle.created_at.asc())
            .all()
        )

    bundle = {
        "device_id": device_id,
        "tenant_id": tenant_id,
        "generated_at": _utcnow().isoformat(),
        "anchors": [
            {"hash": row.hash, "anchored_at": row.anchored_at.isoformat()}
            for row in anchors
        ],
        "policy_timeline": [
            {
                "version": row.version,
                "policy_hash": row.policy_hash,
                "revoked": bool(row.revoked),
                "created_at": row.created_at.isoformat(),
            }
            for row in policies
        ],
        "command_ledger": [
            {
                "command_id": row.command_id,
                "command_type": row.command_type,
                "issued_at": row.issued_at.isoformat(),
                "status": row.status,
                "terminal_state": row.terminal_state,
                "signature": row.signature,
            }
            for row in cmds
        ],
        "verification": {
            "instructions": "verify anchor hash chain continuity and command signatures with tenant trust root",
            "result": "PASS" if anchors else "WARN_NO_ANCHORS",
        },
    }
    _audit_action(
        action=f"agent-evidence-export:{device_id}",
        tenant_id=tenant_id,
        request=request,
        actor_id="admin",
        scope=["system"],
        params={"device_id": device_id},
    )
    return bundle
