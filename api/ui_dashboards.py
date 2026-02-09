from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import secrets
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import asc, desc, func, select
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_api_key_always, require_scopes
from api.deps import get_db, tenant_db_required
from api.db_models import DecisionRecord
from api.security_audit import audit_admin_action
from api.stats import _compute_stats, _trend_flag
from api.ui_guard import ui_enabled_guard

CSRF_COOKIE_NAME = os.getenv("FG_UI_CSRF_COOKIE", "fg_ui_csrf")
CSRF_HEADER_NAME = "X-CSRF-Token"

router = APIRouter(
    prefix="/ui",
    tags=["ui-dashboards"],
    dependencies=[Depends(ui_enabled_guard)],
)


class PostureTile(BaseModel):
    label: str
    value: str
    trend: Optional[str] = None


class PostureResponse(BaseModel):
    tenant_id: str
    generated_at: str
    request_id: Optional[str]
    tiles: list[PostureTile]
    trends: dict[str, Any]
    top_deny_reasons: list[dict[str, Any]]


class DecisionListItem(BaseModel):
    id: int
    created_at: Optional[str] = None
    event_id: str
    event_type: str
    source: str
    threat_level: str
    action_taken: Optional[str] = None
    explain_summary: Optional[str] = None
    latency_ms: int = 0


class DecisionsPage(BaseModel):
    items: list[DecisionListItem]
    limit: int
    offset: int
    total: int
    request_id: Optional[str]


class DecisionDetail(BaseModel):
    id: int
    created_at: Optional[str]
    tenant_id: str
    source: str
    event_id: str
    event_type: str
    threat_level: str
    anomaly_score: float
    ai_adversarial_score: float
    pq_fallback: bool
    rules_triggered: list[str] = Field(default_factory=list)
    explain_summary: Optional[str] = None
    latency_ms: int = 0
    request: Optional[Any] = None
    response: Optional[Any] = None
    decision_diff: Optional[Any] = None
    chain_hash: Optional[str] = None
    prev_hash: Optional[str] = None
    request_id: Optional[str] = None


class ChainVerifyResponse(BaseModel):
    tenant_id: str
    status: str
    checked: int
    first_bad: Optional[dict[str, Any]] = None

    # Verification metadata
    # mode:
    #   - "linkage": verifies prev_hash chaining only
    #   - "strict": fully recomputes canonical payload + chain hash
    mode: str = "linkage"
    strict_ok: Optional[bool] = None
    strict_reason: Optional[str] = None

    request_id: Optional[str] = None


class AuditPacketRequest(BaseModel):
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    from_ts: Optional[str] = None
    to_ts: Optional[str] = None


class AuditPacketResponse(BaseModel):
    tenant_id: str
    packet_id: str
    created_at: str
    download_url: str
    request_id: Optional[str]
    manifest: dict[str, Any]


class ControlSummary(BaseModel):
    inv_id: str
    name: str
    status: str
    evidence_count: int
    remediation: str


class ControlsPage(BaseModel):
    items: list[ControlSummary]
    limit: int
    offset: int
    total: int
    request_id: Optional[str]


class ControlDetail(BaseModel):
    inv_id: str
    name: str
    status: str
    description: str
    evidence: list[dict[str, Any]]
    remediation: str
    request_id: Optional[str]


def _iso(dt: Any) -> Optional[str]:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.astimezone(timezone.utc).isoformat()
    return str(dt)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _loads_json_text(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return v
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("utf-8", errors="ignore")
    if isinstance(v, str):
        v = v.strip()
        if not v:
            return None
        try:
            return json.loads(v)
        except Exception:
            return None
    return None


def _request_id(request: Request) -> Optional[str]:
    return getattr(getattr(request, "state", None), "request_id", None)


def _resolve_tenant(request: Request, tenant_id: Optional[str]) -> str:
    existing = getattr(getattr(request, "state", None), "tenant_id", None)
    if existing:
        if tenant_id and tenant_id != existing:
            raise HTTPException(status_code=403, detail="Tenant mismatch")
        return existing
    bound = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    if not bound or bound == "unknown":
        raise HTTPException(
            status_code=400,
            detail="tenant_id is required and must be a known tenant",
        )
    return bound


def _parse_dt(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    try:
        return datetime.fromisoformat(val)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid timestamp format")


def _cleanup_packets() -> None:
    ttl_seconds = int(os.getenv("FG_AUDIT_PACKET_TTL_SECONDS", "3600"))
    if ttl_seconds <= 0:
        return
    packet_dir = Path(
        os.getenv("FG_AUDIT_PACKET_DIR", "artifacts/audit_packets")
    ).resolve()
    if not packet_dir.exists():
        return
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=ttl_seconds)
    for path in packet_dir.iterdir():
        if not path.is_dir():
            continue
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except Exception:
            continue
        if mtime < cutoff:
            shutil.rmtree(path, ignore_errors=True)


def _ensure_csrf(request: Request) -> None:
    token = request.headers.get(CSRF_HEADER_NAME)
    cookie = request.cookies.get(CSRF_COOKIE_NAME)
    if (
        not isinstance(token, str)
        or not isinstance(cookie, str)
        or not hmac.compare_digest(token, cookie)
    ):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


def _packet_metadata_path(packet_dir: Path) -> Path:
    return packet_dir / "metadata.json"


def _audit_packet_dir() -> Path:
    return Path(os.getenv("FG_AUDIT_PACKET_DIR", "artifacts/audit_packets")).resolve()


def _zip_packet(packet_dir: Path, files: list[str]) -> Path:
    import zipfile

    zip_path = packet_dir / "audit_packet.zip"
    fixed_time = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            file_path = packet_dir / name
            if not file_path.exists():
                continue
            info = zipfile.ZipInfo(name)
            info.date_time = fixed_time
            data = file_path.read_bytes()
            zf.writestr(info, data)
    return zip_path


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _derive_action_taken(decision_diff: Any) -> Optional[str]:
    if not isinstance(decision_diff, dict):
        return None
    curr = decision_diff.get("curr") or {}
    prev = decision_diff.get("prev") or {}
    for key in ("action_taken", "action", "decision"):
        value = curr.get(key) or prev.get(key)
        if isinstance(value, str) and value.strip():
            return value
    summary = str(decision_diff.get("summary") or "").lower()
    if "block" in summary or "deny" in summary:
        return "blocked"
    if "rate" in summary or "throttle" in summary:
        return "rate_limited"
    return None


def _controls_matrix() -> list[dict[str, Any]]:
    return [
        {
            "inv_id": "INV-001",
            "name": "Authenticated access enforced",
            "status": "enforced",
            "description": "Protected routes require valid API keys and scopes.",
            "evidence": [
                {"type": "test", "path": "tests/test_auth_hardening.py"},
                {"type": "test", "path": "tests/test_core_invariants.py"},
            ],
            "remediation": "Rotate or revoke leaked keys; enforce scoped keys only.",
        },
        {
            "inv_id": "INV-002",
            "name": "Tenant isolation enforced",
            "status": "enforced",
            "description": "All reads/writes are tenant-bound with explicit checks.",
            "evidence": [
                {"type": "test", "path": "tests/test_tenant_invariant.py"},
                {"type": "test", "path": "tests/test_auth_tenants.py"},
            ],
            "remediation": "Reject unscoped keys without tenant_id and audit access.",
        },
        {
            "inv_id": "INV-003",
            "name": "Fail-closed authentication",
            "status": "enforced",
            "description": "Auth/tenant failures return 401/403 without fallback.",
            "evidence": [
                {"type": "test", "path": "tests/test_auth_hardening.py"},
                {"type": "test", "path": "tests/test_security_hardening.py"},
            ],
            "remediation": "Disable fail-open flags and review auth logs.",
        },
        {
            "inv_id": "INV-004",
            "name": "Single decision enforcement path",
            "status": "enforced",
            "description": "Decision engine evaluation is centralized.",
            "evidence": [
                {"type": "test", "path": "tests/test_decision_pipeline_unified.py"},
            ],
            "remediation": "Refactor any bypasses to route through evaluate().",
        },
        {
            "inv_id": "INV-005",
            "name": "Governance changes auditable",
            "status": "enforced",
            "description": "Governance updates require scopes and logging.",
            "evidence": [
                {"type": "test", "path": "tests/test_governance_approval_flow.py"},
            ],
            "remediation": "Require approvals and log all policy changes.",
        },
        {
            "inv_id": "INV-006",
            "name": "Startup config validation",
            "status": "enforced",
            "description": "Unsafe configuration fails fast on boot.",
            "evidence": [
                {"type": "doc", "path": "docs/HARDENING_PLAN_7DAY.md"},
            ],
            "remediation": "Fix config errors before deploying to production.",
        },
        {
            "inv_id": "INV-007",
            "name": "Health probes reflect dependencies",
            "status": "enforced",
            "description": "Readiness checks validate key dependencies.",
            "evidence": [
                {"type": "test", "path": "tests/test_core_invariants.py"},
            ],
            "remediation": "Ensure DB/queue dependencies are configured.",
        },
    ]


@dataclass(frozen=True)
class _ChainVerifyResult:
    status: str
    checked: int
    first_bad: Optional[dict[str, Any]]
    mode: str
    strict_ok: Optional[bool]
    strict_reason: Optional[str]


def _verify_chain(db: Session, tenant_id: str) -> _ChainVerifyResult:
    """
    Chain verification for UI and audit packets.

    Behavior:
    - Always performs linkage verification (prev_hash integrity) where possible.
    - Performs strict verification only if canonical payload can be reconstructed.
    - Avoids false FAILs due to missing legacy fields.
    """
    from api.evidence_chain import build_chain_payload, compute_chain_hash

    stmt = (
        select(DecisionRecord)
        .where(DecisionRecord.tenant_id == tenant_id)
        .order_by(asc(DecisionRecord.created_at), asc(DecisionRecord.id))
    )
    rows = db.execute(stmt).scalars().all()

    checked = 0
    prev_chain_hash: Optional[str] = None

    # -------------------------
    # 1) Linkage verification
    # -------------------------
    for record in rows:
        record_prev = getattr(record, "prev_hash", None)
        record_chain = getattr(record, "chain_hash", None)

        if record_prev:
            if prev_chain_hash is None or record_prev != prev_chain_hash:
                return _ChainVerifyResult(
                    status="FAIL",
                    checked=checked,
                    first_bad={
                        "id": int(record.id),
                        "event_id": str(record.event_id),
                        "reason": "prev_hash_mismatch",
                    },
                    mode="linkage",
                    strict_ok=None,
                    strict_reason="unverifiable",
                )

        if record_chain:
            prev_chain_hash = record_chain

        checked += 1

    if not rows:
        return _ChainVerifyResult(
            status="PASS",
            checked=0,
            first_bad=None,
            mode="linkage",
            strict_ok=None,
            strict_reason="no_records",
        )

    # -------------------------
    # 2) Strict verification (best-effort)
    # -------------------------
    def _strict_eligible(rec: DecisionRecord) -> bool:
        rq = _loads_json_text(getattr(rec, "request_json", None)) or {}
        rs = _loads_json_text(getattr(rec, "response_json", None)) or {}
        return (
            isinstance(rq, dict)
            and isinstance(rs, dict)
            and "request_id" in rq
            and "policy_version" in rs
        )

    if not all(_strict_eligible(r) for r in rows):
        return _ChainVerifyResult(
            status="PASS",
            checked=len(rows),
            first_bad=None,
            mode="linkage",
            strict_ok=None,
            strict_reason="insufficient_fields_for_strict",
        )

    strict_checked = 0
    for record in rows:
        created_at = getattr(record, "created_at", None) or datetime.now(timezone.utc)
        req = _loads_json_text(getattr(record, "request_json", None)) or {}
        resp = _loads_json_text(getattr(record, "response_json", None)) or {}

        payload = build_chain_payload(
            tenant_id=record.tenant_id,
            request_json=req,
            response_json=resp,
            threat_level=getattr(record, "threat_level", None) or "unknown",
            chain_ts=created_at,
            event_id=str(record.event_id),
        )

        prev_for_compute = getattr(record, "prev_hash", None) or "GENESIS"
        expected = compute_chain_hash(prev_for_compute, payload)
        record_chain = getattr(record, "chain_hash", None)

        if record_chain and record_chain != expected:
            return _ChainVerifyResult(
                status="FAIL",
                checked=strict_checked,
                first_bad={
                    "id": int(record.id),
                    "event_id": str(record.event_id),
                    "reason": "chain_hash_mismatch",
                },
                mode="strict",
                strict_ok=False,
                strict_reason="chain_hash_mismatch",
            )

        strict_checked += 1

    return _ChainVerifyResult(
        status="PASS",
        checked=strict_checked,
        first_bad=None,
        mode="strict",
        strict_ok=True,
        strict_reason=None,
    )


@router.get("/scopes", dependencies=[Depends(require_api_key_always)])
async def ui_scopes(request: Request) -> dict[str, Any]:
    auth = getattr(getattr(request, "state", None), "auth", None)
    scopes = sorted(getattr(auth, "scopes", set()) or [])
    allowed = {"ui:read", "forensics:read", "controls:read", "audit:read", "admin:read"}
    if not set(scopes) & allowed:
        raise HTTPException(status_code=403, detail="Insufficient scope")
    return {"scopes": scopes, "request_id": _request_id(request)}


@router.get("/csrf", dependencies=[Depends(require_api_key_always)])
async def ui_csrf(request: Request):
    token = secrets.token_urlsafe(32)
    payload = {
        "csrf_token": token,
        "header_name": CSRF_HEADER_NAME,
        "request_id": _request_id(request),
    }
    from fastapi.responses import JSONResponse

    resp = JSONResponse(payload)
    resp.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        httponly=False,
        samesite="strict",
        secure=os.getenv("FG_ENV", "").lower() == "prod",
        path="/",
        max_age=60 * 60,
    )
    return resp


@router.get(
    "/posture",
    response_model=PostureResponse,
    dependencies=[Depends(require_scopes("ui:read"))],
)
async def ui_posture(
    request: Request,
    db: Session = Depends(tenant_db_required),
    tenant_id: Optional[str] = Query(default=None, max_length=128),
) -> PostureResponse:
    tenant_id = _resolve_tenant(request, tenant_id)
    stats = _compute_stats(db, tenant_id=tenant_id)
    trend = _trend_flag(int(stats.decisions_24h), int(stats.decisions_7d))
    top_rules = [
        {"reason": item.name, "count": int(item.count)} for item in stats.top_rules_24h
    ]

    tiles = [
        PostureTile(
            label="Decisions (24h)", value=str(int(stats.decisions_24h)), trend=trend
        ),
        PostureTile(
            label="High threat rate (1h)",
            value=f"{float(stats.high_threat_rate_1h):.2f}%",
        ),
        PostureTile(
            label="Unique IPs (24h)", value=str(int(stats.unique_source_ips_24h))
        ),
        PostureTile(
            label="Avg latency (24h)", value=f"{float(stats.avg_latency_ms_24h):.1f} ms"
        ),
    ]

    trends = {
        "decisions_1h": int(stats.decisions_1h),
        "decisions_24h": int(stats.decisions_24h),
        "decisions_7d": int(stats.decisions_7d),
        "trend_flag": trend,
        "threat_counts_24h": stats.threat_counts_24h.model_dump(),
    }

    return PostureResponse(
        tenant_id=tenant_id,
        generated_at=_iso(stats.now) or _iso(datetime.now(timezone.utc)),
        request_id=_request_id(request),
        tiles=tiles,
        trends=trends,
        top_deny_reasons=top_rules,
    )


@router.get(
    "/decisions",
    response_model=DecisionsPage,
    dependencies=[Depends(require_scopes("ui:read"))],
)
async def ui_decisions(
    request: Request,
    db: Session = Depends(tenant_db_required),
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0, le=200000),
    tenant_id: Optional[str] = Query(default=None, max_length=128),
    event_type: Optional[str] = Query(default=None, min_length=1),
    threat_level: Optional[str] = Query(default=None, min_length=1),
    source: Optional[str] = Query(default=None, min_length=1),
    from_ts: Optional[str] = Query(default=None),
    to_ts: Optional[str] = Query(default=None),
) -> DecisionsPage:
    tenant_id = _resolve_tenant(request, tenant_id)
    from_dt = _parse_dt(from_ts)
    to_dt = _parse_dt(to_ts)

    where = [DecisionRecord.tenant_id == tenant_id]
    if event_type:
        where.append(DecisionRecord.event_type == event_type)
    if threat_level:
        where.append(DecisionRecord.threat_level == threat_level)
    if source:
        where.append(DecisionRecord.source == source)
    if from_dt:
        where.append(DecisionRecord.created_at >= from_dt)
    if to_dt:
        where.append(DecisionRecord.created_at <= to_dt)

    count_stmt = select(func.count()).select_from(DecisionRecord)
    for clause in where:
        count_stmt = count_stmt.where(clause)
    total = int(db.execute(count_stmt).scalar_one())

    stmt = select(DecisionRecord)
    for clause in where:
        stmt = stmt.where(clause)
    stmt = stmt.order_by(desc(DecisionRecord.created_at), desc(DecisionRecord.id))
    stmt = stmt.limit(limit).offset(offset)

    rows = db.execute(stmt).scalars().all()
    items: list[DecisionListItem] = []
    for record in rows:
        decision_diff = _loads_json_text(getattr(record, "decision_diff_json", None))
        items.append(
            DecisionListItem(
                id=int(record.id),
                created_at=_iso(getattr(record, "created_at", None)),
                event_id=str(record.event_id),
                event_type=record.event_type,
                source=record.source,
                threat_level=record.threat_level,
                action_taken=_derive_action_taken(decision_diff),
                explain_summary=getattr(record, "explain_summary", None),
                latency_ms=int(getattr(record, "latency_ms", 0) or 0),
            )
        )

    return DecisionsPage(
        items=items,
        limit=limit,
        offset=offset,
        total=total,
        request_id=_request_id(request),
    )


@router.get(
    "/decision/{decision_id}",
    response_model=DecisionDetail,
    dependencies=[Depends(require_scopes("ui:read"))],
)
async def ui_decision_detail(
    decision_id: int,
    request: Request,
    db: Session = Depends(tenant_db_required),
    tenant_id: Optional[str] = Query(default=None, max_length=128),
) -> DecisionDetail:
    tenant_id = _resolve_tenant(request, tenant_id)
    record = db.get(DecisionRecord, decision_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    if record.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")

    return DecisionDetail(
        id=int(record.id),
        created_at=_iso(getattr(record, "created_at", None)),
        tenant_id=record.tenant_id,
        source=record.source,
        event_id=str(record.event_id),
        event_type=record.event_type,
        threat_level=record.threat_level,
        anomaly_score=float(getattr(record, "anomaly_score", 0.0) or 0.0),
        ai_adversarial_score=float(getattr(record, "ai_adversarial_score", 0.0) or 0.0),
        pq_fallback=bool(getattr(record, "pq_fallback", False)),
        rules_triggered=list(
            _loads_json_text(getattr(record, "rules_triggered_json", None)) or []
        ),
        explain_summary=getattr(record, "explain_summary", None),
        latency_ms=int(getattr(record, "latency_ms", 0) or 0),
        request=_loads_json_text(getattr(record, "request_json", None)),
        response=_loads_json_text(getattr(record, "response_json", None)),
        decision_diff=_loads_json_text(getattr(record, "decision_diff_json", None)),
        chain_hash=getattr(record, "chain_hash", None),
        prev_hash=getattr(record, "prev_hash", None),
        request_id=_request_id(request),
    )


@router.get(
    "/forensics/chain/verify",
    response_model=ChainVerifyResponse,
    dependencies=[Depends(require_scopes("forensics:read"))],
)
async def ui_chain_verify(
    request: Request,
    db: Session = Depends(tenant_db_required),
    tenant_id: Optional[str] = Query(default=None, max_length=128),
) -> ChainVerifyResponse:
    tenant_id = _resolve_tenant(request, tenant_id)
    res = _verify_chain(db, tenant_id)
    return ChainVerifyResponse(
        tenant_id=tenant_id,
        status=res.status,
        checked=res.checked,
        first_bad=res.first_bad,
        mode=res.mode,
        strict_ok=res.strict_ok,
        strict_reason=res.strict_reason,
        request_id=_request_id(request),
    )


@router.post(
    "/audit/packet",
    response_model=AuditPacketResponse,
    dependencies=[Depends(require_scopes("audit:read"))],
)
async def ui_audit_packet(
    payload: AuditPacketRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AuditPacketResponse:
    _ensure_csrf(request)
    tenant_id = _resolve_tenant(request, payload.tenant_id)
    from_dt = _parse_dt(payload.from_ts)
    to_dt = _parse_dt(payload.to_ts)

    _cleanup_packets()
    packet_root = _audit_packet_dir()
    packet_root.mkdir(parents=True, exist_ok=True)

    created_at = datetime.now(timezone.utc)
    packet_id = f"packet-{tenant_id}-{created_at.strftime('%Y%m%d%H%M%S')}"
    packet_dir = packet_root / packet_id
    packet_dir.mkdir(parents=True, exist_ok=True)

    stmt = select(DecisionRecord).where(DecisionRecord.tenant_id == tenant_id)
    if from_dt:
        stmt = stmt.where(DecisionRecord.created_at >= from_dt)
    if to_dt:
        stmt = stmt.where(DecisionRecord.created_at <= to_dt)
    stmt = stmt.order_by(asc(DecisionRecord.created_at), asc(DecisionRecord.id))
    rows = db.execute(stmt).scalars().all()

    decisions_path = packet_dir / "decisions.jsonl"
    with decisions_path.open("w", encoding="utf-8") as handle:
        for record in rows:
            entry = {
                "id": int(record.id),
                "created_at": _iso(getattr(record, "created_at", None)),
                "tenant_id": record.tenant_id,
                "source": record.source,
                "event_id": str(record.event_id),
                "event_type": record.event_type,
                "threat_level": record.threat_level,
                "anomaly_score": float(getattr(record, "anomaly_score", 0.0) or 0.0),
                "ai_adversarial_score": float(
                    getattr(record, "ai_adversarial_score", 0.0) or 0.0
                ),
                "pq_fallback": bool(getattr(record, "pq_fallback", False)),
                "rules_triggered": _loads_json_text(
                    getattr(record, "rules_triggered_json", None)
                )
                or [],
                "explain_summary": getattr(record, "explain_summary", None),
                "latency_ms": int(getattr(record, "latency_ms", 0) or 0),
                "decision_diff": _loads_json_text(
                    getattr(record, "decision_diff_json", None)
                ),
                "request": _loads_json_text(getattr(record, "request_json", None)),
                "response": _loads_json_text(getattr(record, "response_json", None)),
                "chain_hash": getattr(record, "chain_hash", None),
                "prev_hash": getattr(record, "prev_hash", None),
            }
            handle.write(_canonical_json(entry) + "\n")

    # IMPORTANT: updated call signature (no tuple unpack)
    res = _verify_chain(db, tenant_id)
    chain_verify = ChainVerifyResponse(
        tenant_id=tenant_id,
        status=res.status,
        checked=res.checked,
        first_bad=res.first_bad,
        mode=res.mode,
        strict_ok=res.strict_ok,
        strict_reason=res.strict_reason,
        request_id=_request_id(request),
    )
    chain_path = packet_dir / "chain_verification.json"
    chain_path.write_text(_canonical_json(chain_verify.model_dump()), encoding="utf-8")

    files = ["decisions.jsonl", "chain_verification.json"]
    artifacts_dir = Path(os.getenv("FG_ARTIFACTS_DIR", "artifacts"))
    for extra in ("sbom.json", "provenance.json"):
        extra_path = artifacts_dir / extra
        if extra_path.exists():
            target = packet_dir / extra
            shutil.copy2(extra_path, target)
            files.append(extra)

    manifest_entries: list[dict[str, Any]] = []
    for name in sorted(files):
        manifest_entries.append(
            {"name": name, "sha256": _sha256_file(packet_dir / name)}
        )

    manifest = {"algorithm": "sha256", "version": 1, "files": manifest_entries}
    manifest_path = packet_dir / "manifest.json"
    manifest_path.write_text(_canonical_json(manifest), encoding="utf-8")
    files.append("manifest.json")

    metadata = {
        "tenant_id": tenant_id,
        "packet_id": packet_id,
        "created_at": _iso(created_at),
    }
    _packet_metadata_path(packet_dir).write_text(
        _canonical_json(metadata), encoding="utf-8"
    )

    token = secrets.token_urlsafe(24)
    token_path = packet_dir / "token.txt"
    token_path.write_text(token, encoding="utf-8")

    _zip_packet(packet_dir, files)

    audit_admin_action(
        action="audit_packet_created",
        tenant_id=tenant_id,
        request=request,
        details={"packet_id": packet_id},
    )

    return AuditPacketResponse(
        tenant_id=tenant_id,
        packet_id=packet_id,
        created_at=_iso(created_at) or _iso(datetime.now(timezone.utc)),
        download_url=f"/ui/audit/packet/{packet_id}/download?token={token}",
        request_id=_request_id(request),
        manifest=manifest,
    )


@router.get(
    "/audit/packet/{packet_id}/download",
    dependencies=[Depends(require_scopes("audit:read"))],
)
async def ui_audit_packet_download(
    packet_id: str,
    request: Request,
    tenant_id: Optional[str] = Query(default=None, max_length=128),
    token: str = Query(..., min_length=8),
) -> FileResponse:
    tenant_id = _resolve_tenant(request, tenant_id)
    packet_dir = _audit_packet_dir() / packet_id
    if not packet_dir.exists():
        raise HTTPException(status_code=404, detail="Packet not found")
    token_path = packet_dir / "token.txt"
    file_token = (
        token_path.read_text(encoding="utf-8").strip() if token_path.exists() else None
    )
    if (
        not token_path.exists()
        or not isinstance(token, str)
        or not isinstance(file_token, str)
        or not hmac.compare_digest(file_token, token)
    ):
        raise HTTPException(status_code=403, detail="Invalid token")
    meta_path = _packet_metadata_path(packet_dir)
    if meta_path.exists():
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        if metadata.get("tenant_id") != tenant_id:
            raise HTTPException(status_code=403, detail="Tenant mismatch")
    zip_path = packet_dir / "audit_packet.zip"
    if not zip_path.exists():
        raise HTTPException(status_code=404, detail="Packet archive missing")
    return FileResponse(
        path=zip_path, filename=zip_path.name, media_type="application/zip"
    )


@router.get(
    "/controls",
    response_model=ControlsPage,
    dependencies=[Depends(require_scopes("controls:read"))],
)
async def ui_controls(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0, le=1000),
    tenant_id: Optional[str] = Query(default=None, max_length=128),
) -> ControlsPage:
    _resolve_tenant(request, tenant_id)
    matrix = _controls_matrix()
    total = len(matrix)
    sliced = matrix[offset : offset + limit]
    items = [
        ControlSummary(
            inv_id=item["inv_id"],
            name=item["name"],
            status=item["status"],
            evidence_count=len(item["evidence"]),
            remediation=item["remediation"],
        )
        for item in sliced
    ]
    return ControlsPage(
        items=items,
        limit=limit,
        offset=offset,
        total=total,
        request_id=_request_id(request),
    )


@router.get(
    "/controls/{inv_id}",
    response_model=ControlDetail,
    dependencies=[Depends(require_scopes("controls:read"))],
)
async def ui_control_detail(
    inv_id: str,
    request: Request,
    tenant_id: Optional[str] = Query(default=None, max_length=128),
) -> ControlDetail:
    _resolve_tenant(request, tenant_id)
    matrix = {item["inv_id"]: item for item in _controls_matrix()}
    if inv_id not in matrix:
        raise HTTPException(status_code=404, detail="Control not found")
    item = matrix[inv_id]
    return ControlDetail(
        inv_id=item["inv_id"],
        name=item["name"],
        status=item["status"],
        description=item["description"],
        evidence=item["evidence"],
        remediation=item["remediation"],
        request_id=_request_id(request),
    )
