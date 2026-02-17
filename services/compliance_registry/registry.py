from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models import (
    ComplianceFindingRecord,
    ComplianceRequirementRecord,
    ComplianceRequirementUpdateRecord,
)
from services.canonical import (
    canonical_json_bytes,
    parse_utc_iso8601_z,
    utc_iso8601_z_now,
)
from services.crypto_keys import load_hmac_keys

Severity = Literal["low", "med", "high", "critical"]
ReqStatus = Literal["active", "deprecated"]
EvidenceType = Literal["automated", "manual", "hybrid"]
FindingStatus = Literal["open", "mitigating", "resolved", "waived"]


class RequirementPackageMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_name: str
    source_version: str
    published_at_utc: str
    retrieved_at_utc: str
    bundle_sha256: str

    @field_validator("published_at_utc", "retrieved_at_utc")
    @classmethod
    def _validate_ts(cls, value: str) -> str:
        return parse_utc_iso8601_z(value)


def _utc_now_z() -> str:
    return utc_iso8601_z_now()


def _canonical_bytes(payload: Any) -> bytes:
    return canonical_json_bytes(payload)


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _key_pair(prefix: str) -> tuple[str, bytes]:
    key_id, keys = load_hmac_keys(prefix)
    return key_id, keys[key_id]


def _sign_hash(record_hash: str, key_id: str, key: bytes) -> str:
    import hmac

    digest = hmac.new(key, bytes.fromhex(record_hash), hashlib.sha256).hexdigest()
    return f"{key_id}:{digest}"


class RequirementImportItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    req_id: str
    source: Literal["GLBA", "SOC2", "FFIEC", "INTERNAL"]
    source_ref: str
    title: str
    description: str
    severity: Severity
    effective_date_utc: str
    version: str
    status: ReqStatus
    evidence_type: EvidenceType
    owner: str
    tags: list[str] = Field(default_factory=list)

    @field_validator("effective_date_utc")
    @classmethod
    def _validate_effective_ts(cls, value: str) -> str:
        return parse_utc_iso8601_z(value)


class FindingCreateItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    req_ids: list[str]
    title: str
    details: str
    severity: Severity
    status: FindingStatus
    waiver: dict[str, str] | None = None
    detected_at_utc: str
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator("detected_at_utc")
    @classmethod
    def _validate_detected_ts(cls, value: str) -> str:
        return parse_utc_iso8601_z(value)


class ComplianceRegistry:
    def __init__(self) -> None:
        self.engine = get_engine()

    def _latest_requirement_hash(self, session: Session, tenant_id: str) -> str:
        row = (
            session.query(ComplianceRequirementRecord)
            .filter(ComplianceRequirementRecord.tenant_id == tenant_id)
            .order_by(ComplianceRequirementRecord.id.desc())
            .limit(1)
            .one_or_none()
        )
        return row.record_hash if row is not None else "GENESIS"

    def _latest_finding_hash(self, session: Session, tenant_id: str) -> str:
        row = (
            session.query(ComplianceFindingRecord)
            .filter(ComplianceFindingRecord.tenant_id == tenant_id)
            .order_by(ComplianceFindingRecord.id.desc())
            .limit(1)
            .one_or_none()
        )
        return row.record_hash if row is not None else "GENESIS"

    def _latest_update_hash(self, session: Session, tenant_id: str) -> str:
        row = (
            session.query(ComplianceRequirementUpdateRecord)
            .filter(ComplianceRequirementUpdateRecord.tenant_id == tenant_id)
            .order_by(ComplianceRequirementUpdateRecord.id.desc())
            .limit(1)
            .one_or_none()
        )
        return row.record_hash if row is not None else "GENESIS"

    def record_update_available(
        self, tenant_id: str, package: RequirementPackageMeta, diff: dict[str, Any]
    ) -> str:
        key_id, key = _key_pair("FG_COMPLIANCE")
        with Session(self.engine) as session:
            update_id = str(uuid.uuid4())
            prev = self._latest_update_hash(session, tenant_id)
            created = _utc_now_z()
            material = {
                "update_id": update_id,
                "tenant_id": tenant_id,
                **package.model_dump(),
                "status": "available",
                "diff": diff,
                "created_at_utc": created,
                "previous_record_hash": prev,
            }
            rec_hash = _sha256_hex(_canonical_bytes(material))
            session.add(
                ComplianceRequirementUpdateRecord(
                    tenant_id=tenant_id,
                    update_id=update_id,
                    source_name=package.source_name,
                    source_version=package.source_version,
                    published_at_utc=package.published_at_utc,
                    retrieved_at_utc=package.retrieved_at_utc,
                    bundle_sha256=package.bundle_sha256,
                    status="available",
                    diff_json=diff,
                    previous_record_hash=prev,
                    record_hash=rec_hash,
                    signature=_sign_hash(rec_hash, key_id, key),
                    key_id=key_id,
                    created_at_utc=created,
                )
            )
            session.commit()
            return update_id

    def import_requirements(
        self,
        tenant_id: str,
        requirements: list[RequirementImportItem],
        actor: str,
        package: RequirementPackageMeta,
        update_id: str | None = None,
    ) -> list[dict[str, Any]]:
        key_id, key = _key_pair("FG_COMPLIANCE")
        created: list[dict[str, Any]] = []
        with Session(self.engine) as session:
            prev = self._latest_requirement_hash(session, tenant_id)
            for item in requirements:
                payload = item.model_dump()
                created_at_utc = _utc_now_z()
                material = {
                    **payload,
                    **package.model_dump(),
                    "created_at_utc": created_at_utc,
                    "previous_record_hash": prev,
                    "tenant_id": tenant_id,
                    "actor": actor,
                }
                record_hash = _sha256_hex(_canonical_bytes(material))
                signature = _sign_hash(record_hash, key_id, key)
                rec = ComplianceRequirementRecord(
                    tenant_id=tenant_id,
                    req_id=item.req_id,
                    source=item.source,
                    source_ref=item.source_ref,
                    title=item.title,
                    description=item.description,
                    severity=item.severity,
                    effective_date_utc=item.effective_date_utc,
                    version=item.version,
                    status=item.status,
                    evidence_type=item.evidence_type,
                    owner=item.owner,
                    source_name=package.source_name,
                    source_version=package.source_version,
                    published_at_utc=package.published_at_utc,
                    retrieved_at_utc=package.retrieved_at_utc,
                    bundle_sha256=package.bundle_sha256,
                    tags_json=item.tags,
                    created_at_utc=created_at_utc,
                    previous_record_hash=prev,
                    record_hash=record_hash,
                    signature=signature,
                    key_id=key_id,
                )
                session.add(rec)
                prev = record_hash
                created.append(rec.to_dict())
            if update_id:
                row = (
                    session.query(ComplianceRequirementUpdateRecord)
                    .filter(ComplianceRequirementUpdateRecord.tenant_id == tenant_id)
                    .filter(ComplianceRequirementUpdateRecord.update_id == update_id)
                    .order_by(ComplianceRequirementUpdateRecord.id.desc())
                    .limit(1)
                    .one_or_none()
                )
                if row is not None:
                    prev_u = self._latest_update_hash(session, tenant_id)
                    created_u = _utc_now_z()
                    material_u = {
                        "update_id": str(uuid.uuid4()),
                        "tenant_id": tenant_id,
                        "source_name": row.source_name,
                        "source_version": row.source_version,
                        "published_at_utc": row.published_at_utc,
                        "retrieved_at_utc": row.retrieved_at_utc,
                        "bundle_sha256": row.bundle_sha256,
                        "status": "applied",
                        "diff": row.diff_json,
                        "created_at_utc": created_u,
                        "previous_record_hash": prev_u,
                    }
                    h_u = _sha256_hex(_canonical_bytes(material_u))
                    session.add(
                        ComplianceRequirementUpdateRecord(
                            tenant_id=tenant_id,
                            update_id=material_u["update_id"],
                            source_name=row.source_name,
                            source_version=row.source_version,
                            published_at_utc=row.published_at_utc,
                            retrieved_at_utc=row.retrieved_at_utc,
                            bundle_sha256=row.bundle_sha256,
                            status="applied",
                            diff_json=row.diff_json,
                            previous_record_hash=prev_u,
                            record_hash=h_u,
                            signature=_sign_hash(h_u, key_id, key),
                            key_id=key_id,
                            created_at_utc=created_u,
                        )
                    )
            session.commit()
        return created

    def add_findings(
        self, tenant_id: str, findings: list[FindingCreateItem]
    ) -> list[dict[str, Any]]:
        key_id, key = _key_pair("FG_COMPLIANCE")
        created: list[dict[str, Any]] = []
        with Session(self.engine) as session:
            prev = self._latest_finding_hash(session, tenant_id)
            for item in findings:
                created_at_utc = _utc_now_z()
                material = {
                    **item.model_dump(),
                    "created_at_utc": created_at_utc,
                    "previous_record_hash": prev,
                    "tenant_id": tenant_id,
                }
                record_hash = _sha256_hex(_canonical_bytes(material))
                signature = _sign_hash(record_hash, key_id, key)
                rec = ComplianceFindingRecord(
                    tenant_id=tenant_id,
                    finding_id=item.finding_id,
                    req_ids_json=item.req_ids,
                    title=item.title,
                    details=item.details,
                    severity=item.severity,
                    status=item.status,
                    waiver_json=item.waiver,
                    detected_at_utc=item.detected_at_utc,
                    evidence_refs_json=item.evidence_refs,
                    created_at_utc=created_at_utc,
                    previous_record_hash=prev,
                    record_hash=record_hash,
                    signature=signature,
                    key_id=key_id,
                )
                session.add(rec)
                prev = record_hash
                created.append(rec.to_dict())
            session.commit()
        return created

    def requirements_diff(self, tenant_id: str, since: str) -> list[dict[str, Any]]:
        with Session(self.engine) as session:
            rows = (
                session.query(ComplianceRequirementRecord)
                .filter(ComplianceRequirementRecord.tenant_id == tenant_id)
                .filter(ComplianceRequirementRecord.created_at_utc >= since)
                .order_by(
                    ComplianceRequirementRecord.req_id.asc(),
                    ComplianceRequirementRecord.version.asc(),
                    ComplianceRequirementRecord.id.asc(),
                )
                .all()
            )
        return [r.to_dict() for r in rows]

    def list_updates(self, tenant_id: str) -> list[dict[str, Any]]:
        with Session(self.engine) as session:
            rows = (
                session.query(ComplianceRequirementUpdateRecord)
                .filter(ComplianceRequirementUpdateRecord.tenant_id == tenant_id)
                .order_by(ComplianceRequirementUpdateRecord.id.desc())
                .all()
            )
        return [
            {
                "update_id": r.update_id,
                "source_name": r.source_name,
                "source_version": r.source_version,
                "bundle_sha256": r.bundle_sha256,
                "status": r.status,
                "created_at_utc": r.created_at_utc,
                "key_id": r.key_id,
            }
            for r in rows
        ]

    def snapshot(self, tenant_id: str) -> dict[str, Any]:
        with Session(self.engine) as session:
            req = (
                session.query(ComplianceRequirementRecord)
                .filter(ComplianceRequirementRecord.tenant_id == tenant_id)
                .order_by(ComplianceRequirementRecord.id.asc())
                .all()
            )
            fin = (
                session.query(ComplianceFindingRecord)
                .filter(ComplianceFindingRecord.tenant_id == tenant_id)
                .order_by(ComplianceFindingRecord.id.asc())
                .all()
            )
        by_req = {r.req_id: r for r in req if r.status == "active"}
        latest_findings: dict[str, ComplianceFindingRecord] = {}
        for row in fin:
            latest_findings.setdefault(row.finding_id, row)

        open_by_req: dict[str, str] = {}
        for row in latest_findings.values():
            for req_id in row.req_ids_json or []:
                if row.status in {"open", "mitigating", "waived"}:
                    open_by_req[str(req_id)] = row.status

        covered = {"pass": 0, "fail": 0, "unknown": 0}
        unknown_critical_count = 0
        for req_id, rec in by_req.items():
            if req_id in open_by_req:
                covered["fail"] += 1
            elif rec.severity == "critical" and rec.evidence_type != "automated":
                covered["unknown"] += 1
                unknown_critical_count += 1
            else:
                covered["pass"] += 1

        finding_counts = {"open": 0, "mitigating": 0, "resolved": 0, "waived": 0}
        waiver_expiring: list[str] = []
        now = datetime.now(UTC)
        for f in fin:
            finding_counts[f.status] = finding_counts.get(f.status, 0) + 1
            waiver = f.waiver_json or {}
            exp = waiver.get("expires_utc") if isinstance(waiver, dict) else None
            if exp:
                try:
                    dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
                    if dt <= now:
                        waiver_expiring.append(f.finding_id)
                except Exception:
                    waiver_expiring.append(f.finding_id)
        threshold = int(os.getenv("FG_CRITICAL_UNKNOWN_THRESHOLD", "0"))
        max_age_days = int(os.getenv("FG_REQUIREMENTS_MAX_AGE_DAYS", "30"))
        stale_sources: list[str] = []
        source_latest: dict[str, datetime] = {}
        for rec in by_req.values():
            if rec.published_at_utc:
                try:
                    dt = datetime.fromisoformat(
                        str(rec.published_at_utc).replace("Z", "+00:00")
                    )
                    src = rec.source_name or rec.source
                    prev = source_latest.get(src)
                    if prev is None or dt > prev:
                        source_latest[src] = dt
                except Exception:
                    stale_sources.append(rec.source_name or rec.source)
        for src, dt in source_latest.items():
            age_days = (now - dt).days
            if age_days > max_age_days:
                stale_sources.append(src)
        stale_sources = sorted(set(stale_sources))
        return {
            "requirements_total": len(by_req),
            "coverage": covered,
            "findings": finding_counts,
            "expired_waivers": sorted(waiver_expiring),
            "expired_waiver_count": len(set(waiver_expiring)),
            "unknown_critical_count": unknown_critical_count,
            "unknown_critical_threshold": threshold,
            "unknown_critical_threshold_exceeded": unknown_critical_count > threshold,
            "requirements_freshness_max_age_days": max_age_days,
            "stale_requirement_sources": stale_sources,
            "requirements_stale": bool(stale_sources),
            "timestamp_utc": _utc_now_z(),
        }
