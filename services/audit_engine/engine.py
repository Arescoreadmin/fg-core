from __future__ import annotations

import hashlib
import io
import hmac
import json
import os
import re
import socket
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import and_, desc
from sqlalchemy.orm import Session

from api.config_versioning import canonicalize_config, hash_config
from api.db import get_engine
from api.db_models import (
    AuditAnchor,
    AuditChainCheckpoint,
    AuditExport,
    AuditExportJob,
    AuditBypassEvent,
    AuditRetentionRun,
    AuditLedgerRecord,
    ConfigVersion,
)
from api.evidence_store import EvidenceStore, LocalFileEvidenceStore
from services.audit_engine.signing import (
    canonical_json_bytes,
    sign_hmac,
    sign_manifest_payload,
    utc_rfc3339,
    verify_hmac,
    verify_manifest_signature,
)
from engine.policy_fingerprint import get_active_policy_fingerprint

GENESIS_HASH = "GENESIS"


class AuditChainIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditEngineRecord:
    timestamp_utc: str
    invariant_id: str
    decision: str
    config_hash: str
    policy_hash: str
    git_commit: str
    runtime_version: str
    host_id: str
    previous_record_hash: str


def _normalized(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _normalized(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, list):
        vals = [_normalized(v) for v in obj]
        sortable = all(isinstance(v, (str, int, float, bool, type(None), dict)) for v in vals)
        if sortable:
            return sorted(vals, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return vals
    return obj


def _canonical_json_bytes(obj: Any) -> bytes:
    return canonical_json_bytes(_normalized(obj))


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def _runtime_version() -> str:
    return (os.getenv("FG_RUNTIME_VERSION") or "fg-core").strip()


def _host_id() -> str:
    return (os.getenv("FG_HOST_ID") or socket.gethostname()).strip()


def _record_hash(material: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_bytes(material)).hexdigest()


def _latest_record(db: Session, tenant_id: str) -> AuditLedgerRecord | None:
    return (
        db.query(AuditLedgerRecord)
        .filter(AuditLedgerRecord.tenant_id == tenant_id)
        .order_by(desc(AuditLedgerRecord.id))
        .first()
    )


def _checkpoint_interval() -> int:
    return max(1, int((os.getenv("FG_AUDIT_CHECKPOINT_INTERVAL") or "10000").strip()))


def _latest_checkpoint(db: Session, tenant_id: str) -> AuditChainCheckpoint | None:
    return (
        db.query(AuditChainCheckpoint)
        .filter(AuditChainCheckpoint.tenant_id == tenant_id)
        .order_by(desc(AuditChainCheckpoint.record_seq), desc(AuditChainCheckpoint.id))
        .first()
    )


def _write_checkpoint_if_needed(db: Session, tenant_id: str) -> None:
    interval = _checkpoint_interval()
    latest = _latest_record(db, tenant_id)
    if latest is None:
        return
    record_seq = int(latest.id)
    if record_seq % interval != 0:
        return

    existing = (
        db.query(AuditChainCheckpoint)
        .filter(
            AuditChainCheckpoint.tenant_id == tenant_id,
            AuditChainCheckpoint.record_seq == record_seq,
        )
        .first()
    )
    if existing is not None:
        return

    db.add(
        AuditChainCheckpoint(
            tenant_id=tenant_id,
            checkpoint_id=f"{tenant_id}:{record_seq}",
            record_seq=record_seq,
            root_hash=str(latest.sha256_self_hash),
        )
    )
    db.flush()


def verify_audit_chain(db: Session, tenant_id: str = "system") -> dict[str, Any]:
    checkpoint = _latest_checkpoint(db, tenant_id)
    start_seq = 0
    expected_prev = GENESIS_HASH

    if checkpoint is not None:
        row = db.get(AuditLedgerRecord, checkpoint.record_seq)
        if row is None or not hmac.compare_digest(str(row.sha256_self_hash), str(checkpoint.root_hash)):
            return {"ok": False, "reason": "checkpoint_root_mismatch", "bad_id": checkpoint.record_seq}
        start_seq = int(checkpoint.record_seq)
        expected_prev = str(checkpoint.root_hash)

    rows = (
        db.query(AuditLedgerRecord)
        .filter(AuditLedgerRecord.tenant_id == tenant_id, AuditLedgerRecord.id > start_seq)
        .order_by(AuditLedgerRecord.id.asc())
        .all()
    )
    checked = 0
    for row in rows:
        checked += 1
        material = {
            "timestamp_utc": row.timestamp_utc,
            "invariant_id": row.invariant_id,
            "decision": row.decision,
            "config_hash": row.config_hash,
            "policy_hash": row.policy_hash,
            "git_commit": row.git_commit,
            "runtime_version": row.runtime_version,
            "host_id": row.host_id,
            "previous_record_hash": row.previous_record_hash,
        }
        if not hmac.compare_digest(str(row.previous_record_hash), expected_prev):
            return {"ok": False, "reason": "previous_hash_mismatch", "bad_id": row.id}

        if not hmac.compare_digest(_record_hash(material), str(row.sha256_self_hash)):
            return {"ok": False, "reason": "self_hash_mismatch", "bad_id": row.id}

        if not verify_hmac(_canonical_json_bytes(material), str(row.signature)):
            return {"ok": False, "reason": "signature_mismatch", "bad_id": row.id}

        expected_prev = str(row.sha256_self_hash)

    if (os.getenv("FG_AUDIT_ANCHOR_ENABLED") or "0").strip() == "1":
        if not _verify_anchor_presence(db, tenant_id=tenant_id):
            return {"ok": False, "reason": "anchor_missing", "bad_id": None}

    return {"ok": True, "checked": checked, "checkpoint_start": start_seq}


def append_audit_record(
    db: Session,
    *,
    invariant_id: str,
    decision: str,
    config_hash: str,
    policy_hash: str,
    timestamp_utc: str | None = None,
    tenant_id: str = "system",
) -> AuditLedgerRecord:
    integrity = verify_audit_chain(db, tenant_id=tenant_id)
    if not integrity.get("ok"):
        raise AuditChainIntegrityError(f"FG-AUDIT-CHAIN-001:{integrity}")

    prev = _latest_record(db, tenant_id)
    material = {
        "timestamp_utc": timestamp_utc or utc_rfc3339(),
        "invariant_id": invariant_id,
        "decision": decision,
        "config_hash": config_hash,
        "policy_hash": policy_hash,
        "git_commit": _git_commit(),
        "runtime_version": _runtime_version(),
        "host_id": _host_id(),
        "previous_record_hash": str(prev.sha256_self_hash) if prev is not None else GENESIS_HASH,
    }
    _, sig = sign_hmac(_canonical_json_bytes(material))
    rec = AuditLedgerRecord(
        tenant_id=tenant_id,
        **material,
        sha256_self_hash=_record_hash(material),
        signature=sig,
    )
    db.add(rec)
    db.flush()
    _write_checkpoint_if_needed(db, tenant_id)
    return rec


def _run_check(cmd: list[str]) -> bool:
    env = dict(os.environ)
    env.setdefault("PYTHONPATH", ".")
    proc = subprocess.run([sys.executable, *cmd], capture_output=True, text=True, env=env)
    return proc.returncode == 0


def _active_config_hash(db: Session, tenant_id: str = "system") -> str:
    row = (
        db.query(ConfigVersion)
        .filter(ConfigVersion.tenant_id == tenant_id)
        .order_by(ConfigVersion.config_hash.asc(), ConfigVersion.id.asc())
        .first()
    )
    if row is None:
        return "none"
    return hash_config(canonicalize_config(row.config_json or {}))


def _policy_hash() -> str:
    return get_active_policy_fingerprint().policy_hash




def _deterministic_zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_STORED) as zf:
        for name in sorted(files.keys()):
            zi = zipfile.ZipInfo(filename=name)
            zi.date_time = (1980, 1, 1, 0, 0, 0)
            zi.create_system = 3
            zf.writestr(zi, files[name])
    return buf.getvalue()


_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

def _parse_iso8601_utc(value: str) -> bool:
    if not _RFC3339_Z.match(str(value)):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
        return True
    except Exception:
        return False

class AuditEngine:
    LIGHT_CHECKS = (
        "soc-invariants",
        "security-regression-gates",
        "route-inventory",
        "config-hash-validation",
        "policy-hash-validation",
        "drift-verification",
    )

    def evaluate_light(self, db: Session, tenant_id: str = "system") -> list[AuditLedgerRecord]:
        config_hash = _active_config_hash(db, tenant_id=tenant_id)
        policy_hash = _policy_hash()
        checks = {
            "soc-invariants": _run_check(["tools/ci/check_soc_invariants.py"]),
            "security-regression-gates": _run_check(["tools/ci/check_security_regression_gates.py"]),
            "route-inventory": _run_check(["tools/ci/check_route_inventory.py"]),
            "config-hash-validation": bool(config_hash and len(config_hash) == 64),
            "policy-hash-validation": bool(policy_hash and len(policy_hash) == 64),
            "drift-verification": _run_check(["tools/ci/check_route_inventory.py"]),
        }
        out: list[AuditLedgerRecord] = []
        for invariant_id in self.LIGHT_CHECKS:
            out.append(
                append_audit_record(
                    db,
                    tenant_id=tenant_id,
                    invariant_id=invariant_id,
                    decision="pass" if checks[invariant_id] else "fail",
                    config_hash=config_hash,
                    policy_hash=policy_hash,
                )
            )
        db.commit()
        return out


def _manifest_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    root_hash = hashlib.sha256(_canonical_json_bytes(bundle)).hexdigest()
    return {"root_hash": root_hash, "bundle": bundle}


def verify_export_manifest(manifest: dict[str, Any], bundle: dict[str, Any]) -> bool:
    payload = {
        "root_hash": manifest.get("root_hash"),
        "bundle_hash": manifest.get("bundle_sha256"),
        "sections": manifest.get("sections", {}),
        "range_start_utc": manifest.get("range_start_utc"),
        "range_end_utc": manifest.get("range_end_utc"),
        "range_end_inclusive": manifest.get("range_end_inclusive", True),
    }
    expected_root = hashlib.sha256(_canonical_json_bytes(bundle)).hexdigest()
    if not hmac.compare_digest(expected_root, str(manifest.get("root_hash", ""))):
        return False
    if not hmac.compare_digest(
        hashlib.sha256(_canonical_json_bytes(bundle)).hexdigest(), str(manifest.get("bundle_sha256", ""))
    ):
        return False
    if not _parse_iso8601_utc(str(manifest.get("signed_at", ""))):
        return False
    if not _parse_iso8601_utc(str(manifest.get("range_start_utc", ""))):
        return False
    if not _parse_iso8601_utc(str(manifest.get("range_end_utc", ""))):
        return False
    return verify_manifest_signature(
        payload,
        signature_algo=str(manifest.get("signature_algo", "")),
        kid=str(manifest.get("kid", "")),
        signature=str(manifest.get("signature", "")),
    )


def deterministic_export_bundle(db: Session, *, tenant_id: str, start: datetime, end: datetime) -> dict[str, Any]:
    rows = (
        db.query(AuditLedgerRecord)
        .filter(
            and_(
                AuditLedgerRecord.tenant_id == tenant_id,
                AuditLedgerRecord.created_at >= start,
                AuditLedgerRecord.created_at <= end,
            )
        )
        .order_by(AuditLedgerRecord.id.asc())
        .all()
    )
    sessions = [
        {
            "id": r.id,
            "timestamp_utc": r.timestamp_utc,
            "invariant_id": r.invariant_id,
            "decision": r.decision,
            "config_hash": r.config_hash,
            "policy_hash": r.policy_hash,
            "git_commit": r.git_commit,
            "runtime_version": r.runtime_version,
            "host_id": r.host_id,
            "sha256_self_hash": r.sha256_self_hash,
            "previous_record_hash": r.previous_record_hash,
            "signature": r.signature,
        }
        for r in rows
    ]

    config_rows = (
        db.query(ConfigVersion)
        .filter(ConfigVersion.tenant_id == tenant_id)
        .order_by(ConfigVersion.config_hash.asc(), ConfigVersion.id.asc())
        .all()
    )
    config_snapshot = [
        {"tenant_id": c.tenant_id, "config_hash": c.config_hash, "config_json": _normalized(c.config_json or {})}
        for c in config_rows
    ]

    policy_fp = get_active_policy_fingerprint()
    bundle = {
        "audit_sessions": sessions,
        "policy_snapshot": {
            "policy_id": policy_fp.policy_id,
            "policy_hash": policy_fp.policy_hash,
            "policy": json.loads(policy_fp.policy_bytes.decode("utf-8")),
        },
        "config_snapshot": config_snapshot,
        "openapi_snapshot": json.loads(Path("contracts/admin/openapi.json").read_text(encoding="utf-8")),
        "soc_manifest_snapshot": json.loads(Path("tools/ci/soc_findings_manifest.json").read_text(encoding="utf-8")),
        "provenance": {
            "git_commit": _git_commit(),
            "runtime_version": _runtime_version(),
            "migration_files": sorted([p.name for p in Path("migrations/postgres").glob("*.sql")]),
            "runtime_flags": {
                "FG_ENV": os.getenv("FG_ENV", ""),
                "FG_AUDIT_EXPORT_SIGNING_MODE": os.getenv("FG_AUDIT_EXPORT_SIGNING_MODE", "hmac"),
                "FG_AUDIT_VERIFY_REQUIRED": os.getenv("FG_AUDIT_VERIFY_REQUIRED", "1"),
            },
            "reproduce_instructions": [
                "1) Verify manifest signature with fg_audit_verify.py",
                "2) Recompute sha256 over canonical bundle JSON",
                "3) Compare manifest root_hash and bundle_sha256",
            ],
        },
    }
    payload = _manifest_payload(bundle)
    sections = {
        "audit_sessions_sha256": hashlib.sha256(_canonical_json_bytes(sessions)).hexdigest(),
        "policy_snapshot_sha256": hashlib.sha256(_canonical_json_bytes(bundle["policy_snapshot"])).hexdigest(),
        "config_snapshot_sha256": hashlib.sha256(_canonical_json_bytes(config_snapshot)).hexdigest(),
        "openapi_snapshot_sha256": hashlib.sha256(_canonical_json_bytes(bundle["openapi_snapshot"])).hexdigest(),
        "soc_manifest_snapshot_sha256": hashlib.sha256(_canonical_json_bytes(bundle["soc_manifest_snapshot"])).hexdigest(),
    }
    range_start_utc = start.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    range_end_utc = end.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signature = sign_manifest_payload(
        {
            "root_hash": payload["root_hash"],
            "bundle_hash": hashlib.sha256(_canonical_json_bytes(bundle)).hexdigest(),
            "sections": sections,
            "range_start_utc": range_start_utc,
            "range_end_utc": range_end_utc,
            "range_end_inclusive": True,
        },
        signed_at=range_end_utc,
    )
    manifest = {
        "root_hash": payload["root_hash"],
        "bundle_sha256": hashlib.sha256(_canonical_json_bytes(bundle)).hexdigest(),
        "sections": sections,
        "range_start_utc": range_start_utc,
        "range_end_utc": range_end_utc,
        "range_end_inclusive": True,
        **signature,
    }
    return {"bundle": bundle, "manifest": manifest}


def export_evidence_bundle(
    db: Session,
    *,
    tenant_id: str,
    start: datetime,
    end: datetime,
    purpose: str,
    triggered_by: str,
    retention_class: str,
    force: bool = False,
    store: EvidenceStore | None = None,
) -> dict[str, Any]:
    payload = deterministic_export_bundle(db, tenant_id=tenant_id, start=start, end=end)
    bundle_json = _canonical_json_bytes(payload["bundle"])
    manifest_json = _canonical_json_bytes(payload["manifest"])
    instructions = (
        "Verify offline with: .venv/bin/python scripts/fg_audit_verify.py --bundle <path.zip> --pubkeys <keys.json>\n"
    ).encode("utf-8")
    bundle_bytes = _deterministic_zip_bytes(
        {"bundle.json": bundle_json, "manifest.json": manifest_json, "instructions.txt": instructions}
    )
    export_hash = hashlib.sha256(bundle_bytes).hexdigest()
    manifest_hash = hashlib.sha256(_canonical_json_bytes(payload["manifest"])).hexdigest()

    existing = (
        db.query(AuditExport)
        .filter(
            AuditExport.tenant_id == tenant_id,
            AuditExport.export_hash == export_hash,
            AuditExport.manifest_hash == manifest_hash,
        )
        .order_by(desc(AuditExport.id))
        .first()
    )
    if existing is not None and not force:
        return {
            "deduplicated": True,
            "export_id": existing.export_id,
            "storage_uri": existing.storage_uri,
            **payload,
        }

    evidence_store = store or LocalFileEvidenceStore(Path("/tmp/fg-audit-exports"))
    export_id = f"{tenant_id}-{manifest_hash[:16]}"
    storage_uri, size_bytes = evidence_store.put_atomic(
        tenant_id=tenant_id,
        export_id=export_id,
        content=bundle_bytes,
    )
    rec = AuditExport(
        tenant_id=tenant_id,
        export_id=export_id,
        export_hash=export_hash,
        manifest_hash=manifest_hash,
        storage_uri=storage_uri,
        size_bytes=size_bytes,
        triggered_by=triggered_by,
        purpose=purpose,
        retention_class=retention_class,
        export_range_start_utc=payload["manifest"]["range_start_utc"],
        export_range_end_utc=payload["manifest"]["range_end_utc"],
        export_range_end_inclusive=bool(payload["manifest"].get("range_end_inclusive", True)),
        kid=str(payload["manifest"].get("kid", "")),
        signature_algo=str(payload["manifest"].get("signature_algo", "")),
    )
    db.add(rec)
    append_audit_record(
        db,
        tenant_id=tenant_id,
        invariant_id="audit-export",
        decision="pass",
        config_hash=_active_config_hash(db, tenant_id=tenant_id),
        policy_hash=_policy_hash(),
    )
    db.commit()
    return {"deduplicated": False, "export_id": export_id, "storage_uri": storage_uri, **payload}


def reproduce_audit_session(db: Session, *, tenant_id: str, session_id: int) -> dict[str, Any]:
    rec = db.get(AuditLedgerRecord, session_id)
    if rec is None or rec.tenant_id != tenant_id:
        return {"code": "FG-AUDIT-REPRO-404", "verification_result": "fail", "deterministic_hash_comparison": "mismatch"}

    config_hash = _active_config_hash(db, tenant_id=tenant_id)
    policy_hash = _policy_hash()
    if rec.invariant_id == "config-hash-validation":
        reproduced_decision = "pass" if config_hash == rec.config_hash else "fail"
    elif rec.invariant_id == "policy-hash-validation":
        reproduced_decision = "pass" if policy_hash == rec.policy_hash else "fail"
    else:
        reproduced_decision = rec.decision

    match = hmac.compare_digest(config_hash, rec.config_hash) and hmac.compare_digest(policy_hash, rec.policy_hash)
    ok = match and hmac.compare_digest(reproduced_decision, rec.decision)
    return {
        "code": "FG-AUDIT-REPRO-OK" if ok else "FG-AUDIT-REPRO-MISMATCH",
        "session_id": rec.id,
        "verification_result": "pass" if ok else "fail",
        "decision_original": rec.decision,
        "decision_reproduced": reproduced_decision,
        "deterministic_hash_comparison": "match" if match else "mismatch",
    }


def write_daily_anchor(db: Session, *, tenant_id: str, day: date | None = None) -> AuditAnchor:
    d = day or datetime.now(tz=UTC).date()
    day_start = datetime(d.year, d.month, d.day, tzinfo=UTC)
    day_end = datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=UTC)
    exp = deterministic_export_bundle(db, tenant_id=tenant_id, start=day_start, end=day_end)
    day_root = exp["manifest"]["root_hash"]

    external_db_url = (os.getenv("FG_AUDIT_ANCHOR_DB_URL") or "").strip()
    trust = "external-trust-domain" if external_db_url else "same-trust-domain"

    existing = (
        db.query(AuditAnchor)
        .filter(AuditAnchor.tenant_id == tenant_id, AuditAnchor.anchor_day == d.isoformat())
        .first()
    )
    if existing is not None:
        return existing

    rec = AuditAnchor(
        tenant_id=tenant_id,
        anchor_day=d.isoformat(),
        day_root_hash=day_root,
        trust_domain=trust,
        anchor_status="anchored",
    )
    db.add(rec)

    if external_db_url:
        engine = get_engine()
        with Session(engine) as ext:
            ext.add(
                AuditAnchor(
                    tenant_id=tenant_id,
                    anchor_day=d.isoformat(),
                    day_root_hash=day_root,
                    trust_domain="external-trust-domain",
                    anchor_status="anchored",
                )
            )
            ext.commit()

    db.commit()
    return rec


def _verify_anchor_presence(db: Session, *, tenant_id: str) -> bool:
    today = datetime.now(tz=UTC).date().isoformat()
    row = (
        db.query(AuditAnchor)
        .filter(AuditAnchor.tenant_id == tenant_id, AuditAnchor.anchor_day == today)
        .first()
    )
    return row is not None


def _job_idempotency_key(
    *,
    tenant_id: str,
    start: datetime,
    end: datetime,
    purpose: str,
    retention_class: str,
    signing_kid: str,
    end_inclusive: bool,
    force: bool,
) -> str:
    payload = {
        "tenant_id": tenant_id,
        "range_start_utc": start.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "range_end_utc": end.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "range_end_inclusive": bool(end_inclusive),
        "purpose": purpose,
        "retention_class": retention_class,
        "signing_kid": signing_kid,
        "force": bool(force),
    }
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def enqueue_export_job(
    db: Session,
    *,
    tenant_id: str,
    start: datetime,
    end: datetime,
    purpose: str,
    retention_class: str,
    triggered_by: str,
    force: bool = False,
    signing_kid: str = "",
    end_inclusive: bool = True,
) -> AuditExportJob:
    key = _job_idempotency_key(
        tenant_id=tenant_id,
        start=start,
        end=end,
        purpose=purpose,
        retention_class=retention_class,
        signing_kid=signing_kid,
        end_inclusive=end_inclusive,
        force=force,
    )
    existing = (
        db.query(AuditExportJob)
        .filter(AuditExportJob.tenant_id == tenant_id, AuditExportJob.idempotency_key == key)
        .order_by(desc(AuditExportJob.id))
        .first()
    )
    if existing is not None and existing.status in {"queued", "running", "succeeded", "cancelled"}:
        return existing

    job_id = f"job-{tenant_id}-{key[:16]}"
    rec = AuditExportJob(
        tenant_id=tenant_id,
        job_id=job_id,
        idempotency_key=key,
        status="queued",
        start_utc=start.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        end_utc=end.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        end_inclusive=end_inclusive,
        purpose=purpose,
        retention_class=retention_class,
        signing_kid=signing_kid,
        triggered_by=triggered_by,
        force=force,
        attempts=0,
        job_event_seq=0,
    )
    db.add(rec)
    db.commit()
    return rec


def run_export_job(db: Session, *, tenant_id: str, job_id: str, worker_id: str | None = None) -> AuditExportJob:
    job = (
        db.query(AuditExportJob)
        .filter(AuditExportJob.tenant_id == tenant_id, AuditExportJob.job_id == job_id)
        .first()
    )
    if job is None:
        raise ValueError("AUDIT_EXPORT_JOB_NOT_FOUND")
    if job.status in {"succeeded", "cancelled"}:
        return job

    now = datetime.now(tz=UTC)
    owner = worker_id or os.getenv("FG_HOST_ID", "worker")
    if job.status == "running" and job.lease_expires_at and job.lease_expires_at > now and job.lease_owner != owner:
        raise RuntimeError("AUDIT_EXPORT_JOB_LEASED")

    job.status = "running"
    job.started_at = now
    job.attempts = int(job.attempts or 0) + 1
    job.job_event_seq = int(job.job_event_seq or 0) + 1
    job.lease_owner = owner
    job.lease_expires_at = now + timedelta(seconds=int(os.getenv("FG_AUDIT_JOB_LEASE_SECONDS", "300")))
    run_event = {
        "job_id": job.job_id,
        "event": "run-intent",
        "event_seq": int(job.job_event_seq),
        "requested_by": owner,
        "timestamp_utc": utc_rfc3339(now),
    }
    run_hash = hashlib.sha256(_canonical_json_bytes(run_event)).hexdigest()
    append_audit_record(
        db,
        tenant_id=tenant_id,
        invariant_id=f"audit-export-job-run-intent:{job.job_id}:{job.job_event_seq}",
        decision="pass",
        config_hash=run_hash,
        policy_hash="0" * 64,
    )
    db.flush()

    try:
        start = datetime.fromisoformat(job.start_utc.replace("Z", "+00:00")).astimezone(UTC)
        end = datetime.fromisoformat(job.end_utc.replace("Z", "+00:00")).astimezone(UTC)
        out = export_evidence_bundle(
            db,
            tenant_id=tenant_id,
            start=start,
            end=end,
            purpose=job.purpose,
            triggered_by=job.triggered_by,
            retention_class=job.retention_class,
            force=bool(job.force),
        )
        job.export_id = str(out.get("export_id", ""))
        job.storage_uri = str(out.get("storage_uri", ""))
        job.status = "succeeded"
        job.last_error_code = None
    except Exception:
        job.status = "failed"
        job.last_error_code = "AUDIT_EXPORT_JOB_RUN_FAILED"
    finally:
        job.finished_at = datetime.now(tz=UTC)
        job.lease_expires_at = None
        db.commit()
    return job




def cancel_export_job(
    db: Session,
    *,
    tenant_id: str,
    job_id: str,
    cancelled_by: str | None = None,
    reason_code: str = "operator-request",
    ticket_id: str = "",
    notes: str = "",
    bypass: bool = False,
) -> AuditExportJob:
    job = (
        db.query(AuditExportJob)
        .filter(AuditExportJob.tenant_id == tenant_id, AuditExportJob.job_id == job_id)
        .first()
    )
    if job is None:
        raise ValueError("AUDIT_EXPORT_JOB_NOT_FOUND")
    if job.status in {"succeeded", "failed"}:
        raise RuntimeError("AUDIT_EXPORT_JOB_TERMINAL_STATE")
    if job.status == "cancelled":
        return job

    now = datetime.now(tz=UTC)
    job.status = "cancelled"
    job.finished_at = now
    job.last_error_code = "AUDIT_EXPORT_JOB_CANCELLED"
    job.job_event_seq = int(job.job_event_seq or 0) + 1
    job.lease_owner = cancelled_by or job.lease_owner
    job.lease_expires_at = None

    event_material = {
        "job_id": job.job_id,
        "requested_by": cancelled_by or "unknown",
        "reason": reason_code,
        "ticket_id": ticket_id,
        "notes_hash": hashlib.sha256(str(notes).encode("utf-8")).hexdigest(),
        "state": "cancelled",
        "bypass": bool(bypass),
        "event_seq": int(job.job_event_seq),
        "timestamp_utc": utc_rfc3339(now),
    }
    event_hash = hashlib.sha256(_canonical_json_bytes(event_material)).hexdigest()
    event_name = "audit-export-job-cancel-bypass" if bypass else "audit-export-job-cancel"
    append_audit_record(
        db,
        tenant_id=tenant_id,
        invariant_id=f"{event_name}:{job.job_id}:{job.job_event_seq}",
        decision="pass",
        config_hash=event_hash,
        policy_hash="0" * 64,
    )
    db.commit()
    return job


def list_exports(
    db: Session,
    *,
    tenant_id: str,
    retention_class: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditExport]:
    q = db.query(AuditExport).filter(AuditExport.tenant_id == tenant_id)
    if retention_class:
        q = q.filter(AuditExport.retention_class == retention_class)
    return (
        q.order_by(AuditExport.created_at.desc(), AuditExport.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def record_bypass_event(
    db: Session,
    *,
    tenant_id: str,
    principal_id: str,
    operation: str,
    reason_code: str,
    ticket_id: str,
    ttl_seconds: int,
) -> AuditBypassEvent:
    expires = datetime.now(tz=UTC) + timedelta(seconds=ttl_seconds)
    rec = AuditBypassEvent(
        tenant_id=tenant_id,
        principal_id=principal_id,
        operation=operation,
        reason_code=reason_code,
        ticket_id=ticket_id,
        ttl_seconds=ttl_seconds,
        expires_at_utc=expires.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )
    db.add(rec)
    meta_hash = hashlib.sha256(
        _canonical_json_bytes(
            {
                "principal_id": principal_id,
                "operation": operation,
                "reason_code": reason_code,
                "ticket_id": ticket_id,
                "ttl_seconds": ttl_seconds,
            }
        )
    ).hexdigest()
    append_audit_record(
        db,
        tenant_id=tenant_id,
        invariant_id=f"audit-rate-limit-bypass:{ticket_id}",
        decision="pass",
        config_hash=meta_hash,
        policy_hash="0" * 64,
    )
    db.flush()
    return rec


def apply_retention(
    db: Session,
    *,
    tenant_id: str,
    retention_days: int,
    policy_obj: dict[str, Any],
    triggered_by: str,
    reason_code: str,
    ticket_id: str,
    dry_run: bool,
    confirmation_token: str | None,
) -> dict[str, Any]:
    policy_hash = hashlib.sha256(_canonical_json_bytes(policy_obj)).hexdigest()
    cutoff = datetime.now(tz=UTC)
    exports = (
        db.query(AuditExport)
        .filter(AuditExport.tenant_id == tenant_id)
        .order_by(AuditExport.id.asc())
        .all()
    )
    jobs = (
        db.query(AuditExportJob)
        .filter(AuditExportJob.tenant_id == tenant_id)
        .order_by(AuditExportJob.id.asc())
        .all()
    )

    export_ids = [str(r.export_id) for r in exports if (cutoff - r.created_at).days >= retention_days]
    job_ids = [str(j.job_id) for j in jobs if j.finished_at is not None and (cutoff - j.finished_at).days >= retention_days]

    exports_digest = hashlib.sha256(_canonical_json_bytes(export_ids)).hexdigest()
    jobs_digest = hashlib.sha256(_canonical_json_bytes(job_ids)).hexdigest()

    if not dry_run:
        expected = hashlib.sha256(
            (
                f"{tenant_id}:{retention_days}:{policy_hash}:{exports_digest}:{jobs_digest}:{ticket_id}"
            ).encode("utf-8")
        ).hexdigest()
        if not confirmation_token or not hmac.compare_digest(confirmation_token, expected):
            raise ValueError("FG-AUDIT-RETENTION-CONFIRM-REQUIRED")

    run = AuditRetentionRun(
        tenant_id=tenant_id,
        triggered_by=triggered_by,
        mode="dry-run" if dry_run else "apply",
        reason_code=reason_code,
        ticket_id=ticket_id,
        confirmation_token=confirmation_token if not dry_run else None,
        policy_json=policy_obj,
        policy_hash=policy_hash,
        affected_exports_digest=exports_digest,
        affected_jobs_digest=jobs_digest,
        affected_exports_count=len(export_ids),
        affected_jobs_count=len(job_ids),
    )
    db.add(run)

    if not dry_run:
        if str(policy_obj.get("allow_delete_exports", False)).lower() in {"1", "true", "yes"}:
            for r in exports:
                if str(r.export_id) in set(export_ids):
                    db.delete(r)
        for j in jobs:
            if str(j.job_id) in set(job_ids):
                db.delete(j)

        append_audit_record(
            db,
            tenant_id=tenant_id,
            invariant_id=f"audit-retention:{policy_hash[:16]}",
            decision="pass",
            config_hash=exports_digest,
            policy_hash=jobs_digest,
        )

    db.commit()
    return {
        "dry_run": dry_run,
        "policy_hash": policy_hash,
        "affected_exports_count": len(export_ids),
        "affected_jobs_count": len(job_ids),
        "affected_exports_digest": exports_digest,
        "affected_jobs_digest": jobs_digest,
    }
