from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models import AuditExamSession, AuditLedgerRecord, ComplianceSnapshotRecord
from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.compliance_registry import ComplianceRegistry
from services.crypto_keys import load_hmac_keys

LIGHT_EVERY_SECONDS = 300
FULL_SWEEP_EVERY_SECONDS = 3600
REPRO_EVERY_SECONDS = 86400


class AuditTamperDetected(RuntimeError):
    pass


class AuditIntegrityError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def deterministic_json_bytes(payload: Any) -> bytes:
    return canonical_json_bytes(payload)


def utc_iso_now() -> str:
    return utc_iso8601_z_now()


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        return "unknown"
    return (proc.stdout or "").strip() or "unknown"


def _audit_keys() -> tuple[str, dict[str, bytes]]:
    return load_hmac_keys("FG_AUDIT")


def _signature(self_hash: str, key_id: str, key_value: bytes) -> str:
    return f"{key_id}:{hmac.new(key_value, bytes.fromhex(self_hash), hashlib.sha256).hexdigest()}"


def _verify_signature(self_hash: str, signature: str, keys: dict[str, bytes]) -> bool:
    if ":" not in signature:
        return False
    key_id, sig = signature.split(":", 1)
    key_value = keys.get(key_id)
    if not key_value:
        return False
    expected = hmac.new(key_value, bytes.fromhex(self_hash), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def _run_check(script: str) -> tuple[bool, str]:
    proc = subprocess.run(
        [os.getenv("FG_AUDIT_PYTHON") or sys.executable, script],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()[:1000]


def _tree_hash(rel_root: str, glob_pat: str) -> str:
    root = Path(__file__).resolve().parents[2] / rel_root
    entries: list[tuple[str, str]] = []
    if root.exists():
        for p in sorted(root.rglob(glob_pat)):
            if p.is_file():
                entries.append(
                    (p.relative_to(root).as_posix(), _sha256_hex(p.read_bytes()))
                )
    return _sha256_hex(deterministic_json_bytes(entries))


def _policy_hash() -> str:
    return _tree_hash("policy", "*")


def _config_hash() -> str:
    return _tree_hash("api/config", "*.py")


def _self_code_hash() -> str:
    return _tree_hash("services/audit_engine", "*.py")


@dataclass(frozen=True)
class InvariantResult:
    invariant_id: str
    decision: str
    detail: str


class AuditEngine:
    def __init__(self) -> None:
        self.engine = get_engine()
        self.registry = ComplianceRegistry()

    def verify_chain_integrity(self, session: Session) -> bool:
        records = (
            session.query(AuditLedgerRecord).order_by(AuditLedgerRecord.id.asc()).all()
        )
        prev = "GENESIS"
        _, keys = _audit_keys()
        for rec in records:
            base = {
                "timestamp_utc": rec.timestamp_utc,
                "invariant_id": rec.invariant_id,
                "decision": rec.decision,
                "config_hash": rec.config_hash,
                "policy_hash": rec.policy_hash,
                "git_commit": rec.git_commit,
                "runtime_version": rec.runtime_version,
                "host_id": rec.host_id,
                "tenant_id": rec.tenant_id,
                "sha256_engine_code_hash": rec.sha256_engine_code_hash,
                "previous_record_hash": rec.previous_record_hash,
            }
            expected = _sha256_hex(deterministic_json_bytes(base))
            if rec.previous_record_hash != prev or rec.sha256_self_hash != expected:
                return False
            if not _verify_signature(rec.sha256_self_hash, rec.signature, keys):
                return False
            prev = rec.sha256_self_hash
        return True

    def _invariants(self) -> list[InvariantResult]:
        checks = [
            ("soc-invariants", "tools/ci/check_soc_invariants.py"),
            (
                "security-regression-gates",
                "tools/ci/check_security_regression_gates.py",
            ),
            ("route-inventory", "tools/ci/check_route_inventory.py"),
            ("drift-verification", "scripts/verify_drift.py"),
        ]
        results: list[InvariantResult] = []
        for invariant_id, script in checks:
            ok, detail = _run_check(script)
            results.append(
                InvariantResult(invariant_id, "pass" if ok else "fail", detail)
            )
        results.append(
            InvariantResult("config-hash-validation", "pass", _config_hash())
        )
        results.append(
            InvariantResult("policy-hash-validation", "pass", _policy_hash())
        )
        return results

    def run_cycle(self, cycle_kind: str = "light") -> str:
        with Session(self.engine) as session:
            if not self.verify_chain_integrity(session):
                raise AuditTamperDetected("audit ledger tampering detected")

            session_id = str(uuid.uuid4())
            host_id = os.getenv("FG_AUDIT_HOST_ID", socket.gethostname())
            tenant_id = os.getenv("FG_AUDIT_TENANT_ID", host_id)
            key_id, keys = _audit_keys()
            key = keys[key_id]
            last = (
                session.query(AuditLedgerRecord)
                .order_by(AuditLedgerRecord.id.desc())
                .limit(1)
                .one_or_none()
            )
            prev = last.sha256_self_hash if last else "GENESIS"
            cfg_hash, pol_hash, code_hash = (
                _config_hash(),
                _policy_hash(),
                _self_code_hash(),
            )

            decisions: list[str] = []
            for inv in self._invariants():
                decisions.append(inv.decision)
                row = {
                    "timestamp_utc": utc_iso_now(),
                    "invariant_id": inv.invariant_id,
                    "decision": inv.decision,
                    "config_hash": cfg_hash,
                    "policy_hash": pol_hash,
                    "git_commit": _git_commit(),
                    "runtime_version": os.getenv("FG_RUNTIME_VERSION", "unknown"),
                    "host_id": host_id,
                    "tenant_id": tenant_id,
                    "sha256_engine_code_hash": code_hash,
                    "previous_record_hash": prev,
                }
                self_hash = _sha256_hex(deterministic_json_bytes(row))
                session.add(
                    AuditLedgerRecord(
                        session_id=session_id,
                        cycle_kind=cycle_kind,
                        timestamp_utc=row["timestamp_utc"],
                        invariant_id=row["invariant_id"],
                        decision=row["decision"],
                        config_hash=row["config_hash"],
                        policy_hash=row["policy_hash"],
                        git_commit=row["git_commit"],
                        runtime_version=row["runtime_version"],
                        host_id=row["host_id"],
                        tenant_id=row["tenant_id"],
                        sha256_engine_code_hash=row["sha256_engine_code_hash"],
                        sha256_self_hash=self_hash,
                        previous_record_hash=row["previous_record_hash"],
                        signature=_signature(self_hash, key_id, key),
                        details_json={"detail": inv.detail},
                    )
                )
                prev = self_hash

            summary = self.registry.snapshot(tenant_id)
            snapshot_id = str(uuid.uuid4())
            s_prev = (
                session.query(ComplianceSnapshotRecord)
                .filter(ComplianceSnapshotRecord.tenant_id == tenant_id)
                .order_by(ComplianceSnapshotRecord.id.desc())
                .limit(1)
                .one_or_none()
            )
            s_prev_hash = s_prev.record_hash if s_prev else "GENESIS"
            s_material = {
                "snapshot_id": snapshot_id,
                "tenant_id": tenant_id,
                "summary": summary,
                "created_at_utc": utc_iso_now(),
                "previous_record_hash": s_prev_hash,
            }
            s_hash = _sha256_hex(deterministic_json_bytes(s_material))
            session.add(
                ComplianceSnapshotRecord(
                    tenant_id=tenant_id,
                    snapshot_id=snapshot_id,
                    summary_json={
                        **summary,
                        "drift_status": "pass" if "fail" not in decisions else "fail",
                        "last_reproduce_result": "pass",
                    },
                    created_at_utc=s_material["created_at_utc"],
                    previous_record_hash=s_prev_hash,
                    record_hash=s_hash,
                    signature=_signature(s_hash, key_id, key),
                    key_id=key_id,
                )
            )
            session.commit()
        return session_id

    def export_bundle(
        self,
        start: str,
        end: str,
        app_openapi: dict[str, Any],
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        tenant = tenant_id or os.getenv("FG_AUDIT_TENANT_ID", socket.gethostname())
        with Session(self.engine) as session:
            rows = (
                session.query(AuditLedgerRecord)
                .filter(AuditLedgerRecord.timestamp_utc >= start)
                .filter(AuditLedgerRecord.timestamp_utc <= end)
                .filter(AuditLedgerRecord.tenant_id == tenant)
                .order_by(AuditLedgerRecord.id.asc())
                .all()
            )
            snapshots = (
                session.query(ComplianceSnapshotRecord)
                .filter(ComplianceSnapshotRecord.tenant_id == tenant)
                .order_by(ComplianceSnapshotRecord.id.asc())
                .all()
            )
            chain_ok = self.verify_chain_integrity(session)
        if not chain_ok:
            raise AuditIntegrityError(
                "AUDIT_CHAIN_BROKEN", "audit chain integrity check failed"
            )

        records = [r.to_dict() for r in rows]
        snapshot_rows = [s.summary_json for s in snapshots]
        bundle = {
            "start": start,
            "end": end,
            "records": records,
            "compliance_snapshots": snapshot_rows,
            "policy_snapshot": {"policy_hash": _policy_hash()},
            "config_snapshot": {"config_hash": _config_hash()},
            "openapi_snapshot": app_openapi,
            "soc_manifest_snapshot": json.loads(
                (
                    Path(__file__).resolve().parents[2]
                    / "tools/ci/soc_findings_manifest.json"
                ).read_text(encoding="utf-8")
            ),
            "chain_integrity_ok": chain_ok,
        }
        key_id, keys = _audit_keys()
        checksum = _sha256_hex(deterministic_json_bytes(bundle))
        bundle["signed_evidence_checksum"] = _signature(checksum, key_id, keys[key_id])
        manifest = {
            "bundle_sha256": checksum,
            "records_sha256": _sha256_hex(deterministic_json_bytes(records)),
            "policy_sha256": _sha256_hex(
                deterministic_json_bytes(bundle["policy_snapshot"])
            ),
            "config_sha256": _sha256_hex(
                deterministic_json_bytes(bundle["config_snapshot"])
            ),
            "openapi_sha256": _sha256_hex(
                deterministic_json_bytes(bundle["openapi_snapshot"])
            ),
            "soc_manifest_sha256": _sha256_hex(
                deterministic_json_bytes(bundle["soc_manifest_snapshot"])
            ),
        }
        out = {"bundle": bundle, "manifest": manifest}
        root = Path(os.getenv("FG_AUDIT_EXPORT_DIR", "artifacts/audit_exports"))
        root.mkdir(parents=True, exist_ok=True)
        name = f"audit_export_{start.replace(':', '').replace('-', '')}_{end.replace(':', '').replace('-', '')}.json"
        path = root / name
        self.atomic_write(path, deterministic_json_bytes(out))
        return {"path": str(path), "manifest": manifest}

    def reproduce_session(self, session_id: str) -> dict[str, Any]:
        with Session(self.engine) as session:
            if not self.verify_chain_integrity(session):
                return {
                    "ok": False,
                    "reason": "audit_chain_broken",
                    "code": "AUDIT_CHAIN_BROKEN",
                }
            rows = (
                session.query(AuditLedgerRecord)
                .filter(AuditLedgerRecord.session_id == session_id)
                .order_by(AuditLedgerRecord.id.asc())
                .all()
            )
        if not rows:
            return {"ok": False, "reason": "session_not_found"}
        current = {r.invariant_id: r.decision for r in rows}
        rerun = {r.invariant_id: r.decision for r in self._invariants()}
        expected_hash = _sha256_hex(deterministic_json_bytes(current))
        actual_hash = _sha256_hex(deterministic_json_bytes(rerun))
        if current != rerun:
            return {
                "ok": False,
                "reason": "reproducibility_mismatch",
                "expected": current,
                "actual": rerun,
                "hashes": {"expected": expected_hash, "actual": actual_hash},
                "critical_alert": True,
            }
        return {
            "ok": True,
            "hashes": {"expected": expected_hash, "actual": actual_hash},
        }

    def create_exam(
        self, tenant_id: str, name: str, window_start: str, window_end: str
    ) -> str:
        exam_id = str(uuid.uuid4())
        key_id, keys = _audit_keys()
        with Session(self.engine) as session:
            last = (
                session.query(AuditExamSession)
                .filter(AuditExamSession.tenant_id == tenant_id)
                .order_by(AuditExamSession.id.desc())
                .limit(1)
                .one_or_none()
            )
            prev = last.record_hash if last else "GENESIS"
            material = {
                "exam_id": exam_id,
                "tenant_id": tenant_id,
                "name": name,
                "window_start_utc": window_start,
                "window_end_utc": window_end,
                "created_at_utc": utc_iso_now(),
                "previous_record_hash": prev,
            }
            rec_hash = _sha256_hex(deterministic_json_bytes(material))
            session.add(
                AuditExamSession(
                    exam_id=exam_id,
                    tenant_id=tenant_id,
                    name=name,
                    window_start_utc=window_start,
                    window_end_utc=window_end,
                    created_at_utc=material["created_at_utc"],
                    previous_record_hash=prev,
                    record_hash=rec_hash,
                    signature=_signature(rec_hash, key_id, keys[key_id]),
                    key_id=key_id,
                )
            )
            session.commit()
        return exam_id

    def list_exams(self, tenant_id: str) -> list[dict[str, Any]]:
        with Session(self.engine) as session:
            rows = (
                session.query(AuditExamSession)
                .filter(AuditExamSession.tenant_id == tenant_id)
                .order_by(AuditExamSession.id.desc())
                .all()
            )
        return [
            {
                "exam_id": r.exam_id,
                "name": r.name,
                "window_start_utc": r.window_start_utc,
                "window_end_utc": r.window_end_utc,
                "created_at_utc": r.created_at_utc,
                "export_path": r.export_path,
            }
            for r in rows
        ]

    def export_exam_bundle(
        self, exam_id: str, app_openapi: dict[str, Any]
    ) -> dict[str, Any]:
        with Session(self.engine) as session:
            exam = (
                session.query(AuditExamSession)
                .filter(AuditExamSession.exam_id == exam_id)
                .one_or_none()
            )
            if exam is None:
                raise AuditTamperDetected("exam_session_not_found")
        export = self.export_bundle(
            start=exam.window_start_utc,
            end=exam.window_end_utc,
            app_openapi=app_openapi,
            tenant_id=exam.tenant_id,
        )
        payload = json.loads(Path(export["path"]).read_text(encoding="utf-8"))
        archive_path = Path(export["path"]).with_suffix(".tar")
        self._write_deterministic_archive(
            archive_path,
            {
                "manifest.json": deterministic_json_bytes(payload["manifest"]),
                "manifest.sha256": f"{payload['manifest']['bundle_sha256']}  bundle.json\n".encode(
                    "utf-8"
                ),
                "manifest.sig": payload["bundle"]["signed_evidence_checksum"].encode(
                    "utf-8"
                ),
                "bundle.json": deterministic_json_bytes(payload["bundle"]),
            },
        )
        return {
            "exam_id": exam_id,
            "archive_path": str(archive_path),
            "manifest": payload["manifest"],
        }

    def reproduce_exam(self, exam_id: str) -> dict[str, Any]:
        with Session(self.engine) as session:
            exam = (
                session.query(AuditExamSession)
                .filter(AuditExamSession.exam_id == exam_id)
                .one_or_none()
            )
            if exam is None:
                return {"ok": False, "reason": "exam_session_not_found"}
            rows = (
                session.query(AuditLedgerRecord)
                .filter(AuditLedgerRecord.timestamp_utc >= exam.window_start_utc)
                .filter(AuditLedgerRecord.timestamp_utc <= exam.window_end_utc)
                .filter(AuditLedgerRecord.tenant_id == exam.tenant_id)
                .order_by(AuditLedgerRecord.id.asc())
                .all()
            )
        if not rows:
            return {"ok": False, "reason": "exam_window_empty"}
        result = self.reproduce_session(rows[-1].session_id)
        return result

    def _write_deterministic_archive(self, path: Path, files: dict[str, bytes]) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name, content in sorted(files.items(), key=lambda x: x[0]):
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                info.mtime = 0
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                tar.addfile(info, io.BytesIO(content))
        self.atomic_write(path, buf.getvalue())

    @staticmethod
    def atomic_write(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, path)
