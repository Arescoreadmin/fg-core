"""tools/testing/production/evidence.py — PROD-AUTH-AUTOMATION-001 evidence schema.

Machine-readable evidence records for production authentication verification.
PASS / FAIL / NOT_PROVEN classification. Fingerprinted with SHA-256.

Never write tokens, cookies, passwords, or authorization headers into evidence.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


SCHEMA_VERSION = "prod-auth-automation-001/v1"
WORK_ITEM = "PROD-AUTH-AUTOMATION-001"


class EvidenceResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_PROVEN = "NOT_PROVEN"


@dataclass
class CheckResult:
    id: str
    description: str
    expected: str
    observed: str
    result: EvidenceResult
    timestamp: str
    diagnostic: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "description": self.description,
            "expected": self.expected,
            "observed": self.observed,
            "result": self.result.value,
            "timestamp": self.timestamp,
        }
        if self.diagnostic:
            d["diagnostic"] = self.diagnostic
        return d


@dataclass
class EvidenceRecord:
    schema_version: str = SCHEMA_VERSION
    work_item: str = WORK_ITEM
    timestamp: str = ""
    run_id: str = ""
    repo_sha: str = "UNKNOWN"
    deployed_sha: str = "NOT_PROVEN"
    deployment_id: str = "NOT_PROVEN"
    verification_environment: str = "public_smoke"
    test_identity_ref: str = "NOT_APPLICABLE"
    checks: list[CheckResult] = field(default_factory=list)
    unverified_production_checks: list[str] = field(default_factory=list)
    overall_result: EvidenceResult = EvidenceResult.NOT_PROVEN
    evidence_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "work_item": self.work_item,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "repo_sha": self.repo_sha,
            "deployed_sha": self.deployed_sha,
            "deployment_id": self.deployment_id,
            "verification_environment": self.verification_environment,
            "test_identity_ref": self.test_identity_ref,
            "checks": [c.to_dict() for c in self.checks],
            "unverified_production_checks": self.unverified_production_checks,
            "overall_result": self.overall_result.value,
            "evidence_fingerprint": self.evidence_fingerprint,
        }


def _canonical_json(obj: Any) -> bytes:
    def _norm(v: Any) -> Any:
        if isinstance(v, dict):
            return {str(k): _norm(val) for k, val in sorted(v.items())}
        if isinstance(v, (list, tuple)):
            return [_norm(i) for i in v]
        if v is None or isinstance(v, (str, int, float, bool)):
            return v
        return str(v)

    return json.dumps(
        _norm(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def fingerprint(record: EvidenceRecord) -> str:
    """SHA-256 fingerprint of the evidence record (excluding the fingerprint field)."""
    d = record.to_dict()
    d["evidence_fingerprint"] = ""
    return "sha256:" + hashlib.sha256(_canonical_json(d)).hexdigest()


def finalize(record: EvidenceRecord) -> EvidenceRecord:
    """Compute overall_result and evidence_fingerprint. Mutates in place."""
    results = [c.result for c in record.checks]
    if any(r == EvidenceResult.FAIL for r in results):
        record.overall_result = EvidenceResult.FAIL
    elif all(r == EvidenceResult.PASS for r in results) and results:
        record.overall_result = EvidenceResult.PASS
    else:
        record.overall_result = EvidenceResult.NOT_PROVEN
    record.evidence_fingerprint = fingerprint(record)
    return record


def write_evidence(record: EvidenceRecord, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(record.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def repo_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "UNKNOWN"
