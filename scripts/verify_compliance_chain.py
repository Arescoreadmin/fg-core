#!/usr/bin/env python3
from __future__ import annotations

# ruff: noqa: E402

import hashlib
import hmac
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy.orm import Session

from api.db import init_db, reset_engine_cache
from api.db_models import ComplianceFindingRecord, ComplianceRequirementRecord
from services.compliance_registry import (
    ComplianceRegistry,
    FindingCreateItem,
    RequirementImportItem,
    RequirementPackageMeta,
)
from services.canonical import canonical_json_bytes


def _sha(payload: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _verify_sig(record_hash: str, signature: str, key: str) -> bool:
    if ":" not in signature:
        return False
    _, sig = signature.split(":", 1)
    exp = hmac.new(
        key.encode("utf-8"), bytes.fromhex(record_hash), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(exp, sig)


def main() -> int:
    db_path = Path("/tmp/fg-compliance-chain-check.db")
    db_path.unlink(missing_ok=True)
    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_COMPLIANCE_HMAC_KEY_CURRENT"] = (
        "test-compliance-key-test-compliance-key-0000"
    )
    os.environ["FG_COMPLIANCE_HMAC_KEY_ID_CURRENT"] = "k1"
    reset_engine_cache()
    init_db()

    reg = ComplianceRegistry()
    package = RequirementPackageMeta(
        source_name="fg-curated-feed",
        source_version="2026.02",
        published_at_utc="2026-02-01T00:00:00Z",
        retrieved_at_utc="2026-02-02T00:00:00Z",
        bundle_sha256="a" * 64,
    )
    reg.import_requirements(
        "tenant-a",
        [
            RequirementImportItem(
                req_id="FG-BANK-AC-001",
                source="INTERNAL",
                source_ref="CTRL-1",
                title="Access",
                description="desc",
                severity="critical",
                effective_date_utc="2026-01-01T00:00:00Z",
                version="1.0.0",
                status="active",
                evidence_type="automated",
                owner="secops",
                tags=["bank"],
            )
        ],
        actor="ci",
        package=package,
    )
    reg.add_findings(
        "tenant-a",
        [
            FindingCreateItem(
                finding_id="FG-FIND-2026-0001",
                req_ids=["FG-BANK-AC-001"],
                title="gap",
                details="details",
                severity="critical",
                status="waived",
                waiver={"approved_by": "risk", "expires_utc": "2020-01-01T00:00:00Z"},
                detected_at_utc="2026-01-02T00:00:00Z",
                evidence_refs=[],
            )
        ],
    )

    with Session(reg.engine) as session:
        req_rows = (
            session.query(ComplianceRequirementRecord)
            .order_by(ComplianceRequirementRecord.id.asc())
            .all()
        )
        prev = "GENESIS"
        for row in req_rows:
            material = {
                "req_id": row.req_id,
                "source": row.source,
                "source_ref": row.source_ref,
                "title": row.title,
                "description": row.description,
                "severity": row.severity,
                "effective_date_utc": row.effective_date_utc,
                "version": row.version,
                "status": row.status,
                "evidence_type": row.evidence_type,
                "owner": row.owner,
                "source_name": row.source_name,
                "source_version": row.source_version,
                "published_at_utc": row.published_at_utc,
                "retrieved_at_utc": row.retrieved_at_utc,
                "bundle_sha256": row.bundle_sha256,
                "tags": row.tags_json,
                "created_at_utc": row.created_at_utc,
                "previous_record_hash": row.previous_record_hash,
                "tenant_id": row.tenant_id,
                "actor": "ci",
            }
            if row.previous_record_hash != prev or row.record_hash != _sha(material):
                raise SystemExit("requirement chain broken")
            if not _verify_sig(
                row.record_hash,
                row.signature,
                "test-compliance-key-test-compliance-key-0000",
            ):
                raise SystemExit("requirement signature invalid")
            prev = row.record_hash

        find_rows = (
            session.query(ComplianceFindingRecord)
            .order_by(ComplianceFindingRecord.id.asc())
            .all()
        )
        prev = "GENESIS"
        for row in find_rows:
            material = {
                "finding_id": row.finding_id,
                "req_ids": row.req_ids_json,
                "title": row.title,
                "details": row.details,
                "severity": row.severity,
                "status": row.status,
                "waiver": row.waiver_json,
                "detected_at_utc": row.detected_at_utc,
                "evidence_refs": row.evidence_refs_json,
                "created_at_utc": row.created_at_utc,
                "previous_record_hash": row.previous_record_hash,
                "tenant_id": row.tenant_id,
            }
            if row.previous_record_hash != prev or row.record_hash != _sha(material):
                raise SystemExit("finding chain broken")
            if not _verify_sig(
                row.record_hash,
                row.signature,
                "test-compliance-key-test-compliance-key-0000",
            ):
                raise SystemExit("finding signature invalid")
            prev = row.record_hash

    snap = reg.snapshot("tenant-a")
    if not snap["expired_waivers"]:
        raise SystemExit("expired waivers must fail")
    if bool(snap.get("unknown_critical_threshold_exceeded")):
        raise SystemExit("critical requirements unknown coverage exceeds threshold")

    print("compliance chain verification gate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
