from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.db import init_db, reset_engine_cache
from services.compliance_registry import (
    ComplianceRegistry,
    FindingCreateItem,
    RequirementImportItem,
    RequirementPackageMeta,
)


@pytest.fixture
def registry(tmp_path, monkeypatch) -> ComplianceRegistry:
    db_path = tmp_path / "compliance.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_COMPLIANCE_HMAC_KEY_CURRENT", "cmp-key-cmp-key-cmp-key-cmp-key-0")
    monkeypatch.setenv("FG_COMPLIANCE_HMAC_KEY_ID_CURRENT", "ck1")
    monkeypatch.setenv("FG_CRITICAL_UNKNOWN_THRESHOLD", "0")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return ComplianceRegistry()


def _pkg() -> RequirementPackageMeta:
    return RequirementPackageMeta(
        source_name="fg-curated-feed",
        source_version="2026.02",
        published_at_utc="2026-02-01T00:00:00Z",
        retrieved_at_utc="2026-02-02T00:00:00Z",
        bundle_sha256="a" * 64,
    )


def test_requirement_append_only_and_chain(registry: ComplianceRegistry) -> None:
    registry.import_requirements(
        "tenant-a",
        [
            RequirementImportItem(
                req_id="FG-BANK-AC-001",
                source="INTERNAL",
                source_ref="A1",
                title="Title",
                description="desc",
                severity="critical",
                effective_date_utc="2026-01-01T00:00:00Z",
                version="1.0",
                status="active",
                evidence_type="automated",
                owner="team",
                tags=["bank"],
            )
        ],
        actor="tester",
        package=_pkg(),
    )
    with Session(registry.engine) as session:
        with pytest.raises(SQLAlchemyError):
            session.execute(text("UPDATE compliance_requirements SET title='x' WHERE id=1"))
            session.commit()


def test_findings_and_waiver_expiry_and_threshold(registry: ComplianceRegistry) -> None:
    registry.import_requirements(
        "tenant-a",
        [
            RequirementImportItem(
                req_id="FG-BANK-AC-002",
                source="INTERNAL",
                source_ref="A2",
                title="Title2",
                description="desc",
                severity="critical",
                effective_date_utc="2026-01-01T00:00:00Z",
                version="1.0",
                status="active",
                evidence_type="manual",
                owner="team",
                tags=[],
            )
        ],
        actor="tester",
        package=_pkg(),
    )
    registry.add_findings(
        "tenant-a",
        [
            FindingCreateItem(
                finding_id="FG-FIND-2026-0001",
                req_ids=["FG-BANK-AC-002"],
                title="Gap",
                details="details",
                severity="critical",
                status="waived",
                waiver={"approved_by": "risk", "expires_utc": "2020-01-01T00:00:00Z"},
                detected_at_utc="2026-01-01T00:00:00Z",
                evidence_refs=[],
            )
        ],
    )
    snap = registry.snapshot("tenant-a")
    assert snap["expired_waiver_count"] == 1
    assert snap["expired_waivers"] == ["FG-FIND-2026-0001"]
    assert snap["unknown_critical_threshold_exceeded"] is False


def test_update_available_recorded(registry: ComplianceRegistry) -> None:
    update_id = registry.record_update_available(
        "tenant-a",
        _pkg(),
        {"added": ["FG-BANK-AC-010"], "removed": []},
    )
    updates = registry.list_updates("tenant-a")
    assert updates[0]["update_id"] == update_id
    assert updates[0]["status"] == "available"


def test_tenant_isolation_in_registry_queries(registry: ComplianceRegistry) -> None:
    registry.import_requirements(
        "tenant-a",
        [
            RequirementImportItem(
                req_id="FG-BANK-AC-003",
                source="INTERNAL",
                source_ref="A3",
                title="A",
                description="A",
                severity="low",
                effective_date_utc="2026-01-01T00:00:00Z",
                version="1",
                status="active",
                evidence_type="manual",
                owner="team",
                tags=[],
            )
        ],
        actor="tester",
        package=_pkg(),
    )
    registry.import_requirements(
        "tenant-b",
        [
            RequirementImportItem(
                req_id="FG-BANK-AC-004",
                source="INTERNAL",
                source_ref="A4",
                title="B",
                description="B",
                severity="low",
                effective_date_utc="2026-01-01T00:00:00Z",
                version="1",
                status="active",
                evidence_type="manual",
                owner="team",
                tags=[],
            )
        ],
        actor="tester",
        package=_pkg(),
    )

    a = registry.requirements_diff("tenant-a", "1970-01-01T00:00:00Z")
    b = registry.requirements_diff("tenant-b", "1970-01-01T00:00:00Z")
    assert {x["req_id"] for x in a} == {"FG-BANK-AC-003"}
    assert {x["req_id"] for x in b} == {"FG-BANK-AC-004"}


def test_update_available_then_applied_record(registry: ComplianceRegistry) -> None:
    update_id = registry.record_update_available("tenant-a", _pkg(), {"added": ["FG-BANK-AC-011"]})
    registry.import_requirements(
        "tenant-a",
        [
            RequirementImportItem(
                req_id="FG-BANK-AC-011",
                source="INTERNAL",
                source_ref="A11",
                title="Req11",
                description="desc",
                severity="low",
                effective_date_utc="2026-01-01T00:00:00Z",
                version="1.0",
                status="active",
                evidence_type="automated",
                owner="team",
                tags=[],
            )
        ],
        actor="tester",
        package=_pkg(),
        update_id=update_id,
    )
    statuses = [u["status"] for u in registry.list_updates("tenant-a")]
    assert "available" in statuses and "applied" in statuses
