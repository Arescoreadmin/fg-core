from __future__ import annotations

import pytest
from sqlalchemy import text

from api.db import get_sessionmaker, init_db
from services.evidence_index.storage import list_retention_policies


def test_retention_policies_list_is_tenant_scoped(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    db_path = str(tmp_path / "iso.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")
    init_db(sqlite_path=db_path)
    SessionLocal = get_sessionmaker()

    with SessionLocal() as db:
        db.execute(
            text(
                "INSERT INTO retention_policies(tenant_id, artifact_type, retention_days, immutable_required) "
                "VALUES ('tenant-a','ai_plane_evidence',30,1),('tenant-b','ai_plane_evidence',10,1)"
            )
        )
        db.commit()

        rows_a = list_retention_policies(db, "tenant-a")
        rows_b = list_retention_policies(db, "tenant-b")

    assert len(rows_a) == 1 and rows_a[0]["tenant_id"] == "tenant-a"
    assert len(rows_b) == 1 and rows_b[0]["tenant_id"] == "tenant-b"


def test_retention_policies_requires_tenant(monkeypatch: pytest.MonkeyPatch, tmp_path):
    db_path = str(tmp_path / "iso2.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")
    init_db(sqlite_path=db_path)
    SessionLocal = get_sessionmaker()

    with SessionLocal() as db:
        with pytest.raises(ValueError, match="EVIDENCE_TENANT_REQUIRED"):
            list_retention_policies(db, "")
