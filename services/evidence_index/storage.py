from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def _require_tenant_id(tenant_id: str) -> None:
    if not str(tenant_id or "").strip():
        raise ValueError("EVIDENCE_TENANT_REQUIRED")


def insert_run(db: Session, payload: dict[str, object]) -> None:
    _require_tenant_id(str(payload.get("tenant_id") or ""))
    db.execute(
        text(
            """
            INSERT INTO evidence_runs(
                id, tenant_id, plane_id, artifact_type, artifact_path, artifact_sha256,
                schema_version, git_sha, status, summary_json, retention_class, anchor_status
            ) VALUES (
                :id, :tenant_id, :plane_id, :artifact_type, :artifact_path, :artifact_sha256,
                :schema_version, :git_sha, :status, :summary_json, :retention_class, :anchor_status
            )
            """
        ),
        payload,
    )


def list_runs(db: Session, tenant_id: str) -> list[dict[str, object]]:
    _require_tenant_id(tenant_id)
    rows = db.execute(
        text(
            "SELECT id, plane_id, artifact_type, artifact_path, artifact_sha256, schema_version, git_sha, created_at, status, summary_json, retention_class, anchor_status "
            "FROM evidence_runs WHERE tenant_id=:tenant_id ORDER BY created_at DESC"
        ),
        {"tenant_id": tenant_id},
    ).mappings()
    return [dict(r) for r in rows]


def get_run(db: Session, tenant_id: str, run_id: str) -> dict[str, object] | None:
    _require_tenant_id(tenant_id)
    row = db.execute(
        text(
            "SELECT id, tenant_id, plane_id, artifact_type, artifact_path, artifact_sha256, schema_version, git_sha, created_at, status, summary_json, retention_class, anchor_status "
            "FROM evidence_runs WHERE tenant_id=:tenant_id AND id=:id"
        ),
        {"tenant_id": tenant_id, "id": run_id},
    ).mappings().first()
    return dict(row) if row else None


def list_retention_policies(db: Session, tenant_id: str) -> list[dict[str, object]]:
    _require_tenant_id(tenant_id)
    rows = db.execute(
        text(
            "SELECT id, tenant_id, artifact_type, retention_days, immutable_required, created_at "
            "FROM retention_policies WHERE tenant_id=:tenant_id ORDER BY id DESC"
        ),
        {"tenant_id": tenant_id},
    ).mappings()
    return [dict(r) for r in rows]
