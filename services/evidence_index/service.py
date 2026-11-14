from __future__ import annotations

import json
import uuid

from sqlalchemy.orm import Session

from services.artifact_paths import (
    authorize_platform_artifact,
    authorize_tenant_artifact,
    hash_authorized_artifact,
    sha256_file,
)
from services.evidence_index import storage


class EvidenceIndexService:
    def register_run(
        self,
        db: Session,
        *,
        tenant_id: str,
        plane_id: str,
        artifact_type: str,
        artifact_path: str,
        schema_version: str,
        git_sha: str,
        status: str,
        summary_json: dict[str, object],
        retention_class: str,
        anchor_status: str,
        platform_authority: str | None = None,
    ) -> dict[str, object]:
        # Containment, then ownership, before any read (CODEQL-REMEDIATE-005,
        # EVIDENCE-ARTIFACT-TENANT-AUTH-001). Tenant callers need a canonical
        # owner record; only internal producers pass a platform authority, and
        # the HTTP route never does.
        if platform_authority is None:
            artifact = authorize_tenant_artifact(db, tenant_id, artifact_path)
            artifact_sha256 = hash_authorized_artifact(artifact)
        else:
            artifact = authorize_platform_artifact(
                artifact_path,
                authority=platform_authority,
                operation="register_run",
                plane_id=plane_id,
                artifact_type=artifact_type,
            )
            # Degraded-safe for the producer: an unwritten artifact is recorded.
            artifact_sha256 = (
                sha256_file(artifact.path) if artifact.path.is_file() else "missing"
            )
        payload: dict[str, object] = {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "plane_id": plane_id,
            "artifact_type": artifact_type,
            "artifact_path": str(artifact.path),
            "artifact_sha256": artifact_sha256,
            "schema_version": schema_version,
            "git_sha": git_sha,
            "status": status,
            "summary_json": json.dumps(summary_json, sort_keys=True),
            "retention_class": retention_class,
            "anchor_status": anchor_status,
        }
        storage.insert_run(db, payload)
        db.commit()
        return {**payload, "artifact_ref": artifact.ref}

    def list_runs(self, db: Session, tenant_id: str) -> list[dict[str, object]]:
        return storage.list_runs(db, tenant_id)

    def get_run(
        self, db: Session, tenant_id: str, run_id: str
    ) -> dict[str, object] | None:
        return storage.get_run(db, tenant_id, run_id)
