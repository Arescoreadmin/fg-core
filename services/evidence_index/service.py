from __future__ import annotations

import json
import uuid

from sqlalchemy.orm import Session

from services.artifact_paths import resolve_contained_artifact, sha256_file
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
    ) -> dict[str, object]:
        # Refuse anything outside the artifact root before touching it
        # (CODEQL-REMEDIATE-005): no existence oracle, no foreign file hashes.
        contained = resolve_contained_artifact(artifact_path)
        artifact_sha256 = sha256_file(contained) if contained.is_file() else "missing"
        payload: dict[str, object] = {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "plane_id": plane_id,
            "artifact_type": artifact_type,
            "artifact_path": artifact_path,
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
        return payload

    def list_runs(self, db: Session, tenant_id: str) -> list[dict[str, object]]:
        return storage.list_runs(db, tenant_id)

    def get_run(
        self, db: Session, tenant_id: str, run_id: str
    ) -> dict[str, object] | None:
        return storage.get_run(db, tenant_id, run_id)
