from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

from services.enterprise_controls_extension.models import TenantControlStateUpsert

SEED_PATH = Path("seeds/enterprise_control_catalog_v1.json")


class EnterpriseControlsService:
    def _seed_payload(self) -> dict[str, object]:
        if not SEED_PATH.exists():
            return {"frameworks": [], "controls": [], "crosswalk": []}
        return json.loads(SEED_PATH.read_text(encoding="utf-8"))

    def frameworks(self, db: Session) -> list[dict[str, object]]:
        rows = db.execute(
            text(
                "SELECT framework_id, name, version, metadata_json "
                "FROM enterprise_framework_catalog ORDER BY framework_id"
            )
        ).mappings()
        return [dict(r) for r in rows]

    def catalog(self, db: Session) -> list[dict[str, object]]:
        rows = db.execute(
            text(
                "SELECT control_id, domain, title, description, metadata_json "
                "FROM enterprise_control_catalog ORDER BY control_id"
            )
        ).mappings()
        return [dict(r) for r in rows]

    def crosswalk(self, db: Session) -> list[dict[str, object]]:
        rows = db.execute(
            text(
                "SELECT crosswalk_id, control_id, framework_id, framework_control_ref, mapping_strength "
                "FROM enterprise_control_crosswalk ORDER BY crosswalk_id"
            )
        ).mappings()
        return [dict(r) for r in rows]

    def upsert_tenant_state(
        self, db: Session, tenant_id: str, payload: TenantControlStateUpsert
    ) -> dict[str, object]:
        db.execute(
            text(
                """
                INSERT INTO tenant_control_state(tenant_id, control_id, status, note)
                VALUES (:tenant_id, :control_id, :status, :note)
                ON CONFLICT(tenant_id, control_id)
                DO UPDATE SET status = excluded.status, note = excluded.note, updated_at = CURRENT_TIMESTAMP
                """
            ),
            {
                "tenant_id": tenant_id,
                "control_id": payload.control_id,
                "status": payload.status,
                "note": payload.note,
            },
        )
        db.commit()
        return {
            "tenant_id": tenant_id,
            "control_id": payload.control_id,
            "status": payload.status,
            "note": payload.note,
        }

    def seed_minimal(self, db: Session) -> None:
        payload = self._seed_payload()
        for framework in payload.get("frameworks", []):
            db.execute(
                text(
                    """
                    INSERT INTO enterprise_framework_catalog(framework_id, name, version, metadata_json)
                    VALUES (:framework_id, :name, :version, :metadata_json)
                    ON CONFLICT(framework_id) DO NOTHING
                    """
                ),
                framework,
            )
        for control in payload.get("controls", []):
            db.execute(
                text(
                    """
                    INSERT INTO enterprise_control_catalog(control_id, domain, title, description, metadata_json)
                    VALUES (:control_id, :domain, :title, :description, :metadata_json)
                    ON CONFLICT(control_id) DO NOTHING
                    """
                ),
                control,
            )
        for x in payload.get("crosswalk", []):
            db.execute(
                text(
                    """
                    INSERT INTO enterprise_control_crosswalk(crosswalk_id, control_id, framework_id, framework_control_ref, mapping_strength)
                    VALUES (:crosswalk_id, :control_id, :framework_id, :framework_control_ref, :mapping_strength)
                    ON CONFLICT(crosswalk_id) DO NOTHING
                    """
                ),
                x,
            )
        db.commit()
