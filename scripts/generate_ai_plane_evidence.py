from __future__ import annotations

import os
import subprocess
from pathlib import Path

from sqlalchemy import text

from api.db import get_sessionmaker, init_db
from services.ai_plane_extension.service import write_ai_plane_evidence
from services.evidence_index import EvidenceIndexService


def _git_sha() -> str:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return (proc.stdout or "").strip() or "unknown"


def main() -> int:
    init_db()
    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        total_inference = db.execute(text("SELECT COUNT(*) FROM ai_inference_records WHERE model_id='SIMULATED_V1'" )).scalar_one()
        total_blocked = db.execute(text("SELECT COUNT(*) FROM ai_policy_violations")).scalar_one()
        total_violations = total_blocked

    payload = write_ai_plane_evidence(
        out_path="artifacts/ai_plane_evidence.json",
        schema_path="contracts/artifacts/ai_plane_evidence.schema.json",
        git_sha=_git_sha(),
        feature_flag_snapshot={
            "FG_AI_PLANE_ENABLED": (os.getenv("FG_AI_PLANE_ENABLED") or "0"),
            "FG_AI_EXTERNAL_PROVIDER_ENABLED": (os.getenv("FG_AI_EXTERNAL_PROVIDER_ENABLED") or "0"),
        },
        total_inference_calls=int(total_inference or 0),
        total_blocked_calls=int(total_blocked or 0),
        total_policy_violations=int(total_violations or 0),
        route_snapshot=["/ai/infer"],
    )

    # Additive evidence index registration (degraded-safe)
    try:
        svc = EvidenceIndexService()
        with SessionLocal() as db:
            svc.register_run(
                db,
                tenant_id=os.getenv("FG_EVIDENCE_TENANT_ID", "tenant-dev"),
                plane_id="ai_plane",
                artifact_type="ai_plane_evidence",
                artifact_path="artifacts/ai_plane_evidence.json",
                schema_version="v1",
                git_sha=str(payload.get("git_sha", "unknown")),
                status="PASS",
                summary_json={"simulated_mode": True},
                retention_class="hot",
                anchor_status="none",
            )
    except Exception:
        # degraded mode: artifact already written; mark index unavailable finding
        art = Path("artifacts/ai_plane_evidence.json")
        if art.exists():
            import json

            body = json.loads(art.read_text(encoding="utf-8"))
            body["evidence_index_status"] = "EVIDENCE_INDEX_UNAVAILABLE"
            art.write_text(json.dumps(body, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
