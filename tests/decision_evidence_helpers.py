"""Create tenant-owned decision evidence through the real producer (tests only).

Evidence anchoring and registration require a canonical owner record
(EVIDENCE-ARTIFACT-TENANT-AUTH-001), so tests that need a usable artifact
create one the same way production does: ``emit_decision_evidence``. The
decision record is a synthetic stand-in; the producer reads only attributes.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from api.db import get_sessionmaker


def emit_synthetic_decision_evidence(
    tenant_id: str, decision_id: int
) -> tuple[Path, str]:
    """Return (storage path, SHA-256) of new decision evidence owned by ``tenant_id``.

    Writes under ``FG_ARTIFACTS_DIR``; set it to a temporary directory first.
    """
    from api.evidence_artifacts import emit_decision_evidence

    record = SimpleNamespace(
        id=decision_id,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        tenant_id=tenant_id,
        event_id=f"evt-{decision_id}",
        event_type="synthetic",
        source="synthetic",
        threat_level="low",
        policy_hash="0" * 64,
        request_json={"synthetic": True},
        response_json={"synthetic": True},
        rules_triggered_json=[],
        decision_diff_json=None,
        chain_hash=None,
        prev_hash=None,
        chain_alg=None,
        chain_ts=None,
    )
    with get_sessionmaker()() as db:
        artifact = emit_decision_evidence(db, record)  # type: ignore[arg-type]
        db.commit()
        path = Path(artifact.storage_path)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()
