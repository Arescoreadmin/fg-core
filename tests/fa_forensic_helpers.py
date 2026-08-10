from __future__ import annotations

import uuid as _uuid
from dataclasses import dataclass
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text as sa_text
from sqlalchemy.orm import Session

from api.credential_authority import issue_credential
from api.db import get_engine
from api.tenant_rbac import assign_role
from services.field_assessment.store import create_finding

TENANT_A = "test-tenant-fa"
TENANT_B = "tenant-other"
TENANT_ADMIN = "test-tenant-fa-admin"

ENGAGEMENT_BODY = {
    "client_name": "Forensic Corp",
    "client_domain": "forensic.example",
    "assessor_id": "assessor-forensic",
    "assessment_type": "ai_governance",
    "engagement_metadata": {"case": "baseline"},
}

SCAN_BODY = {
    "source_type": "microsoft_graph",
    "schema_version": "1.0",
    "collected_at": "2026-06-02T12:00:00Z",
    "raw_payload": {"users": []},
    "object_count": 0,
}

OBSERVATION_BODY = {
    "domain": "ai_governance",
    "observation_type": "gap",
    "severity": "high",
    "title": "Missing AI policy",
    "description": "No approved AI usage policy was produced.",
}

DOC_BODY = {
    "document_name": "AI Policy.pdf",
    "document_classification": "ai_policy",
}


@dataclass
class ForensicContext:
    client_a: TestClient
    client_b: TestClient
    engine: Any
    promote_client_a: TestClient = None  # type: ignore[assignment]


def _mint_admin_key(app: Any, tenant_id: str) -> TestClient:
    """Issue a canonical credential with tenant_admin role (has governance.promote)."""
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            sa_text(
                "INSERT OR IGNORE INTO tenants (tenant_id, lifecycle_state)"
                " VALUES (:tid, 'active')"
            ),
            {"tid": tenant_id},
        )
    result = issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="tenant_api_key",
        credential_slot=f"test:{_uuid.uuid4()}",
        scopes=["governance:read", "governance:write"],
    )
    with Session(engine) as db:
        assign_role(
            db,
            tenant_id=tenant_id,
            actor_key_prefix="pytest",
            credential_id=result.record.credential_id,
            role_name="tenant_admin",
        )
        db.commit()
    plaintext_secret = result.plaintext_secret
    assert plaintext_secret is not None
    return TestClient(app, headers={"X-API-Key": plaintext_secret})


def make_context(build_app: object) -> ForensicContext:
    app = build_app(auth_enabled=True)  # type: ignore[operator]
    engine = get_engine()

    for tid in (TENANT_A, TENANT_B):
        with engine.begin() as conn:
            conn.execute(
                sa_text(
                    "INSERT OR IGNORE INTO tenants (tenant_id, lifecycle_state)"
                    " VALUES (:tid, 'active')"
                ),
                {"tid": tid},
            )

    # No DB role assigned — scope fallback unions assessor (governance:write) and
    # qa_reviewer (governance:qa_approve) capabilities for the migration period.
    key_a = issue_credential(
        engine,
        tenant_id=TENANT_A,
        credential_type="tenant_api_key",
        credential_slot=f"test:{_uuid.uuid4()}",
        scopes=["governance:read", "governance:write", "governance:qa_approve"],
    ).plaintext_secret
    assert key_a is not None
    key_b = issue_credential(
        engine,
        tenant_id=TENANT_B,
        credential_type="tenant_api_key",
        credential_slot=f"test:{_uuid.uuid4()}",
        scopes=["governance:read", "governance:write", "governance:qa_approve"],
    ).plaintext_secret
    assert key_b is not None

    promote_client = _mint_admin_key(app, TENANT_A)

    return ForensicContext(
        client_a=TestClient(app, headers={"X-API-Key": key_a}),
        client_b=TestClient(app, headers={"X-API-Key": key_b}),
        engine=engine,
        promote_client_a=promote_client,
    )


def create_engagement(client: TestClient, **overrides: Any) -> dict[str, Any]:
    body = {**ENGAGEMENT_BODY, **overrides}
    response = client.post("/field-assessment/engagements", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def create_observation(
    client: TestClient, engagement_id: str, **overrides: Any
) -> dict[str, Any]:
    body = {**OBSERVATION_BODY, **overrides}
    response = client.post(
        f"/field-assessment/engagements/{engagement_id}/observations", json=body
    )
    assert response.status_code == 201, response.text
    return response.json()


def insert_finding(
    session: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    marker: str,
    severity: str = "high",
    status: str = "open",
) -> Any:
    finding = create_finding(
        session,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        finding_type="forensic_gap",
        source_ref=marker,
        severity=severity,
        title=f"Forensic finding {marker}",
        description="Auditor-created finding used to verify persisted state.",
        source_attribution="forensic_test",
        confidence_score=90,
        framework_mappings=[],
        nist_ai_rmf_mappings=[],
        evidence_ref_ids=[],
        remediation_hint=None,
    )
    finding.status = status
    session.commit()
    session.refresh(finding)
    return finding
