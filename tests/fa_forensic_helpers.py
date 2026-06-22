from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text as sa_text
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_sessionmaker
from api.tenant_rbac import assign_role
from api.db import get_engine
from services.field_assessment.store import create_finding

TENANT_A = "test-tenant-fa"
TENANT_B = "tenant-other"

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


def make_context(build_app: object) -> ForensicContext:
    app = build_app(auth_enabled=True)  # type: ignore[operator]

    key_a = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=TENANT_A,
    )
    key_b = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=TENANT_B,
    )

    SM = get_sessionmaker()

    for tenant_id in (TENANT_A, TENANT_B):
        db = SM()
        try:
            key_id = db.execute(
                sa_text(
                    """
                    SELECT id
                    FROM api_keys
                    WHERE tenant_id = :tenant_id
                    ORDER BY id DESC
                    LIMIT 1
                    """
                ),
                {"tenant_id": tenant_id},
            ).scalar_one()

            assign_role(
                db,
                tenant_id=tenant_id,
                actor_key_prefix="pytest",
                target_key_id=int(key_id),
                role_name="auditor",
            )
        finally:
            db.close()

    return ForensicContext(
        client_a=TestClient(app, headers={"X-API-Key": key_a}),
        client_b=TestClient(app, headers={"X-API-Key": key_b}),
        engine=get_engine(),
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
