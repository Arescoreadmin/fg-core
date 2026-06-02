from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceLink, FaScanResult
from services.field_assessment.store import compute_evidence_hash
from tests.fa_forensic_helpers import (
    SCAN_BODY,
    TENANT_A,
    create_engagement,
    insert_finding,
    make_context,
)


def test_hash_sensitivity_and_engagement_scoped_deduplication(
    build_app: object,
) -> None:
    """Canonical evidence hashes must change for one-byte payload mutations while deduplication stays engagement-scoped."""
    ctx = make_context(build_app)
    first_engagement = create_engagement(ctx.client_a)
    second_engagement = create_engagement(ctx.client_a, client_name="Second Corp")
    payloads = [{"users": ["a"]}, {"users": ["b"]}, {"users": ["c"]}, {"users": ["d"]}]
    hashes = {compute_evidence_hash(payload) for payload in payloads}
    assert len(hashes) == 4
    body = {**SCAN_BODY, "raw_payload": payloads[0], "object_count": 1}
    first = ctx.client_a.post(
        f"/field-assessment/engagements/{first_engagement['id']}/scan-results",
        json=body,
    )
    duplicate = ctx.client_a.post(
        f"/field-assessment/engagements/{first_engagement['id']}/scan-results",
        json=body,
    )
    other_engagement = ctx.client_a.post(
        f"/field-assessment/engagements/{second_engagement['id']}/scan-results",
        json=body,
    )
    assert first.status_code == 201, first.text
    assert duplicate.status_code == 201, duplicate.text
    assert duplicate.json()["id"] == first.json()["id"]
    assert other_engagement.status_code == 201, other_engagement.text
    assert other_engagement.json()["id"] != first.json()["id"]
    with Session(ctx.engine) as session:
        assert session.scalar(select(func.count(FaScanResult.id))) == 2


def test_evidence_link_rejects_foreign_finding_source(build_app: object) -> None:
    """A link source finding from another same-tenant engagement must be rejected without inserting an edge."""
    ctx = make_context(build_app)
    source_engagement = create_engagement(ctx.client_a)
    target_engagement = create_engagement(ctx.client_a, client_name="Target Corp")
    scan = ctx.client_a.post(
        f"/field-assessment/engagements/{target_engagement['id']}/scan-results",
        json=SCAN_BODY,
    )
    assert scan.status_code == 201, scan.text
    with Session(ctx.engine) as session:
        finding = insert_finding(
            session,
            tenant_id=TENANT_A,
            engagement_id=source_engagement["id"],
            marker="foreign",
        )
        finding_id = finding.id
    response = ctx.client_a.post(
        f"/field-assessment/engagements/{target_engagement['id']}/evidence-links",
        json={
            "source_entity_type": "finding",
            "source_entity_id": finding_id,
            "evidence_entity_type": "scan_result",
            "evidence_entity_id": scan.json()["id"],
        },
    )
    assert response.status_code == 422, response.text
    with Session(ctx.engine) as session:
        assert session.scalar(select(func.count(FaEvidenceLink.id))) == 1
