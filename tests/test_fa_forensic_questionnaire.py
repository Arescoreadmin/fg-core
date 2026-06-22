from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db_models_questionnaire import FaQuestionnaire
from tests.fa_forensic_helpers import create_engagement, make_context


def test_questionnaire_init_is_idempotent_and_response_patch_persists(
    build_app: object,
) -> None:
    """Repeated initialization must reuse one questionnaire and response edits must survive GET."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    url = f"/field-assessment/engagements/{engagement['id']}/questionnaires"
    first = ctx.client_a.post(url, json={"framework": "nist_ai_rmf"})
    second = ctx.client_a.post(url, json={"framework": "nist_ai_rmf"})
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["id"] == first.json()["id"]
    control_id = first.json()["responses"][0]["control_id"]
    patched = ctx.client_a.patch(
        f"{url}/{first.json()['id']}/responses/{control_id}",
        json={"response_status": "implemented", "evidence_text": "confirmed"},
    )
    fetched = ctx.client_a.get(f"{url}/{first.json()['id']}")
    assert patched.status_code == 200, patched.text
    assert fetched.status_code == 200, fetched.text
    control = next(
        item for item in fetched.json()["responses"] if item["control_id"] == control_id
    )
    assert control["response_status"] == "implemented"
    assert control["evidence_text"] == "confirmed"
    with Session(ctx.engine) as session:
        assert session.scalar(select(func.count(FaQuestionnaire.id))) == 1
