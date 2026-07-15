"""P-2: Auto-enable AI assistant on QA approval acceptance tests.

Acceptance criteria:
  P2-1  QA approve → GET engagement shows portal_ai_enabled = True.
  P2-2  portal_ai_enabled set even when delivery_blocked = True (gates unmet).
  P2-3  Pre-existing engagement_metadata fields are preserved (merge, not replace).
  P2-4  portal_ai_enabled absent before QA approve, present after.
  P2-5  QA approve is idempotent — repeated calls keep portal_ai_enabled = True.
  P2-6  QA approve returns 200 with qa_approved_by and delivery_blocked fields.
  P2-7  Unit: _build_engagement_system_prompt returns None when portal_ai_enabled absent.
  P2-8  Unit: _build_engagement_system_prompt returns str when portal_ai_enabled = True.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)  # 64-char hex test seed

import pytest
from fastapi.testclient import TestClient

_TENANT_ID = "tenant-p2-ai-auto-enable"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app: object) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=_TENANT_ID,
    )
    return TestClient(app, headers={"X-API-Key": key})


def _create_engagement(client: TestClient) -> str:
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": "P2 Test Corp",
            "assessor_id": "assessor-p2",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _create_report(client: TestClient, eng_id: str) -> str:
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert resp.status_code in (200, 201), resp.text
    data = resp.json()
    return data.get("id") or data.get("report_id") or data["items"][0]["report_id"]


def _qa_approve(client: TestClient, eng_id: str, report_id: str) -> dict:
    resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
        json={},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _get_engagement(client: TestClient, eng_id: str) -> dict:
    resp = client.get(f"/field-assessment/engagements/{eng_id}")
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# P2-1: QA approve → portal_ai_enabled = True in engagement metadata
# ---------------------------------------------------------------------------


class TestP21AiEnabledAfterQaApprove:
    def test_p2_1_portal_ai_enabled_after_qa_approve(self, client: TestClient) -> None:
        """QA approve sets portal_ai_enabled = True in engagement_metadata."""
        eng_id = _create_engagement(client)
        report_id = _create_report(client, eng_id)
        _qa_approve(client, eng_id, report_id)

        eng = _get_engagement(client, eng_id)
        metadata = eng.get("engagement_metadata") or {}
        assert metadata.get("portal_ai_enabled") is True


# ---------------------------------------------------------------------------
# P2-2: portal_ai_enabled set even when delivery is blocked by other gates
# ---------------------------------------------------------------------------


class TestP22AiEnabledWhenDeliveryBlocked:
    def test_p2_2_ai_enabled_when_delivery_blocked(self, client: TestClient) -> None:
        """portal_ai_enabled = True even when delivery_blocked = True."""
        eng_id = _create_engagement(client)
        report_id = _create_report(client, eng_id)
        data = _qa_approve(client, eng_id, report_id)

        # Delivery must be blocked (new engagement has unmet gates)
        assert data["delivery_blocked"] is True

        # AI must still be enabled despite blocked delivery
        eng = _get_engagement(client, eng_id)
        metadata = eng.get("engagement_metadata") or {}
        assert metadata.get("portal_ai_enabled") is True


# ---------------------------------------------------------------------------
# P2-3: Pre-existing metadata fields are preserved after QA approve
# ---------------------------------------------------------------------------


class TestP23MetadataMerge:
    def test_p2_3_existing_metadata_preserved(self, client: TestClient) -> None:
        """QA approve merges portal_ai_enabled into existing metadata without overwriting."""
        eng_id = _create_engagement(client)

        # Seed metadata with a custom field before QA approve
        resp = client.patch(
            f"/field-assessment/engagements/{eng_id}",
            json={"engagement_metadata": {"custom_field": "sentinel-value"}},
        )
        assert resp.status_code in (200, 204), resp.text

        report_id = _create_report(client, eng_id)
        _qa_approve(client, eng_id, report_id)

        eng = _get_engagement(client, eng_id)
        metadata = eng.get("engagement_metadata") or {}
        assert metadata.get("portal_ai_enabled") is True
        assert metadata.get("custom_field") == "sentinel-value"


# ---------------------------------------------------------------------------
# P2-4: portal_ai_enabled absent before QA approve, present after
# ---------------------------------------------------------------------------


class TestP24BeforeAfterState:
    def test_p2_4_ai_flag_absent_before_approve_present_after(
        self, client: TestClient
    ) -> None:
        """portal_ai_enabled is not set before QA approve, and is True after."""
        eng_id = _create_engagement(client)

        before = _get_engagement(client, eng_id)
        before_meta = before.get("engagement_metadata") or {}
        assert not before_meta.get("portal_ai_enabled")

        report_id = _create_report(client, eng_id)
        _qa_approve(client, eng_id, report_id)

        after = _get_engagement(client, eng_id)
        after_meta = after.get("engagement_metadata") or {}
        assert after_meta.get("portal_ai_enabled") is True


# ---------------------------------------------------------------------------
# P2-5: Idempotent — repeated QA approve keeps portal_ai_enabled = True
# ---------------------------------------------------------------------------


class TestP25Idempotent:
    def test_p2_5_repeated_qa_approve_keeps_ai_enabled(
        self, client: TestClient
    ) -> None:
        """portal_ai_enabled remains True when QA approve is called multiple times."""
        eng_id = _create_engagement(client)
        report_id = _create_report(client, eng_id)
        _qa_approve(client, eng_id, report_id)

        # Second QA approve — same report
        resp = client.post(
            f"/field-assessment/engagements/{eng_id}/reports/{report_id}/qa-approve",
            json={},
        )
        assert resp.status_code in (200, 409), resp.text

        eng = _get_engagement(client, eng_id)
        metadata = eng.get("engagement_metadata") or {}
        assert metadata.get("portal_ai_enabled") is True


# ---------------------------------------------------------------------------
# P2-6: QA approve response schema
# ---------------------------------------------------------------------------


class TestP26QaApproveResponseSchema:
    def test_p2_6_qa_approve_response_has_required_fields(
        self, client: TestClient
    ) -> None:
        """QA approve returns 200 with qa_approved_by, delivery_blocked, and engagement_status."""
        eng_id = _create_engagement(client)
        report_id = _create_report(client, eng_id)
        data = _qa_approve(client, eng_id, report_id)

        assert data["qa_approved_by"] != ""
        assert data["qa_approved_at"] != ""
        assert isinstance(data["delivery_blocked"], bool)
        assert data["engagement_status"] in ("in_progress", "delivered")


# ---------------------------------------------------------------------------
# P2-7 & P2-8: Unit tests for _build_engagement_system_prompt
# ---------------------------------------------------------------------------


class TestP27BuildSystemPrompt:
    def test_p2_7_system_prompt_none_when_ai_flag_absent(
        self, client: TestClient
    ) -> None:
        """_build_engagement_system_prompt returns None when portal_ai_enabled not set."""
        from api.db import get_sessionmaker
        from api.ui_ai_console import _build_engagement_system_prompt

        eng_id = _create_engagement(client)

        db = get_sessionmaker()()
        try:
            result = _build_engagement_system_prompt(
                db, tenant_id=_TENANT_ID, engagement_id=eng_id
            )
        finally:
            db.close()

        assert result is None

    def test_p2_8_system_prompt_string_when_ai_enabled(
        self, client: TestClient
    ) -> None:
        """_build_engagement_system_prompt returns a string when portal_ai_enabled = True."""
        from api.db import get_sessionmaker
        from api.ui_ai_console import _build_engagement_system_prompt

        eng_id = _create_engagement(client)
        report_id = _create_report(client, eng_id)
        _qa_approve(client, eng_id, report_id)

        db = get_sessionmaker()()
        try:
            result = _build_engagement_system_prompt(
                db, tenant_id=_TENANT_ID, engagement_id=eng_id
            )
        finally:
            db.close()

        assert isinstance(result, str)
        assert len(result) > 0
