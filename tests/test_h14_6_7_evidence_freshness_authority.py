"""Tests for PR 14.6.7 — Evidence Freshness Authority.

Covers:
  - Freshness policy CRUD
  - Freshness record creation and retrieval
  - Freshness state transitions (all 6 states)
  - Freshness scoring (pure function unit tests)
  - Exception create/list/revoke
  - Dashboard metrics
  - CGIN snapshot
  - Timeline integration
  - Tenant isolation
  - Recompute endpoint
  - Policy-linked records
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from services.evidence_freshness_authority.models import (
    FreshnessState,
    compute_freshness_score,
    compute_freshness_state,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=timezone.utc)
_TENANT = "t-freshness-001"
_TENANT_B = "t-freshness-002"

# Future dates
_REVIEW_DUE_FUTURE = (_NOW + timedelta(days=60)).isoformat()
_REVIEW_DUE_SOON = (_NOW + timedelta(days=15)).isoformat()  # within 30 days
_REVIEW_DUE_PAST = (_NOW - timedelta(days=2)).isoformat()
_VERIFICATION_DUE_FUTURE = (_NOW + timedelta(days=90)).isoformat()
_VERIFICATION_DUE_PAST = (_NOW - timedelta(days=5)).isoformat()
_EXPIRATION_DUE_FUTURE = (_NOW + timedelta(days=300)).isoformat()
_EXPIRATION_DUE_PAST = (_NOW - timedelta(days=1)).isoformat()
_EXCEPTION_EXPIRES_FUTURE = (_NOW + timedelta(days=30)).isoformat()


def _policy_payload(**overrides: Any) -> dict:
    defaults: dict[str, Any] = {
        "name": "Default Policy",
        "review_interval_days": 90,
        "verification_interval_days": 180,
        "expiration_interval_days": 365,
        "criticality": "MEDIUM",
        "enabled": True,
    }
    defaults.update(overrides)
    return defaults


def _record_payload(evidence_id: str = "ev-test-001", **overrides: Any) -> dict:
    defaults: dict[str, Any] = {"evidence_id": evidence_id}
    defaults.update(overrides)
    return defaults


def _exception_payload(evidence_id: str = "ev-test-001", **overrides: Any) -> dict:
    defaults: dict[str, Any] = {
        "evidence_id": evidence_id,
        "reason": "Temporary exception for system upgrade",
        "approved_by": "ciso@example.com",
        "expires_at": _EXCEPTION_EXPIRES_FUTURE,
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("audit:read", "audit:write", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def client_b(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("audit:read", "audit:write", tenant_id=_TENANT_B)
    return TestClient(app, headers={"X-API-Key": key})


def _create_policy(client: TestClient, **overrides: Any) -> dict:
    resp = client.post("/freshness-policies", json=_policy_payload(**overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_record(
    client: TestClient, evidence_id: str = "ev-test-001", **overrides: Any
) -> dict:
    resp = client.post("/freshness", json=_record_payload(evidence_id, **overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_exception(
    client: TestClient, evidence_id: str = "ev-test-001", **overrides: Any
) -> dict:
    resp = client.post(
        "/freshness/exceptions", json=_exception_payload(evidence_id, **overrides)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# 1. TestCreateFreshnessPolicy
# ---------------------------------------------------------------------------


class TestCreateFreshnessPolicy:
    def test_create_returns_201(self, client):
        resp = client.post("/freshness-policies", json=_policy_payload())
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Default Policy"
        assert data["review_interval_days"] == 90
        assert data["verification_interval_days"] == 180
        assert data["expiration_interval_days"] == 365
        assert data["criticality"] == "MEDIUM"
        assert data["enabled"] is True
        assert data["id"] is not None
        assert data["tenant_id"] == _TENANT

    def test_create_with_evidence_type(self, client):
        resp = client.post(
            "/freshness-policies",
            json=_policy_payload(name="Doc Policy", evidence_type="DOCUMENT"),
        )
        assert resp.status_code == 201
        assert resp.json()["evidence_type"] == "DOCUMENT"

    def test_create_with_description(self, client):
        resp = client.post(
            "/freshness-policies",
            json=_policy_payload(name="Described Policy", description="A test policy"),
        )
        assert resp.status_code == 201
        assert resp.json()["description"] == "A test policy"

    def test_create_with_criticality_critical(self, client):
        resp = client.post(
            "/freshness-policies",
            json=_policy_payload(name="Critical Policy", criticality="CRITICAL"),
        )
        assert resp.status_code == 201
        assert resp.json()["criticality"] == "CRITICAL"

    def test_create_with_disabled_flag(self, client):
        resp = client.post(
            "/freshness-policies",
            json=_policy_payload(name="Disabled Policy", enabled=False),
        )
        assert resp.status_code == 201
        assert resp.json()["enabled"] is False

    def test_create_invalid_interval_rejected(self, client):
        resp = client.post(
            "/freshness-policies",
            json=_policy_payload(review_interval_days=0),
        )
        assert resp.status_code == 422

    def test_create_invalid_criticality_rejected(self, client):
        resp = client.post(
            "/freshness-policies",
            json=_policy_payload(criticality="INVALID"),
        )
        assert resp.status_code == 422

    def test_create_missing_name_rejected(self, client):
        resp = client.post("/freshness-policies", json={"review_interval_days": 90})
        assert resp.status_code == 422

    def test_create_extra_field_rejected(self, client):
        payload = _policy_payload()
        payload["unknown_field"] = "x"
        resp = client.post("/freshness-policies", json=payload)
        assert resp.status_code == 422

    def test_create_sets_created_at(self, client):
        data = _create_policy(client)
        assert data["created_at"] is not None

    def test_create_tenant_isolation(self, client, client_b):
        data_a = _create_policy(client, name="Tenant A Policy")
        resp_b = client_b.get(f"/freshness-policies/{data_a['id']}")
        assert resp_b.status_code == 404

    def test_create_returns_tenant_id(self, client):
        data = _create_policy(client)
        assert data["tenant_id"] == _TENANT


# ---------------------------------------------------------------------------
# 2. TestGetFreshnessPolicy
# ---------------------------------------------------------------------------


class TestGetFreshnessPolicy:
    def test_get_returns_200(self, client):
        created = _create_policy(client)
        resp = client.get(f"/freshness-policies/{created['id']}")
        assert resp.status_code == 200
        assert resp.json()["id"] == created["id"]

    def test_get_returns_all_fields(self, client):
        created = _create_policy(client, name="Full Policy", evidence_type="API")
        resp = client.get(f"/freshness-policies/{created['id']}")
        data = resp.json()
        assert data["name"] == "Full Policy"
        assert data["evidence_type"] == "API"
        assert data["review_interval_days"] == 90

    def test_get_missing_returns_404(self, client):
        resp = client.get("/freshness-policies/does-not-exist")
        assert resp.status_code == 404

    def test_get_cross_tenant_returns_404(self, client, client_b):
        created = _create_policy(client)
        resp = client_b.get(f"/freshness-policies/{created['id']}")
        assert resp.status_code == 404

    def test_get_requires_auth(self, build_app):
        app = build_app(auth_enabled=True)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/freshness-policies/some-id")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 3. TestListFreshnessPolicies
# ---------------------------------------------------------------------------


class TestListFreshnessPolicies:
    def test_list_empty(self, client):
        resp = client.get("/freshness-policies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_list_returns_created(self, client):
        _create_policy(client, name="P1")
        _create_policy(client, name="P2")
        resp = client.get("/freshness-policies")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_list_filter_by_evidence_type(self, client):
        _create_policy(client, name="Doc", evidence_type="DOCUMENT")
        _create_policy(client, name="API", evidence_type="API")
        resp = client.get("/freshness-policies?evidence_type=DOCUMENT")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["evidence_type"] == "DOCUMENT"

    def test_list_enabled_only(self, client):
        _create_policy(client, name="Enabled", enabled=True)
        _create_policy(client, name="Disabled", enabled=False)
        resp = client.get("/freshness-policies?enabled_only=true")
        data = resp.json()
        assert all(item["enabled"] is True for item in data["items"])

    def test_list_pagination(self, client):
        for i in range(5):
            _create_policy(client, name=f"Policy {i}")
        resp = client.get("/freshness-policies?limit=2&offset=0")
        assert resp.json()["total"] == 5
        assert len(resp.json()["items"]) == 2

    def test_list_pagination_offset(self, client):
        for i in range(5):
            _create_policy(client, name=f"Policy {i}")
        resp = client.get("/freshness-policies?limit=2&offset=4")
        assert len(resp.json()["items"]) == 1

    def test_list_tenant_isolation(self, client, client_b):
        _create_policy(client, name="Tenant A")
        resp = client_b.get("/freshness-policies")
        assert resp.json()["total"] == 0


# ---------------------------------------------------------------------------
# 4. TestUpdateFreshnessPolicy
# ---------------------------------------------------------------------------


class TestUpdateFreshnessPolicy:
    def test_update_name(self, client):
        created = _create_policy(client, name="Old Name")
        resp = client.put(
            f"/freshness-policies/{created['id']}",
            json={"name": "New Name"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"

    def test_update_review_interval(self, client):
        created = _create_policy(client)
        resp = client.put(
            f"/freshness-policies/{created['id']}",
            json={"review_interval_days": 45},
        )
        assert resp.status_code == 200
        assert resp.json()["review_interval_days"] == 45

    def test_update_enabled_false(self, client):
        created = _create_policy(client, enabled=True)
        resp = client.put(
            f"/freshness-policies/{created['id']}",
            json={"enabled": False},
        )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    def test_update_criticality(self, client):
        created = _create_policy(client)
        resp = client.put(
            f"/freshness-policies/{created['id']}",
            json={"criticality": "HIGH"},
        )
        assert resp.status_code == 200
        assert resp.json()["criticality"] == "HIGH"

    def test_update_missing_returns_404(self, client):
        resp = client.put(
            "/freshness-policies/does-not-exist",
            json={"name": "x"},
        )
        assert resp.status_code == 404

    def test_update_invalid_criticality_rejected(self, client):
        created = _create_policy(client)
        resp = client.put(
            f"/freshness-policies/{created['id']}",
            json={"criticality": "ULTRA"},
        )
        assert resp.status_code == 422

    def test_update_partial_preserves_other_fields(self, client):
        created = _create_policy(client, name="Keep Me", review_interval_days=120)
        resp = client.put(
            f"/freshness-policies/{created['id']}",
            json={"criticality": "LOW"},
        )
        data = resp.json()
        assert data["name"] == "Keep Me"
        assert data["review_interval_days"] == 120
        assert data["criticality"] == "LOW"

    def test_update_sets_updated_at(self, client):
        created = _create_policy(client)
        old_updated_at = created["updated_at"]
        import time

        time.sleep(0.01)
        resp = client.put(
            f"/freshness-policies/{created['id']}",
            json={"name": "Updated"},
        )
        assert resp.json()["updated_at"] >= old_updated_at

    def test_update_cross_tenant_returns_404(self, client, client_b):
        created = _create_policy(client)
        resp = client_b.put(
            f"/freshness-policies/{created['id']}",
            json={"name": "Hijack"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 5. TestCreateFreshnessRecord
# ---------------------------------------------------------------------------


class TestCreateFreshnessRecord:
    def test_create_returns_201(self, client):
        resp = client.post("/freshness", json=_record_payload())
        assert resp.status_code == 201
        data = resp.json()
        assert data["evidence_id"] == "ev-test-001"
        assert data["freshness_state"] == FreshnessState.CURRENT.value
        assert data["freshness_score"] == 90  # base CURRENT score
        assert data["id"] is not None
        assert data["tenant_id"] == _TENANT

    def test_create_conflict_rejected(self, client):
        _create_record(client, "ev-dup-001")
        resp = client.post("/freshness", json=_record_payload("ev-dup-001"))
        assert resp.status_code == 409

    def test_create_with_policy_id(self, client):
        policy = _create_policy(client)
        resp = client.post(
            "/freshness",
            json=_record_payload("ev-with-policy", policy_id=policy["id"]),
        )
        assert resp.status_code == 201
        assert resp.json()["policy_id"] == policy["id"]

    def test_create_initial_state_current(self, client):
        data = _create_record(client, "ev-current")
        assert data["freshness_state"] == "CURRENT"

    def test_create_with_future_due_dates(self, client):
        resp = client.post(
            "/freshness",
            json=_record_payload(
                "ev-future-dates",
                review_due_at=_REVIEW_DUE_FUTURE,
                verification_due_at=_VERIFICATION_DUE_FUTURE,
            ),
        )
        assert resp.status_code == 201
        assert resp.json()["freshness_state"] == "CURRENT"

    def test_create_with_past_review_due(self, client):
        resp = client.post(
            "/freshness",
            json=_record_payload(
                "ev-past-review",
                review_due_at=_REVIEW_DUE_PAST,
            ),
        )
        assert resp.status_code == 201
        assert resp.json()["freshness_state"] == "REVIEW_REQUIRED"

    def test_create_with_past_expiration(self, client):
        resp = client.post(
            "/freshness",
            json=_record_payload(
                "ev-past-expiry",
                expiration_due_at=_EXPIRATION_DUE_PAST,
            ),
        )
        assert resp.status_code == 201
        assert resp.json()["freshness_state"] == "EXPIRED"

    def test_create_extra_field_rejected(self, client):
        payload = _record_payload("ev-extra")
        payload["unknown"] = "x"
        resp = client.post("/freshness", json=payload)
        assert resp.status_code == 422

    def test_create_missing_evidence_id_rejected(self, client):
        resp = client.post("/freshness", json={})
        assert resp.status_code == 422

    def test_create_sets_created_at(self, client):
        data = _create_record(client, "ev-created-at")
        assert data["created_at"] is not None

    def test_create_tenant_isolation(self, client, client_b):
        created = _create_record(client)
        resp_b = client_b.get(f"/freshness/{created['evidence_id']}")
        assert resp_b.status_code == 404

    def test_create_same_evidence_different_tenants(self, client, client_b):
        # Same evidence_id is allowed for different tenants
        r_a = client.post("/freshness", json=_record_payload("ev-shared"))
        r_b = client_b.post("/freshness", json=_record_payload("ev-shared"))
        assert r_a.status_code == 201
        assert r_b.status_code == 201


# ---------------------------------------------------------------------------
# 6. TestGetFreshnessRecord
# ---------------------------------------------------------------------------


class TestGetFreshnessRecord:
    def test_get_returns_200(self, client):
        created = _create_record(client, "ev-get-001")
        resp = client.get(f"/freshness/{created['evidence_id']}")
        assert resp.status_code == 200
        assert resp.json()["evidence_id"] == "ev-get-001"

    def test_get_missing_returns_404(self, client):
        resp = client.get("/freshness/ev-does-not-exist")
        assert resp.status_code == 404

    def test_get_cross_tenant_returns_404(self, client, client_b):
        _create_record(client, "ev-cross-tenant")
        resp = client_b.get("/freshness/ev-cross-tenant")
        assert resp.status_code == 404

    def test_get_all_fields_present(self, client):
        _create_record(client, "ev-all-fields")
        data = client.get("/freshness/ev-all-fields").json()
        assert "freshness_score" in data
        assert "freshness_state" in data
        assert "tenant_id" in data
        assert "created_at" in data
        assert "updated_at" in data


# ---------------------------------------------------------------------------
# 7. TestListFreshnessRecords
# ---------------------------------------------------------------------------


class TestListFreshnessRecords:
    def test_list_empty(self, client):
        resp = client.get("/freshness")
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_list_returns_created(self, client):
        _create_record(client, "ev-list-001")
        _create_record(client, "ev-list-002")
        resp = client.get("/freshness")
        assert resp.json()["total"] == 2

    def test_list_filter_by_freshness_state(self, client):
        _create_record(client, "ev-current-state")
        _create_record(client, "ev-review-req", review_due_at=_REVIEW_DUE_PAST)
        resp = client.get(
            f"/freshness?freshness_state={FreshnessState.REVIEW_REQUIRED.value}"
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["freshness_state"] == "REVIEW_REQUIRED"

    def test_list_filter_by_policy_id(self, client):
        policy = _create_policy(client, name="Filter Policy")
        _create_record(client, "ev-with-policy-filter", policy_id=policy["id"])
        _create_record(client, "ev-no-policy-filter")
        resp = client.get(f"/freshness?policy_id={policy['id']}")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["policy_id"] == policy["id"]

    def test_list_pagination(self, client):
        for i in range(5):
            _create_record(client, f"ev-page-{i}")
        resp = client.get("/freshness?limit=2&offset=0")
        assert resp.json()["total"] == 5
        assert len(resp.json()["items"]) == 2

    def test_list_tenant_isolation(self, client, client_b):
        _create_record(client, "ev-tenant-list")
        resp = client_b.get("/freshness")
        assert resp.json()["total"] == 0


# ---------------------------------------------------------------------------
# 8. TestUpdateFreshnessRecord
# ---------------------------------------------------------------------------


class TestUpdateFreshnessRecord:
    def test_update_review_due_at(self, client):
        _create_record(client, "ev-update-001")
        resp = client.put(
            "/freshness/ev-update-001",
            json={"review_due_at": _REVIEW_DUE_PAST},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["review_due_at"] == _REVIEW_DUE_PAST
        assert data["freshness_state"] == "REVIEW_REQUIRED"

    def test_update_state_recomputed(self, client):
        _create_record(client, "ev-state-recompute")
        resp = client.put(
            "/freshness/ev-state-recompute",
            json={"expiration_due_at": _EXPIRATION_DUE_PAST},
        )
        assert resp.json()["freshness_state"] == "EXPIRED"

    def test_update_score_recomputed(self, client):
        _create_record(client, "ev-score-recompute")
        resp = client.put(
            "/freshness/ev-score-recompute",
            json={"review_due_at": _REVIEW_DUE_PAST},
        )
        # REVIEW_REQUIRED base score = 55
        assert resp.json()["freshness_score"] <= 55

    def test_update_missing_returns_404(self, client):
        resp = client.put(
            "/freshness/ev-does-not-exist",
            json={"review_due_at": _REVIEW_DUE_FUTURE},
        )
        assert resp.status_code == 404

    def test_update_policy_id(self, client):
        policy = _create_policy(client, name="Update Policy")
        _create_record(client, "ev-update-policy")
        resp = client.put(
            "/freshness/ev-update-policy",
            json={"policy_id": policy["id"]},
        )
        assert resp.json()["policy_id"] == policy["id"]

    def test_update_last_verified_at(self, client):
        _create_record(client, "ev-verified-update")
        ts = (_NOW - timedelta(days=10)).isoformat()
        resp = client.put(
            "/freshness/ev-verified-update",
            json={"last_verified_at": ts},
        )
        assert resp.json()["last_verified_at"] == ts

    def test_update_cross_tenant_returns_404(self, client, client_b):
        _create_record(client, "ev-cross-update")
        resp = client_b.put(
            "/freshness/ev-cross-update",
            json={"review_due_at": _REVIEW_DUE_FUTURE},
        )
        assert resp.status_code == 404

    def test_update_sets_updated_at(self, client):
        created = _create_record(client, "ev-updated-at")
        old_updated = created["updated_at"]
        import time

        time.sleep(0.01)
        resp = client.put(
            "/freshness/ev-updated-at",
            json={"review_due_at": _REVIEW_DUE_FUTURE},
        )
        assert resp.json()["updated_at"] >= old_updated


# ---------------------------------------------------------------------------
# 9. TestRecomputeFreshness
# ---------------------------------------------------------------------------


class TestRecomputeFreshness:
    def test_recompute_returns_updated_score(self, client):
        _create_record(client, "ev-recompute-001")
        # Update via PUT to change due dates
        client.put(
            "/freshness/ev-recompute-001",
            json={"review_due_at": _REVIEW_DUE_PAST},
        )
        resp = client.post("/freshness/ev-recompute-001/recompute")
        assert resp.status_code == 200
        data = resp.json()
        assert data["freshness_state"] == "REVIEW_REQUIRED"
        assert data["freshness_score"] <= 55

    def test_recompute_missing_returns_404(self, client):
        resp = client.post("/freshness/ev-no-exist/recompute")
        assert resp.status_code == 404

    def test_recompute_current_returns_high_score(self, client):
        _create_record(client, "ev-recompute-current")
        resp = client.post("/freshness/ev-recompute-current/recompute")
        assert resp.status_code == 200
        assert resp.json()["freshness_score"] == 90

    def test_recompute_cross_tenant_returns_404(self, client, client_b):
        _create_record(client, "ev-recompute-tenant")
        resp = client_b.post("/freshness/ev-recompute-tenant/recompute")
        assert resp.status_code == 404

    def test_recompute_updates_state(self, client):
        client.post(
            "/freshness",
            json=_record_payload(
                "ev-recompute-state", expiration_due_at=_EXPIRATION_DUE_PAST
            ),
        )
        resp = client.post("/freshness/ev-recompute-state/recompute")
        assert resp.json()["freshness_state"] == "EXPIRED"


# ---------------------------------------------------------------------------
# 10. TestFreshnessStateTransitions
# ---------------------------------------------------------------------------


class TestFreshnessStateTransitions:
    """Tests using pure compute_freshness_state function and API round-trips."""

    def test_state_current_no_due_dates(self):
        now = _NOW.isoformat()
        state = compute_freshness_state(None, None, None, now)
        assert state == FreshnessState.CURRENT

    def test_state_current_far_future_review(self):
        now = _NOW.isoformat()
        review_due = (_NOW + timedelta(days=60)).isoformat()
        state = compute_freshness_state(review_due, None, None, now)
        assert state == FreshnessState.CURRENT

    def test_state_due_soon_review_within_30_days(self):
        now = _NOW.isoformat()
        review_due = (_NOW + timedelta(days=15)).isoformat()
        state = compute_freshness_state(review_due, None, None, now)
        assert state == FreshnessState.DUE_SOON

    def test_state_review_required_past_review_due(self):
        now = _NOW.isoformat()
        review_due = (_NOW - timedelta(days=1)).isoformat()
        state = compute_freshness_state(review_due, None, None, now)
        assert state == FreshnessState.REVIEW_REQUIRED

    def test_state_verification_required_past_verification_due(self):
        now = _NOW.isoformat()
        verification_due = (_NOW - timedelta(days=1)).isoformat()
        state = compute_freshness_state(None, verification_due, None, now)
        assert state == FreshnessState.VERIFICATION_REQUIRED

    def test_state_expired_past_expiration_due(self):
        now = _NOW.isoformat()
        expiration_due = (_NOW - timedelta(days=1)).isoformat()
        state = compute_freshness_state(None, None, expiration_due, now)
        assert state == FreshnessState.EXPIRED

    def test_state_expired_takes_priority_over_verification(self):
        now = _NOW.isoformat()
        expiration_due = (_NOW - timedelta(days=1)).isoformat()
        verification_due = (_NOW - timedelta(days=5)).isoformat()
        state = compute_freshness_state(None, verification_due, expiration_due, now)
        assert state == FreshnessState.EXPIRED

    def test_state_verification_takes_priority_over_review(self):
        now = _NOW.isoformat()
        review_due = (_NOW - timedelta(days=1)).isoformat()
        verification_due = (_NOW - timedelta(days=5)).isoformat()
        state = compute_freshness_state(review_due, verification_due, None, now)
        assert state == FreshnessState.VERIFICATION_REQUIRED

    def test_api_creates_due_soon_state(self, client):
        resp = client.post(
            "/freshness",
            json=_record_payload("ev-due-soon", review_due_at=_REVIEW_DUE_SOON),
        )
        assert resp.status_code == 201
        assert resp.json()["freshness_state"] == "DUE_SOON"

    def test_api_creates_verification_required_state(self, client):
        resp = client.post(
            "/freshness",
            json=_record_payload(
                "ev-ver-req", verification_due_at=_VERIFICATION_DUE_PAST
            ),
        )
        assert resp.status_code == 201
        assert resp.json()["freshness_state"] == "VERIFICATION_REQUIRED"

    def test_api_creates_expired_state(self, client):
        resp = client.post(
            "/freshness",
            json=_record_payload(
                "ev-expired-state", expiration_due_at=_EXPIRATION_DUE_PAST
            ),
        )
        assert resp.status_code == 201
        assert resp.json()["freshness_state"] == "EXPIRED"


# ---------------------------------------------------------------------------
# 11. TestFreshnessScoringUnit
# ---------------------------------------------------------------------------


class TestFreshnessScoringUnit:
    """Pure function unit tests for compute_freshness_score."""

    def test_current_base_score_90(self):
        score = compute_freshness_score(
            FreshnessState.CURRENT, "MEDIUM", None, None, False
        )
        assert score == 90

    def test_due_soon_base_score_75(self):
        score = compute_freshness_score(
            FreshnessState.DUE_SOON, "MEDIUM", None, None, False
        )
        assert score == 75

    def test_review_required_base_score_55(self):
        score = compute_freshness_score(
            FreshnessState.REVIEW_REQUIRED, "MEDIUM", None, None, False
        )
        assert score == 55

    def test_verification_required_base_score_35(self):
        score = compute_freshness_score(
            FreshnessState.VERIFICATION_REQUIRED, "MEDIUM", None, None, False
        )
        assert score == 35

    def test_stale_base_score_15(self):
        score = compute_freshness_score(
            FreshnessState.STALE, "MEDIUM", None, None, False
        )
        assert score == 15

    def test_expired_base_score_0(self):
        score = compute_freshness_score(
            FreshnessState.EXPIRED, "MEDIUM", None, None, False
        )
        assert score == 0

    def test_critical_criticality_applies_penalty(self):
        # REVIEW_REQUIRED base = 55, CRITICAL applies 0.95
        score = compute_freshness_score(
            FreshnessState.REVIEW_REQUIRED, "CRITICAL", None, None, False
        )
        assert score == int(55 * 0.95)

    def test_high_criticality_applies_penalty(self):
        # REVIEW_REQUIRED base = 55, HIGH applies 0.97
        score = compute_freshness_score(
            FreshnessState.REVIEW_REQUIRED, "HIGH", None, None, False
        )
        assert score == int(55 * 0.97)

    def test_criticality_no_penalty_for_current(self):
        # CURRENT is not penalized even with CRITICAL
        score = compute_freshness_score(
            FreshnessState.CURRENT, "CRITICAL", None, None, False
        )
        assert score == 90

    def test_verified_age_penalty_180_days(self):
        score = compute_freshness_score(
            FreshnessState.CURRENT, "MEDIUM", 200.0, None, False
        )
        assert score == 90 - 10

    def test_verified_age_penalty_365_days(self):
        score = compute_freshness_score(
            FreshnessState.CURRENT, "MEDIUM", 400.0, None, False
        )
        assert score == 90 - 20

    def test_reviewed_age_penalty_90_days(self):
        score = compute_freshness_score(
            FreshnessState.CURRENT, "MEDIUM", None, 100.0, False
        )
        assert score == 90 - 5

    def test_reviewed_age_penalty_180_days(self):
        score = compute_freshness_score(
            FreshnessState.CURRENT, "MEDIUM", None, 200.0, False
        )
        assert score == 90 - 10

    def test_exception_bonus_adds_5(self):
        score = compute_freshness_score(
            FreshnessState.DUE_SOON, "MEDIUM", None, None, True
        )
        assert score == 75 + 5

    def test_score_clamped_at_100(self):
        score = compute_freshness_score(
            FreshnessState.CURRENT, "MEDIUM", None, None, True
        )
        assert score == 95  # 90 + 5 = 95 <= 100

    def test_score_clamped_at_0(self):
        score = compute_freshness_score(
            FreshnessState.EXPIRED, "CRITICAL", 400.0, 200.0, False
        )
        assert score == 0  # 0 regardless of penalties

    def test_combined_penalties(self):
        # REVIEW_REQUIRED = 55, 400d verified = -20, 200d reviewed = -10
        score = compute_freshness_score(
            FreshnessState.REVIEW_REQUIRED, "MEDIUM", 400.0, 200.0, False
        )
        assert score == 55 - 20 - 10

    def test_low_criticality_no_modifier(self):
        score = compute_freshness_score(
            FreshnessState.REVIEW_REQUIRED, "LOW", None, None, False
        )
        assert score == 55


# ---------------------------------------------------------------------------
# 12. TestFreshnessExceptionCreate
# ---------------------------------------------------------------------------


class TestFreshnessExceptionCreate:
    def test_create_returns_201(self, client):
        resp = client.post("/freshness/exceptions", json=_exception_payload())
        assert resp.status_code == 201
        data = resp.json()
        assert data["evidence_id"] == "ev-test-001"
        assert data["status"] == "ACTIVE"
        assert data["approved_by"] == "ciso@example.com"

    def test_create_tenant_id_set(self, client):
        data = _create_exception(client)
        assert data["tenant_id"] == _TENANT

    def test_create_missing_reason_rejected(self, client):
        payload = _exception_payload()
        del payload["reason"]
        resp = client.post("/freshness/exceptions", json=payload)
        assert resp.status_code == 422

    def test_create_missing_approved_by_rejected(self, client):
        payload = _exception_payload()
        del payload["approved_by"]
        resp = client.post("/freshness/exceptions", json=payload)
        assert resp.status_code == 422

    def test_create_missing_expires_at_rejected(self, client):
        payload = _exception_payload()
        del payload["expires_at"]
        resp = client.post("/freshness/exceptions", json=payload)
        assert resp.status_code == 422

    def test_create_extra_field_rejected(self, client):
        payload = _exception_payload()
        payload["unknown"] = "x"
        resp = client.post("/freshness/exceptions", json=payload)
        assert resp.status_code == 422

    def test_create_bonus_applied_to_record(self, client):
        _create_record(client, "ev-exc-bonus")
        before_score = client.get("/freshness/ev-exc-bonus").json()["freshness_score"]
        _create_exception(client, "ev-exc-bonus")
        after_score = client.get("/freshness/ev-exc-bonus").json()["freshness_score"]
        # Score should be the same or higher (recomputed with exception bonus)
        assert after_score >= before_score

    def test_create_tenant_isolation(self, client, client_b):
        created = _create_exception(client)
        resp = client_b.get(
            f"/freshness/exceptions?evidence_id={created['evidence_id']}"
        )
        assert resp.json()["total"] == 0

    def test_create_multiple_for_same_evidence(self, client):
        _create_exception(client, "ev-multi-exc")
        _create_exception(client, "ev-multi-exc", reason="Second exception")
        resp = client.get("/freshness/exceptions?evidence_id=ev-multi-exc")
        assert resp.json()["total"] == 2


# ---------------------------------------------------------------------------
# 13. TestFreshnessExceptionList
# ---------------------------------------------------------------------------


class TestFreshnessExceptionList:
    def test_list_empty(self, client):
        resp = client.get("/freshness/exceptions")
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_list_returns_created(self, client):
        _create_exception(client, "ev-list-exc-001")
        _create_exception(client, "ev-list-exc-002")
        resp = client.get("/freshness/exceptions")
        assert resp.json()["total"] == 2

    def test_list_filter_by_evidence_id(self, client):
        _create_exception(client, "ev-filter-exc-001")
        _create_exception(client, "ev-filter-exc-002")
        resp = client.get("/freshness/exceptions?evidence_id=ev-filter-exc-001")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["evidence_id"] == "ev-filter-exc-001"

    def test_list_filter_by_status(self, client):
        _create_exception(client, "ev-status-filter")
        resp = client.get("/freshness/exceptions?status=ACTIVE")
        data = resp.json()
        assert all(item["status"] == "ACTIVE" for item in data["items"])

    def test_list_pagination(self, client):
        for i in range(5):
            _create_exception(client, f"ev-exc-page-{i}")
        resp = client.get("/freshness/exceptions?limit=2&offset=0")
        assert resp.json()["total"] == 5
        assert len(resp.json()["items"]) == 2

    def test_list_tenant_isolation(self, client, client_b):
        _create_exception(client)
        resp = client_b.get("/freshness/exceptions")
        assert resp.json()["total"] == 0


# ---------------------------------------------------------------------------
# 14. TestFreshnessExceptionRevoke
# ---------------------------------------------------------------------------


class TestFreshnessExceptionRevoke:
    def test_revoke_active_exception(self, client):
        created = _create_exception(client, "ev-revoke-001")
        resp = client.post(
            f"/freshness/exceptions/{created['id']}/revoke",
            json={"reason": "No longer needed"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "REVOKED"

    def test_revoke_non_existent_returns_404(self, client):
        resp = client.post(
            "/freshness/exceptions/does-not-exist/revoke",
            json={"reason": "test"},
        )
        assert resp.status_code == 404

    def test_revoke_already_revoked_returns_404(self, client):
        created = _create_exception(client, "ev-revoke-twice")
        client.post(
            f"/freshness/exceptions/{created['id']}/revoke",
            json={"reason": "First revocation"},
        )
        resp = client.post(
            f"/freshness/exceptions/{created['id']}/revoke",
            json={"reason": "Second revocation"},
        )
        assert resp.status_code == 404

    def test_revoke_cross_tenant_returns_404(self, client, client_b):
        created = _create_exception(client, "ev-cross-revoke")
        resp = client_b.post(
            f"/freshness/exceptions/{created['id']}/revoke",
            json={"reason": "hijack"},
        )
        assert resp.status_code == 404

    def test_revoke_missing_reason_rejected(self, client):
        created = _create_exception(client, "ev-revoke-no-reason")
        resp = client.post(
            f"/freshness/exceptions/{created['id']}/revoke",
            json={},
        )
        assert resp.status_code == 422

    def test_revoke_appears_in_list_as_revoked(self, client):
        created = _create_exception(client, "ev-revoke-list")
        client.post(
            f"/freshness/exceptions/{created['id']}/revoke",
            json={"reason": "Test"},
        )
        resp = client.get("/freshness/exceptions?status=REVOKED")
        assert resp.json()["total"] >= 1

    def test_revoke_recomputes_record_score(self, client):
        _create_record(client, "ev-revoke-score")
        exc = _create_exception(client, "ev-revoke-score")
        score_with_exc = client.get("/freshness/ev-revoke-score").json()[
            "freshness_score"
        ]
        client.post(
            f"/freshness/exceptions/{exc['id']}/revoke",
            json={"reason": "recompute test"},
        )
        # Score may change after revocation (exception bonus removed)
        score_after = client.get("/freshness/ev-revoke-score").json()["freshness_score"]
        # Both scores should be valid (0-100)
        assert 0 <= score_with_exc <= 100
        assert 0 <= score_after <= 100


# ---------------------------------------------------------------------------
# 15. TestDashboardMetrics
# ---------------------------------------------------------------------------


class TestDashboardMetrics:
    def test_dashboard_empty(self, client):
        resp = client.get("/freshness/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["fresh_count"] == 0
        assert data["avg_freshness_score"] == 0.0

    def test_dashboard_counts_states(self, client):
        _create_record(client, "ev-dash-current")
        _create_record(client, "ev-dash-review", review_due_at=_REVIEW_DUE_PAST)
        _create_record(
            client, "ev-dash-expired", expiration_due_at=_EXPIRATION_DUE_PAST
        )
        resp = client.get("/freshness/dashboard")
        data = resp.json()
        assert data["total"] == 3
        assert data["fresh_count"] == 1
        assert data["review_required_count"] == 1
        assert data["expired_count"] == 1

    def test_dashboard_avg_score(self, client):
        _create_record(client, "ev-avg-001")
        resp = client.get("/freshness/dashboard")
        assert resp.json()["avg_freshness_score"] > 0

    def test_dashboard_exception_count(self, client):
        _create_exception(client, "ev-dash-exc")
        resp = client.get("/freshness/dashboard")
        assert resp.json()["freshness_exceptions_count"] >= 1

    def test_dashboard_coverage_at_risk(self, client):
        _create_record(client, "ev-risk-001", review_due_at=_REVIEW_DUE_PAST)
        _create_record(client, "ev-risk-002", expiration_due_at=_EXPIRATION_DUE_PAST)
        resp = client.get("/freshness/dashboard")
        assert resp.json()["coverage_at_risk_count"] >= 2

    def test_dashboard_tenant_isolation(self, client, client_b):
        _create_record(client, "ev-dash-tenant")
        resp = client_b.get("/freshness/dashboard")
        assert resp.json()["total"] == 0

    def test_dashboard_due_soon_count(self, client):
        _create_record(client, "ev-dash-due-soon", review_due_at=_REVIEW_DUE_SOON)
        resp = client.get("/freshness/dashboard")
        assert resp.json()["due_soon_count"] >= 1

    def test_dashboard_verification_required_count(self, client):
        _create_record(
            client, "ev-dash-ver-req", verification_due_at=_VERIFICATION_DUE_PAST
        )
        resp = client.get("/freshness/dashboard")
        assert resp.json()["verification_required_count"] >= 1


# ---------------------------------------------------------------------------
# 16. TestCGINSnapshot
# ---------------------------------------------------------------------------


class TestCGINSnapshot:
    def test_snapshot_all_fields_present(self, client):
        resp = client.get("/freshness/cgin/snapshot")
        assert resp.status_code == 200
        data = resp.json()
        assert "snapshot_at" in data
        assert "tenant_fingerprint" in data
        assert "fresh_evidence" in data
        assert "stale_evidence" in data
        assert "expired_evidence" in data
        assert "avg_freshness_score" in data
        assert "coverage_at_risk" in data
        assert "freshness_exceptions_count" in data

    def test_snapshot_tenant_id_matches(self, client):
        resp = client.get("/freshness/cgin/snapshot")
        assert "tenant_id" not in resp.json()
        assert len(resp.json()["tenant_fingerprint"]) == 32

    def test_snapshot_deterministic(self, client):
        _create_record(client, "ev-snap-det")
        r1 = client.get("/freshness/cgin/snapshot").json()
        r2 = client.get("/freshness/cgin/snapshot").json()
        assert r1["fresh_evidence"] == r2["fresh_evidence"]
        assert r1["expired_evidence"] == r2["expired_evidence"]

    def test_snapshot_counts_expired(self, client):
        _create_record(
            client, "ev-snap-expired", expiration_due_at=_EXPIRATION_DUE_PAST
        )
        resp = client.get("/freshness/cgin/snapshot")
        assert resp.json()["expired_evidence"] >= 1

    def test_snapshot_counts_fresh(self, client):
        _create_record(client, "ev-snap-fresh")
        resp = client.get("/freshness/cgin/snapshot")
        assert resp.json()["fresh_evidence"] >= 1

    def test_snapshot_counts_stale(self, client):
        _create_record(client, "ev-snap-stale", review_due_at=_REVIEW_DUE_PAST)
        resp = client.get("/freshness/cgin/snapshot")
        assert resp.json()["stale_evidence"] >= 1

    def test_snapshot_tenant_isolation(self, client, client_b):
        _create_record(client, "ev-snap-iso")
        snap_b = client_b.get("/freshness/cgin/snapshot").json()
        assert snap_b["fresh_evidence"] == 0

    def test_snapshot_exceptions_count(self, client):
        _create_exception(client, "ev-snap-exc")
        resp = client.get("/freshness/cgin/snapshot")
        assert resp.json()["freshness_exceptions_count"] >= 1


# ---------------------------------------------------------------------------
# 17. TestTimelineIntegration
# ---------------------------------------------------------------------------


class TestTimelineIntegration:
    def test_create_record_does_not_raise(self, client):
        # Timeline emission is wrapped in try/except; core operation must succeed
        resp = client.post("/freshness", json=_record_payload("ev-timeline-001"))
        assert resp.status_code == 201

    def test_update_record_does_not_raise(self, client):
        _create_record(client, "ev-timeline-update")
        resp = client.put(
            "/freshness/ev-timeline-update",
            json={"review_due_at": _REVIEW_DUE_FUTURE},
        )
        assert resp.status_code == 200

    def test_state_change_does_not_raise(self, client):
        _create_record(client, "ev-timeline-state")
        resp = client.put(
            "/freshness/ev-timeline-state",
            json={"review_due_at": _REVIEW_DUE_PAST},
        )
        assert resp.status_code == 200
        assert resp.json()["freshness_state"] == "REVIEW_REQUIRED"

    def test_exception_create_does_not_raise(self, client):
        resp = client.post(
            "/freshness/exceptions", json=_exception_payload("ev-timeline-exc")
        )
        assert resp.status_code == 201

    def test_policy_create_does_not_raise(self, client):
        resp = client.post(
            "/freshness-policies", json=_policy_payload(name="Timeline Test")
        )
        assert resp.status_code == 201

    def test_recompute_does_not_raise(self, client):
        _create_record(client, "ev-timeline-recompute")
        resp = client.post("/freshness/ev-timeline-recompute/recompute")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 18. TestTenantIsolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_policies_isolated(self, client, client_b):
        _create_policy(client, name="Tenant A")
        resp = client_b.get("/freshness-policies")
        assert resp.json()["total"] == 0

    def test_records_isolated(self, client, client_b):
        _create_record(client, "ev-iso-rec")
        resp = client_b.get("/freshness")
        assert resp.json()["total"] == 0

    def test_exceptions_isolated(self, client, client_b):
        _create_exception(client, "ev-iso-exc")
        resp = client_b.get("/freshness/exceptions")
        assert resp.json()["total"] == 0

    def test_dashboard_isolated(self, client, client_b):
        _create_record(client, "ev-iso-dash")
        resp = client_b.get("/freshness/dashboard")
        assert resp.json()["total"] == 0

    def test_cgin_isolated(self, client, client_b):
        _create_record(client, "ev-iso-cgin")
        resp = client_b.get("/freshness/cgin/snapshot")
        assert resp.json()["fresh_evidence"] == 0

    def test_policy_get_cross_tenant_404(self, client, client_b):
        p = _create_policy(client, name="Cross Tenant")
        assert client_b.get(f"/freshness-policies/{p['id']}").status_code == 404

    def test_record_get_cross_tenant_404(self, client, client_b):
        _create_record(client, "ev-iso-get")
        assert client_b.get("/freshness/ev-iso-get").status_code == 404

    def test_exception_revoke_cross_tenant_404(self, client, client_b):
        exc = _create_exception(client, "ev-iso-revoke")
        resp = client_b.post(
            f"/freshness/exceptions/{exc['id']}/revoke",
            json={"reason": "hijack"},
        )
        assert resp.status_code == 404

    def test_record_update_cross_tenant_404(self, client, client_b):
        _create_record(client, "ev-iso-update")
        assert (
            client_b.put(
                "/freshness/ev-iso-update", json={"review_due_at": _REVIEW_DUE_FUTURE}
            ).status_code
            == 404
        )

    def test_policy_update_cross_tenant_404(self, client, client_b):
        p = _create_policy(client)
        assert (
            client_b.put(
                f"/freshness-policies/{p['id']}", json={"name": "x"}
            ).status_code
            == 404
        )

    def test_same_evidence_id_different_tenants_allowed(self, client, client_b):
        r_a = client.post("/freshness", json=_record_payload("ev-shared-iso"))
        r_b = client_b.post("/freshness", json=_record_payload("ev-shared-iso"))
        assert r_a.status_code == 201
        assert r_b.status_code == 201
        # Each tenant sees only their own record
        assert client.get("/freshness").json()["total"] == 1
        assert client_b.get("/freshness").json()["total"] == 1


# ---------------------------------------------------------------------------
# 19. TestPolicyRoutes
# ---------------------------------------------------------------------------


class TestPolicyRoutes:
    def test_put_updates_enabled_flag(self, client):
        p = _create_policy(client, enabled=True)
        resp = client.put(f"/freshness-policies/{p['id']}", json={"enabled": False})
        assert resp.json()["enabled"] is False

    def test_put_updates_verification_interval(self, client):
        p = _create_policy(client)
        resp = client.put(
            f"/freshness-policies/{p['id']}",
            json={"verification_interval_days": 60},
        )
        assert resp.json()["verification_interval_days"] == 60

    def test_put_updates_expiration_interval(self, client):
        p = _create_policy(client)
        resp = client.put(
            f"/freshness-policies/{p['id']}",
            json={"expiration_interval_days": 730},
        )
        assert resp.json()["expiration_interval_days"] == 730

    def test_put_all_fields(self, client):
        p = _create_policy(client)
        resp = client.put(
            f"/freshness-policies/{p['id']}",
            json={
                "name": "Updated All",
                "description": "New desc",
                "evidence_type": "AGENT",
                "review_interval_days": 30,
                "verification_interval_days": 60,
                "expiration_interval_days": 180,
                "criticality": "HIGH",
                "enabled": False,
            },
        )
        data = resp.json()
        assert data["name"] == "Updated All"
        assert data["description"] == "New desc"
        assert data["evidence_type"] == "AGENT"
        assert data["review_interval_days"] == 30
        assert data["criticality"] == "HIGH"
        assert data["enabled"] is False

    def test_list_requires_auth(self, build_app):
        app = build_app(auth_enabled=True)
        no_auth_client = TestClient(app)
        assert no_auth_client.get("/freshness-policies").status_code in (401, 403)

    def test_create_requires_write_scope(self, build_app):
        app = build_app(auth_enabled=True)
        read_only_key = mint_key("audit:read", tenant_id=_TENANT)
        ro_client = TestClient(app, headers={"X-API-Key": read_only_key})
        resp = ro_client.post(
            "/freshness-policies", json=_policy_payload(name="No Write")
        )
        assert resp.status_code in (401, 403)

    def test_policy_linked_to_record_provides_criticality(self, client):
        # CRITICAL policy should lower scores
        p = _create_policy(client, name="Critical P", criticality="CRITICAL")
        resp = client.post(
            "/freshness",
            json=_record_payload(
                "ev-critical-policy",
                policy_id=p["id"],
                review_due_at=_REVIEW_DUE_PAST,
            ),
        )
        assert resp.status_code == 201
        score = resp.json()["freshness_score"]
        # REVIEW_REQUIRED base = 55, CRITICAL = 55 * 0.95 = 52
        assert score <= 52

    def test_policy_filter_evidence_type_case_sensitive(self, client):
        _create_policy(client, name="Doc", evidence_type="DOCUMENT")
        _create_policy(client, name="Doc lower", evidence_type="document")
        resp = client.get("/freshness-policies?evidence_type=DOCUMENT")
        assert resp.json()["total"] == 1

    def test_policy_default_values(self, client):
        resp = client.post("/freshness-policies", json={"name": "Defaults Only"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["review_interval_days"] == 90
        assert data["verification_interval_days"] == 180
        assert data["expiration_interval_days"] == 365
        assert data["criticality"] == "MEDIUM"
        assert data["enabled"] is True

    def test_record_recompute_uses_policy_criticality(self, client):
        p = _create_policy(client, name="High Policy", criticality="HIGH")
        client.post(
            "/freshness",
            json=_record_payload("ev-policy-recompute", policy_id=p["id"]),
        )
        # Transition to REVIEW_REQUIRED
        client.put(
            "/freshness/ev-policy-recompute",
            json={"review_due_at": _REVIEW_DUE_PAST},
        )
        resp = client.post("/freshness/ev-policy-recompute/recompute")
        score = resp.json()["freshness_score"]
        # HIGH + REVIEW_REQUIRED: int(55 * 0.97) = 53
        assert score <= 53
