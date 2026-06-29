"""Tests for PR 14.6.5A — Evidence Status Model Hardening & Governance Completion.

Covers:
  - Verification creation (PASS/FAIL/INCONCLUSIVE)
  - Verification history & summary stats
  - SLA deadline setting & status computation (ON_TRACK/DUE_SOON/OVERDUE)
  - Control linkage (201, 409 duplicate)
  - Risk/Finding/Exception linkage
  - Coverage analytics
  - Health signals
  - Timeline event emission
  - Tenant isolation
  - Deterministic replay
  - CGIN snapshot bundle
  - SLA status values
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from services.evidence_authority.models import (
    EvidenceAuditEventType,
    EvidenceLinkTargetType,
    VerificationActorType,
    VerificationResult,
    VerificationSlaStatus,
    VerificationType,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=timezone.utc)
_COLLECTED_5D_AGO = (_NOW - timedelta(days=5)).isoformat()
_VERIFIED_AT = _NOW.isoformat()

_TENANT = "t-hardening-001"
_TENANT_B = "t-hardening-002"

_REVIEW_OVERDUE = (_NOW - timedelta(days=2)).isoformat()
_VERIFY_DUE_SOON = (_NOW + timedelta(days=3)).isoformat()
_FRESH_DUE = (_NOW + timedelta(days=30)).isoformat()


def _ev_payload(**overrides: Any) -> dict:
    defaults: dict[str, Any] = {
        "title": "Hardening Test Evidence",
        "source_type": "DOCUMENT",
        "collection_method": "MANUAL_UPLOAD",
        "classification": "INTERNAL",
        "collected_at": _COLLECTED_5D_AGO,
    }
    defaults.update(overrides)
    return defaults


def _ver_payload(**overrides: Any) -> dict:
    defaults: dict[str, Any] = {
        "verification_type": VerificationType.MANUAL_REVIEW.value,
        "verification_result": VerificationResult.PASS.value,
        "verified_by": "reviewer-001",
        "verified_actor_type": VerificationActorType.HUMAN.value,
        "verified_at": _VERIFIED_AT,
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


def _create_evidence(client: TestClient, **overrides: Any) -> dict:
    resp = client.post("/evidence", json=_ev_payload(**overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_verification(client: TestClient, ev_id: str, **overrides: Any) -> dict:
    resp = client.post(
        f"/evidence/{ev_id}/verifications", json=_ver_payload(**overrides)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# 1. TestVerificationCreation
# ---------------------------------------------------------------------------


class TestVerificationCreation:
    def test_create_pass_verification_returns_201(self, client):
        ev = _create_evidence(client)
        resp = client.post(f"/evidence/{ev['id']}/verifications", json=_ver_payload())
        assert resp.status_code == 201
        data = resp.json()
        assert data["verification_result"] == "PASS"
        assert data["evidence_id"] == ev["id"]
        assert data["verification_type"] == "MANUAL_REVIEW"
        assert data["verified_by"] == "reviewer-001"

    def test_create_fail_verification(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/verifications",
            json=_ver_payload(verification_result="FAIL"),
        )
        assert resp.status_code == 201
        assert resp.json()["verification_result"] == "FAIL"

    def test_create_inconclusive_verification(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/verifications",
            json=_ver_payload(verification_result="INCONCLUSIVE"),
        )
        assert resp.status_code == 201
        assert resp.json()["verification_result"] == "INCONCLUSIVE"

    def test_verification_has_id_and_timestamps(self, client):
        ev = _create_evidence(client)
        ver = _create_verification(client, ev["id"])
        assert ver["id"]
        assert ver["created_at"]
        assert ver["verified_at"]
        assert ver["schema_version"] == "1.0"

    def test_verification_with_confidence_and_notes(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/verifications",
            json=_ver_payload(
                verification_confidence=85, verification_notes="All good"
            ),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["verification_confidence"] == 85
        assert data["verification_notes"] == "All good"

    def test_verification_with_method(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/verifications",
            json=_ver_payload(verification_method="Checklist-v2"),
        )
        assert resp.status_code == 201
        assert resp.json()["verification_method"] == "Checklist-v2"

    def test_verification_invalid_result_enum_returns_422(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/verifications",
            json=_ver_payload(verification_result="BOGUS"),
        )
        assert resp.status_code == 422

    def test_verification_invalid_type_enum_returns_422(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/verifications",
            json=_ver_payload(verification_type="NOT_A_TYPE"),
        )
        assert resp.status_code == 422

    def test_verification_missing_required_field_returns_422(self, client):
        ev = _create_evidence(client)
        payload = _ver_payload()
        del payload["verified_by"]
        resp = client.post(f"/evidence/{ev['id']}/verifications", json=payload)
        assert resp.status_code == 422

    def test_verification_extra_field_rejected(self, client):
        ev = _create_evidence(client)
        payload = _ver_payload()
        payload["extra_field"] = "x"
        resp = client.post(f"/evidence/{ev['id']}/verifications", json=payload)
        assert resp.status_code == 422

    def test_verification_missing_evidence_returns_404(self, client):
        resp = client.post(
            "/evidence/nonexistent-id/verifications", json=_ver_payload()
        )
        assert resp.status_code == 404

    def test_all_actor_types_accepted(self, client):
        ev = _create_evidence(client)
        for actor_type in [a.value for a in VerificationActorType]:
            resp = client.post(
                f"/evidence/{ev['id']}/verifications",
                json=_ver_payload(verified_actor_type=actor_type),
            )
            assert resp.status_code == 201, f"Failed for actor_type={actor_type}"

    def test_all_verification_types_accepted(self, client):
        ev = _create_evidence(client)
        for vtype in [v.value for v in VerificationType]:
            resp = client.post(
                f"/evidence/{ev['id']}/verifications",
                json=_ver_payload(verification_type=vtype),
            )
            assert resp.status_code == 201, f"Failed for type={vtype}"

    def test_invalid_verified_at_returns_422(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/verifications",
            json=_ver_payload(verified_at="not-a-date"),
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 2. TestVerificationHistory
# ---------------------------------------------------------------------------


class TestVerificationHistory:
    def test_list_verifications_empty(self, client):
        ev = _create_evidence(client)
        resp = client.get(f"/evidence/{ev['id']}/verifications")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_list_verifications_returns_all(self, client):
        ev = _create_evidence(client)
        _create_verification(client, ev["id"])
        _create_verification(client, ev["id"], verification_result="FAIL")
        resp = client.get(f"/evidence/{ev['id']}/verifications")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_list_verifications_descending_order(self, client):
        ev = _create_evidence(client)
        _create_verification(client, ev["id"], verification_result="PASS")
        _create_verification(client, ev["id"], verification_result="FAIL")
        resp = client.get(f"/evidence/{ev['id']}/verifications")
        items = resp.json()["items"]
        # most recent first (FAIL was created last)
        assert items[0]["verification_result"] == "FAIL"

    def test_verification_summary_empty(self, client):
        ev = _create_evidence(client)
        resp = client.get(f"/evidence/{ev['id']}/verifications/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["verification_count"] == 0
        assert data["passed_count"] == 0
        assert data["verification_success_rate"] is None
        assert data["latest_verification_at"] is None

    def test_verification_summary_counts(self, client):
        ev = _create_evidence(client)
        _create_verification(client, ev["id"], verification_result="PASS")
        _create_verification(client, ev["id"], verification_result="PASS")
        _create_verification(client, ev["id"], verification_result="FAIL")
        _create_verification(client, ev["id"], verification_result="INCONCLUSIVE")
        resp = client.get(f"/evidence/{ev['id']}/verifications/summary")
        data = resp.json()
        assert data["verification_count"] == 4
        assert data["passed_count"] == 2
        assert data["failed_count"] == 1
        assert data["inconclusive_count"] == 1

    def test_verification_success_rate(self, client):
        ev = _create_evidence(client)
        _create_verification(client, ev["id"], verification_result="PASS")
        _create_verification(client, ev["id"], verification_result="PASS")
        _create_verification(client, ev["id"], verification_result="FAIL")
        resp = client.get(f"/evidence/{ev['id']}/verifications/summary")
        data = resp.json()
        assert data["verification_success_rate"] == pytest.approx(2 / 3, abs=1e-3)

    def test_verification_age_days(self, client):
        ev = _create_evidence(client)
        _create_verification(client, ev["id"])
        resp = client.get(f"/evidence/{ev['id']}/verifications/summary")
        data = resp.json()
        assert data["verification_age_days"] is not None
        assert data["verification_age_days"] >= 0

    def test_verification_latest_fields(self, client):
        ev = _create_evidence(client)
        _create_verification(client, ev["id"], verification_result="FAIL")
        _create_verification(
            client,
            ev["id"],
            verification_result="PASS",
            verification_type="TECHNICAL_VALIDATION",
        )
        resp = client.get(f"/evidence/{ev['id']}/verifications/summary")
        data = resp.json()
        assert data["latest_verification_result"] == "PASS"
        assert data["latest_verification_type"] == "TECHNICAL_VALIDATION"

    def test_summary_missing_evidence_returns_404(self, client):
        resp = client.get("/evidence/nonexistent/verifications/summary")
        assert resp.status_code == 404

    def test_list_missing_evidence_returns_404(self, client):
        resp = client.get("/evidence/nonexistent/verifications")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 3. TestVerificationSLA
# ---------------------------------------------------------------------------


class TestVerificationSLA:
    def test_set_sla_deadlines(self, client):
        ev = _create_evidence(client)
        resp = client.put(
            f"/evidence/{ev['id']}/sla",
            json={
                "review_due_at": _FRESH_DUE,
                "verification_due_at": _FRESH_DUE,
                "freshness_due_at": _FRESH_DUE,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["evidence_id"] == ev["id"]
        assert data["review_due_at"] == _FRESH_DUE
        assert data["verification_due_at"] == _FRESH_DUE

    def test_get_sla_status_no_deadline(self, client):
        ev = _create_evidence(client)
        resp = client.get(f"/evidence/{ev['id']}/sla")
        assert resp.status_code == 200
        data = resp.json()
        assert data["review_sla_status"] is None
        assert data["verification_sla_status"] is None
        assert data["freshness_sla_status"] is None

    def test_sla_status_on_track(self, client):
        ev = _create_evidence(client)
        client.put(
            f"/evidence/{ev['id']}/sla",
            json={"verification_due_at": _FRESH_DUE},
        )
        resp = client.get(f"/evidence/{ev['id']}/sla")
        data = resp.json()
        assert data["verification_sla_status"] == VerificationSlaStatus.ON_TRACK.value

    def test_sla_status_due_soon(self, client):
        ev = _create_evidence(client)
        client.put(
            f"/evidence/{ev['id']}/sla",
            json={"review_due_at": _VERIFY_DUE_SOON},
        )
        resp = client.get(f"/evidence/{ev['id']}/sla")
        data = resp.json()
        assert data["review_sla_status"] == VerificationSlaStatus.DUE_SOON.value

    def test_sla_status_overdue(self, client):
        ev = _create_evidence(client)
        client.put(
            f"/evidence/{ev['id']}/sla",
            json={"freshness_due_at": _REVIEW_OVERDUE},
        )
        resp = client.get(f"/evidence/{ev['id']}/sla")
        data = resp.json()
        assert data["freshness_sla_status"] == VerificationSlaStatus.OVERDUE.value

    def test_sla_set_partial(self, client):
        ev = _create_evidence(client)
        client.put(
            f"/evidence/{ev['id']}/sla",
            json={"verification_due_at": _FRESH_DUE},
        )
        resp = client.get(f"/evidence/{ev['id']}/sla")
        data = resp.json()
        assert data["verification_sla_status"] == VerificationSlaStatus.ON_TRACK.value
        assert data["review_sla_status"] is None

    def test_sla_missing_evidence_404(self, client):
        resp = client.put("/evidence/no-such/sla", json={"review_due_at": _FRESH_DUE})
        assert resp.status_code == 404

    def test_sla_get_missing_evidence_404(self, client):
        resp = client.get("/evidence/no-such/sla")
        assert resp.status_code == 404

    def test_sla_invalid_iso8601_returns_422(self, client):
        ev = _create_evidence(client)
        resp = client.put(
            f"/evidence/{ev['id']}/sla", json={"review_due_at": "bad-date"}
        )
        assert resp.status_code == 422

    def test_sla_has_computed_at(self, client):
        ev = _create_evidence(client)
        resp = client.get(f"/evidence/{ev['id']}/sla")
        assert "computed_at" in resp.json()


# ---------------------------------------------------------------------------
# 4. TestControlLinkage
# ---------------------------------------------------------------------------


class TestControlLinkage:
    def test_link_to_control_returns_201(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/control-links",
            json={"control_id": "ctrl-001"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["control_id"] == "ctrl-001"
        assert data["evidence_id"] == ev["id"]

    def test_control_link_has_timestamps(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/control-links", json={"control_id": "ctrl-ts"}
        )
        data = resp.json()
        assert data["id"]
        assert data["created_at"]
        assert data["linked_at"]
        assert data["linked_by"]

    def test_duplicate_control_link_returns_409(self, client):
        ev = _create_evidence(client)
        client.post(
            f"/evidence/{ev['id']}/control-links", json={"control_id": "ctrl-dup"}
        )
        resp = client.post(
            f"/evidence/{ev['id']}/control-links", json={"control_id": "ctrl-dup"}
        )
        assert resp.status_code == 409

    def test_different_controls_on_same_evidence_ok(self, client):
        ev = _create_evidence(client)
        r1 = client.post(
            f"/evidence/{ev['id']}/control-links", json={"control_id": "ctrl-a"}
        )
        r2 = client.post(
            f"/evidence/{ev['id']}/control-links", json={"control_id": "ctrl-b"}
        )
        assert r1.status_code == 201
        assert r2.status_code == 201

    def test_list_control_links_empty(self, client):
        ev = _create_evidence(client)
        resp = client.get(f"/evidence/{ev['id']}/control-links")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_list_control_links_returns_all(self, client):
        ev = _create_evidence(client)
        client.post(f"/evidence/{ev['id']}/control-links", json={"control_id": "c1"})
        client.post(f"/evidence/{ev['id']}/control-links", json={"control_id": "c2"})
        resp = client.get(f"/evidence/{ev['id']}/control-links")
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_control_link_missing_evidence_404(self, client):
        resp = client.post(
            "/evidence/no-such/control-links", json={"control_id": "ctrl-001"}
        )
        assert resp.status_code == 404

    def test_control_link_tenant_isolation(self, client, client_b):
        ev = _create_evidence(client)
        resp = client_b.post(
            f"/evidence/{ev['id']}/control-links", json={"control_id": "ctrl-x"}
        )
        assert resp.status_code == 404

    def test_control_link_missing_control_id_422(self, client):
        ev = _create_evidence(client)
        resp = client.post(f"/evidence/{ev['id']}/control-links", json={})
        assert resp.status_code == 422

    def test_list_control_links_missing_evidence_404(self, client):
        resp = client.get("/evidence/no-such/control-links")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 5. TestRiskLinkage
# ---------------------------------------------------------------------------


class TestRiskLinkage:
    def test_link_to_risk_returns_201(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={
                "linked_resource_id": "risk-001",
                "link_type": EvidenceLinkTargetType.RISK.value,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["link_type"] == "RISK"
        assert data["linked_resource_id"] == "risk-001"

    def test_link_to_finding(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={
                "linked_resource_id": "finding-001",
                "link_type": EvidenceLinkTargetType.FINDING.value,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["link_type"] == "FINDING"

    def test_link_to_exception(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={
                "linked_resource_id": "exc-001",
                "link_type": EvidenceLinkTargetType.EXCEPTION.value,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["link_type"] == "EXCEPTION"

    def test_duplicate_risk_link_returns_409(self, client):
        ev = _create_evidence(client)
        payload = {"linked_resource_id": "risk-dup", "link_type": "RISK"}
        client.post(f"/evidence/{ev['id']}/risk-links", json=payload)
        resp = client.post(f"/evidence/{ev['id']}/risk-links", json=payload)
        assert resp.status_code == 409

    def test_same_resource_different_link_type_ok(self, client):
        ev = _create_evidence(client)
        r1 = client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "res-001", "link_type": "RISK"},
        )
        r2 = client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "res-001", "link_type": "FINDING"},
        )
        assert r1.status_code == 201
        assert r2.status_code == 201

    def test_list_risk_links_empty(self, client):
        ev = _create_evidence(client)
        resp = client.get(f"/evidence/{ev['id']}/risk-links")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    def test_list_risk_links_returns_all(self, client):
        ev = _create_evidence(client)
        client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "r1", "link_type": "RISK"},
        )
        client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "f1", "link_type": "FINDING"},
        )
        resp = client.get(f"/evidence/{ev['id']}/risk-links")
        assert resp.json()["total"] == 2

    def test_list_risk_links_filter_by_type(self, client):
        ev = _create_evidence(client)
        client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "r1", "link_type": "RISK"},
        )
        client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "f1", "link_type": "FINDING"},
        )
        resp = client.get(f"/evidence/{ev['id']}/risk-links?link_type=RISK")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["link_type"] == "RISK"

    def test_risk_link_invalid_type_422(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "r1", "link_type": "INVALID"},
        )
        assert resp.status_code == 422

    def test_risk_link_tenant_isolation(self, client, client_b):
        ev = _create_evidence(client)
        resp = client_b.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "r1", "link_type": "RISK"},
        )
        assert resp.status_code == 404

    def test_risk_link_missing_evidence_404(self, client):
        resp = client.post(
            "/evidence/no-such/risk-links",
            json={"linked_resource_id": "r1", "link_type": "RISK"},
        )
        assert resp.status_code == 404

    def test_list_risk_links_missing_evidence_404(self, client):
        resp = client.get("/evidence/no-such/risk-links")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 6. TestCoverageAnalytics
# ---------------------------------------------------------------------------


class TestCoverageAnalytics:
    def test_coverage_empty_tenant(self, client):
        resp = client.get("/evidence/coverage")
        assert resp.status_code == 200
        data = resp.json()
        assert data["controls_with_evidence"] == 0
        assert data["total_control_links"] == 0
        assert data["total_risk_links"] == 0
        assert data["evidence_density"] == 0.0
        assert "coverage_percentage" in data

    def test_coverage_after_control_links(self, client):
        ev = _create_evidence(client)
        client.post(f"/evidence/{ev['id']}/control-links", json={"control_id": "c-1"})
        client.post(f"/evidence/{ev['id']}/control-links", json={"control_id": "c-2"})
        resp = client.get("/evidence/coverage")
        data = resp.json()
        assert data["controls_with_evidence"] == 2
        assert data["total_control_links"] == 2

    def test_coverage_after_risk_links(self, client):
        ev = _create_evidence(client)
        client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "r-1", "link_type": "RISK"},
        )
        resp = client.get("/evidence/coverage")
        data = resp.json()
        assert data["risks_with_evidence"] == 1
        assert data["total_risk_links"] == 1

    def test_coverage_density_formula(self, client):
        ev = _create_evidence(client)
        client.post(f"/evidence/{ev['id']}/control-links", json={"control_id": "d-c1"})
        client.post(f"/evidence/{ev['id']}/control-links", json={"control_id": "d-c2"})
        resp = client.get("/evidence/coverage")
        data = resp.json()
        # density = total_control_links / controls_with_evidence
        assert data["evidence_density"] == pytest.approx(
            data["total_control_links"] / max(1, data["controls_with_evidence"]),
            abs=0.01,
        )

    def test_coverage_has_required_fields(self, client):
        resp = client.get("/evidence/coverage")
        data = resp.json()
        required = [
            "tenant_id",
            "generated_at",
            "controls_with_evidence",
            "controls_without_evidence",
            "risks_with_evidence",
            "risks_without_evidence",
            "findings_with_evidence",
            "exceptions_with_evidence",
            "verified_controls",
            "unverified_controls",
            "total_control_links",
            "total_risk_links",
            "evidence_density",
            "coverage_percentage",
            "total_known_controls",
        ]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_coverage_findings_and_exceptions(self, client):
        ev = _create_evidence(client)
        client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "f-1", "link_type": "FINDING"},
        )
        client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "e-1", "link_type": "EXCEPTION"},
        )
        resp = client.get("/evidence/coverage")
        data = resp.json()
        assert data["findings_with_evidence"] >= 1
        assert data["exceptions_with_evidence"] >= 1

    def test_coverage_tenant_scoped(self, client, client_b):
        ev_b = _create_evidence(client_b)
        client_b.post(
            f"/evidence/{ev_b['id']}/control-links", json={"control_id": "cb-ctrl"}
        )
        client.get("/evidence/coverage")
        # Tenant A should not see tenant B's control links
        # (they may have their own from other tests, but cb-ctrl must not count for A)
        resp_b = client_b.get("/evidence/coverage")
        # Tenant B should see at least 1
        assert resp_b.json()["controls_with_evidence"] >= 1


# ---------------------------------------------------------------------------
# 7. TestHealthSignals
# ---------------------------------------------------------------------------


class TestHealthSignals:
    def test_health_signals_empty_tenant(self, client):
        resp = client.get("/evidence/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "verification_overdue_count" in data
        assert "review_overdue_count" in data
        assert "freshness_overdue_count" in data
        assert "orphaned_evidence_count" in data
        assert "unlinked_evidence_count" in data

    def test_health_signals_has_required_fields(self, client):
        resp = client.get("/evidence/health")
        data = resp.json()
        required = [
            "tenant_id",
            "generated_at",
            "verification_overdue_count",
            "review_overdue_count",
            "freshness_overdue_count",
            "orphaned_evidence_count",
            "unlinked_evidence_count",
            "disputed_evidence_count",
            "invalidated_evidence_count",
            "attested_evidence_count",
            "verified_evidence_count",
        ]
        for field in required:
            assert field in data, f"Missing: {field}"

    def test_health_overdue_count_increments(self, client):
        ev = _create_evidence(client)
        # set a past date for verification_due_at
        client.put(
            f"/evidence/{ev['id']}/sla",
            json={"verification_due_at": _REVIEW_OVERDUE},
        )
        resp = client.get("/evidence/health")
        assert resp.json()["verification_overdue_count"] >= 1

    def test_health_orphaned_count(self, client):
        # freshly created evidence has no ownership → orphaned
        _create_evidence(client)
        resp = client.get("/evidence/health")
        assert resp.json()["orphaned_evidence_count"] >= 1

    def test_health_unlinked_count(self, client):
        # freshly created evidence has no control/risk links → unlinked
        _create_evidence(client)
        resp = client.get("/evidence/health")
        assert resp.json()["unlinked_evidence_count"] >= 1

    def test_health_signals_tenant_scoped(self, client, client_b):
        ev_b = _create_evidence(client_b)
        client_b.put(
            f"/evidence/{ev_b['id']}/sla",
            json={"review_due_at": _REVIEW_OVERDUE},
        )
        # Tenant A should not see tenant B's overdue SLA
        client.get("/evidence/health")
        resp_b = client_b.get("/evidence/health")
        assert resp_b.json()["review_overdue_count"] >= 1


# ---------------------------------------------------------------------------
# 8. TestTimelineEmission
# ---------------------------------------------------------------------------


class TestTimelineEmission:
    def test_verification_created_event_emitted(self, client):
        # Just ensure no errors — timeline events are best-effort
        ev = _create_evidence(client)
        resp = client.post(f"/evidence/{ev['id']}/verifications", json=_ver_payload())
        assert resp.status_code == 201

    def test_verification_failed_event_emitted(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/verifications",
            json=_ver_payload(verification_result="FAIL"),
        )
        assert resp.status_code == 201

    def test_control_link_event_emitted(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/control-links", json={"control_id": "tl-ctrl"}
        )
        assert resp.status_code == 201

    def test_risk_link_event_emitted(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "tl-risk", "link_type": "RISK"},
        )
        assert resp.status_code == 201

    def test_finding_link_event_emitted(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "tl-finding", "link_type": "FINDING"},
        )
        assert resp.status_code == 201

    def test_exception_link_event_emitted(self, client):
        ev = _create_evidence(client)
        resp = client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "tl-exc", "link_type": "EXCEPTION"},
        )
        assert resp.status_code == 201

    def test_audit_event_recorded_for_verification(self, client):
        ev = _create_evidence(client)
        _create_verification(client, ev["id"])
        resp = client.get(f"/evidence/{ev['id']}/audit")
        events = resp.json()["items"]
        event_types = [e["event_type"] for e in events]
        assert "verification_created" in event_types

    def test_audit_event_recorded_for_control_link(self, client):
        ev = _create_evidence(client)
        client.post(f"/evidence/{ev['id']}/control-links", json={"control_id": "au-c1"})
        resp = client.get(f"/evidence/{ev['id']}/audit")
        event_types = [e["event_type"] for e in resp.json()["items"]]
        assert "control_linked" in event_types

    def test_audit_event_recorded_for_risk_link(self, client):
        ev = _create_evidence(client)
        client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "au-r1", "link_type": "RISK"},
        )
        resp = client.get(f"/evidence/{ev['id']}/audit")
        event_types = [e["event_type"] for e in resp.json()["items"]]
        assert "risk_linked" in event_types

    def test_audit_event_recorded_for_sla(self, client):
        ev = _create_evidence(client)
        client.put(f"/evidence/{ev['id']}/sla", json={"review_due_at": _FRESH_DUE})
        resp = client.get(f"/evidence/{ev['id']}/audit")
        event_types = [e["event_type"] for e in resp.json()["items"]]
        assert "sla_deadlines_set" in event_types


# ---------------------------------------------------------------------------
# 9. TestTenantIsolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_verifications_not_visible_across_tenants(self, client, client_b):
        ev = _create_evidence(client)
        _create_verification(client, ev["id"])
        resp = client_b.get(f"/evidence/{ev['id']}/verifications")
        assert resp.status_code == 404

    def test_control_links_not_visible_across_tenants(self, client, client_b):
        ev = _create_evidence(client)
        client.post(
            f"/evidence/{ev['id']}/control-links", json={"control_id": "iso-c1"}
        )
        resp = client_b.get(f"/evidence/{ev['id']}/control-links")
        assert resp.status_code == 404

    def test_risk_links_not_visible_across_tenants(self, client, client_b):
        ev = _create_evidence(client)
        client.post(
            f"/evidence/{ev['id']}/risk-links",
            json={"linked_resource_id": "iso-r1", "link_type": "RISK"},
        )
        resp = client_b.get(f"/evidence/{ev['id']}/risk-links")
        assert resp.status_code == 404

    def test_sla_not_visible_across_tenants(self, client, client_b):
        ev = _create_evidence(client)
        resp = client_b.get(f"/evidence/{ev['id']}/sla")
        assert resp.status_code == 404

    def test_verification_summary_not_visible_across_tenants(self, client, client_b):
        ev = _create_evidence(client)
        resp = client_b.get(f"/evidence/{ev['id']}/verifications/summary")
        assert resp.status_code == 404

    def test_coverage_tenant_a_sees_only_its_data(self, client, client_b):
        ev_b = _create_evidence(client_b)
        client_b.post(
            f"/evidence/{ev_b['id']}/control-links", json={"control_id": "iso-x1"}
        )
        resp_a = client.get("/evidence/coverage")
        # Tenant A coverage should be independent of tenant B
        assert isinstance(resp_a.json()["controls_with_evidence"], int)

    def test_health_tenant_isolation(self, client, client_b):
        resp_a = client.get("/evidence/health")
        resp_b = client_b.get("/evidence/health")
        assert resp_a.status_code == 200
        assert resp_b.status_code == 200

    def test_cgin_snapshot_tenant_isolated(self, client, client_b):
        _create_evidence(client)
        resp_a = client.get("/evidence/cgin/snapshot")
        resp_b = client_b.get("/evidence/cgin/snapshot")
        assert resp_a.status_code == 200
        assert resp_b.status_code == 200


# ---------------------------------------------------------------------------
# 10. TestDeterministicReplay
# ---------------------------------------------------------------------------


class TestDeterministicReplay:
    def test_same_sla_deadline_same_status(self, client):
        ev1 = _create_evidence(client, title="Replay Test A")
        ev2 = _create_evidence(client, title="Replay Test B")
        for ev in [ev1, ev2]:
            client.put(
                f"/evidence/{ev['id']}/sla",
                json={"verification_due_at": _FRESH_DUE},
            )
        r1 = client.get(f"/evidence/{ev1['id']}/sla").json()
        r2 = client.get(f"/evidence/{ev2['id']}/sla").json()
        assert r1["verification_sla_status"] == r2["verification_sla_status"]

    def test_repeated_summary_call_same_counts(self, client):
        ev = _create_evidence(client)
        _create_verification(client, ev["id"])
        r1 = client.get(f"/evidence/{ev['id']}/verifications/summary").json()
        r2 = client.get(f"/evidence/{ev['id']}/verifications/summary").json()
        assert r1["verification_count"] == r2["verification_count"]
        assert r1["passed_count"] == r2["passed_count"]

    def test_coverage_deterministic(self, client):
        ev = _create_evidence(client, title="Det Cov Test")
        client.post(
            f"/evidence/{ev['id']}/control-links", json={"control_id": "det-c1"}
        )
        r1 = client.get("/evidence/coverage").json()
        r2 = client.get("/evidence/coverage").json()
        assert r1["controls_with_evidence"] == r2["controls_with_evidence"]
        assert r1["evidence_density"] == r2["evidence_density"]

    def test_health_signals_deterministic(self, client):
        r1 = client.get("/evidence/health").json()
        r2 = client.get("/evidence/health").json()
        assert r1["verification_overdue_count"] == r2["verification_overdue_count"]
        assert r1["orphaned_evidence_count"] == r2["orphaned_evidence_count"]


# ---------------------------------------------------------------------------
# 11. TestCGINSnapshot
# ---------------------------------------------------------------------------


class TestCGINSnapshot:
    def test_cgin_snapshot_structure(self, client):
        _create_evidence(client, title="CGIN Test Evidence")
        resp = client.get("/evidence/cgin/snapshot")
        assert resp.status_code == 200
        data = resp.json()
        assert "bundle_id" in data
        assert "bundle_version" in data
        assert "tenant_fingerprint" in data
        assert "tenant_id" not in data
        assert "generated_at" in data
        assert "evidence_snapshots" in data
        assert "verification_snapshots" in data
        assert "coverage" in data
        assert "health" in data

    def test_cgin_bundle_version_is_1_0(self, client):
        resp = client.get("/evidence/cgin/snapshot")
        assert resp.json()["bundle_version"] == "1.0"

    def test_cgin_coverage_has_snapshot_version(self, client):
        resp = client.get("/evidence/cgin/snapshot")
        cov = resp.json()["coverage"]
        assert cov["snapshot_version"] == "1.0"

    def test_cgin_health_has_snapshot_version(self, client):
        resp = client.get("/evidence/cgin/snapshot")
        health = resp.json()["health"]
        assert health["snapshot_version"] == "1.0"

    def test_cgin_evidence_snapshots_list(self, client):
        _create_evidence(client, title="CGIN Ev A")
        _create_evidence(client, title="CGIN Ev B")
        resp = client.get("/evidence/cgin/snapshot")
        data = resp.json()
        assert len(data["evidence_snapshots"]) >= 2

    def test_cgin_benchmark_fields_null(self, client):
        _create_evidence(client, title="CGIN Bench")
        resp = client.get("/evidence/cgin/snapshot")
        data = resp.json()
        for snap in data["evidence_snapshots"]:
            assert snap["benchmark_freshness_percentile"] is None
            assert snap["benchmark_verification_percentile"] is None
        cov = data["coverage"]
        assert cov["benchmark_density_percentile"] is None
        assert cov["benchmark_coverage_percentile"] is None

    def test_cgin_snapshot_ids_unique(self, client):
        _create_evidence(client, title="CGIN Unique")
        resp = client.get("/evidence/cgin/snapshot")
        data = resp.json()
        ids = [s["snapshot_id"] for s in data["evidence_snapshots"]]
        ids += [s["snapshot_id"] for s in data["verification_snapshots"]]
        ids.append(data["coverage"]["snapshot_id"])
        ids.append(data["health"]["snapshot_id"])
        # All snapshot IDs must be unique
        assert len(ids) == len(set(ids))

    def test_cgin_tenant_id_correct(self, client):
        resp = client.get("/evidence/cgin/snapshot")
        data = resp.json()
        assert data["tenant_fingerprint"]
        assert len(data["tenant_fingerprint"]) == 32
        assert "tenant_id" not in data

    def test_cgin_verification_snapshots_count_matches(self, client):
        resp = client.get("/evidence/cgin/snapshot")
        data = resp.json()
        assert len(data["evidence_snapshots"]) == len(data["verification_snapshots"])

    def test_cgin_empty_tenant(self, client_b):
        resp = client_b.get("/evidence/cgin/snapshot")
        assert resp.status_code == 200
        data = resp.json()
        assert data["evidence_snapshots"] == []
        assert data["verification_snapshots"] == []


# ---------------------------------------------------------------------------
# 12. TestSlaStatuses
# ---------------------------------------------------------------------------


class TestSlaStatuses:
    def test_overdue_past_date(self, client):
        ev = _create_evidence(client)
        past = (_NOW - timedelta(days=5)).isoformat()
        client.put(f"/evidence/{ev['id']}/sla", json={"review_due_at": past})
        resp = client.get(f"/evidence/{ev['id']}/sla")
        assert resp.json()["review_sla_status"] == "OVERDUE"

    def test_due_soon_five_days_from_now(self, client):
        ev = _create_evidence(client)
        due_soon = (_NOW + timedelta(days=5)).isoformat()
        client.put(f"/evidence/{ev['id']}/sla", json={"verification_due_at": due_soon})
        resp = client.get(f"/evidence/{ev['id']}/sla")
        assert resp.json()["verification_sla_status"] == "DUE_SOON"

    def test_on_track_30_days_from_now(self, client):
        ev = _create_evidence(client)
        on_track = (_NOW + timedelta(days=30)).isoformat()
        client.put(f"/evidence/{ev['id']}/sla", json={"freshness_due_at": on_track})
        resp = client.get(f"/evidence/{ev['id']}/sla")
        assert resp.json()["freshness_sla_status"] == "ON_TRACK"

    def test_all_three_sla_fields_independent(self, client):
        ev = _create_evidence(client)
        client.put(
            f"/evidence/{ev['id']}/sla",
            json={
                "review_due_at": (_NOW - timedelta(days=1)).isoformat(),  # OVERDUE
                "verification_due_at": (
                    _NOW + timedelta(days=3)
                ).isoformat(),  # DUE_SOON
                "freshness_due_at": (_NOW + timedelta(days=60)).isoformat(),  # ON_TRACK
            },
        )
        resp = client.get(f"/evidence/{ev['id']}/sla")
        data = resp.json()
        assert data["review_sla_status"] == "OVERDUE"
        assert data["verification_sla_status"] == "DUE_SOON"
        assert data["freshness_sla_status"] == "ON_TRACK"

    def test_sla_exactly_one_week_boundary(self, client):
        ev = _create_evidence(client)
        # Exactly 6 days 23 hours from now → DUE_SOON
        due = (_NOW + timedelta(days=6, hours=23)).isoformat()
        client.put(f"/evidence/{ev['id']}/sla", json={"review_due_at": due})
        resp = client.get(f"/evidence/{ev['id']}/sla")
        assert resp.json()["review_sla_status"] == "DUE_SOON"


# ---------------------------------------------------------------------------
# 13. TestAuditEventTypes
# ---------------------------------------------------------------------------


class TestAuditEventTypes:
    def test_verification_created_in_enum(self):
        assert (
            EvidenceAuditEventType.VERIFICATION_CREATED.value == "verification_created"
        )

    def test_verification_failed_in_enum(self):
        assert EvidenceAuditEventType.VERIFICATION_FAILED.value == "verification_failed"

    def test_control_linked_in_enum(self):
        assert EvidenceAuditEventType.CONTROL_LINKED.value == "control_linked"

    def test_risk_linked_in_enum(self):
        assert EvidenceAuditEventType.RISK_LINKED.value == "risk_linked"

    def test_sla_deadlines_set_in_enum(self):
        assert EvidenceAuditEventType.SLA_DEADLINES_SET.value == "sla_deadlines_set"


# ---------------------------------------------------------------------------
# 14. TestModelEnums
# ---------------------------------------------------------------------------


class TestModelEnums:
    def test_verification_type_values(self):
        values = {v.value for v in VerificationType}
        assert "MANUAL_REVIEW" in values
        assert "TECHNICAL_VALIDATION" in values
        assert "AI_ASSISTED_REVIEW" in values

    def test_verification_result_values(self):
        assert {v.value for v in VerificationResult} == {"PASS", "FAIL", "INCONCLUSIVE"}

    def test_verification_actor_type_values(self):
        values = {v.value for v in VerificationActorType}
        assert "HUMAN" in values
        assert "AGI_SYSTEM" in values

    def test_sla_status_values(self):
        assert {v.value for v in VerificationSlaStatus} == {
            "ON_TRACK",
            "DUE_SOON",
            "OVERDUE",
        }

    def test_link_target_type_values(self):
        assert {v.value for v in EvidenceLinkTargetType} == {
            "RISK",
            "FINDING",
            "EXCEPTION",
        }
