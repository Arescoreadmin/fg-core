"""Tests for Microsoft Graph connector import bridge into Field Assessment."""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from fastapi.testclient import TestClient

from services.canonical import canonical_json_bytes
from services.connectors.msgraph.integrity import build_content_hashes
from services.connectors.msgraph.acknowledgment import generate_receipt
from services.connectors.msgraph.findings.derivation import (
    derive_finding_id,
    hash_tenant_id,
)
from services.connectors.msgraph.schema.scan_result import (
    EvidenceRef,
    Finding,
    ScanResult,
)

_TENANT_ID = "tenant-msgraph-bridge"


@pytest.fixture()
def client(build_app: object) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    return TestClient(app, headers={"X-API-Key": key})


def _create_engagement(client: TestClient) -> dict[str, Any]:
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": "Bridge Corp",
            "assessor_id": "assessor-bridge",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _manifest(
    *,
    content_hashes: dict[str, str],
    tampered: bool = False,
) -> dict[str, Any]:
    signed_at = "2026-05-20T12:00:00+00:00"
    payload: dict[str, Any] = {
        "manifest_id": "manifest-msgraph-001",
        "endpoints_called": ["/oauth2PermissionGrants", "/servicePrincipals"],
        "record_counts": {
            "/oauth2PermissionGrants": 3,
            "/servicePrincipals": 4,
        },
        "call_timestamps": {
            "/oauth2PermissionGrants": signed_at,
            "/servicePrincipals": signed_at,
        },
        "response_structure_hashes": {
            "/oauth2PermissionGrants": "a" * 64,
            "/servicePrincipals": "b" * 64,
        },
        "content_hashes": content_hashes,
        "signed_at": signed_at,
    }
    canonical = {
        "manifest_id": payload["manifest_id"],
        "endpoints_called": sorted(payload["endpoints_called"]),
        "record_counts": {
            k: payload["record_counts"][k] for k in sorted(payload["record_counts"])
        },
        "call_timestamps": {
            k: payload["call_timestamps"][k] for k in sorted(payload["call_timestamps"])
        },
        "response_structure_hashes": {
            k: payload["response_structure_hashes"][k]
            for k in sorted(payload["response_structure_hashes"])
        },
        "content_hashes": {
            k: payload["content_hashes"][k] for k in sorted(payload["content_hashes"])
        },
        "signed_at": signed_at,
    }
    digest = hmac.new(
        b"\x00" * 32,
        canonical_json_bytes(canonical),
        hashlib.sha256,
    ).hexdigest()
    payload["manifest_hmac"] = "0" * 64 if tampered else digest
    return payload


def _scan_result(
    *,
    tenant_id: str,
    engagement_id: str,
    tampered_manifest: bool = False,
) -> dict[str, Any]:
    receipt = generate_receipt(
        operator_name="Operator",
        operator_org="FrostGate",
        client_org_name="Bridge Corp",
        scan_authorized_at="2026-05-20T11:00:00Z",
        engagement_id=engagement_id,
    )
    evidence = EvidenceRef(
        ref_id="oauth-grants-bridge",
        endpoint="/oauth2PermissionGrants",
        record_count=3,
        config_state={"score_3_critical": 1},
        collected_at="2026-05-20T12:00:00Z",
        data_hash="c" * 64,
    )
    finding = Finding(
        finding_id=derive_finding_id(
            tenant_id=tenant_id,
            control_id="NIST-AI-RMF-MAP-4.2",
            evidence_key="oauth-critical:1",
        ),
        control_id="NIST-AI-RMF-MAP-4.2",
        framework_refs=["NIST-AI-RMF", "SOC2"],
        severity="high",
        title="Risky OAuth application consent detected",
        evidence_summary="1 OAuth grant has critical data-access risk.",
        affected_count=1,
        affected_entities=["app"],
        recommendation="Review and revoke risky OAuth consent.",
        remediation_effort="medium",
        remediation_owner="IT",
        evidence_refs=[evidence.ref_id],
    )
    analyzer_outputs = {
        "oauth_consent": {"score_3_critical": 1, "score_2_high": 0},
        "enterprise_apps": {"unverified_publisher_high_priv": 1, "new_apps_30d": 0},
        "ai_signals": {"shadow_ai_apps": 1, "unapproved_ai_apps": 1},
        "privileged_roles": {"permanent_assignments": 0},
        "guest_exposure": {"privileged_role_guests": 0},
        "dlp_exposure": {"critical_count": 1, "high_count": 0, "profiles": []},
    }
    content_hashes = build_content_hashes(
        findings=[finding],
        evidence_refs=[evidence],
        analyzer_outputs=analyzer_outputs,
    )
    scan = ScanResult(
        scan_id="msgraph-run-001",
        tenant_id_hash=hash_tenant_id(tenant_id),
        engagement_id=engagement_id,
        operator_acknowledgment_receipt=receipt,
        scan_initiated_at="2026-05-20T11:30:00Z",
        scan_completed_at="2026-05-20T12:00:00Z",
        scan_duration_seconds=1800,
        scan_status="completed",
        scopes_authorized=["User.Read.All", "Application.Read.All"],
        scopes_in_token=["User.Read.All", "Application.Read.All"],
        pages_fetched={"/oauth2PermissionGrants": 1, "/servicePrincipals": 1},
        endpoints_called=["/oauth2PermissionGrants", "/servicePrincipals"],
        findings=[finding],
        evidence_references=[evidence],
        analyzer_outputs=analyzer_outputs,
        integrity_manifest=_manifest(
            content_hashes=content_hashes,
            tampered=tampered_manifest,
        ),
    )
    return scan.model_dump(mode="json")


def _import_payload(scan_result: dict[str, Any]) -> dict[str, Any]:
    manifest_hash = hashlib.sha256(
        canonical_json_bytes(scan_result["integrity_manifest"])
    ).hexdigest()
    return {
        "connector_type": "microsoft_graph",
        "connector_run_id": scan_result["scan_id"],
        "connector_manifest_hash": manifest_hash,
        "scan_result": scan_result,
    }


def test_msgraph_import_creates_scan_findings_links_and_clears_gate(
    client: TestClient,
) -> None:
    engagement = _create_engagement(client)
    scan_result = _scan_result(tenant_id=_TENANT_ID, engagement_id=engagement["id"])

    resp = client.post(
        f"/field-assessment/engagements/{engagement['id']}/connector-runs/msgraph/import",
        json=_import_payload(scan_result),
    )

    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["verification_status"] == "verified"
    assert result["findings_imported"] == 1
    assert result["evidence_links_imported"] == 1
    assert result["asset_candidates_detected"] >= 3

    scans = client.get(f"/field-assessment/engagements/{engagement['id']}/scan-results")
    assert scans.status_code == 200
    assert scans.json()[0]["source_type"] == "microsoft_graph"

    findings = client.get(f"/field-assessment/engagements/{engagement['id']}/findings")
    assert findings.status_code == 200
    assert findings.json()["total_count"] == 1

    links = client.get(
        f"/field-assessment/engagements/{engagement['id']}/evidence-links"
    )
    assert links.status_code == 200
    assert len(links.json()) == 1

    execution = client.get(
        f"/field-assessment/engagements/{engagement['id']}/execution-state"
    )
    assert execution.status_code == 200
    body = execution.json()
    graph_gate = next(
        gate
        for gate in body["gates"]
        if gate["gate_id"] == "scan.microsoft_graph.required"
    )
    assert graph_gate["status"] == "passed"
    assert body["asset_candidate_actions"]
    assert "raw_payload" not in execution.text
    assert "access_token" not in execution.text
    assert "client_secret" not in execution.text


def test_msgraph_import_is_idempotent(client: TestClient) -> None:
    engagement = _create_engagement(client)
    scan_result = _scan_result(tenant_id=_TENANT_ID, engagement_id=engagement["id"])
    payload = _import_payload(scan_result)

    first = client.post(
        f"/field-assessment/engagements/{engagement['id']}/connector-runs/msgraph/import",
        json=payload,
    )
    second = client.post(
        f"/field-assessment/engagements/{engagement['id']}/connector-runs/msgraph/import",
        json=payload,
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["import_status"] == "replayed"
    scans = client.get(f"/field-assessment/engagements/{engagement['id']}/scan-results")
    findings = client.get(f"/field-assessment/engagements/{engagement['id']}/findings")
    links = client.get(
        f"/field-assessment/engagements/{engagement['id']}/evidence-links"
    )
    assert len(scans.json()) == 1
    assert findings.json()["total_count"] == 1
    assert len(links.json()) == 1


def test_msgraph_import_wrong_tenant_fails_closed(build_app: object) -> None:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    client_b = TestClient(
        app,
        headers={
            "X-API-Key": mint_key(
                "governance:read", "governance:write", tenant_id="tenant-b"
            )
        },
    )
    created = client_b.post(
        "/field-assessment/engagements",
        json={
            "client_name": "Tenant B",
            "assessor_id": "assessor-b",
            "assessment_type": "ai_governance",
        },
    )
    assert created.status_code == 201, created.text
    scan_result = _scan_result(
        tenant_id="tenant-a",
        engagement_id=created.json()["id"],
    )

    resp = client_b.post(
        f"/field-assessment/engagements/{created.json()['id']}/connector-runs/msgraph/import",
        json=_import_payload(scan_result),
    )

    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "CONNECTOR_TENANT_MISMATCH"


def test_msgraph_import_tampered_manifest_fails_closed(client: TestClient) -> None:
    engagement = _create_engagement(client)
    scan_result = _scan_result(
        tenant_id=_TENANT_ID,
        engagement_id=engagement["id"],
        tampered_manifest=True,
    )

    resp = client.post(
        f"/field-assessment/engagements/{engagement['id']}/connector-runs/msgraph/import",
        json=_import_payload(scan_result),
    )

    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "CONNECTOR_MANIFEST_UNVERIFIED"


def test_msgraph_import_tampered_finding_content_fails_closed(
    client: TestClient,
) -> None:
    engagement = _create_engagement(client)
    scan_result = _scan_result(tenant_id=_TENANT_ID, engagement_id=engagement["id"])
    scan_result["findings"][0]["severity"] = "low"
    scan_result["findings"][0]["title"] = "Downgraded finding content"

    resp = client.post(
        f"/field-assessment/engagements/{engagement['id']}/connector-runs/msgraph/import",
        json=_import_payload(scan_result),
    )

    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "CONNECTOR_MANIFEST_UNVERIFIED"


def test_msgraph_import_malformed_scan_payload_returns_422(
    client: TestClient,
) -> None:
    engagement = _create_engagement(client)

    resp = client.post(
        f"/field-assessment/engagements/{engagement['id']}/connector-runs/msgraph/import",
        json={
            "connector_type": "microsoft_graph",
            "connector_run_id": "broken-run",
            "scan_result": {
                "scan_id": "broken-run",
                "schema_version": "1.0",
            },
        },
    )

    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "CONNECTOR_PAYLOAD_INVALID"


def test_msgraph_import_audit_events_are_safe(client: TestClient) -> None:
    engagement = _create_engagement(client)
    scan_result = _scan_result(tenant_id=_TENANT_ID, engagement_id=engagement["id"])
    resp = client.post(
        f"/field-assessment/engagements/{engagement['id']}/connector-runs/msgraph/import",
        json=_import_payload(scan_result),
    )
    assert resp.status_code == 200, resp.text

    audit = client.get(f"/field-assessment/engagements/{engagement['id']}/audit-events")

    assert audit.status_code == 200
    text = audit.text
    assert "connector.msgraph.import_completed" in text
    assert "client_secret" not in text
    assert "access_token" not in text
    assert "raw_payload" not in text
