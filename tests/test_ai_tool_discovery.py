"""AI Tool Discovery scan tests."""

from __future__ import annotations

import os
from typing import Any
from pathlib import Path

os.environ.setdefault("FG_ENV", "test")

from fastapi.testclient import TestClient

from services.connectors.ai_tool_discovery.runner import run_ai_tool_discovery
from services.connectors.ai_tool_discovery.vendor_registry import match_ai_vendor
from services.field_assessment.connectors.ai_tool_discovery_bridge import (
    import_ai_tool_discovery_scan,
)
from services.field_assessment.scan_registry import (
    validate_required_fields,
    validate_schema_version,
)

_TENANT_ID = "tenant-ai-tool-discovery"


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise AssertionError(f"unexpected http status {self.status_code}")


def test_registry_detects_known_vendors_by_display_publisher_domain_and_negative() -> (
    None
):
    display = match_ai_vendor(
        display_name="ChatGPT Enterprise", publisher="unknown", app_id=None
    )
    publisher = match_ai_vendor(
        display_name="Enterprise App", publisher="Anthropic PBC", app_id=None
    )
    domain = match_ai_vendor(
        display_name="Workspace Helper",
        publisher="unknown",
        app_id=None,
        domains=["https://www.perplexity.ai/oauth/callback"],
    )
    negative = match_ai_vendor(
        display_name="Payroll Portal", publisher="Contoso", app_id=None
    )

    assert display and display["vendor_name"] == "OpenAI"
    assert publisher and publisher["product_name"] == "Claude"
    assert domain and domain["vendor_name"] == "Perplexity"
    assert negative is None


def test_scan_registry_accepts_ai_tool_discovery() -> None:
    assert validate_schema_version("ai_tool_discovery", "1.0") is None
    validate_required_fields("ai_tool_discovery", {"tools": []})


def test_runner_extracts_permissions_admin_consent_verified_publisher_and_risk(
    monkeypatch,
) -> None:
    def fake_get(url: str, headers: dict[str, str], timeout: int):  # noqa: ARG001
        if "/applications" in url:
            return FakeResponse(
                200,
                {
                    "value": [
                        {
                            "id": "app-reg-1",
                            "appId": "openai-app",
                            "displayName": "ChatGPT Enterprise",
                            "web": {"homePageUrl": "https://chatgpt.com"},
                            "identifierUris": [],
                        }
                    ]
                },
            )
        if "appRoleAssignedTo" in url:
            return FakeResponse(
                200,
                {
                    "value": [
                        {
                            "principalId": "sp-openai",
                            "appRoleId": "role-files-rw",
                            "resourceId": "graph-sp",
                        }
                    ]
                },
            )
        if "/servicePrincipals" in url:
            return FakeResponse(
                200,
                {
                    "value": [
                        {
                            "id": "graph-sp",
                            "appId": "00000003-0000-0000-c000-000000000000",
                            "displayName": "Microsoft Graph",
                            "appRoles": [
                                {"id": "role-files-rw", "value": "Files.ReadWrite.All"}
                            ],
                        },
                        {
                            "id": "sp-openai",
                            "appId": "openai-app",
                            "displayName": "ChatGPT Enterprise",
                            "verifiedPublisher": {"displayName": "OpenAI"},
                            "publisherName": "OpenAI",
                            "appRoles": [],
                        },
                    ]
                },
            )
        if "/oauth2PermissionGrants" in url:
            return FakeResponse(
                200,
                {
                    "value": [
                        {
                            "clientId": "sp-openai",
                            "principalId": None,
                            "resourceId": "graph-sp",
                            "scope": "Files.Read.All offline_access",
                            "consentType": "AllPrincipals",
                        }
                    ]
                },
            )
        if "/auditLogs/signIns" in url:
            return FakeResponse(
                200,
                {
                    "value": [
                        {
                            "appId": "openai-app",
                            "appDisplayName": "ChatGPT Enterprise",
                            "createdDateTime": "2026-05-01T12:00:00Z",
                        }
                    ]
                },
            )
        if "/auditLogs/directoryAudits" in url:
            return FakeResponse(200, {"value": []})
        raise AssertionError(url)

    monkeypatch.setattr("httpx.get", fake_get)
    result = run_ai_tool_discovery(
        access_token="token", tenant_id=_TENANT_ID, engagement_id="eng-1"
    )

    assert result["scan_type"] == "ai_tool_discovery_v1"
    assert result["summary"]["total_tools"] == 1
    tool = result["tools"][0]
    assert tool["tool_name"] == "ChatGPT"
    assert tool["verified_publisher"] is True
    assert tool["admin_consent"] is True
    assert tool["delegated_permissions"] == ["Files.Read.All", "offline_access"]
    assert tool["application_permissions"] == ["Files.ReadWrite.All"]
    assert "tenant_wide_access" in tool["risk_indicators"]
    assert "files_read_write_all" in tool["risk_indicators"]
    assert "offline_access" in tool["risk_indicators"]
    assert tool["graph_node_id"] == f"ai_tool:{_TENANT_ID}:openai-app"
    assert result["findings"][0]["type"] == "ai_tool_sensitive_permissions"


def test_runner_gracefully_skips_optional_403_sources(monkeypatch) -> None:
    def fake_get(url: str, headers: dict[str, str], timeout: int):  # noqa: ARG001
        if "/auditLogs/signIns" in url or "/auditLogs/directoryAudits" in url:
            return FakeResponse(403)
        if "/applications" in url:
            return FakeResponse(200, {"value": []})
        if "appRoleAssignedTo" in url:
            return FakeResponse(200, {"value": []})
        if "/servicePrincipals" in url:
            return FakeResponse(
                200,
                {
                    "value": [
                        {
                            "id": "sp-claude",
                            "appId": "claude-app",
                            "displayName": "Claude",
                            "verifiedPublisher": {},
                            "publisherName": "Anthropic",
                            "appRoles": [],
                        }
                    ]
                },
            )
        if "/oauth2PermissionGrants" in url:
            return FakeResponse(200, {"value": []})
        raise AssertionError(url)

    monkeypatch.setattr("httpx.get", fake_get)
    result = run_ai_tool_discovery(
        access_token="token", tenant_id=_TENANT_ID, engagement_id="eng-1"
    )

    assert result["summary"]["skipped"] == 2
    assert result["tools"][0]["last_seen"] == "unknown"
    assert "inactive_application" in result["tools"][0]["risk_indicators"]


def _make_client(build_app: object) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    return TestClient(app, headers={"X-API-Key": key})


def _create_engagement(client: TestClient) -> str:
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": "AI Discovery Corp",
            "assessor_id": "assessor-ai",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_bridge_creates_scan_result_findings_evidence_refs_and_links(build_app) -> None:
    client = _make_client(build_app)
    engagement_id = _create_engagement(client)

    from api.db import get_sessionmaker
    from api.field_assessment import _auto_link_scan_evidence

    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        imported = import_ai_tool_discovery_scan(
            db=db,
            tenant_id=_TENANT_ID,
            engagement_id=engagement_id,
            actor="tester",
            scan_result={
                "scan_completed_at": "2026-06-01T00:00:00Z",
                "tools": [
                    {
                        "tool_name": "ChatGPT",
                        "vendor": "OpenAI",
                        "permissions_summary": "delegated:1",
                        "evidence_refs": ["servicePrincipal:sp-1"],
                    }
                ],
                "summary": {
                    "discovered": 1,
                    "suspected": 0,
                    "unknown": 0,
                    "skipped": 0,
                },
                "findings": [
                    {
                        "type": "ai_tool_sensitive_permissions",
                        "severity": "medium",
                        "title": "Sensitive AI permissions",
                        "description": "Evidence-backed review input",
                        "recommendation": "Review scopes",
                    }
                ],
            },
        )
        _auto_link_scan_evidence(
            db,
            tenant_id=_TENANT_ID,
            engagement_id=engagement_id,
            scan_result_id=imported.scan_result_id,
            source_type="ai_tool_discovery",
        )
        db.commit()
    finally:
        db.close()

    scans = client.get(
        f"/field-assessment/engagements/{engagement_id}/scan-results"
    ).json()
    assert scans[0]["source_type"] == "ai_tool_discovery"
    detail = client.get(
        f"/field-assessment/engagements/{engagement_id}/scan-results/{imported.scan_result_id}"
    ).json()
    assert (
        detail["normalized_payload"]["tools"][0]["permissions_summary"] == "delegated:1"
    )
    findings = client.get(
        f"/field-assessment/engagements/{engagement_id}/findings"
    ).json()
    assert (
        findings["items"][0]["finding_type"]
        == "ai_tool_discovery.ai_tool_sensitive_permissions"
    )
    assert imported.scan_result_id in findings["items"][0]["evidence_ref_ids"]
    links = client.get(
        f"/field-assessment/engagements/{engagement_id}/evidence-links"
    ).json()
    assert any(link["evidence_entity_id"] == imported.scan_result_id for link in links)


def test_ai_tool_discovery_report_console_and_portal_integration_static() -> None:
    from services.governance.report.serialization import _CONNECTOR_DATA_COLLECTED

    assert "AI Tool Discovery" in _CONNECTOR_DATA_COLLECTED["ai_tool_discovery"][0]
    assert "initiateAiToolDiscoveryScan" in Path(
        "apps/console/lib/fieldAssessmentApi.ts"
    ).read_text(encoding="utf-8")
    assert "Run AI Tool Discovery Scan" in Path(
        "apps/console/app/field-assessment/[engagementId]/page.tsx"
    ).read_text(encoding="utf-8")
    portal_page = Path("apps/portal/app/engagement/[engagementId]/page.tsx").read_text(
        encoding="utf-8"
    )
    assert "AiToolDetails" in portal_page
    assert "permissions_summary" in portal_page


def test_runner_deterministic_ordering(monkeypatch) -> None:
    """Tools must be sorted by vendor, tool_name, application_id — deterministic output."""

    def fake_get(url: str, headers: dict, timeout: int):  # noqa: ARG001
        if "/applications" in url:
            return FakeResponse(200, {"value": []})
        if "appRoleAssignedTo" in url:
            return FakeResponse(200, {"value": []})
        if "/servicePrincipals" in url:
            return FakeResponse(
                200,
                {
                    "value": [
                        {
                            "id": "sp-notion",
                            "appId": "notion-app",
                            "displayName": "Notion AI",
                            "verifiedPublisher": {},
                            "publisherName": "Notion",
                            "appRoles": [],
                        },
                        {
                            "id": "sp-chatgpt",
                            "appId": "chatgpt-app",
                            "displayName": "ChatGPT",
                            "verifiedPublisher": {},
                            "publisherName": "OpenAI",
                            "appRoles": [],
                        },
                        {
                            "id": "sp-gemini",
                            "appId": "gemini-app",
                            "displayName": "Gemini",
                            "verifiedPublisher": {},
                            "publisherName": "Google",
                            "appRoles": [],
                        },
                    ]
                },
            )
        if "/oauth2PermissionGrants" in url:
            return FakeResponse(200, {"value": []})
        if "/auditLogs" in url:
            return FakeResponse(403)
        raise AssertionError(url)

    monkeypatch.setattr("httpx.get", fake_get)
    result = run_ai_tool_discovery(
        access_token="token", tenant_id=_TENANT_ID, engagement_id="eng-ordering"
    )

    vendors = [t["vendor"] for t in result["tools"]]
    assert vendors == sorted(vendors, key=str.casefold)


def test_tenant_isolation_cross_tenant_scan_results_not_visible(build_app) -> None:
    """Scan results imported for tenant A must not appear for tenant B."""
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker

    app = build_app(auth_enabled=True)
    tenant_a = "tenant-aitd-isolation-a"
    tenant_b = "tenant-aitd-isolation-b"
    key_a = mint_key("governance:read", "governance:write", tenant_id=tenant_a)
    key_b = mint_key("governance:read", "governance:write", tenant_id=tenant_b)
    client_a = TestClient(app, headers={"X-API-Key": key_a})
    client_b = TestClient(app, headers={"X-API-Key": key_b})

    resp = client_a.post(
        "/field-assessment/engagements",
        json={
            "client_name": "Tenant A Corp",
            "assessor_id": "assessor-a",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201
    eng_a = resp.json()["id"]

    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        import_ai_tool_discovery_scan(
            db=db,
            tenant_id=tenant_a,
            engagement_id=eng_a,
            actor="tester",
            scan_result={
                "scan_completed_at": "2026-06-01T00:00:00Z",
                "tools": [{"tool_name": "ChatGPT", "vendor": "OpenAI"}],
                "summary": {
                    "discovered": 1,
                    "suspected": 0,
                    "unknown": 0,
                    "skipped": 0,
                },
                "findings": [],
            },
        )
        db.commit()
    finally:
        db.close()

    scans_a = client_a.get(f"/field-assessment/engagements/{eng_a}/scan-results").json()
    assert any(s["source_type"] == "ai_tool_discovery" for s in scans_a)

    resp_b = client_b.post(
        "/field-assessment/engagements",
        json={
            "client_name": "Tenant B Corp",
            "assessor_id": "assessor-b",
            "assessment_type": "ai_governance",
        },
    )
    assert resp_b.status_code == 201
    eng_b = resp_b.json()["id"]

    scans_b = client_b.get(f"/field-assessment/engagements/{eng_b}/scan-results").json()
    assert not any(s["source_type"] == "ai_tool_discovery" for s in scans_b)

    cross = client_b.get(f"/field-assessment/engagements/{eng_a}/scan-results")
    assert cross.status_code in {403, 404}


def test_engagement_isolation_scan_result_not_in_other_engagement(build_app) -> None:
    """A scan result created in engagement A must not appear in engagement B for the same tenant."""
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker

    app = build_app(auth_enabled=True)
    tenant_id = "tenant-aitd-eng-isolation"
    key = mint_key("governance:read", "governance:write", tenant_id=tenant_id)
    client = TestClient(app, headers={"X-API-Key": key})

    def create_eng() -> str:
        resp = client.post(
            "/field-assessment/engagements",
            json={
                "client_name": "Isolation Corp",
                "assessor_id": "assessor-iso",
                "assessment_type": "ai_governance",
            },
        )
        assert resp.status_code == 201
        return resp.json()["id"]

    eng_a = create_eng()
    eng_b = create_eng()

    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        result = import_ai_tool_discovery_scan(
            db=db,
            tenant_id=tenant_id,
            engagement_id=eng_a,
            actor="tester",
            scan_result={
                "scan_completed_at": "2026-06-01T00:00:00Z",
                "tools": [{"tool_name": "Cursor", "vendor": "Anysphere"}],
                "summary": {
                    "discovered": 1,
                    "suspected": 0,
                    "unknown": 0,
                    "skipped": 0,
                },
                "findings": [],
            },
        )
        db.commit()
    finally:
        db.close()

    scans_a = client.get(f"/field-assessment/engagements/{eng_a}/scan-results").json()
    scans_b = client.get(f"/field-assessment/engagements/{eng_b}/scan-results").json()

    assert any(s["source_type"] == "ai_tool_discovery" for s in scans_a)
    assert not any(s["source_type"] == "ai_tool_discovery" for s in scans_b)
    assert result.scan_result_id not in [s["id"] for s in scans_b]


def test_report_section_ai_tool_discovery_populated(build_app, monkeypatch) -> None:
    """The generated report JSON must contain an ai_tool_discovery section."""
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", "a1" * 32)

    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.field_assessment import _auto_link_scan_evidence

    app = build_app(auth_enabled=True)
    tenant_id = "tenant-aitd-report-section"
    key = mint_key("governance:read", "governance:write", tenant_id=tenant_id)
    client = TestClient(app, headers={"X-API-Key": key})

    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": "Report Section Corp",
            "assessor_id": "assessor-rs",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201
    eng_id = resp.json()["id"]

    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        imported = import_ai_tool_discovery_scan(
            db=db,
            tenant_id=tenant_id,
            engagement_id=eng_id,
            actor="tester",
            scan_result={
                "scan_completed_at": "2026-06-01T00:00:00Z",
                "tools": [
                    {
                        "tool_name": "ChatGPT",
                        "vendor": "OpenAI",
                        "publisher": "OpenAI",
                        "verified_publisher": True,
                        "permissions_summary": "delegated:2",
                        "admin_consent": True,
                        "last_seen": "2026-05-01T12:00:00Z",
                        "risk_indicators": [
                            "admin_consent_granted",
                            "ai_vendor_detected",
                        ],
                        "evidence_refs": ["servicePrincipal:sp-1"],
                        "confidence": "confirmed",
                    }
                ],
                "summary": {
                    "discovered": 1,
                    "suspected": 0,
                    "unknown": 0,
                    "skipped": 1,
                },
                "findings": [],
            },
        )
        _auto_link_scan_evidence(
            db,
            tenant_id=tenant_id,
            engagement_id=eng_id,
            scan_result_id=imported.scan_result_id,
            source_type="ai_tool_discovery",
        )
        db.commit()
    finally:
        db.close()

    report_resp = client.post(
        f"/field-assessment/engagements/{eng_id}/reports",
        json={"report_type": "full_assessment"},
    )
    assert report_resp.status_code == 201, report_resp.text
    created = report_resp.json()
    report_version = created["version"]

    report_data = client.get(
        f"/field-assessment/engagements/{eng_id}/reports/{report_version}"
    ).json()
    report_content = report_data.get("report") or {}

    assert "ai_tool_discovery" in report_content, (
        "Report must include ai_tool_discovery section"
    )
    ai_section = report_content["ai_tool_discovery"]
    assert ai_section["scan_count"] == 1
    assert ai_section["summary"]["discovered"] == 1
    assert ai_section["summary"]["skipped"] == 1
    assert len(ai_section["tools"]) == 1

    tool = ai_section["tools"][0]
    assert tool["tool_name"] == "ChatGPT"
    assert tool["vendor"] == "OpenAI"
    assert tool["verified_publisher"] is True
    assert tool["admin_consent"] is True
    assert tool["permissions_summary"] == "delegated:2"
    assert "admin_consent_granted" in tool["risk_indicators"]
    assert tool["status"] == "discovered"
    assert tool["confidence"] == "confirmed"
