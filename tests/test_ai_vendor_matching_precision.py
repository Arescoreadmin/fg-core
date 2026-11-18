"""AI vendor matching precision: no AI label from a multi-product vendor's name
alone, and AI meeting assistants are detected."""

from __future__ import annotations

import pytest

from services.connectors.ai_tool_discovery import runner
from services.connectors.ai_tool_discovery.vendor_registry import match_ai_vendor
from services.connectors.msgraph.analyzers.ai_signals import _is_ai_app, _load_vendor_db


@pytest.mark.parametrize(
    ("display_name", "publisher"),
    [
        # Microsoft first-party service principals present in every tenant.
        ("Office 365 Exchange Online", "Microsoft Corporation"),
        ("Microsoft Teams Services", "Microsoft Corporation"),
        ("Azure Portal", "Microsoft"),
        # Multi-product vendors whose core product is not an AI tool.
        ("Salesforce", "Salesforce.com"),
        ("ServiceNow", "ServiceNow"),
        ("Notion", "Notion Labs"),
        ("Canva", "Canva Pty Ltd"),
        ("Google Drive", "Google LLC"),
        ("Google Workspace", "Google LLC"),
        ("GitHub", "GitHub, Inc."),
        # Substring traps for the new meeting-assistant names.
        ("Potter Logistics Portal", "Potter Freight"),
        ("Spreadsheet Sync", "Contoso"),
    ],
)
def test_multi_product_vendor_name_alone_is_not_ai(display_name, publisher) -> None:
    assert (
        match_ai_vendor(display_name=display_name, publisher=publisher, app_id=None)
        is None
    )


@pytest.mark.parametrize(
    ("display_name", "publisher", "product"),
    [
        ("Microsoft 365 Copilot", "Microsoft Corporation", "Microsoft Copilot"),
        ("Microsoft Copilot", "Microsoft", "Microsoft Copilot"),
        ("Salesforce Einstein", "Salesforce.com", "Salesforce AI"),
        ("Now Assist", "ServiceNow", "ServiceNow AI"),
        ("Notion AI", "Notion Labs", "Notion AI"),
        ("Gemini", "Google LLC", "Gemini"),
        ("Google Workspace AI", "Google LLC", "Gemini"),
        ("GitHub Copilot", "GitHub, Inc.", "GitHub Copilot"),
    ],
)
def test_ai_products_of_multi_product_vendors_still_match(
    display_name, publisher, product
) -> None:
    match = match_ai_vendor(display_name=display_name, publisher=publisher, app_id=None)
    assert match is not None and match["product_name"] == product


@pytest.mark.parametrize("app_id", [None, "1fec8e78-bce4-4aaf-ab1b-5451cc387264"])
def test_google_workspace_ai_has_explicit_product_evidence(app_id) -> None:
    match = match_ai_vendor(
        display_name="Google Workspace AI", publisher="Google LLC", app_id=app_id
    )
    assert match is not None
    assert match["vendor_name"] == "Google"
    assert "display_name" in match["match_reasons"]
    assert match["signature"]["publisher_implies_ai"] is False


def test_runner_preserves_google_ai_permission_exposure(monkeypatch) -> None:
    def fake_get_all(access_token, path, params=None):
        rows = {
            "/applications": [],
            "/servicePrincipals": [
                {
                    "id": "sp-google-ai",
                    "appId": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
                    "displayName": "Google Workspace AI",
                    "publisherName": "Google LLC",
                },
                {
                    "id": "sp-google-drive",
                    "appId": "non-ai-google-app",
                    "displayName": "Google Drive",
                    "publisherName": "Google LLC",
                },
            ],
            "/oauth2PermissionGrants": [
                {
                    "clientId": "sp-google-ai",
                    "scope": "Files.Read.All offline_access",
                    "consentType": "AllPrincipals",
                }
            ],
            "/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoleAssignedTo": [],
            "/auditLogs/signIns": [],
            "/auditLogs/directoryAudits": [],
        }[path]
        return rows, {"status": "collected", "count": len(rows), "path": path}

    monkeypatch.setattr(runner, "_get_all", fake_get_all)
    result = runner.run_ai_tool_discovery(
        access_token="synthetic-token",
        tenant_id="test-tenant",
        engagement_id="test-eng",
    )
    assert result["summary"]["total_tools"] == 1
    tool = result["tools"][0]
    assert tool["service_principal_id"] == "sp-google-ai"
    assert tool["vendor"] == "Google"
    assert tool["delegated_permissions"] == ["Files.Read.All", "offline_access"]
    assert tool["admin_consent"] is True
    assert {"files_read_all", "sensitive_permissions", "tenant_wide_access"} <= set(
        tool["risk_indicators"]
    )


def test_ai_only_vendor_publisher_still_matches_alone() -> None:
    match = match_ai_vendor(
        display_name="Enterprise App", publisher="Anthropic PBC", app_id=None
    )
    assert match is not None and match["product_name"] == "Claude"


@pytest.mark.parametrize(
    ("display_name", "publisher", "vendor"),
    [
        ("Otter.ai", "Otter.ai", "Otter.ai"),
        ("Fireflies.ai Notetaker", "Fireflies.ai", "Fireflies.ai"),
        ("Read AI Meeting Copilot", "Read AI", "Read AI"),
        ("Fathom Notetaker", "Fathom Video", "Fathom"),
        ("MeetScribe Notetaker", "MeetScribe Inc", "Unattributed"),
        ("Acme AI Meeting Assistant", "Acme", "Unattributed"),
    ],
)
def test_ai_meeting_assistants_are_detected(display_name, publisher, vendor) -> None:
    match = match_ai_vendor(display_name=display_name, publisher=publisher, app_id=None)
    assert match is not None and match["vendor_name"] == vendor


def test_msgraph_ai_signals_detects_meeting_note_takers() -> None:
    known_ids, _, patterns = _load_vendor_db()
    for name in (
        "MeetScribe Notetaker",
        "Otter.ai",
        "Fireflies.ai",
        "Fathom Notetaker",
    ):
        assert _is_ai_app({"appId": "x", "displayName": name}, known_ids, patterns), (
            name
        )
    assert not _is_ai_app(
        {"appId": "x", "displayName": "Office 365 Exchange Online"}, known_ids, patterns
    )
