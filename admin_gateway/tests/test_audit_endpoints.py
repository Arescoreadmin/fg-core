"""Tests for audit search/export endpoints."""

from fastapi.testclient import TestClient


def test_audit_requires_tenant_filter(client: TestClient) -> None:
    response = client.get("/admin/audit/search")
    assert response.status_code == 400
    assert response.json()["detail"] == "tenant_id is required"


def test_audit_search_allows_tenant(client: TestClient) -> None:
    response = client.get("/admin/audit/search", params={"tenant_id": "tenant-dev"})
    assert response.status_code == 200
    data = response.json()
    assert data["items"][0]["tenant_id"] == "tenant-dev"
    assert data["items"]


def test_audit_search_redacts_ip_and_user_agent(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("FG_AUDIT_REDACT", "true")
    response = client.get("/admin/audit/search", params={"tenant_id": "tenant-dev"})
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["ip"] is None
    assert item["user_agent"] is None


def test_audit_search_rejects_unauthorized_tenant(client: TestClient) -> None:
    response = client.get("/admin/audit/search", params={"tenant_id": "tenant-x"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Access denied to tenant: tenant-x"


def test_audit_export_returns_csv(client: TestClient) -> None:
    csrf = client.get("/admin/csrf-token")
    token = csrf.json()["csrf_token"]
    header_name = csrf.json()["header_name"]
    response = client.post(
        "/admin/audit/export",
        headers={header_name: token},
        json={"tenant_id": "tenant-dev", "format": "csv"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "id,action,status" in response.text
