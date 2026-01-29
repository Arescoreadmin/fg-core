"""Tests for audit search/export endpoints."""

from fastapi.testclient import TestClient


def test_audit_requires_tenant_filter(client: TestClient) -> None:
    response = client.get("/admin/audit")
    assert response.status_code == 400
    assert response.json()["detail"] == "tenant_id or tenant_ids is required"


def test_audit_search_allows_tenant(client: TestClient) -> None:
    response = client.get("/admin/audit", params={"tenant_id": "tenant-dev"})
    assert response.status_code == 200
    data = response.json()
    assert data["tenant_id"] == "tenant-dev"
    assert data["events"]


def test_audit_export_returns_csv(client: TestClient) -> None:
    response = client.get(
        "/admin/audit/export",
        params={"tenant_id": "tenant-dev", "format": "csv"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "id,event_type" in response.text
