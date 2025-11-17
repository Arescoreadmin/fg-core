"""Smoke tests for the FastAPI scaffold."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_returns_message() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Frostgate backend is online"}


def test_health_endpoint_reports_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
