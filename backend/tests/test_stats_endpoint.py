import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_stats_requires_auth():
    r = client.get("/stats")
    assert r.status_code in (401, 403)


def test_stats_schema_with_auth():
    r = client.get("/stats", headers={"x-api-key": "supersecret"})
    assert r.status_code == 200
    data = r.json()

    # Fast sanity checks: this endpoint must be useful instantly
    assert "generated_at" in data
    assert "decisions_1h" in data
    assert "decisions_24h" in data
    assert "decisions_7d" in data
    assert "threat_counts_24h" in data
    assert "top_event_types_24h" in data
    assert "top_rules_24h" in data
    assert "avg_latency_ms_24h" in data
    assert "pct_high_medium_24h" in data

def test_stats_has_buyer_fields():
    r = client.get("/stats", headers={"X-API-Key": "supersecret"})
    assert r.status_code == 200
    data = r.json()
    assert "top_sources_24h" in data
    assert "unique_source_ips_24h" in data
    assert "high_threat_rate_1h" in data
