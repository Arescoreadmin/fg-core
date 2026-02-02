import json
import sqlite3
import time
import requests
import pytest

pytestmark = pytest.mark.integration


def test_defend_persists_decision(base_url, api_key, sqlite_path, clear_decisions):
    payload = {
        "tenant_id": "acme-prod",
        "source": "test-suite",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "auth",
        "event": {"src_ip": "192.0.2.10", "failed_auths": 1, "service": "ssh"},
    }

    r = requests.post(
        f"{base_url}/defend",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=10,
    )
    assert r.status_code == 200, r.text

    con = sqlite3.connect(sqlite_path)
    try:
        n = con.execute("SELECT COUNT(*) FROM decisions;").fetchone()[0]
    finally:
        con.close()

    assert n >= 1, "Expected at least 1 decision persisted to SQLite"
