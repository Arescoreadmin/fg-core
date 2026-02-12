from __future__ import annotations

import sqlite3
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _insert_decision(db_path: str, tenant_id: str, event_id: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO decisions (
                tenant_id, source, event_id, event_type, threat_level,
                request_json, response_json, rules_triggered_json
            ) VALUES (?, 'sensor', ?, 'login', 'low', '{}', '{}', '[]')
            """,
            (tenant_id, event_id),
        )
        conn.commit()
    finally:
        conn.close()


def test_cross_tenant_queries_blocked_for_decisions_and_ui(
    build_app,
    fresh_db: str,
) -> None:
    _insert_decision(fresh_db, "tenant-a", "event-a")
    _insert_decision(fresh_db, "tenant-b", "event-b")

    app = build_app(sqlite_path=fresh_db)
    client = TestClient(app)

    key_tenant_b = mint_key("decisions:read", "ui:read", tenant_id="tenant-b")
    headers = {"X-API-Key": key_tenant_b}

    decisions_resp = client.get("/decisions?tenant_id=tenant-a", headers=headers)
    assert decisions_resp.status_code == 403

    ui_resp = client.get("/ui/decisions?tenant_id=tenant-a", headers=headers)
    assert ui_resp.status_code == 403
