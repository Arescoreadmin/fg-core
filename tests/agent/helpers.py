from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def admin_headers() -> dict[str, str]:
    admin_key = mint_key("keys:admin", tenant_id="tenant-a")
    return {"X-API-Key": admin_key, "X-Tenant-Id": "tenant-a"}


def enroll_device(client: TestClient) -> dict[str, str]:
    issue = client.post(
        "/admin/agent/enrollment-tokens",
        json={
            "reason": "provision endpoint",
            "ticket": "CHG-100",
            "ttl_minutes": 15,
            "max_uses": 1,
        },
        headers=admin_headers(),
    )
    assert issue.status_code == 200
    token = issue.json()["token"]
    enroll = client.post(
        "/agent/enroll",
        json={"enrollment_token": token, "device_fingerprint": "fp-abcdefgh"},
    )
    assert enroll.status_code == 200
    return enroll.json()


def signed_headers(
    path: str,
    body: dict,
    key_id: str,
    secret: str,
    ts: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    ts_s = str(ts or int(time.time()))
    nonce_s = nonce or uuid.uuid4().hex[:24]
    body_hash = hashlib.sha256(
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    canonical = "\n".join(["POST", path, body_hash, ts_s, nonce_s])
    sig = hmac.new(
        secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return {
        "X-FG-DEVICE-KEY": key_id,
        "X-FG-TS": ts_s,
        "X-FG-NONCE": nonce_s,
        "X-FG-SIG": sig,
    }
