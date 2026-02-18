from __future__ import annotations

import hashlib
import hmac
import json
from urllib.parse import urlencode

from api.agent_enrollment import _canonical_request


def _canonical_path(path: str, query: list[tuple[str, str]]) -> str:
    if not query:
        return path
    return f"{path}?{urlencode(sorted(query, key=lambda x: (x[0], x[1])), doseq=True)}"


def test_shared_signing_vector() -> None:
    method = "POST"
    path = _canonical_path("/agent/heartbeat", [("b", "2"), ("a", "1")])
    body = {"hostname": "host-1", "os": "linux"}
    ts = "1700000000"
    nonce = "abc123nonce"
    secret = "test-secret"

    body_hash = hashlib.sha256(
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    canonical = _canonical_request(method, path, body_hash, ts, nonce)
    sig = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    assert canonical == (
        "POST\n"
        "/agent/heartbeat?a=1&b=2\n"
        "ab091d3221061fa87966d84c02da635664a6a0b39730f99629966bd0adc60740\n"
        "1700000000\n"
        "abc123nonce"
    )
    assert sig == "4f70d52e74880e519cdcae05ba6a8748a47579f5437354d409a5a7db2dfef6a2"
