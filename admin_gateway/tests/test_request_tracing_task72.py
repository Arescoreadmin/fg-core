"""Task 7.2 — Gateway request ID validation.

Proves DoD requirements for admin_gateway RequestIdMiddleware:
1. Valid UUID v4 inbound header is accepted and echoed back unchanged
2. Non-UUID inbound header is replaced with a fresh UUID v4 (injection prevention)
3. Missing header generates a fresh UUID v4
4. Generated/echoed request_id appears in X-Request-Id response header
"""

from __future__ import annotations

import re
import uuid

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# _safe_request_id unit tests (no HTTP server required)
# ---------------------------------------------------------------------------


def test_safe_request_id_accepts_valid_uuid4():
    """_safe_request_id must return the supplied UUID v4 (lowercased)."""
    from admin_gateway.middleware.request_id import _safe_request_id

    rid = str(uuid.uuid4())
    result = _safe_request_id(rid)
    assert result == rid.lower()


def test_safe_request_id_accepts_uppercase_uuid4():
    """_safe_request_id must accept uppercase UUID v4 and lowercase it."""
    from admin_gateway.middleware.request_id import _safe_request_id

    rid = str(uuid.uuid4()).upper()
    result = _safe_request_id(rid)
    assert result == rid.lower()
    assert _UUID4_RE.match(result)


def test_safe_request_id_rejects_non_uuid_string():
    """Non-UUID strings must be replaced with a fresh UUID v4."""
    from admin_gateway.middleware.request_id import _safe_request_id

    result = _safe_request_id("not-a-uuid")
    assert _UUID4_RE.match(result), f"Expected UUID v4, got {result!r}"


def test_safe_request_id_rejects_injection_attempt():
    """Attacker-controlled values (e.g. log injection) must be replaced."""
    from admin_gateway.middleware.request_id import _safe_request_id

    for malicious in [
        "../../etc/passwd",
        "<script>alert(1)</script>",
        "'; DROP TABLE logs; --",
        "a" * 200,
        "",
    ]:
        result = _safe_request_id(malicious)
        assert _UUID4_RE.match(result), (
            f"Injection value {malicious!r} was not replaced: {result!r}"
        )


def test_safe_request_id_generates_uuid4_when_none():
    """None input must produce a valid UUID v4."""
    from admin_gateway.middleware.request_id import _safe_request_id

    result = _safe_request_id(None)
    assert _UUID4_RE.match(result), f"Expected UUID v4, got {result!r}"


def test_safe_request_id_rejects_uuid_version_1():
    """UUID v1 values must be replaced (only v4 is accepted)."""
    from admin_gateway.middleware.request_id import _safe_request_id
    import uuid as _uuid

    v1 = str(_uuid.uuid1())
    result = _safe_request_id(v1)
    # v1 UUIDs have version digit = 1, not 4 — must not pass
    assert _UUID4_RE.match(result), "Should generate a fresh UUID4"
    assert result != v1.lower(), "v1 UUID must not be passed through as-is"


# ---------------------------------------------------------------------------
# Integration: middleware via TestClient (uses conftest `client` fixture)
# ---------------------------------------------------------------------------


def test_valid_uuid4_passthrough_in_gateway(client):
    """Gateway must echo a valid UUID v4 back in X-Request-Id response header."""
    rid = str(uuid.uuid4())
    response = client.get("/health", headers={"X-Request-Id": rid})
    assert response.headers.get("X-Request-Id") == rid


def test_invalid_request_id_replaced_in_gateway(client):
    """Gateway must replace a non-UUID X-Request-Id with a fresh UUID v4."""
    response = client.get("/health", headers={"X-Request-Id": "inject-me-not"})
    echoed = response.headers.get("X-Request-Id")
    assert echoed is not None
    assert _UUID4_RE.match(echoed), f"Expected UUID v4, got {echoed!r}"
    assert echoed != "inject-me-not"


def test_missing_request_id_generated_in_gateway(client):
    """Gateway must generate and return a UUID v4 when X-Request-Id is absent."""
    response = client.get("/health")
    echoed = response.headers.get("X-Request-Id")
    assert echoed is not None, "X-Request-Id must be present in response"
    assert _UUID4_RE.match(echoed), f"Expected UUID v4, got {echoed!r}"
