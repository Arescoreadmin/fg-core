"""AUTH-TENANT-CONTEXT-001: Principal-to-tenant binding lookup endpoint.

Tests for GET /admin/identity/principal-tenant/{principal_id}.

Covers:
  PTL-001  valid single active bound membership → 200
  PTL-002  missing membership (no rows) → 404
  PTL-003  inactive membership (active=0) → 404
  PTL-004  unbound identity (identity_binding_status != 'bound') → 404
  PTL-005  multiple active bound memberships → 409
  PTL-006  invalid principal_id format → 422
  PTL-007  internal token enforced when FG_INTERNAL_GATEWAY_SECRET is set
  PTL-008  response payload structure and types
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

ENDPOINT = "/admin/identity/principal-tenant/{principal_id}"

# Valid UUID v4s for test isolation (each test uses its own to avoid cross-test bleed).
# Variant byte (4th segment, first nibble) must be [89ab] per RFC 4122.
_P_VALID = "a1b2c3d4-e5f6-4a7b-8c9d-e0f1a2b3c4d5"
_P_INACTIVE = "b2c3d4e5-f6a7-4b8c-9d0e-f1a2b3c4d5e6"
_P_UNBOUND = "c3d4e5f6-a7b8-4c9d-8e1f-a2b3c4d5e6f7"
_P_AMBIGUOUS = "d4e5f6a7-b8c9-4d0e-8f2a-b3c4d5e6f7a8"
_P_ABSENT = "e5f6a7b8-c9d0-4e1f-8a3b-c4d5e6f7a8b9"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_principal(engine, principal_id: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO fg_principals
                    (id, principal_type, lifecycle_state, mfa_verified,
                     authority_version, created_at, updated_at)
                VALUES (:id, 'human', 'active', 0, 1, :now, :now)
                """
            ),
            {"id": principal_id, "now": _now_iso()},
        )


def _seed_member(
    engine,
    *,
    tenant_id: str,
    principal_id: str,
    role: str = "client_executive",
    active: int = 1,
    binding_status: str = "bound",
    membership_id: str | None = None,
) -> str:
    mid = membership_id or str(uuid.uuid4())
    _seed_principal(engine, principal_id)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO tenant_users
                    (id, tenant_id, email, display_name, role, active,
                     identity_binding_status, principal_id, created_at, updated_at)
                VALUES
                    (:id, :t, :e, :dn, :role, :active, :binding, :pid, :now, :now)
                """
            ),
            {
                "id": mid,
                "t": tenant_id,
                "e": f"{principal_id[:8]}@example.com",
                "dn": f"User {principal_id[:8]}",
                "role": role,
                "active": active,
                "binding": binding_status,
                "pid": principal_id,
                "now": _now_iso(),
            },
        )
    return mid


def _internal_headers(token: str = "ci-internal-secret") -> dict[str, str]:
    return {
        "X-FG-Internal-Token": token,
        "X-Admin-Gateway-Internal": "true",
    }


# ── PTL-001: Valid single active bound membership ────────────────────────────


def test_ptl_001_valid_active_bound_membership(build_app) -> None:
    app = build_app(auth_enabled=False)
    from api.db import get_engine

    engine = get_engine()
    mid = _seed_member(engine, tenant_id="acme-corp", principal_id=_P_VALID)

    c = TestClient(app)
    r = c.get(
        f"/admin/identity/principal-tenant/{_P_VALID}",
        headers=_internal_headers(),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["tenant_id"] == "acme-corp"
    assert body["role"] == "client_executive"
    assert body["membership_id"] == mid


# ── PTL-008: Response payload structure ──────────────────────────────────────


def test_ptl_008_response_payload_structure(build_app) -> None:
    app = build_app(auth_enabled=False)
    from api.db import get_engine

    engine = get_engine()
    _seed_member(
        engine,
        tenant_id="payload-tenant",
        principal_id=_P_VALID,
        role="tenant_admin",
    )

    c = TestClient(app)
    r = c.get(
        f"/admin/identity/principal-tenant/{_P_VALID}",
        headers=_internal_headers(),
    )
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"tenant_id", "role", "membership_id"}
    assert isinstance(body["tenant_id"], str) and body["tenant_id"]
    assert isinstance(body["role"], str) and body["role"]
    assert isinstance(body["membership_id"], str) and body["membership_id"]


# ── PTL-002: Missing membership → 404 ────────────────────────────────────────


def test_ptl_002_missing_membership_returns_404(build_app) -> None:
    app = build_app(auth_enabled=False)
    c = TestClient(app)
    r = c.get(
        f"/admin/identity/principal-tenant/{_P_ABSENT}",
        headers=_internal_headers(),
    )
    assert r.status_code == 404
    body = r.json()
    assert body["detail"]["code"] == "MEMBERSHIP_NOT_FOUND"


# ── PTL-003: Inactive membership → 404 ───────────────────────────────────────


def test_ptl_003_inactive_membership_returns_404(build_app) -> None:
    app = build_app(auth_enabled=False)
    from api.db import get_engine

    engine = get_engine()
    _seed_member(
        engine,
        tenant_id="inactive-tenant",
        principal_id=_P_INACTIVE,
        active=0,
    )

    c = TestClient(app)
    r = c.get(
        f"/admin/identity/principal-tenant/{_P_INACTIVE}",
        headers=_internal_headers(),
    )
    assert r.status_code == 404
    body = r.json()
    assert body["detail"]["code"] == "MEMBERSHIP_NOT_FOUND"


# ── PTL-004: Unbound identity → 404 ──────────────────────────────────────────


def test_ptl_004_unbound_identity_returns_404(build_app) -> None:
    app = build_app(auth_enabled=False)
    from api.db import get_engine

    engine = get_engine()
    _seed_member(
        engine,
        tenant_id="unbound-tenant",
        principal_id=_P_UNBOUND,
        binding_status="pending",
    )

    c = TestClient(app)
    r = c.get(
        f"/admin/identity/principal-tenant/{_P_UNBOUND}",
        headers=_internal_headers(),
    )
    assert r.status_code == 404
    body = r.json()
    assert body["detail"]["code"] == "MEMBERSHIP_NOT_FOUND"


# ── PTL-005: Multiple active bound memberships → 409 ────────────────────────


def test_ptl_005_ambiguous_memberships_returns_409(build_app) -> None:
    app = build_app(auth_enabled=False)
    from api.db import get_engine

    engine = get_engine()
    _seed_member(engine, tenant_id="tenant-alpha", principal_id=_P_AMBIGUOUS)
    _seed_member(engine, tenant_id="tenant-beta", principal_id=_P_AMBIGUOUS)

    c = TestClient(app)
    r = c.get(
        f"/admin/identity/principal-tenant/{_P_AMBIGUOUS}",
        headers=_internal_headers(),
    )
    assert r.status_code == 409
    body = r.json()
    assert body["detail"]["code"] == "MEMBERSHIP_AMBIGUOUS"


# ── PTL-006: Invalid UUID format → 422 ───────────────────────────────────────


@pytest.mark.parametrize(
    "bad_id",
    [
        "not-a-uuid",
        "12345678-1234-1234-1234-12345678901",  # too short
        "12345678-1234-1234-1234-1234567890123",  # too long
        "12345678-1234-5234-1234-123456789012",  # version 5 not 4
        "not-a-uuid-at-all",
        "00000000-0000-0000-0000-000000000000",  # version 0
    ],
)
def test_ptl_006_invalid_uuid_returns_422(build_app, bad_id: str) -> None:
    app = build_app(auth_enabled=False)
    c = TestClient(app)
    r = c.get(
        f"/admin/identity/principal-tenant/{bad_id}",
        headers=_internal_headers(),
    )
    assert r.status_code == 422
    body = r.json()
    assert body["detail"]["code"] == "PRINCIPAL_ID_INVALID"


# ── PTL-007: Internal token enforced when secret is configured ────────────────


def test_ptl_007_token_enforced_when_secret_configured(
    build_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    # build_app clears all internal gateway secrets during setup (FG_ENV=test).
    # Build first, then set the secret — require_internal_admin_gateway reads
    # env at request time (not at startup), so this takes effect immediately.
    app = build_app(auth_enabled=False)
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "ci-internal-secret")
    c = TestClient(app)

    # No header → 403
    r_no_header = c.get(f"/admin/identity/principal-tenant/{_P_ABSENT}")
    assert r_no_header.status_code == 403
    assert r_no_header.json()["detail"]["code"] == "ADMIN_GATEWAY_FORBIDDEN"

    # Wrong token → 403
    r_bad = c.get(
        f"/admin/identity/principal-tenant/{_P_ABSENT}",
        headers={"X-FG-Internal-Token": "wrong-secret"},
    )
    assert r_bad.status_code == 403

    # Correct token (404 means auth passed, no membership found) → not 403
    r_ok = c.get(
        f"/admin/identity/principal-tenant/{_P_ABSENT}",
        headers=_internal_headers("ci-internal-secret"),
    )
    assert r_ok.status_code == 404
