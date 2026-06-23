# mypy: ignore-errors
from __future__ import annotations

import os
import sqlite3
import warnings

import pytest
from pydantic.warnings import PydanticDeprecatedSince20
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.main import build_app
from services.enterprise_controls_extension.service import EnterpriseControlsService
from services.framework_authority.engine import (
    CONTROL_FRAMEWORK_MAPPINGS_TOTAL,
    CONTROL_FRAMEWORK_MAPPING_TRANSITIONS_TOTAL,
    FRAMEWORK_CONTROLS_TOTAL,
    FRAMEWORK_COVERAGE_VIEWS_TOTAL,
    FRAMEWORKS_TOTAL,
)
from services.framework_authority.schemas import (
    FrameworkStatus,
    MappingStatus,
    VALID_FRAMEWORK_TRANSITIONS,
    VALID_MAPPING_TRANSITIONS,
    validate_framework_transition,
    validate_mapping_transition,
)

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "1")
os.environ.setdefault("FG_API_KEY", "")
os.environ.setdefault("FG_KEY_PEPPER", "framework-authority-test-pepper")
os.environ.setdefault(
    "FG_COMPLIANCE_HMAC_KEY_CURRENT", "0123456789abcdef0123456789abcdef"
)
os.environ.setdefault("FG_COMPLIANCE_HMAC_KEY_ID_CURRENT", "v1")

REQUIRED_PATHS = [
    ("POST", "/frameworks"),
    ("GET", "/frameworks"),
    ("GET", "/frameworks/{framework_id}"),
    ("PATCH", "/frameworks/{framework_id}"),
    ("POST", "/frameworks/{framework_id}/transitions"),
    ("POST", "/frameworks/{framework_id}/controls"),
    ("GET", "/frameworks/{framework_id}/controls"),
    ("GET", "/frameworks/{framework_id}/controls/{framework_control_id}"),
    ("PATCH", "/frameworks/{framework_id}/controls/{framework_control_id}"),
    ("POST", "/controls/{control_id}/framework-mappings"),
    ("GET", "/controls/{control_id}/framework-mappings"),
    ("GET", "/frameworks/{framework_id}/control-mappings"),
    ("GET", "/control-framework-mappings/{mapping_id}"),
    ("PATCH", "/control-framework-mappings/{mapping_id}"),
    ("POST", "/control-framework-mappings/{mapping_id}/transitions"),
    ("GET", "/control-framework-mappings/{mapping_id}/audit"),
    ("GET", "/frameworks/{framework_id}/coverage"),
    ("GET", "/controls/{control_id}/framework-coverage"),
]

READ_ROUTE_CASES = [
    ("GET", "/frameworks", None),
    ("GET", "/frameworks/fw-1", None),
    ("GET", "/frameworks/fw-1/controls", None),
    ("GET", "/frameworks/fw-1/controls/fc-1", None),
    ("GET", "/controls/ctrl-1/framework-mappings", None),
    ("GET", "/frameworks/fw-1/control-mappings", None),
    ("GET", "/control-framework-mappings/map-1", None),
    ("GET", "/control-framework-mappings/map-1/audit", None),
    ("GET", "/frameworks/fw-1/coverage", None),
    ("GET", "/controls/ctrl-1/framework-coverage", None),
]

WRITE_ROUTE_CASES = [
    (
        "POST",
        "/frameworks",
        {
            "framework_key": "auth-fw",
            "name": "Auth Framework",
            "version": "1.0",
            "category": "Security",
            "publisher": "FrostGate",
        },
    ),
    ("PATCH", "/frameworks/fw-1", {"description": "updated"}),
    ("POST", "/frameworks/fw-1/transitions", {"to_status": "ACTIVE"}),
    (
        "POST",
        "/frameworks/fw-1/controls",
        {"control_ref": "A-1", "title": "Access", "status": "ACTIVE"},
    ),
    ("PATCH", "/frameworks/fw-1/controls/fc-1", {"title": "Updated"}),
    (
        "POST",
        "/controls/ctrl-1/framework-mappings",
        {
            "framework_id": "fw-1",
            "framework_control_id": "fc-1",
            "mapping_type": "FULL",
            "coverage_level": "COMPLETE",
            "confidence": 100,
            "rationale": "test",
        },
    ),
    ("PATCH", "/control-framework-mappings/map-1", {"rationale": "updated"}),
    (
        "POST",
        "/control-framework-mappings/map-1/transitions",
        {"to_status": "ACTIVE", "reason": "approve"},
    ),
]

FRAMEWORK_TRANSITION_VALID = [
    (FrameworkStatus.DRAFT, FrameworkStatus.ACTIVE),
    (FrameworkStatus.ACTIVE, FrameworkStatus.RETIRED),
]
FRAMEWORK_TRANSITION_INVALID = [
    (src, dst)
    for src in FrameworkStatus
    for dst in FrameworkStatus
    if dst not in VALID_FRAMEWORK_TRANSITIONS[src]
]
MAPPING_TRANSITION_VALID = [
    (MappingStatus.DRAFT, MappingStatus.ACTIVE),
    (MappingStatus.DRAFT, MappingStatus.REJECTED),
    (MappingStatus.ACTIVE, MappingStatus.SUPERSEDED),
    (MappingStatus.ACTIVE, MappingStatus.RETIRED),
]
MAPPING_TRANSITION_INVALID = [
    (src, dst)
    for src in MappingStatus
    for dst in MappingStatus
    if dst not in VALID_MAPPING_TRANSITIONS[src]
]


@pytest.fixture(scope="module")
def api_bundle(tmp_path_factory):
    db_dir = tmp_path_factory.mktemp("framework_authority")
    db_path = db_dir / "framework-authority.db"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_ENV"] = "test"
    os.environ["FG_AUTH_ENABLED"] = "1"
    os.environ["FG_API_KEY"] = ""
    os.environ["FG_KEY_PEPPER"] = "framework-authority-test-pepper"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    client = TestClient(build_app(auth_enabled=True), raise_server_exceptions=False)
    SessionLocal = get_sessionmaker(sqlite_path=str(db_path))
    bundle = {
        "client": client,
        "db_path": db_path,
        "SessionLocal": SessionLocal,
        "headers_admin_a": _headers(
            mint_key(
                "governance:read",
                "governance:write",
                "admin:write",
                tenant_id="tenant-a",
            ),
            "tenant-a",
            actor="tenant-a-admin",
        ),
        "headers_rw_a": _headers(
            mint_key("governance:read", "governance:write", tenant_id="tenant-a"),
            "tenant-a",
            actor="tenant-a-operator",
        ),
        "headers_read_a": _headers(
            mint_key("governance:read", tenant_id="tenant-a"),
            "tenant-a",
            actor="tenant-a-reader",
        ),
        "headers_admin_b": _headers(
            mint_key(
                "governance:read",
                "governance:write",
                "admin:write",
                tenant_id="tenant-b",
            ),
            "tenant-b",
            actor="tenant-b-admin",
        ),
        "headers_rw_b": _headers(
            mint_key("governance:read", "governance:write", tenant_id="tenant-b"),
            "tenant-b",
            actor="tenant-b-operator",
        ),
        "headers_wrong_scope_a": _headers(
            mint_key("compliance:read", tenant_id="tenant-a"),
            "tenant-a",
            actor="tenant-a-wrong-scope",
        ),
    }
    yield bundle
    client.close()
    reset_engine_cache()


def _headers(key: str, tenant_id: str, *, actor: str) -> dict[str, str]:
    return {"X-API-Key": key, "X-Tenant-Id": tenant_id, "X-Actor": actor}


def _session(bundle):
    return bundle["SessionLocal"]()


def _seed_controls(bundle, tenant_id: str, *, count: int = 2) -> list[str]:
    with _session(bundle) as db:
        EnterpriseControlsService().seed_minimal(db)
        rows = [
            row[0]
            for row in db.execute(
                text(
                    "SELECT control_id FROM enterprise_control_catalog ORDER BY control_id"
                )
            ).all()
        ]
        selected = rows[:count]
        for control_id in selected:
            db.execute(
                text(
                    "INSERT OR IGNORE INTO tenant_control_state(tenant_id, control_id, status, note) "
                    "VALUES (:tenant_id, :control_id, :status, :note)"
                ),
                {
                    "tenant_id": tenant_id,
                    "control_id": control_id,
                    "status": "adopted",
                    "note": "test-owned",
                },
            )
        db.commit()
    return selected


def _framework_payload(label: str, *, scope_type: str = "TENANT") -> dict[str, object]:
    return {
        "framework_key": f"{label}-key",
        "name": f"{label} Framework",
        "version": f"{label}.1",
        "category": "Security",
        "publisher": "FrostGate",
        "description": f"{label} description",
        "scope_type": scope_type,
        "status": "DRAFT",
    }


def _framework_control_payload(
    label: str, *, status: str = "ACTIVE"
) -> dict[str, object]:
    return {
        "control_ref": f"{label}-REF",
        "title": f"{label} Control",
        "description": f"{label} description",
        "domain": "Governance",
        "family": "Access",
        "clause": f"{label}.1",
        "objective": "Objective",
        "implementation_guidance": "Guidance",
        "status": status,
    }


def _create_framework(
    bundle, label: str, headers: dict[str, str], *, scope_type: str = "TENANT"
) -> dict[str, object]:
    response = bundle["client"].post(
        "/frameworks",
        json=_framework_payload(label, scope_type=scope_type),
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _create_framework_control(
    bundle,
    framework_id: str,
    label: str,
    headers: dict[str, str],
    *,
    status: str = "ACTIVE",
) -> dict[str, object]:
    response = bundle["client"].post(
        f"/frameworks/{framework_id}/controls",
        json=_framework_control_payload(label, status=status),
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _create_mapping(
    bundle,
    control_id: str,
    framework_id: str,
    framework_control_id: str,
    headers: dict[str, str],
    *,
    mapping_type: str = "FULL",
    coverage_level: str = "COMPLETE",
    confidence: int = 100,
    status: str = "ACTIVE",
    rationale: str = "explicit mapping",
) -> dict[str, object]:
    response = bundle["client"].post(
        f"/controls/{control_id}/framework-mappings",
        json={
            "framework_id": framework_id,
            "framework_control_id": framework_control_id,
            "mapping_type": mapping_type,
            "coverage_level": coverage_level,
            "confidence": confidence,
            "rationale": rationale,
            "status": status,
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _counter_value(counter) -> float:
    value = getattr(counter, "_value", None)
    if value is None:
        return 0.0
    return float(value.get())


@pytest.mark.parametrize(("method", "path"), REQUIRED_PATHS)
def test_openapi_contains_required_routes(api_bundle, method: str, path: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", PydanticDeprecatedSince20)
        openapi = api_bundle["client"].app.openapi()
    assert path in openapi["paths"]
    assert method.lower() in openapi["paths"][path]


@pytest.mark.parametrize(
    ("method", "path", "payload"), READ_ROUTE_CASES + WRITE_ROUTE_CASES
)
def test_routes_require_authentication(
    api_bundle, method: str, path: str, payload
) -> None:
    response = api_bundle["client"].request(method, path, json=payload)
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("method", "path", "payload"), READ_ROUTE_CASES + WRITE_ROUTE_CASES
)
def test_routes_require_governance_scope(
    api_bundle, method: str, path: str, payload
) -> None:
    response = api_bundle["client"].request(
        method,
        path,
        json=payload,
        headers=api_bundle["headers_wrong_scope_a"],
    )
    assert response.status_code == 403


@pytest.mark.parametrize(("from_status", "to_status"), FRAMEWORK_TRANSITION_VALID)
def test_framework_transition_validator_accepts_valid_pairs(
    from_status, to_status
) -> None:
    validate_framework_transition(from_status, to_status)


@pytest.mark.parametrize(("from_status", "to_status"), FRAMEWORK_TRANSITION_INVALID)
def test_framework_transition_validator_rejects_invalid_pairs(
    from_status, to_status
) -> None:
    with pytest.raises(ValueError):
        validate_framework_transition(from_status, to_status)


@pytest.mark.parametrize(("from_status", "to_status"), MAPPING_TRANSITION_VALID)
def test_mapping_transition_validator_accepts_valid_pairs(
    from_status, to_status
) -> None:
    validate_mapping_transition(from_status, to_status)


@pytest.mark.parametrize(("from_status", "to_status"), MAPPING_TRANSITION_INVALID)
def test_mapping_transition_validator_rejects_invalid_pairs(
    from_status, to_status
) -> None:
    with pytest.raises(ValueError):
        validate_mapping_transition(from_status, to_status)


def test_create_list_get_update_framework(api_bundle) -> None:
    created = _create_framework(api_bundle, "tenant-crud", api_bundle["headers_rw_a"])
    listed = api_bundle["client"].get("/frameworks", headers=api_bundle["headers_rw_a"])
    assert listed.status_code == 200
    assert any(item["id"] == created["id"] for item in listed.json())
    fetched = api_bundle["client"].get(
        f"/frameworks/{created['id']}", headers=api_bundle["headers_rw_a"]
    )
    assert fetched.status_code == 200
    updated = api_bundle["client"].patch(
        f"/frameworks/{created['id']}",
        json={"description": "tenant-crud-updated"},
        headers=api_bundle["headers_rw_a"],
    )
    assert updated.status_code == 200
    assert updated.json()["description"] == "tenant-crud-updated"


def test_framework_transition_happy_path(api_bundle) -> None:
    created = _create_framework(api_bundle, "transition-ok", api_bundle["headers_rw_a"])
    activated = api_bundle["client"].post(
        f"/frameworks/{created['id']}/transitions",
        json={"to_status": "ACTIVE"},
        headers=api_bundle["headers_rw_a"],
    )
    assert activated.status_code == 200
    assert activated.json()["status"] == "ACTIVE"
    retired = api_bundle["client"].post(
        f"/frameworks/{created['id']}/transitions",
        json={"to_status": "RETIRED"},
        headers=api_bundle["headers_rw_a"],
    )
    assert retired.status_code == 200
    assert retired.json()["status"] == "RETIRED"


def test_framework_transition_invalid_returns_422(api_bundle) -> None:
    created = _create_framework(
        api_bundle, "transition-bad", api_bundle["headers_rw_a"]
    )
    response = api_bundle["client"].post(
        f"/frameworks/{created['id']}/transitions",
        json={"to_status": "RETIRED"},
        headers=api_bundle["headers_rw_a"],
    )
    assert response.status_code == 422


def test_system_framework_visible_to_other_tenants(api_bundle) -> None:
    created = _create_framework(
        api_bundle,
        "system-visible",
        api_bundle["headers_admin_a"],
        scope_type="SYSTEM",
    )
    visible = api_bundle["client"].get(
        f"/frameworks/{created['id']}", headers=api_bundle["headers_rw_b"]
    )
    assert visible.status_code == 200
    assert visible.json()["scope_type"] == "SYSTEM"


def test_system_framework_write_denied_without_admin(api_bundle) -> None:
    created = _create_framework(
        api_bundle,
        "system-protected",
        api_bundle["headers_admin_a"],
        scope_type="SYSTEM",
    )
    response = api_bundle["client"].patch(
        f"/frameworks/{created['id']}",
        json={"description": "forbidden"},
        headers=api_bundle["headers_rw_a"],
    )
    assert response.status_code == 403


def test_tenant_framework_hidden_from_other_tenant(api_bundle) -> None:
    created = _create_framework(
        api_bundle, "tenant-private", api_bundle["headers_rw_a"]
    )
    response = api_bundle["client"].get(
        f"/frameworks/{created['id']}", headers=api_bundle["headers_rw_b"]
    )
    assert response.status_code == 404


def test_create_list_get_update_framework_control(api_bundle) -> None:
    framework = _create_framework(
        api_bundle, "control-crud", api_bundle["headers_rw_a"]
    )
    control = _create_framework_control(
        api_bundle, framework["id"], "control-crud", api_bundle["headers_rw_a"]
    )
    listed = api_bundle["client"].get(
        f"/frameworks/{framework['id']}/controls", headers=api_bundle["headers_rw_a"]
    )
    assert listed.status_code == 200
    assert any(item["id"] == control["id"] for item in listed.json())
    fetched = api_bundle["client"].get(
        f"/frameworks/{framework['id']}/controls/{control['id']}",
        headers=api_bundle["headers_rw_a"],
    )
    assert fetched.status_code == 200
    updated = api_bundle["client"].patch(
        f"/frameworks/{framework['id']}/controls/{control['id']}",
        json={"title": "Control CRUD Updated", "status": "DEPRECATED"},
        headers=api_bundle["headers_rw_a"],
    )
    assert updated.status_code == 200
    assert updated.json()["title"] == "Control CRUD Updated"
    assert updated.json()["status"] == "DEPRECATED"


def test_duplicate_framework_control_ref_returns_409(api_bundle) -> None:
    framework = _create_framework(
        api_bundle, "control-dupe", api_bundle["headers_rw_a"]
    )
    _create_framework_control(
        api_bundle, framework["id"], "control-dupe", api_bundle["headers_rw_a"]
    )
    duplicate = api_bundle["client"].post(
        f"/frameworks/{framework['id']}/controls",
        json=_framework_control_payload("control-dupe"),
        headers=api_bundle["headers_rw_a"],
    )
    assert duplicate.status_code == 409


def test_control_mapping_create_list_get_update_transition_and_audit(
    api_bundle,
) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework = _create_framework(
        api_bundle, "mapping-crud", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle, framework["id"], "mapping-crud", api_bundle["headers_rw_a"]
    )
    created = _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
        status="DRAFT",
    )
    listed = api_bundle["client"].get(
        f"/controls/{control_id}/framework-mappings", headers=api_bundle["headers_rw_a"]
    )
    assert listed.status_code == 200
    assert any(item["id"] == created["id"] for item in listed.json())
    fetched = api_bundle["client"].get(
        f"/control-framework-mappings/{created['id']}",
        headers=api_bundle["headers_rw_a"],
    )
    assert fetched.status_code == 200
    updated = api_bundle["client"].patch(
        f"/control-framework-mappings/{created['id']}",
        json={"rationale": "updated rationale", "confidence": 88},
        headers=api_bundle["headers_rw_a"],
    )
    assert updated.status_code == 200
    assert updated.json()["confidence"] == 88
    transitioned = api_bundle["client"].post(
        f"/control-framework-mappings/{created['id']}/transitions",
        json={"to_status": "ACTIVE", "reason": "approved"},
        headers=api_bundle["headers_rw_a"],
    )
    assert transitioned.status_code == 200
    assert transitioned.json()["status"] == "ACTIVE"
    audit = api_bundle["client"].get(
        f"/control-framework-mappings/{created['id']}/audit",
        headers=api_bundle["headers_rw_a"],
    )
    assert audit.status_code == 200
    event_types = [item["event_type"] for item in audit.json()]
    assert event_types == ["CREATED", "UPDATED", "ACTIVATED"]


def test_mapping_invalid_transition_returns_422(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework = _create_framework(
        api_bundle, "mapping-bad-transition", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle,
        framework["id"],
        "mapping-bad-transition",
        api_bundle["headers_rw_a"],
    )
    created = _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
        status="DRAFT",
    )
    response = api_bundle["client"].post(
        f"/control-framework-mappings/{created['id']}/transitions",
        json={"to_status": "SUPERSEDED", "reason": "skip"},
        headers=api_bundle["headers_rw_a"],
    )
    assert response.status_code == 422


def test_mapping_terminal_record_cannot_be_patched(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework = _create_framework(
        api_bundle, "mapping-terminal", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle, framework["id"], "mapping-terminal", api_bundle["headers_rw_a"]
    )
    created = _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
        status="REJECTED",
    )
    response = api_bundle["client"].patch(
        f"/control-framework-mappings/{created['id']}",
        json={"rationale": "nope"},
        headers=api_bundle["headers_rw_a"],
    )
    assert response.status_code == 409


def test_cross_tenant_mapping_access_returns_404(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework = _create_framework(
        api_bundle, "mapping-cross-tenant", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle, framework["id"], "mapping-cross-tenant", api_bundle["headers_rw_a"]
    )
    created = _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
    )
    response = api_bundle["client"].get(
        f"/control-framework-mappings/{created['id']}",
        headers=api_bundle["headers_rw_b"],
    )
    assert response.status_code == 404


def test_cross_tenant_framework_mapping_create_returns_404(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework = _create_framework(
        api_bundle, "mapping-foreign-framework", api_bundle["headers_rw_b"]
    )
    framework_control = _create_framework_control(
        api_bundle,
        framework["id"],
        "mapping-foreign-framework",
        api_bundle["headers_rw_b"],
    )
    response = api_bundle["client"].post(
        f"/controls/{control_id}/framework-mappings",
        json={
            "framework_id": framework["id"],
            "framework_control_id": framework_control["id"],
            "mapping_type": "FULL",
            "coverage_level": "COMPLETE",
            "confidence": 90,
            "rationale": "forbidden",
            "status": "ACTIVE",
        },
        headers=api_bundle["headers_rw_a"],
    )
    assert response.status_code == 404


def test_cross_tenant_control_mapping_create_returns_404(api_bundle) -> None:
    framework = _create_framework(
        api_bundle, "mapping-foreign-control", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle,
        framework["id"],
        "mapping-foreign-control",
        api_bundle["headers_rw_a"],
    )
    response = api_bundle["client"].post(
        "/controls/non-owned-control/framework-mappings",
        json={
            "framework_id": framework["id"],
            "framework_control_id": framework_control["id"],
            "mapping_type": "FULL",
            "coverage_level": "COMPLETE",
            "confidence": 90,
            "rationale": "forbidden",
            "status": "ACTIVE",
        },
        headers=api_bundle["headers_rw_a"],
    )
    assert response.status_code == 404


def test_duplicate_mapping_returns_409(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework = _create_framework(
        api_bundle, "mapping-duplicate", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle, framework["id"], "mapping-duplicate", api_bundle["headers_rw_a"]
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
    )
    response = api_bundle["client"].post(
        f"/controls/{control_id}/framework-mappings",
        json={
            "framework_id": framework["id"],
            "framework_control_id": framework_control["id"],
            "mapping_type": "PARTIAL",
            "coverage_level": "MEDIUM",
            "confidence": 70,
            "rationale": "duplicate",
            "status": "ACTIVE",
        },
        headers=api_bundle["headers_rw_a"],
    )
    assert response.status_code == 409


def test_one_control_can_map_to_many_framework_controls(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework_one = _create_framework(
        api_bundle, "many-fw-one", api_bundle["headers_rw_a"]
    )
    framework_two = _create_framework(
        api_bundle, "many-fw-two", api_bundle["headers_rw_a"]
    )
    control_one = _create_framework_control(
        api_bundle, framework_one["id"], "many-fw-one", api_bundle["headers_rw_a"]
    )
    control_two = _create_framework_control(
        api_bundle, framework_two["id"], "many-fw-two", api_bundle["headers_rw_a"]
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework_one["id"],
        control_one["id"],
        api_bundle["headers_rw_a"],
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework_two["id"],
        control_two["id"],
        api_bundle["headers_rw_a"],
    )
    listed = api_bundle["client"].get(
        f"/controls/{control_id}/framework-mappings", headers=api_bundle["headers_rw_a"]
    )
    assert listed.status_code == 200
    assert len(listed.json()) >= 2


def test_one_framework_control_can_map_to_many_controls(api_bundle) -> None:
    control_ids = _seed_controls(api_bundle, "tenant-a", count=2)
    framework = _create_framework(
        api_bundle, "many-controls", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle, framework["id"], "many-controls", api_bundle["headers_rw_a"]
    )
    _create_mapping(
        api_bundle,
        control_ids[0],
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
    )
    _create_mapping(
        api_bundle,
        control_ids[1],
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
    )
    listed = api_bundle["client"].get(
        f"/frameworks/{framework['id']}/control-mappings",
        headers=api_bundle["headers_rw_a"],
    )
    assert listed.status_code == 200
    assert (
        len(
            [
                item
                for item in listed.json()
                if item["framework_control_id"] == framework_control["id"]
            ]
        )
        == 2
    )


def test_framework_coverage_no_mappings(api_bundle) -> None:
    framework = _create_framework(
        api_bundle, "coverage-none", api_bundle["headers_rw_a"]
    )
    _create_framework_control(
        api_bundle, framework["id"], "coverage-none-a", api_bundle["headers_rw_a"]
    )
    _create_framework_control(
        api_bundle, framework["id"], "coverage-none-b", api_bundle["headers_rw_a"]
    )
    response = api_bundle["client"].get(
        f"/frameworks/{framework['id']}/coverage", headers=api_bundle["headers_rw_a"]
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_framework_controls"] == 2
    assert body["mapped_framework_controls"] == 0
    assert body["coverage_percentage"] == 0.0


def test_framework_coverage_counts_mapping_types(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework = _create_framework(
        api_bundle, "coverage-mixed", api_bundle["headers_rw_a"]
    )
    fc_full = _create_framework_control(
        api_bundle, framework["id"], "coverage-full", api_bundle["headers_rw_a"]
    )
    fc_partial = _create_framework_control(
        api_bundle, framework["id"], "coverage-partial", api_bundle["headers_rw_a"]
    )
    fc_support = _create_framework_control(
        api_bundle, framework["id"], "coverage-support", api_bundle["headers_rw_a"]
    )
    fc_na = _create_framework_control(
        api_bundle, framework["id"], "coverage-na", api_bundle["headers_rw_a"]
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        fc_full["id"],
        api_bundle["headers_rw_a"],
        mapping_type="FULL",
        coverage_level="COMPLETE",
        confidence=100,
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        fc_partial["id"],
        api_bundle["headers_rw_a"],
        mapping_type="PARTIAL",
        coverage_level="MEDIUM",
        confidence=80,
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        fc_support["id"],
        api_bundle["headers_rw_a"],
        mapping_type="SUPPORTING",
        coverage_level="LOW",
        confidence=60,
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        fc_na["id"],
        api_bundle["headers_rw_a"],
        mapping_type="NOT_APPLICABLE",
        coverage_level="NONE",
        confidence=50,
    )
    response = api_bundle["client"].get(
        f"/frameworks/{framework['id']}/coverage", headers=api_bundle["headers_rw_a"]
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_framework_controls"] == 4
    assert body["mapped_framework_controls"] == 3
    assert body["full_coverage_count"] == 1
    assert body["partial_coverage_count"] == 1
    assert body["supporting_count"] == 1
    assert body["not_applicable_count"] == 1
    assert body["coverage_percentage"] == 75.0
    assert body["average_confidence"] == 72.5


def test_control_framework_coverage_rollup(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework_one = _create_framework(
        api_bundle, "control-rollup-one", api_bundle["headers_rw_a"]
    )
    framework_two = _create_framework(
        api_bundle, "control-rollup-two", api_bundle["headers_rw_a"]
    )
    fc_one = _create_framework_control(
        api_bundle,
        framework_one["id"],
        "control-rollup-one",
        api_bundle["headers_rw_a"],
    )
    fc_two = _create_framework_control(
        api_bundle,
        framework_two["id"],
        "control-rollup-two",
        api_bundle["headers_rw_a"],
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework_one["id"],
        fc_one["id"],
        api_bundle["headers_rw_a"],
        confidence=90,
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework_two["id"],
        fc_two["id"],
        api_bundle["headers_rw_a"],
        confidence=70,
    )
    response = api_bundle["client"].get(
        f"/controls/{control_id}/framework-coverage", headers=api_bundle["headers_rw_a"]
    )
    assert response.status_code == 200
    body = response.json()
    assert body["control_id"] == control_id
    assert body["mapped_frameworks"] >= 2
    assert {item["framework_id"] for item in body["framework_coverage"]} >= {
        framework_one["id"],
        framework_two["id"],
    }


def test_coverage_routes_increment_metrics(api_bundle) -> None:
    framework = _create_framework(
        api_bundle, "coverage-metric", api_bundle["headers_rw_a"]
    )
    _create_framework_control(
        api_bundle, framework["id"], "coverage-metric", api_bundle["headers_rw_a"]
    )
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    before = _counter_value(FRAMEWORK_COVERAGE_VIEWS_TOTAL)
    first = api_bundle["client"].get(
        f"/frameworks/{framework['id']}/coverage", headers=api_bundle["headers_rw_a"]
    )
    second = api_bundle["client"].get(
        f"/controls/{control_id}/framework-coverage", headers=api_bundle["headers_rw_a"]
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert _counter_value(FRAMEWORK_COVERAGE_VIEWS_TOTAL) >= before + 2


def test_create_metrics_increment(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    before_frameworks = _counter_value(FRAMEWORKS_TOTAL)
    before_controls = _counter_value(FRAMEWORK_CONTROLS_TOTAL)
    before_mappings = _counter_value(CONTROL_FRAMEWORK_MAPPINGS_TOTAL)
    framework = _create_framework(
        api_bundle, "metric-create", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle, framework["id"], "metric-create", api_bundle["headers_rw_a"]
    )
    _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
    )
    assert _counter_value(FRAMEWORKS_TOTAL) >= before_frameworks + 1
    assert _counter_value(FRAMEWORK_CONTROLS_TOTAL) >= before_controls + 1
    assert _counter_value(CONTROL_FRAMEWORK_MAPPINGS_TOTAL) >= before_mappings + 1


def test_transition_metrics_increment(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework = _create_framework(
        api_bundle, "metric-transition", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle, framework["id"], "metric-transition", api_bundle["headers_rw_a"]
    )
    mapping = _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
        status="DRAFT",
    )
    before = _counter_value(CONTROL_FRAMEWORK_MAPPING_TRANSITIONS_TOTAL)
    response = api_bundle["client"].post(
        f"/control-framework-mappings/{mapping['id']}/transitions",
        json={"to_status": "ACTIVE", "reason": "metrics"},
        headers=api_bundle["headers_rw_a"],
    )
    assert response.status_code == 200
    assert _counter_value(CONTROL_FRAMEWORK_MAPPING_TRANSITIONS_TOTAL) >= before + 1


def test_mapping_audit_table_is_append_only(api_bundle) -> None:
    control_id = _seed_controls(api_bundle, "tenant-a", count=1)[0]
    framework = _create_framework(
        api_bundle, "audit-append-only", api_bundle["headers_rw_a"]
    )
    framework_control = _create_framework_control(
        api_bundle, framework["id"], "audit-append-only", api_bundle["headers_rw_a"]
    )
    mapping = _create_mapping(
        api_bundle,
        control_id,
        framework["id"],
        framework_control["id"],
        api_bundle["headers_rw_a"],
    )
    audit = (
        api_bundle["client"]
        .get(
            f"/control-framework-mappings/{mapping['id']}/audit",
            headers=api_bundle["headers_rw_a"],
        )
        .json()
    )
    audit_id = audit[0]["id"]
    conn = sqlite3.connect(api_bundle["db_path"])
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(
                "UPDATE control_framework_mapping_audits SET reason = ? WHERE id = ?",
                ("tamper", audit_id),
            )
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(
                "DELETE FROM control_framework_mapping_audits WHERE id = ?",
                (audit_id,),
            )
    finally:
        conn.close()


def test_framework_listing_includes_system_and_tenant_rows(api_bundle) -> None:
    tenant_framework = _create_framework(
        api_bundle, "list-mixed-tenant", api_bundle["headers_rw_a"]
    )
    system_framework = _create_framework(
        api_bundle,
        "list-mixed-system",
        api_bundle["headers_admin_a"],
        scope_type="SYSTEM",
    )
    response = api_bundle["client"].get(
        "/frameworks", headers=api_bundle["headers_rw_a"]
    )
    assert response.status_code == 200
    ids = {item["id"] for item in response.json()}
    assert tenant_framework["id"] in ids
    assert system_framework["id"] in ids


def test_framework_control_isolation_returns_404(api_bundle) -> None:
    framework = _create_framework(
        api_bundle, "control-isolation", api_bundle["headers_rw_a"]
    )
    control = _create_framework_control(
        api_bundle, framework["id"], "control-isolation", api_bundle["headers_rw_a"]
    )
    response = api_bundle["client"].get(
        f"/frameworks/{framework['id']}/controls/{control['id']}",
        headers=api_bundle["headers_rw_b"],
    )
    assert response.status_code == 404
