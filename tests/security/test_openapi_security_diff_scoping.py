from __future__ import annotations

import json
import subprocess
import sys


def _run(
    tmp_path, baseline: dict, current: dict, allow: dict, inv: list[dict]
) -> subprocess.CompletedProcess:
    b = tmp_path / "base.json"
    c = tmp_path / "cur.json"
    a = tmp_path / "allow.json"
    r = tmp_path / "routes.json"
    b.write_text(json.dumps(baseline), encoding="utf-8")
    c.write_text(json.dumps(current), encoding="utf-8")
    a.write_text(json.dumps(allow), encoding="utf-8")
    r.write_text(json.dumps(inv), encoding="utf-8")
    env = {
        "OPENAPI_BASELINE_PATH": str(b),
        "OPENAPI_TARGET_PATH": str(c),
        "OPENAPI_PROTECTED_ALLOWLIST_PATH": str(a),
        "OPENAPI_ROUTE_INVENTORY_PATH": str(r),
        "PYTHONPATH": ".",
        **__import__("os").environ,
    }
    return subprocess.run(
        [sys.executable, "tools/ci/check_openapi_security_diff.py"],
        text=True,
        capture_output=True,
        env=env,
    )


def test_cosmetic_diff_does_not_fail(tmp_path):
    base = {"paths": {"/x": {"get": {"summary": "a", "responses": {"200": {}}}}}}
    cur = {"paths": {"/x": {"get": {"summary": "b", "responses": {"200": {}}}}}}
    # use repo files for allowlist/inventory by making no changed protected routes
    proc = _run(
        tmp_path, base, cur, {"protected_prefixes": [], "waived_401_403": {}}, []
    )
    assert proc.returncode == 0


def test_new_protected_route_missing_401_403_fails(tmp_path):
    base = {"paths": {}}
    cur = {"paths": {"/foo": {"get": {"responses": {"200": {}}}}}}
    inv = [{"method": "GET", "path": "/foo", "scoped": True, "tenant_bound": True}]
    proc = _run(
        tmp_path, base, cur, {"protected_prefixes": ["/foo"], "waived_401_403": {}}, inv
    )
    assert proc.returncode != 0
    assert "OPENAPI_SECURITY_401_403_REQUIRED" in proc.stdout


def test_unprotected_route_no_401_403_ok(tmp_path):
    base = {"paths": {}}
    cur = {"paths": {"/foo": {"get": {"responses": {"200": {}}}}}}
    proc = _run(
        tmp_path, base, cur, {"protected_prefixes": [], "waived_401_403": {}}, []
    )
    assert proc.returncode == 0


def test_unexpected_ai_route_fails(tmp_path):
    base = {"paths": {}}
    cur = {
        "paths": {
            "/ai/other": {"get": {"responses": {"200": {}, "401": {}, "403": {}}}}
        }
    }
    inv = [{"method": "GET", "path": "/ai/other", "scoped": True, "tenant_bound": True}]
    proc = _run(
        tmp_path, base, cur, {"protected_prefixes": ["/ai/"], "waived_401_403": {}}, inv
    )
    assert proc.returncode != 0
    assert "OPENAPI_SECURITY_UNEXPECTED_AI_ROUTE" in proc.stdout


def test_known_ai_chat_route_is_allowed_when_protected(tmp_path):
    base = {"paths": {}}
    cur = {
        "paths": {
            "/ai/chat": {
                "post": {
                    "responses": {
                        "200": {},
                        "400": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {"error_code": {"type": "string"}}
                                    }
                                }
                            }
                        },
                        "401": {},
                        "403": {},
                    }
                }
            }
        }
    }
    inv = [
        {
            "method": "POST",
            "path": "/ai/chat",
            "scoped": True,
            "tenant_bound": True,
        }
    ]
    proc = _run(
        tmp_path,
        base,
        cur,
        {"protected_prefixes": ["/ai/chat"], "waived_401_403": {}},
        inv,
    )
    assert proc.returncode == 0


def _protected_op(schema: dict) -> dict:
    return {
        "paths": {
            "/foo": {
                "get": {
                    "responses": {
                        "200": {"content": {"application/json": {"schema": schema}}}
                    }
                }
            }
        }
    }


_PROTECTED = {"protected_prefixes": ["/foo"], "waived_401_403": {}}
_INV = [{"method": "GET", "path": "/foo", "scoped": True, "tenant_bound": True}]


def test_schema_equivalent_spellings_are_not_treated_as_changes(tmp_path):
    # Baseline route lacks 401/403 (grandfathered). FastAPI 0.162 / Pydantic
    # 2.14 add "additionalProperties": true and drop enum-duplicating-const;
    # neither changes the schema, so the route must not be re-examined.
    base = _protected_op(
        {"type": "object", "properties": {"v": {"const": "v1", "enum": ["v1"]}}}
    )
    cur = _protected_op(
        {
            "type": "object",
            "additionalProperties": True,
            "properties": {"v": {"const": "v1"}},
        }
    )
    proc = _run(tmp_path, base, cur, _PROTECTED, _INV)
    assert proc.returncode == 0, proc.stdout
    assert "checked_changed_ops=0" in proc.stdout


def test_additional_properties_false_is_still_a_change(tmp_path):
    base = _protected_op({"type": "object"})
    cur = _protected_op({"type": "object", "additionalProperties": False})
    proc = _run(tmp_path, base, cur, _PROTECTED, _INV)
    assert proc.returncode != 0
    assert "OPENAPI_SECURITY_401_403_REQUIRED GET /foo" in proc.stdout


def test_additional_properties_schema_is_still_a_change(tmp_path):
    base = _protected_op({"type": "object"})
    cur = _protected_op({"type": "object", "additionalProperties": {"type": "string"}})
    proc = _run(tmp_path, base, cur, _PROTECTED, _INV)
    assert proc.returncode != 0
    assert "OPENAPI_SECURITY_401_403_REQUIRED GET /foo" in proc.stdout


def test_enum_differing_from_const_is_still_a_change(tmp_path):
    base = _protected_op({"const": "v1"})
    cur = _protected_op({"const": "v1", "enum": ["v1", "v2"]})
    proc = _run(tmp_path, base, cur, _PROTECTED, _INV)
    assert proc.returncode != 0
    assert "OPENAPI_SECURITY_401_403_REQUIRED GET /foo" in proc.stdout


def test_enum_without_const_is_still_compared(tmp_path):
    base = _protected_op({"type": "string", "enum": ["a"]})
    cur = _protected_op({"type": "string", "enum": ["b"]})
    proc = _run(tmp_path, base, cur, _PROTECTED, _INV)
    assert proc.returncode != 0
    assert "OPENAPI_SECURITY_401_403_REQUIRED GET /foo" in proc.stdout
