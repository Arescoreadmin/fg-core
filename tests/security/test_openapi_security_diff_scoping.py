from __future__ import annotations

import json
import subprocess
import sys


def _run(tmp_path, baseline: dict, current: dict, allow: dict, inv: list[dict]) -> subprocess.CompletedProcess:
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
    return subprocess.run([sys.executable, "tools/ci/check_openapi_security_diff.py"], text=True, capture_output=True, env=env)


def test_cosmetic_diff_does_not_fail(tmp_path):
    base = {"paths": {"/x": {"get": {"summary": "a", "responses": {"200": {}}}}}}
    cur = {"paths": {"/x": {"get": {"summary": "b", "responses": {"200": {}}}}}}
    # use repo files for allowlist/inventory by making no changed protected routes
    proc = _run(tmp_path, base, cur, {"protected_prefixes": [], "waived_401_403": {}}, [])
    assert proc.returncode == 0


def test_new_protected_route_missing_401_403_fails(tmp_path):
    base = {"paths": {}}
    cur = {"paths": {"/foo": {"get": {"responses": {"200": {}}}}}}
    inv = [{"method": "GET", "path": "/foo", "scoped": True, "tenant_bound": True}]
    proc = _run(tmp_path, base, cur, {"protected_prefixes": ["/foo"], "waived_401_403": {}}, inv)
    assert proc.returncode != 0
    assert "OPENAPI_SECURITY_401_403_REQUIRED" in proc.stdout


def test_unprotected_route_no_401_403_ok(tmp_path):
    base = {"paths": {}}
    cur = {"paths": {"/foo": {"get": {"responses": {"200": {}}}}}}
    proc = _run(tmp_path, base, cur, {"protected_prefixes": [], "waived_401_403": {}}, [])
    assert proc.returncode == 0


def test_unexpected_ai_route_fails(tmp_path):
    base = {"paths": {}}
    cur = {"paths": {"/ai/other": {"get": {"responses": {"200": {}, "401": {}, "403": {}}}}}}
    inv = [{"method": "GET", "path": "/ai/other", "scoped": True, "tenant_bound": True}]
    proc = _run(tmp_path, base, cur, {"protected_prefixes": ["/ai/"], "waived_401_403": {}}, inv)
    assert proc.returncode != 0
    assert "OPENAPI_SECURITY_UNEXPECTED_AI_ROUTE" in proc.stdout
