"""CODEQL-REMEDIATE-006 — audit export path integrity and tenant isolation.

CodeQL #95–#97 (``py/path-injection``): ``GET /audit/export`` built the export
filename from the raw ``start``/``end`` query strings, stripping only ``:`` and
``-``. ``/`` survived, so an ``audit:export`` caller could:

- write a tenant audit bundle (``.json``) to any directory the service can
  write, including over existing files (``atomic_write`` creates parents);
- smuggle ``..`` via ``%2F`` URL encoding;
- submit non-timestamps and inverted windows that were exported anyway.

Exports also had no tenant segment: two tenants exporting the same window
wrote the same file, and ``export_exam_bundle`` read that shared file back,
so a concurrent export by tenant B could land in tenant A's exam archive.

All tenants, records and keys here are synthetic.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import threading
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from services.audit_engine.engine import (
    AuditEngine,
    InvariantResult,
    _sha256_hex,
    deterministic_json_bytes,
)

_INVALID = "AUDIT_EXPORT_WINDOW_INVALID"
_START = "1970-01-01T00:00:00Z"
_END = "9999-12-31T23:59:59Z"


def _fixed_invariants(self):
    return [InvariantResult("soc-invariants", "pass", "ok")]


@pytest.fixture
def env(build_app, tmp_path, monkeypatch):
    root = tmp_path / "audit_exports"
    monkeypatch.setenv("FG_AUDIT_EXPORT_DIR", str(root))
    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "synthetic-audit-key-synthetic-audit-k"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-synthetic")
    monkeypatch.setattr(AuditEngine, "_invariants", _fixed_invariants)
    client = TestClient(build_app(auth_enabled=True))
    eng = AuditEngine()
    for tenant in ("tenant-a", "tenant-b"):
        eng.run_cycle("light", tenant_id=tenant)

    def headers(tenant: str) -> dict[str, str]:
        key = mint_key("audit:export", "audit:read", "audit:write", tenant_id=tenant)
        return {"X-API-Key": key, "X-Tenant-Id": tenant}

    return {
        "client": client,
        "root": root,
        "tmp": tmp_path,
        "eng": eng,
        "a": headers("tenant-a"),
        "b": headers("tenant-b"),
    }


def _files(base: Path) -> set[Path]:
    return {p for p in base.rglob("*") if p.is_file() or p.is_symlink()}


def _records_tenants(bundle: dict) -> set[str]:
    return {r["tenant_id"] for r in bundle["records"]}


# --- request boundary ---------------------------------------------------------

_BAD_WINDOWS = {
    "slash_in_end": (_START, "../../../escaped/pwn"),
    "dotdot_in_start": ("../../../escaped/pwn", _END),
    "absolute_in_start": ("/tmp/escaped/pwn", _END),
    "not_a_timestamp": ("yesterday", _END),
    "no_utc_designator": ("1970-01-01T00:00:00", _END),
    "control_char": (_START + "\n", _END),
    "overlong": (_START, "9" * 512),
    "inverted_window": (_END, _START),
}


@pytest.mark.parametrize("case", sorted(_BAD_WINDOWS))
def test_export_rejects_untrusted_window(env, case):
    start, end = _BAD_WINDOWS[case]
    before = _files(env["tmp"])

    resp = env["client"].get(
        "/audit/export", params={"start": start, "end": end}, headers=env["a"]
    )

    assert not (env["tmp"] / "escaped").exists(), "export escaped the export root"
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["code"] == _INVALID
    created = _files(env["tmp"]) - before
    assert not [p for p in created if p.suffix == ".json"], created


def test_url_encoded_separators_cannot_escape_root(env):
    before = _files(env["tmp"])
    resp = env["client"].get(
        f"/audit/export?start={_START}&end=..%2F..%2F..%2Fescaped%2Fpwn",
        headers=env["a"],
    )

    assert resp.status_code == 400, resp.text
    assert not (env["tmp"] / "escaped").exists()
    assert not (_files(env["tmp"]) - before)


# --- tenant namespace ---------------------------------------------------------


def test_same_window_exports_do_not_collide_across_tenants(env):
    params = {"start": _START, "end": _END}
    a = env["client"].get("/audit/export", params=params, headers=env["a"])
    b = env["client"].get("/audit/export", params=params, headers=env["b"])
    assert a.status_code == b.status_code == 200, (a.text, b.text)

    path_a, path_b = Path(a.json()["path"]), Path(b.json()["path"])
    assert path_a != path_b, "two tenants share one export file"
    bundle_a = json.loads(path_a.read_text(encoding="utf-8"))["bundle"]
    assert _records_tenants(bundle_a) == {"tenant-a"}
    root = os.path.realpath(env["root"])
    for p in (path_a, path_b):
        assert os.path.realpath(p).startswith(root + os.sep)
        assert os.path.realpath(p.parent) != root, "export is not tenant-namespaced"


def test_tenant_directory_symlink_escape_is_refused(env):
    params = {"start": _START, "end": _END}
    first = env["client"].get("/audit/export", params=params, headers=env["a"])
    assert first.status_code == 200, first.text
    tenant_dir = Path(first.json()["path"]).parent
    assert os.path.realpath(tenant_dir) != os.path.realpath(env["root"])

    outside = env["tmp"] / "outside"
    outside.mkdir()
    for child in tenant_dir.iterdir():
        child.unlink()
    tenant_dir.rmdir()
    tenant_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(Exception):
        env["eng"].export_bundle(
            start=_START, end=_END, app_openapi={}, tenant_id="tenant-a"
        )
    assert not list(outside.iterdir()), "export followed a symlink out of root"


# --- exam export ----------------------------------------------------------------


def test_exam_archive_cannot_be_substituted_by_another_tenant(env, monkeypatch):
    """A concurrent same-window export by tenant B must not end up in A's exam."""
    eng = env["eng"]
    exam_id = eng.create_exam("tenant-a", "synthetic", _START, _END)
    original = AuditEngine.atomic_write
    fired = {"done": False}

    def racing_write(path: Path, payload: bytes) -> None:
        original(path, payload)
        if path.suffix == ".json" and not fired["done"]:
            fired["done"] = True  # tenant B's export lands right after A's write
            AuditEngine().export_bundle(
                start=_START, end=_END, app_openapi={}, tenant_id="tenant-b"
            )

    monkeypatch.setattr(AuditEngine, "atomic_write", staticmethod(racing_write))

    result = eng.export_exam_bundle(exam_id, app_openapi={}, tenant_id="tenant-a")

    assert fired["done"]
    with tarfile.open(
        fileobj=io.BytesIO(Path(result["archive_path"]).read_bytes())
    ) as tar:
        member = tar.extractfile("bundle.json")
        assert member is not None
        bundle = json.loads(member.read())
    assert _records_tenants(bundle) == {"tenant-a"}


def test_exam_window_is_validated_at_creation(env):
    resp = env["client"].post(
        "/audit/exams/run",
        json={
            "name": "synthetic",
            "window_start_utc": "../../escaped/pwn",
            "window_end_utc": _END,
        },
        headers=env["a"],
    )

    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["code"] == _INVALID


def test_foreign_and_unknown_exam_exports_are_indistinguishable(env):
    exam = env["client"].post(
        "/audit/exams/run",
        json={"name": "synthetic", "window_start_utc": _START, "window_end_utc": _END},
        headers=env["a"],
    )
    assert exam.status_code == 200, exam.text
    exam_id = exam.json()["exam_id"]

    foreign = env["client"].get(f"/audit/exams/{exam_id}/export", headers=env["b"])
    unknown = env["client"].get(f"/audit/exams/{uuid.uuid4()}/export", headers=env["b"])

    assert foreign.status_code == unknown.status_code == 404
    assert foreign.json() == unknown.json()
    own = env["client"].get(f"/audit/exams/{exam_id}/export", headers=env["a"])
    assert own.status_code == 200, own.text


# --- write integrity -------------------------------------------------------------


def test_failed_write_leaves_no_partial_artifact(env, monkeypatch):
    import services.audit_engine.engine as engine_mod

    def boom(src, dst):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(engine_mod.os, "replace", boom)
    target_dir = env["tmp"] / "partial"

    with pytest.raises(OSError):
        AuditEngine.atomic_write(target_dir / "out.json", b"{}")

    assert not [p for p in target_dir.iterdir()], "temporary file left behind"


def test_concurrent_writes_leave_one_complete_artifact(env):
    target = env["tmp"] / "concurrent" / "out.json"
    payloads = [json.dumps({"n": i, "pad": "x" * 65536}).encode() for i in range(8)]
    threads = [
        threading.Thread(target=AuditEngine.atomic_write, args=(target, p))
        for p in payloads
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert target.read_bytes() in payloads
    assert [p.name for p in target.parent.iterdir()] == ["out.json"]


def test_legitimate_export_fingerprint_matches_artifact_bytes(env):
    resp = env["client"].get(
        "/audit/export", params={"start": _START, "end": _END}, headers=env["a"]
    )
    assert resp.status_code == 200, resp.text

    stored = json.loads(Path(resp.json()["path"]).read_text(encoding="utf-8"))
    bundle = dict(stored["bundle"])
    bundle.pop("signed_evidence_checksum")
    assert (
        _sha256_hex(deterministic_json_bytes(bundle))
        == (resp.json()["manifest"]["bundle_sha256"])
    )
    assert stored["manifest"] == resp.json()["manifest"]
    assert bundle["start"] == _START and bundle["end"] == _END
    assert _records_tenants(stored["bundle"]) == {"tenant-a"}
