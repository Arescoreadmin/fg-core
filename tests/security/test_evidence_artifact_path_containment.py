"""CODEQL-REMEDIATE-005 — evidence registration must stay inside the artifact root.

CodeQL #100–#105 (``py/path-injection``): ``POST /evidence/anchors``
(``compliance:read``) and ``POST /evidence/runs/register`` (``admin:write``)
took ``artifact_path`` from the request body and opened it as-is. Any tenant
key with those scopes could:

- learn whether any path on the server exists (200 vs 404);
- obtain the SHA-256 of any server-readable file (secrets, ``/proc``,
  another tenant's evidence) in the response and in a stored record;
- record a provenance anchor in its own tenant for a file it does not own;
- force an unbounded ``read_bytes()`` of an arbitrary file.

Paths must resolve (symlinks included) strictly inside ``FG_ARTIFACTS_DIR``.
Anything else is refused with one fixed error, whether or not it exists.
All files and contents here are synthetic.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from tests.decision_evidence_helpers import emit_synthetic_decision_evidence

_SECRET = b"FG_SYNTHETIC_SECRET=never-reveal-this-value-0123456789\n"
_SECRET_SHA = hashlib.sha256(_SECRET).hexdigest()
_INVALID = "EVIDENCE_ARTIFACT_PATH_INVALID"


@pytest.fixture
def env(build_app, tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()
    monkeypatch.setenv("FG_ARTIFACTS_DIR", str(root))
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.env"
    secret.write_bytes(_SECRET)
    client = TestClient(build_app(auth_enabled=True))
    reader = {
        "X-API-Key": mint_key("compliance:read", tenant_id="tenant-a"),
        "X-Tenant-Id": "tenant-a",
    }
    admin = {
        "X-API-Key": mint_key("admin:write", "compliance:read", tenant_id="tenant-a"),
        "X-Tenant-Id": "tenant-a",
    }
    return {
        "client": client,
        "root": root,
        "secret": secret,
        "outside": outside,
        "reader": reader,
        "admin": admin,
    }


def _escapes(env) -> dict[str, str]:
    root: Path = env["root"]
    link = root / "innocent.json"
    link.symlink_to(env["secret"])
    return {
        "absolute": str(env["secret"]),
        "dotdot": str(root / ".." / "outside" / "secret.env"),
        "symlink_in_root": str(link),
        "proc": "/proc/self/environ",
    }


def _anchor(env, path: str):
    return env["client"].post(
        "/evidence/anchors",
        json={"artifact_path": path, "immutable_retention": True},
        headers=env["reader"],
    )


def _register(env, path: str):
    return env["client"].post(
        "/evidence/runs/register",
        json={
            "plane_id": "ai_plane",
            "artifact_type": "ai_plane_evidence",
            "artifact_path": path,
            "schema_version": "v1",
            "git_sha": "abc",
            "status": "PASS",
            "summary_json": {},
        },
        headers=env["admin"],
    )


# --- /evidence/anchors (compliance:read) -------------------------------------


@pytest.mark.parametrize("kind", ["absolute", "dotdot", "symlink_in_root", "proc"])
def test_anchor_refuses_paths_outside_artifact_root(env, kind):
    path = _escapes(env)[kind]
    resp = _anchor(env, path)

    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["error_code"] == _INVALID
    assert _SECRET_SHA not in resp.text
    listed = env["client"].get("/evidence/anchors", headers=env["reader"])
    assert listed.json()["anchors"] == [], "an out-of-root anchor was recorded"


def test_anchor_is_not_an_existence_oracle(env):
    present = _anchor(env, str(env["secret"]))
    absent = _anchor(env, str(env["outside"] / "no-such-file.env"))

    assert (present.status_code, present.json()) == (absent.status_code, absent.json())


def test_anchor_inside_root_still_works(env):
    # In-root artifacts must also be owned (EVIDENCE-ARTIFACT-TENANT-AUTH-001).
    artifact, _ = emit_synthetic_decision_evidence("tenant-a", 1)

    resp = _anchor(env, str(artifact))

    assert resp.status_code == 200, resp.text
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert resp.json()["artifact_sha256"] == expected
    missing = _anchor(env, str(env["root"] / "missing.json"))
    assert missing.status_code == 404
    assert (
        missing.json()["detail"]["error_code"] == "evidence_anchor_artifact_not_found"
    )


# --- /evidence/runs/register (admin:write) -----------------------------------


@pytest.mark.parametrize("kind", ["absolute", "dotdot", "symlink_in_root", "proc"])
def test_register_refuses_paths_outside_artifact_root(env, kind):
    path = _escapes(env)[kind]
    resp = _register(env, path)

    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["error_code"] == _INVALID
    assert _SECRET_SHA not in resp.text
    runs = env["client"].get("/evidence/runs", headers=env["reader"]).json()["runs"]
    assert runs == [], "an out-of-root evidence run was recorded"


def test_register_is_not_an_existence_oracle(env):
    present = _register(env, str(env["secret"]))
    absent = _register(env, str(env["outside"] / "no-such-file.env"))

    assert (present.status_code, present.json()) == (absent.status_code, absent.json())


def test_register_inside_root_still_works(env):
    # In-root artifacts must also be owned (EVIDENCE-ARTIFACT-TENANT-AUTH-001).
    artifact, _ = emit_synthetic_decision_evidence("tenant-a", 1)

    ok = _register(env, str(artifact))
    assert ok.status_code == 200, ok.text
    assert (
        ok.json()["artifact_sha256"]
        == hashlib.sha256(artifact.read_bytes()).hexdigest()
    )

    # Contract change (EVIDENCE-ARTIFACT-TENANT-AUTH-001): an unowned or
    # unwritten tenant artifact is refused like a foreign one, not recorded
    # as "missing". Platform producers keep the "missing" degraded path.
    missing = _register(env, str(env["root"] / "not-yet-written.json"))
    assert missing.status_code == 404
    assert missing.json()["detail"]["error_code"] == "EVIDENCE_ARTIFACT_NOT_FOUND"


def test_relative_path_under_default_root_still_works(env, monkeypatch, tmp_path):
    """The AI-plane evidence generator registers ``artifacts/...`` relative
    to the working directory; that contract must keep working. It calls the
    service directly, as a platform producer holding the code-defined grant
    (EVIDENCE-ARTIFACT-TENANT-AUTH-001); tenants cannot use that grant."""
    from api.db import get_sessionmaker
    from services.evidence_index import EvidenceIndexService

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FG_ARTIFACTS_DIR", "artifacts")
    (tmp_path / "artifacts" / "ai_plane_evidence.json").write_text(
        "{}", encoding="utf-8"
    )

    with get_sessionmaker()() as db:
        run = EvidenceIndexService().register_run(
            db,
            tenant_id="tenant-a",
            plane_id="ai_plane",
            artifact_type="ai_plane_evidence",
            artifact_path="artifacts/ai_plane_evidence.json",
            schema_version="v1",
            git_sha="abc",
            status="PASS",
            summary_json={},
            retention_class="hot",
            anchor_status="none",
            platform_authority="services.ai_plane_extension",
        )

    assert run["artifact_sha256"] != "missing"
