"""EVIDENCE-ARTIFACT-TENANT-AUTH-001 — evidence artifacts need an owner, not a path.

CODEQL-REMEDIATE-005 confined ``POST /evidence/anchors`` (``compliance:read``)
and ``POST /evidence/runs/register`` (``admin:write``) to ``FG_ARTIFACTS_DIR``.
That root is shared by every tenant (``decision_evidence/<sequential id>.json``
and more), so containment alone let tenant B:

- hash tenant A's decision evidence and get the SHA-256 back;
- store an anchor or evidence run claiming it in tenant B;
- enumerate sequential ids (owned-but-foreign 200 vs absent 404);
- impersonate platform evidence such as ``ai_plane_evidence.json``.

An artifact is now usable only when a canonical owner record binds its
resolved path to the caller's bound tenant (``decision_evidence_artifacts``),
or, for platform artifacts, when an internal caller holds a code-defined grant.
All tenants, records and files here are synthetic.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.auth_scopes import mint_key
from api.db import get_sessionmaker
from tests.decision_evidence_helpers import emit_synthetic_decision_evidence

_ANCHOR_NOT_FOUND = "evidence_anchor_artifact_not_found"
_RUN_NOT_FOUND = "EVIDENCE_ARTIFACT_NOT_FOUND"


_emit = emit_synthetic_decision_evidence


@pytest.fixture
def env(build_app, tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()
    monkeypatch.setenv("FG_ARTIFACTS_DIR", str(root))
    client = TestClient(build_app(auth_enabled=True))

    def headers(tenant: str, *scopes: str) -> dict[str, str]:
        return {
            "X-API-Key": mint_key(*scopes, tenant_id=tenant),
            "X-Tenant-Id": tenant,
        }

    a_path, a_sha = _emit("tenant-a", 1)
    b_path, b_sha = _emit("tenant-b", 2)
    return {
        "client": client,
        "root": root,
        "a_path": a_path,
        "a_sha": a_sha,
        "b_path": b_path,
        "b_sha": b_sha,
        "a": headers("tenant-a", "compliance:read", "admin:write"),
        "b": headers("tenant-b", "compliance:read", "admin:write"),
    }


def _anchor(env, who: str, path: str, headers=None):
    return env["client"].post(
        "/evidence/anchors",
        json={"artifact_path": path, "immutable_retention": True},
        headers=headers or env[who],
    )


def _register(env, who: str, path: str, headers=None):
    return env["client"].post(
        "/evidence/runs/register",
        json={
            "plane_id": "decision_plane",
            "artifact_type": "decision_evidence",
            "artifact_path": path,
            "schema_version": "v1",
            "git_sha": "synthetic",
            "status": "PASS",
            "summary_json": {},
        },
        headers=headers or env[who],
    )


def _anchors(env, who: str) -> list:
    return env["client"].get("/evidence/anchors", headers=env[who]).json()["anchors"]


def _runs(env, who: str) -> list:
    return env["client"].get("/evidence/runs", headers=env[who]).json()["runs"]


# --- owner can use its own evidence ------------------------------------------


def test_owner_anchors_and_registers_own_evidence(env):
    anchored = _anchor(env, "a", str(env["a_path"]))
    assert anchored.status_code == 200, anchored.text
    assert anchored.json()["artifact_sha256"] == env["a_sha"]
    assert len(_anchors(env, "a")) == 1

    run = _register(env, "a", str(env["a_path"]))
    assert run.status_code == 200, run.text
    assert run.json()["artifact_sha256"] == env["a_sha"]
    assert len(_runs(env, "a")) == 1


# --- foreign evidence is refused before it is read --------------------------


def test_foreign_evidence_cannot_be_anchored(env):
    resp = _anchor(env, "b", str(env["a_path"]))

    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == {"error_code": _ANCHOR_NOT_FOUND}
    assert env["a_sha"] not in resp.text
    assert _anchors(env, "b") == [] and _anchors(env, "a") == []


def test_foreign_evidence_cannot_be_registered(env):
    resp = _register(env, "b", str(env["a_path"]))

    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == {"error_code": _RUN_NOT_FOUND}
    assert env["a_sha"] not in resp.text
    assert _runs(env, "b") == []


def test_foreign_unknown_and_unowned_are_indistinguishable(env):
    stray = env["root"] / "stray.json"  # in root, but nobody owns it
    stray.write_text('{"synthetic":true}', encoding="utf-8")
    targets = [
        str(env["a_path"]),
        str(env["root"] / "decision_evidence" / "999.json"),
        str(stray),
    ]

    anchors = {(r.status_code, r.text) for r in (_anchor(env, "b", t) for t in targets)}
    runs = {(r.status_code, r.text) for r in (_register(env, "b", t) for t in targets)}

    assert len(anchors) == 1 and next(iter(anchors))[0] == 404, anchors
    assert len(runs) == 1 and next(iter(runs))[0] == 404, runs


def test_sequential_ids_cannot_be_enumerated(env):
    base = env["root"] / "decision_evidence"
    seen = {
        (r.status_code, r.text)
        for r in (_anchor(env, "b", str(base / f"{i}.json")) for i in (1, 3, 4, 5))
    }

    assert len(seen) == 1 and next(iter(seen))[0] == 404, seen


def test_same_layout_across_tenants_is_not_shared_ownership(env):
    """Both tenants' evidence sits in the same directory with the same naming
    pattern; that does not make either tenant's file the other's."""
    assert env["a_path"].parent == env["b_path"].parent
    assert _anchor(env, "b", str(env["b_path"])).status_code == 200
    assert _anchor(env, "b", str(env["a_path"])).status_code == 404


def test_caller_tenant_header_cannot_select_owner(env):
    spoofed = dict(env["b"], **{"X-Tenant-Id": "tenant-a"})

    resp = _anchor(env, "b", str(env["a_path"]), headers=spoofed)

    assert resp.status_code != 200, resp.text
    assert env["a_sha"] not in resp.text
    assert _anchors(env, "a") == [] and _anchors(env, "b") == []


def test_in_root_symlink_to_foreign_evidence_is_refused(env):
    link = env["root"] / "mine.json"
    link.symlink_to(env["a_path"])

    for resp in (_anchor(env, "b", str(link)), _register(env, "b", str(link))):
        assert resp.status_code == 404, resp.text
        assert env["a_sha"] not in resp.text


def test_traversal_outside_root_still_refused(env, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    resp = _anchor(env, "a", str(env["root"] / ".." / "outside.json"))

    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["error_code"] == "EVIDENCE_ARTIFACT_PATH_INVALID"


# --- lifecycle and integrity --------------------------------------------------


def test_mutated_evidence_is_not_anchored(env):
    env["a_path"].write_text('{"tampered":true}', encoding="utf-8")

    resp = _anchor(env, "a", str(env["a_path"]))

    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"] == {
        "error_code": "EVIDENCE_ARTIFACT_INTEGRITY_MISMATCH"
    }
    assert _anchors(env, "a") == []


def test_deleted_owner_record_revokes_use(env):
    with get_sessionmaker()() as db:
        db.execute(
            text("DELETE FROM decision_evidence_artifacts WHERE tenant_id='tenant-a'")
        )
        db.commit()

    assert _anchor(env, "a", str(env["a_path"])).status_code == 404


# --- platform artifacts need an explicit grant -------------------------------


def _platform_artifact(env) -> Path:
    p = env["root"] / "ai_plane_evidence.json"
    p.write_text('{"synthetic":true}', encoding="utf-8")
    return p


def test_tenant_cannot_claim_platform_evidence(env):
    p = _platform_artifact(env)

    reg = env["client"].post(
        "/evidence/runs/register",
        json={
            "plane_id": "ai_plane",
            "artifact_type": "ai_plane_evidence",
            "artifact_path": str(p),
            "schema_version": "v1",
            "git_sha": "synthetic",
            "status": "PASS",
            "summary_json": {},
        },
        headers=env["b"],
    )
    anchor = _anchor(env, "b", str(p))

    assert reg.status_code == 404 and anchor.status_code == 404
    assert _runs(env, "b") == [] and _anchors(env, "b") == []


def _register_platform(env, authority: str, **overrides):
    from services.evidence_index import EvidenceIndexService

    kwargs = dict(
        tenant_id="tenant-dev",
        plane_id="ai_plane",
        artifact_type="ai_plane_evidence",
        artifact_path=str(_platform_artifact(env)),
        schema_version="v1",
        git_sha="synthetic",
        status="PASS",
        summary_json={},
        retention_class="hot",
        anchor_status="none",
        platform_authority=authority,
    )
    kwargs.update(overrides)
    with get_sessionmaker()() as db:
        return EvidenceIndexService().register_run(db, **kwargs)


def test_internal_producer_with_grant_registers_platform_evidence(env):
    run = _register_platform(env, "services.ai_plane_extension")

    expected = hashlib.sha256(
        (env["root"] / "ai_plane_evidence.json").read_bytes()
    ).hexdigest()
    assert run["artifact_sha256"] == expected


@pytest.mark.parametrize(
    "authority,overrides",
    [
        ("services.someone_else", {}),
        ("services.ai_plane_extension", {"artifact_type": "decision_evidence"}),
        ("services.ai_plane_extension", {"plane_id": "decision_plane"}),
    ],
)
def test_platform_grant_is_bound_to_owner_and_artifact(env, authority, overrides):
    from services.artifact_paths import ArtifactNotAuthorized

    with pytest.raises(ArtifactNotAuthorized):
        _register_platform(env, authority, **overrides)


def test_revoked_platform_grant_is_refused(env, monkeypatch):
    import services.artifact_paths as ap
    from services.artifact_paths import ArtifactNotAuthorized

    monkeypatch.setattr(ap, "PLATFORM_ARTIFACT_GRANTS", {})

    with pytest.raises(ArtifactNotAuthorized):
        _register_platform(env, "services.ai_plane_extension")


# --- no disclosure in logs ------------------------------------------------------


def test_denials_do_not_log_foreign_path_or_hash(env, caplog):
    caplog.set_level(logging.DEBUG)

    _anchor(env, "b", str(env["a_path"]))
    _register(env, "b", str(env["a_path"]))

    assert env["a_sha"] not in caplog.text
    assert str(env["a_path"]) not in caplog.text
