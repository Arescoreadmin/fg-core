"""DEP-REMEDIATE-002 — single authoritative lockfile per JS app (fail-closed)."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools/ci/check_lockfile_authority.py"
_spec = importlib.util.spec_from_file_location("_lock_auth_t", TOOL)
assert _spec and _spec.loader
la = importlib.util.module_from_spec(_spec)
sys.modules["_lock_auth_t"] = la
_spec.loader.exec_module(la)

DOCKERFILE = (
    "FROM node:20-alpine\n"
    "COPY apps/console/package.json apps/console/package-lock.json* ./\n"
    "RUN npm ci\nRUN npm run build\n"
)
POLICY: dict[str, Any] = {
    "apps": {
        "apps/console": {
            "package_manager": "npm",
            "lockfile": "package-lock.json",
            "vercel_install_commands": ["npm install", "npm ci"],
            "dockerfile": "Dockerfile",
        }
    }
}
AUTHORITY = {
    "apps/console/package-lock.json": {"status": "AUTHORITATIVE_DEPLOYED"},
    "apps/console/pnpm-lock.yaml": {"status": "RETIRED", "deployed_as": "deleted"},
    "apps/other/yarn.lock": {"status": "AUTHORITATIVE_DEPLOYED"},
}


def _git(repo: Path, *a: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *a],
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
        },
    )


def _repo(tmp: Path, files: dict[str, str]) -> Path:
    repo = tmp / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    for rel, text in files.items():
        f = repo / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    _git(repo, "add", "-A")
    return repo


def _good(**over: str | None) -> dict[str, str]:
    files: dict[str, str | None] = {
        "apps/console/package.json": json.dumps({"name": "console"}),
        "apps/console/package-lock.json": "{}",
        "apps/console/vercel.json": json.dumps({"installCommand": "npm install"}),
        "apps/console/Dockerfile": DOCKERFILE,
    }
    files.update(over)
    return {k: v for k, v in files.items() if v is not None}


def _errors(
    tmp: Path,
    files: dict[str, str],
    policy: dict[str, Any] = POLICY,
    authority: dict[str, Any] = AUTHORITY,
) -> list[str]:
    return la.check(_repo(tmp, files), policy, authority)


def test_single_npm_lockfile_passes(tmp_path: Path) -> None:
    assert _errors(tmp_path, _good()) == []


def test_reappearing_pnpm_lockfile_fails_twice(tmp_path: Path) -> None:
    errs = _errors(
        tmp_path, _good(**{"apps/console/pnpm-lock.yaml": "lockfileVersion: '9.0'"})
    )
    assert any("second lockfile apps/console/pnpm-lock.yaml" in e for e in errs)
    assert any("RETIRED lockfile has reappeared" in e for e in errs)


@pytest.mark.parametrize(
    "name", ["yarn.lock", "bun.lockb", "bun.lock", "npm-shrinkwrap.json"]
)
def test_any_second_lockfile_fails(tmp_path: Path, name: str) -> None:
    auth = {**AUTHORITY, f"apps/console/{name}": {"status": "AUTHORITATIVE_DEPLOYED"}}
    errs = _errors(tmp_path, _good(**{f"apps/console/{name}": "x"}), authority=auth)
    assert any(f"second lockfile apps/console/{name}" in e for e in errs)


def test_missing_canonical_lockfile_fails(tmp_path: Path) -> None:
    errs = _errors(tmp_path, _good(**{"apps/console/package-lock.json": None}))
    assert any(
        "canonical lockfile apps/console/package-lock.json is not tracked" in e
        for e in errs
    )


@pytest.mark.parametrize("pm", ["pnpm@10.0.0", "yarn@4.1.0", "bun@1.1.0"])
def test_foreign_package_manager_field_fails(tmp_path: Path, pm: str) -> None:
    pkg = json.dumps({"name": "console", "packageManager": pm})
    errs = _errors(tmp_path, _good(**{"apps/console/package.json": pkg}))
    assert any("packageManager" in e for e in errs)


def test_npm_package_manager_field_passes(tmp_path: Path) -> None:
    pkg = json.dumps({"name": "console", "packageManager": "npm@10.9.0"})
    assert _errors(tmp_path, _good(**{"apps/console/package.json": pkg})) == []


@pytest.mark.parametrize(
    "vercel",
    [
        json.dumps({"framework": "nextjs"}),
        json.dumps({"installCommand": "pnpm install"}),
        json.dumps({"installCommand": "yarn"}),
    ],
)
def test_vercel_autodetection_or_foreign_installer_fails(
    tmp_path: Path, vercel: str
) -> None:
    errs = _errors(tmp_path, _good(**{"apps/console/vercel.json": vercel}))
    assert any("installCommand" in e for e in errs)


def test_missing_vercel_json_fails_when_policy_requires_explicit_installer(
    tmp_path: Path,
) -> None:
    errs = _errors(tmp_path, _good(**{"apps/console/vercel.json": None}))
    assert any("explicit installCommand" in e for e in errs)


@pytest.mark.parametrize(
    ("docker", "needle"),
    [
        (
            DOCKERFILE.replace("RUN npm ci", "RUN pnpm install --frozen-lockfile"),
            "invokes pnpm",
        ),
        (DOCKERFILE + "RUN corepack enable\n", "corepack"),
        (
            DOCKERFILE.replace("apps/console/package-lock.json* ", ""),
            "does not copy package-lock.json",
        ),
        (
            DOCKERFILE.replace("RUN npm ci", "RUN yarn install"),
            "does not install with npm",
        ),
    ],
)
def test_dockerfile_must_use_policy_manager(
    tmp_path: Path, docker: str, needle: str
) -> None:
    errs = _errors(tmp_path, _good(**{"apps/console/Dockerfile": docker}))
    assert any(needle in e for e in errs), errs


def test_unclassified_lockfile_anywhere_fails(tmp_path: Path) -> None:
    errs = _errors(tmp_path, _good(**{"apps/newapp/package-lock.json": "{}"}))
    assert any(
        "apps/newapp/package-lock.json: lockfile not classified" in e for e in errs
    )


def test_unlisted_app_may_use_another_manager_if_classified(tmp_path: Path) -> None:
    # Independent apps are not forced onto npm; they only need classification.
    assert _errors(tmp_path, _good(**{"apps/other/yarn.lock": "x"})) == []


def test_untracked_lockfile_is_ignored(tmp_path: Path) -> None:
    repo = _repo(tmp_path, _good())
    (repo / "apps/console/pnpm-lock.yaml").write_text("untracked local artifact")
    assert la.check(repo, POLICY, AUTHORITY) == []


def test_policy_lockfile_must_match_manager(tmp_path: Path) -> None:
    bad = {
        "apps": {
            "apps/console": {**POLICY["apps"]["apps/console"], "lockfile": "yarn.lock"}
        }
    }
    errs = _errors(tmp_path, _good(), policy=bad)
    assert any("does not belong to npm" in e for e in errs)


def test_invalid_policy_exits_2(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text("{}")
    assert la.main(["--policy", str(p)]) == 2
    p.write_text("not json")
    assert la.main(["--policy", str(p)]) == 2


def test_repository_is_compliant_and_pnpm_lock_retired() -> None:
    assert la.main([]) == 0
    assert not (REPO / "apps/console/pnpm-lock.yaml").exists()
    auth = la.load_manifest_authority()
    assert auth["apps/console/pnpm-lock.yaml"]["status"] == "RETIRED"
    policy = json.loads((REPO / ".github/security/lockfile-authority.json").read_text())
    assert policy["apps"]["apps/console"]["lockfile"] == "package-lock.json"
    vercel = json.loads((REPO / "apps/console/vercel.json").read_text())
    assert (
        vercel["installCommand"]
        in policy["apps"]["apps/console"]["vercel_install_commands"]
    )


def test_regression_gate_wires_the_guard() -> None:
    src = (REPO / "tools/ci/check_security_regression_gates.py").read_text()
    assert "def check_lockfile_authority(failures" in src
    assert "    check_lockfile_authority(failures)\n" in src
