"""P0-PORTAL-DEPLOY-RECOVERY-001 — Vercel Ignored Build Step is fail-safe.

Each test builds a throwaway git repository that mirrors the monorepo layout
and runs tools/vercel/ignore_build.sh from the Vercel Root Directory
(apps/portal), exactly as Vercel does. Exit 1 = build, exit 0 = skip.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools/vercel/ignore_build.sh"
PORTAL_VERCEL = REPO / "apps/portal/vercel.json"
WATCH = [
    "apps/portal",
    "packages/navigation",
    "packages/ui",
    "tools/vercel/ignore_build.sh",
]
BUILD, SKIP = 1, 0


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
        },
    ).stdout.strip()


def _commit(repo: Path, files: dict[str, str], msg: str = "c") -> str:
    for rel, text in files.items():
        f = repo / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture()
def mono(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _commit(
        repo,
        {
            "apps/portal/app/page.tsx": "v1",
            "apps/portal/middleware.ts": "auth v1",
            "apps/portal/package-lock.json": "{}",
            "apps/console/app/page.tsx": "console v1",
            "packages/navigation/src/index.ts": "nav v1",
            "packages/ui/src/index.ts": "ui v1",
            "docs/readme.md": "doc v1",
            "api/auth.py": "backend v1",
            "tools/vercel/ignore_build.sh": SCRIPT.read_text(),
        },
        "base",
    )
    return repo


def _run(
    repo: Path,
    *paths: str,
    env: dict[str, str] | None = None,
    path_prefix: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    e = {k: v for k, v in os.environ.items() if not k.startswith("VERCEL_")}
    e.update(env or {})
    if path_prefix:
        e["PATH"] = f"{path_prefix}{os.pathsep}{e['PATH']}"
    cwd = repo / "apps/portal"
    return subprocess.run(
        ["bash", str(repo / "tools/vercel/ignore_build.sh"), *(paths or WATCH)],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=e,
        timeout=30,
    )


PREVIEW = {"VERCEL_ENV": "preview"}


@pytest.mark.parametrize(
    ("changed", "expected"),
    [
        ("apps/portal/app/page.tsx", BUILD),  # portal source
        ("packages/ui/src/index.ts", BUILD),  # shared UI
        ("packages/navigation/src/index.ts", BUILD),  # shared navigation
        ("apps/portal/middleware.ts", BUILD),  # portal auth boundary
        ("apps/portal/package-lock.json", BUILD),  # dependency change
        ("tools/vercel/ignore_build.sh", BUILD),  # the skip rule itself
        ("docs/readme.md", SKIP),  # unrelated docs
        ("apps/console/app/page.tsx", SKIP),  # other app
        ("api/auth.py", SKIP),  # backend (deploys on Railway)
    ],
)
def test_change_classification_via_parent(
    mono: Path, changed: str, expected: int
) -> None:
    target = mono / changed
    _commit(mono, {changed: target.read_text() + "\n# changed\n"})
    r = _run(mono, env=PREVIEW)
    assert r.returncode == expected, r.stdout + r.stderr


def test_broken_or_missing_script_is_normalized_to_build(mono: Path) -> None:
    # vercel.json wraps the script so any non-zero exit (e.g. 127) becomes 1.
    cmd = json.loads(PORTAL_VERCEL.read_text())["ignoreCommand"]
    assert cmd.endswith("|| exit 1")
    (mono / "tools/vercel/ignore_build.sh").write_text("exit 127\n")
    r = subprocess.run(["sh", "-c", cmd], cwd=mono / "apps/portal", capture_output=True)
    assert r.returncode == BUILD
    (mono / "tools/vercel/ignore_build.sh").unlink()
    r = subprocess.run(["sh", "-c", cmd], cwd=mono / "apps/portal", capture_output=True)
    assert r.returncode == BUILD


def test_regression_745_old_command_skipped_from_root_directory(mono: Path) -> None:
    # The pre-fix command, run from apps/portal as Vercel does, skips a real
    # portal change; the new script builds it.
    _commit(mono, {"apps/portal/app/page.tsx": "security fix"})
    old = subprocess.run(
        [
            "git",
            "diff",
            "HEAD^",
            "HEAD",
            "--quiet",
            "--",
            "apps/portal",
            "packages/navigation",
            "packages/ui",
        ],
        cwd=mono / "apps/portal",
    )
    assert old.returncode == 0  # the defect: exit 0 => CANCELED
    assert _run(mono, env=PREVIEW).returncode == BUILD


def test_previous_successful_sha_catches_change_hidden_by_skipped_builds(
    mono: Path,
) -> None:
    last_ok = _git(mono, "rev-parse", "HEAD")
    _commit(mono, {"apps/portal/app/page.tsx": "fix"})  # this build was canceled
    _commit(mono, {"docs/readme.md": "unrelated"})  # HEAD^ diff would skip
    r = _run(mono, env={"VERCEL_ENV": "production", "VERCEL_GIT_PREVIOUS_SHA": last_ok})
    assert r.returncode == BUILD, r.stdout


def test_previous_successful_sha_skips_when_nothing_relevant_changed(
    mono: Path,
) -> None:
    last_ok = _git(mono, "rev-parse", "HEAD")
    _commit(mono, {"docs/readme.md": "unrelated"})
    r = _run(mono, env={"VERCEL_ENV": "production", "VERCEL_GIT_PREVIOUS_SHA": last_ok})
    assert r.returncode == SKIP, r.stdout


def test_missing_base_commit_builds(mono: Path) -> None:
    r = _run(
        mono,
        env={
            "VERCEL_ENV": "production",
            "VERCEL_GIT_PREVIOUS_SHA": "ec56641" + "0" * 33,
        },
    )
    assert r.returncode == BUILD
    assert "not in clone history" in r.stdout


def test_production_without_previous_sha_builds(mono: Path) -> None:
    _commit(mono, {"docs/readme.md": "unrelated"})
    assert _run(mono, env={"VERCEL_ENV": "production"}).returncode == BUILD


def test_first_commit_without_parent_builds(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _commit(
        repo,
        {
            "apps/portal/x": "1",
            "packages/ui/x": "1",
            "packages/navigation/x": "1",
            "tools/vercel/ignore_build.sh": SCRIPT.read_text(),
        },
    )
    assert _run(repo, env=PREVIEW).returncode == BUILD


def test_shallow_clone_without_parent_builds(mono: Path, tmp_path: Path) -> None:
    _commit(mono, {"docs/readme.md": "x"})
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth=1", f"file://{mono}", str(shallow)], check=True
    )
    assert _run(shallow, env=PREVIEW).returncode == BUILD


def test_explicit_redeploy_of_same_sha_builds(mono: Path) -> None:
    head = _git(mono, "rev-parse", "HEAD")
    assert (
        _run(
            mono, env={"VERCEL_ENV": "production", "VERCEL_GIT_PREVIOUS_SHA": head}
        ).returncode
        == BUILD
    )


def test_malformed_git_diff_builds(mono: Path, tmp_path: Path) -> None:
    _commit(mono, {"docs/readme.md": "x"})
    shim = tmp_path / "shim"
    shim.mkdir()
    real = shutil.which("git")
    (shim / "git").write_text(
        f'#!/bin/sh\nfor a in "$@"; do [ "$a" = diff ] && echo "fatal: bad object" >&2 && exit 128; done\nexec {real} "$@"\n'
    )
    (shim / "git").chmod(0o755)
    r = _run(mono, env=PREVIEW, path_prefix=shim)
    assert r.returncode == BUILD
    assert "git diff failed (exit 128)" in r.stdout


@pytest.mark.parametrize(
    "paths", [(), ("apps/portl",), ("/abs/path",), ("../escape",), ("-x",)]
)
def test_invalid_or_dead_watch_paths_build(mono: Path, paths: tuple[str, ...]) -> None:
    _commit(mono, {"docs/readme.md": "x"})
    cmd = ["bash", str(mono / "tools/vercel/ignore_build.sh"), *paths]
    r = subprocess.run(
        cmd,
        cwd=mono / "apps/portal",
        capture_output=True,
        text=True,
        env={**os.environ, "VERCEL_ENV": "preview"},
    )
    assert r.returncode == BUILD, r.stdout


def test_outside_git_work_tree_builds(tmp_path: Path) -> None:
    d = tmp_path / "nogit"
    d.mkdir()
    r = subprocess.run(
        ["bash", str(SCRIPT), "apps/portal"],
        cwd=d,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CEILING_DIRECTORIES": str(tmp_path)},
    )
    assert r.returncode == BUILD


def test_script_only_ever_exits_0_or_1() -> None:
    body = SCRIPT.read_text()
    assert re.findall(r"\bexit\s+(\d+)", body) and set(
        re.findall(r"\bexit\s+(\d+)", body)
    ) <= {"0", "1"}
    assert "set -e" not in body  # errexit would turn errors into untested codes


def test_portal_vercel_json_uses_script_with_complete_watch_list() -> None:
    cfg = json.loads(PORTAL_VERCEL.read_text())
    command = cfg["ignoreCommand"]
    assert command.endswith(" || exit 1")
    cmd = command[: -len(" || exit 1")].split()
    assert cmd[:2] == ["bash", "../../tools/vercel/ignore_build.sh"]
    assert (PORTAL_VERCEL.parent / cmd[1]).resolve() == SCRIPT
    watched = cmd[2:]
    assert watched == WATCH
    for p in watched:
        assert (REPO / p).exists(), p
    # Every out-of-tree source the portal consumes must be watched.
    portal = PORTAL_VERCEL.parent
    pkg = json.loads((portal / "package.json").read_text())
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    consumed = {
        str((portal / v.split(":", 1)[1]).resolve().relative_to(REPO))
        for v in deps.values()
        if v.startswith(("file:", "link:"))
    }
    tsconfig = json.loads((portal / "tsconfig.json").read_text())
    for targets in tsconfig["compilerOptions"].get("paths", {}).values():
        for t in targets:
            if t.startswith("../../"):
                consumed.add("/".join(t[len("../../") :].split("/")[:2]))
    assert consumed, "expected shared packages"
    for c in consumed:
        assert any(c == w or c.startswith(w + "/") for w in watched), c
