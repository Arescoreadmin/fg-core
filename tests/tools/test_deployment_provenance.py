"""P0-PORTAL-DEPLOY-RECOVERY-001 — deployment provenance never trusts a skipped build."""

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
TOOL = REPO / "tools/ci/check_deployment_provenance.py"
_spec = importlib.util.spec_from_file_location("_dep_prov", TOOL)
assert _spec and _spec.loader
prov = importlib.util.module_from_spec(_spec)
sys.modules["_dep_prov"] = prov
_spec.loader.exec_module(prov)

ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@t",
}


def _git(repo: Path, *a: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *a],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **ENV},
    ).stdout.strip()


def _commit(repo: Path, rel: str, text: str) -> str:
    f = repo / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", rel)
    return _git(repo, "rev-parse", "HEAD")


def _lock(version: str) -> str:
    return json.dumps({"packages": {"node_modules/next": {"version": version}}})


@pytest.fixture()
def history(tmp_path: Path) -> dict[str, Any]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    old = _commit(repo, "apps/portal/package-lock.json", _lock("14.2.5"))
    baseline = _commit(repo, "apps/portal/package-lock.json", _lock("15.5.29"))
    _commit(repo, "docs/x.md", "unrelated")
    tip = _commit(repo, "apps/portal/app/page.tsx", "latest portal fix")
    _commit(repo, "docs/y.md", "unrelated after")
    policy = {
        "project_id": "prj_portal",
        "project_name": "app.frostgate.ai",
        "production_alias": "app.frostgate.ai",
        "production_branch": "main",
        "git_repo": "Arescoreadmin/fg-core",
        "watch_paths": ["apps/portal", "packages/ui"],
        "security_baseline_commit": baseline,
        "security_baseline_reason": "test",
        "framework_package": "next",
        "framework_lockfile": "apps/portal/package-lock.json",
    }
    return {
        "repo": repo,
        "old": old,
        "baseline": baseline,
        "tip": tip,
        "policy": policy,
    }


def _deployment(sha: str, **over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": "dpl_live",
        "url": "x.vercel.app",
        "name": "app.frostgate.ai",
        "projectId": "prj_portal",
        "target": "production",
        "readyState": "READY",
        "buildSkipped": False,
        "source": "git",
        "createdAt": 1_790_000_000_000,
        "ready": 1_790_000_100_000,
        "aliasAssigned": True,
        "alias": ["app.frostgate.ai", "x-git-main.vercel.app"],
        "meta": {
            "githubCommitSha": sha,
            "githubCommitRef": "main",
            "githubCommitOrg": "Arescoreadmin",
            "githubCommitRepo": "fg-core",
        },
        "env": ["PORTAL_SESSION_SECRET", "CORE_API_KEY"],
    }
    d.update(over)
    return d


def _events(sha: str, version: str) -> list[dict[str, Any]]:
    return [
        {
            "type": "stdout",
            "payload": {
                "text": f"Cloning github.com/Arescoreadmin/fg-core (Branch: main, Commit: {sha[:7]})"
            },
        },
        {"type": "stdout", "payload": {"text": f"Detected Next.js version: {version}"}},
    ]


def _eval(h: dict[str, Any], dep: Any, events: Any = None, attempts: Any = None) -> Any:
    return prov.evaluate(
        "portal", h["policy"], dep, events, attempts, prov.Git(h["repo"]), "main"
    )


def _status(res: Any, control: str) -> str:
    return next(c["status"] for c in res.controls if c["control"] == control)


def test_current_deployment_passes(history: dict[str, Any]) -> None:
    res = _eval(
        history, _deployment(history["tip"]), _events(history["tip"], "15.5.29"), []
    )
    assert res.status == "PASS", res.controls


def test_stale_but_successful_deployment_is_drift(history: dict[str, Any]) -> None:
    res = _eval(
        history,
        _deployment(history["baseline"]),
        _events(history["baseline"], "15.5.29"),
    )
    assert res.status == "DRIFT"
    assert _status(res, "freshness") == "DRIFT"
    assert _status(res, "security_baseline") == "PASS"
    assert len(res.observed["relevant_commits_not_deployed"]) == 1


def test_deployment_older_than_security_baseline_is_drift(
    history: dict[str, Any],
) -> None:
    res = _eval(history, _deployment(history["old"]), _events(history["old"], "14.2.5"))
    assert _status(res, "security_baseline") == "DRIFT"
    assert res.status == "DRIFT"


def test_skipped_newer_builds_do_not_make_production_current(
    history: dict[str, Any],
) -> None:
    # The scenario that hid the portal for five weeks: the alias still serves an
    # old READY build while every newer production attempt was CANCELED (and
    # Vercel reported commit status "success" for each).
    attempts = [
        {
            "uid": f"dpl_c{i}",
            "state": "CANCELED",
            "target": "production",
            "created": 1_795_000_000_000 + i,
            "meta": {"githubCommitSha": history["tip"]},
        }
        for i in range(3)
    ]
    res = _eval(
        history,
        _deployment(history["old"]),
        _events(history["old"], "14.2.5"),
        attempts,
    )
    assert res.status == "DRIFT"
    assert len(res.observed["newer_production_attempts_not_current"]) == 3


@pytest.mark.parametrize("state", ["CANCELED", "ERROR", "BUILDING", "QUEUED"])
def test_failed_or_skipped_deployment_is_never_current(
    history: dict[str, Any], state: str
) -> None:
    res = _eval(
        history,
        _deployment(history["tip"], readyState=state),
        _events(history["tip"], "15.5.29"),
    )
    assert _status(res, "build_outcome") == "DRIFT"
    assert res.status == "DRIFT"


def test_build_skipped_flag_is_drift(history: dict[str, Any]) -> None:
    res = _eval(
        history,
        _deployment(history["tip"], buildSkipped=True),
        _events(history["tip"], "15.5.29"),
    )
    assert _status(res, "build_outcome") == "DRIFT"


def test_wrong_project_is_rejected(history: dict[str, Any]) -> None:
    res = _eval(
        history,
        _deployment(history["tip"], projectId="prj_console"),
        _events(history["tip"], "15.5.29"),
    )
    assert _status(res, "project_identity") == "DRIFT"
    assert res.status == "DRIFT"


def test_wrong_or_unassigned_alias_is_rejected(history: dict[str, Any]) -> None:
    res = _eval(
        history,
        _deployment(history["tip"], alias=["evil.frostgate.ai"]),
        _events(history["tip"], "15.5.29"),
    )
    assert _status(res, "production_alias") == "DRIFT"
    res = _eval(
        history,
        _deployment(history["tip"], aliasAssigned=False),
        _events(history["tip"], "15.5.29"),
    )
    assert _status(res, "production_alias") == "DRIFT"


def test_preview_served_on_production_alias_is_rejected(
    history: dict[str, Any],
) -> None:
    res = _eval(
        history,
        _deployment(history["tip"], target=None),
        _events(history["tip"], "15.5.29"),
    )
    assert _status(res, "target_production") == "DRIFT"


def test_unknown_sha_is_not_verified(history: dict[str, Any]) -> None:
    res = _eval(history, _deployment("f" * 40))
    assert _status(res, "commit_known") == "NOT_VERIFIED"
    assert res.status == "NOT_VERIFIED"


def test_cli_upload_without_git_is_not_verified(history: dict[str, Any]) -> None:
    dep = _deployment(history["tip"], source="cli", meta={})
    res = _eval(history, dep)
    assert _status(res, "git_source") == "NOT_VERIFIED"
    assert res.status == "NOT_VERIFIED"


def test_wrong_branch_or_repo_is_drift(history: dict[str, Any]) -> None:
    dep = _deployment(history["tip"])
    dep["meta"]["githubCommitRef"] = "feature/x"
    assert (
        _status(_eval(history, dep, _events(history["tip"], "15.5.29")), "git_source")
        == "DRIFT"
    )
    dep = _deployment(history["tip"])
    dep["meta"]["githubCommitOrg"] = "attacker"
    assert (
        _status(_eval(history, dep, _events(history["tip"], "15.5.29")), "git_source")
        == "DRIFT"
    )


def test_unresolved_alias_is_not_verified(history: dict[str, Any]) -> None:
    for dep in (None, {}, {"error": {"code": "not_found"}}):
        assert _eval(history, dep).status == "NOT_VERIFIED"


def test_framework_mismatch_is_drift_and_missing_log_not_verified(
    history: dict[str, Any],
) -> None:
    res = _eval(history, _deployment(history["tip"]), _events(history["tip"], "14.2.5"))
    assert _status(res, "framework_version") == "DRIFT"
    res = _eval(history, _deployment(history["tip"]), [])
    assert _status(res, "framework_version") == "NOT_VERIFIED"
    assert res.status == "NOT_VERIFIED"


def test_build_log_commit_must_match_metadata(history: dict[str, Any]) -> None:
    res = _eval(
        history, _deployment(history["tip"]), _events(history["old"], "15.5.29")
    )
    assert _status(res, "build_log_commit") == "DRIFT"


def test_shallow_history_never_reports_false_drift(
    history: dict[str, Any], tmp_path: Path
) -> None:
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth=1", f"file://{history['repo']}", str(shallow)],
        check=True,
    )
    head = _git(shallow, "rev-parse", "HEAD")
    res = prov.evaluate(
        "portal",
        history["policy"],
        _deployment(head),
        _events(head, "15.5.29"),
        [],
        prov.Git(shallow),
        "HEAD",
    )
    assert _status(res, "security_baseline") == "NOT_VERIFIED"
    assert "DRIFT" not in {c["status"] for c in res.controls}


def test_read_errors_are_not_verified(history: dict[str, Any]) -> None:
    def failing(path: str, scope: str) -> Any:
        raise prov.FetchError("vercel api exited 1")

    dep, events, attempts, errors = prov.collect_live(
        history["policy"], "scope", failing
    )
    assert dep is None and errors
    assert _eval(history, dep, events, attempts).status == "NOT_VERIFIED"


def test_evidence_never_contains_env_or_secrets(
    history: dict[str, Any], tmp_path: Path
) -> None:
    fx = tmp_path / "fx"
    fx.mkdir()
    (fx / "alias.json").write_text(json.dumps(_deployment(history["tip"])))
    (fx / "events.json").write_text(json.dumps(_events(history["tip"], "15.5.29")))
    pol = tmp_path / "policy.json"
    pol.write_text(
        json.dumps({"vercel_scope": "s", "deployments": {"portal": history["policy"]}})
    )
    out = tmp_path / "evidence.json"
    rc = prov.main(
        [
            "--project",
            "portal",
            "--policy",
            str(pol),
            "--repo",
            str(history["repo"]),
            "--branch-ref",
            "main",
            "--fixture",
            str(fx),
            "--out",
            str(out),
        ]
    )
    text = out.read_text()
    assert rc == 0, text
    assert "PORTAL_SESSION_SECRET" not in text and "CORE_API_KEY" not in text
    assert '"env"' not in text
    assert json.loads(text)["status"] == "PASS"


@pytest.mark.parametrize(
    ("status", "code"), [("PASS", 0), ("DRIFT", 1), ("NOT_VERIFIED", 2)]
)
def test_exit_codes(status: str, code: int) -> None:
    assert prov.EXIT[status] == code


def test_unknown_project_in_policy_is_not_verified(tmp_path: Path) -> None:
    assert prov.main(["--project", "nope", "--fixture", str(tmp_path)]) == 2


def test_repository_policy_matches_portal_skip_rule() -> None:
    policy = json.loads(
        (REPO / ".github/security/deployment-provenance-policy.json").read_text()
    )
    portal = policy["deployments"]["portal"]
    cmd = json.loads((REPO / "apps/portal/vercel.json").read_text())["ignoreCommand"]
    watched = cmd.removesuffix(" || exit 1").split()[2:]
    assert portal["watch_paths"] == watched
    assert len(portal["security_baseline_commit"]) == 40
    assert portal["production_alias"] == "app.frostgate.ai"


def test_no_mutating_vercel_calls() -> None:
    src = TOOL.read_text()
    for verb in (
        "deploy",
        "promote",
        "rollback",
        "alias set",
        "-X",
        "--method",
        "DELETE",
        "POST",
        "PATCH",
    ):
        assert f'"{verb}"' not in src, verb
