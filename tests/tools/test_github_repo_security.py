"""P0-REPO-SECURITY-ENFORCEMENT-001 — required checks cannot fail open.

Offline negative tests. Each scenario copies the real `.github/` tree into a
temporary fixture, applies one bypass attempt, and proves the static policy
check (run in the Guard job) rejects it. The embedded aggregate and gate
scripts are executed with synthetic job results, so "skipped", "failure",
"cancelled" and missing results are shown to block. The live drift evaluator
is tested with synthetic API responses: access denied is never COMPLIANT.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


chk = _load("check_github_repo_security", "tools/ci/check_github_repo_security.py")


@pytest.fixture
def fake(tmp_path: Path) -> Path:
    shutil.copytree(REPO / ".github", tmp_path / ".github")
    return tmp_path


def _wf(root: Path, name: str) -> Path:
    return root / ".github/workflows" / name


def _edit_yaml(path: Path, fn) -> None:
    data = yaml.safe_load(path.read_text())
    fn(data)
    path.write_text(yaml.safe_dump(data, sort_keys=False))


def _on(d: dict) -> dict:
    return d[True] if True in d else d["on"]


def _expect(root: Path, needle: str) -> None:
    failures = chk.check_workflows(root)
    assert any(needle in f for f in failures), failures


def test_repository_policy_is_currently_satisfied():
    assert chk.check_workflows(REPO) == []


# 1. removing the frontend dependency workflow
def test_removing_frontend_dependency_workflow_fails(fake):
    _wf(fake, "frontend-dependency-security.yml").unlink()
    _expect(fake, "'Frontend Dependency Security': workflow")


# 2. continue-on-error on a required job, a step, or an aggregate member
@pytest.mark.parametrize(
    "wf,job,where",
    [
        ("fg-required.yml", "fg-required", "job"),
        ("fg-required.yml", "fg-required", "step"),
        ("ci.yml", "fg_guard", "job"),
        ("ci.yml", "hardening", "step"),
    ],
)
def test_continue_on_error_is_rejected(fake, wf, job, where):
    def fn(d):
        if where == "job":
            d["jobs"][job]["continue-on-error"] = True
        else:
            d["jobs"][job]["steps"][-1]["continue-on-error"] = True

    _edit_yaml(_wf(fake, wf), fn)
    _expect(fake, "continue-on-error")


# 3. path-filtering a mandatory workflow
@pytest.mark.parametrize(
    "wf",
    ["fg-required.yml", "ci.yml", "frontend-dependency-security.yml", "docker-ci.yml"],
)
def test_path_filtered_required_workflow_fails(fake, wf):
    def fn(d):
        pr = _on(d).get("pull_request") or {}
        pr["paths"] = ["api/**"]
        _on(d)["pull_request"] = pr

    _edit_yaml(_wf(fake, wf), fn)
    _expect(fake, "pull_request has 'paths'")


# 4. removing a child from the aggregate, or adding an uncovered job
def test_removing_aggregate_child_fails(fake):
    _edit_yaml(
        _wf(fake, "ci.yml"),
        lambda d: d["jobs"]["ci_required"]["needs"].remove("migrations_replay"),
    )
    _expect(fake, "needs")


def test_new_ci_job_outside_aggregate_fails(fake):
    _edit_yaml(
        _wf(fake, "ci.yml"),
        lambda d: d["jobs"].__setitem__(
            "sneaky",
            {"name": "Sneaky", "runs-on": "ubuntu-latest", "steps": [{"run": "true"}]},
        ),
    )
    _expect(fake, "not covered by 'CI Required'")


def test_dropping_docker_validation_from_gate_fails(fake):
    _edit_yaml(
        _wf(fake, "docker-ci.yml"),
        lambda d: d["jobs"]["docker-gate"].__setitem__("needs", ["changes"]),
    )
    _expect(fake, "Docker Compose Gate")


# 5. downgrading a blocking gate to advisory (renaming the job context or
#    narrowing the required set in policy + ruleset together)
def test_renaming_required_job_fails(fake):
    _edit_yaml(
        _wf(fake, "fg-required.yml"),
        lambda d: d["jobs"]["fg-required"].__setitem__(
            "name", "fg-required (advisory)"
        ),
    )
    _expect(fake, "context would never report")


def test_narrowing_required_set_fails_even_when_consistent(fake):
    pol = fake / ".github/security/repository-policy.json"
    rs = fake / ".github/security/main-ruleset.json"
    p = json.loads(pol.read_text())
    p["required_status_checks"]["contexts"] = [
        c
        for c in p["required_status_checks"]["contexts"]
        if c["context"] != "Frontend Dependency Security"
    ]
    pol.write_text(json.dumps(p))
    r = json.loads(rs.read_text())
    for rule in r["rules"]:
        if rule["type"] == "required_status_checks":
            rule["parameters"]["required_status_checks"] = [
                c
                for c in rule["parameters"]["required_status_checks"]
                if c["context"] != "Frontend Dependency Security"
            ]
    rs.write_text(json.dumps(r))
    _expect(fake, "dropped mandatory required checks")


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (
            lambda r: r.__setitem__(
                "bypass_actors",
                [
                    {
                        "actor_id": 5,
                        "actor_type": "RepositoryRole",
                        "bypass_mode": "always",
                    }
                ],
            ),
            "bypass actors",
        ),
        (lambda r: r.__setitem__("enforcement", "evaluate"), "enforcement"),
        (lambda r: r["rules"].remove({"type": "non_fast_forward"}), "non_fast_forward"),
    ],
    ids=["bypass-actor", "evaluate-mode", "force-push-allowed"],
)
def test_weakened_ruleset_fails(fake, mutate, needle):
    rs = fake / ".github/security/main-ruleset.json"
    r = json.loads(rs.read_text())
    mutate(r)
    rs.write_text(json.dumps(r))
    _expect(fake, needle)


def test_status_check_not_bound_to_actions_app_fails(fake):
    rs = fake / ".github/security/main-ruleset.json"
    r = json.loads(rs.read_text())
    for rule in r["rules"]:
        if rule["type"] == "required_status_checks":
            for c in rule["parameters"]["required_status_checks"]:
                c.pop("integration_id", None)
    rs.write_text(json.dumps(r))
    _expect(fake, "ruleset required checks")


# 6/7. audit failures and dependency updates are gated by the frontend gate
def test_every_dependabot_npm_frontend_is_audited_by_required_gate():
    dep = yaml.safe_load((REPO / ".github/dependabot.yml").read_text())
    fda = _load("frontend_dependency_audit", "tools/ci/frontend_dependency_audit.py")
    audited = {"/" + p for p in fda.APPS.values()}
    npm_dirs = {
        u["directory"]
        for u in dep["updates"]
        if u["package-ecosystem"] == "npm" and u["directory"].startswith("/apps/")
    }
    assert npm_dirs <= audited, npm_dirs - audited
    assert audited <= npm_dirs, "every audited app has Dependabot coverage"
    # Dependabot PRs trigger pull_request; the gate runs on every PR.
    pol = json.loads((REPO / ".github/security/repository-policy.json").read_text())
    assert "Frontend Dependency Security" in {
        c["context"] for c in pol["required_status_checks"]["contexts"]
    }
    pr = _on(
        yaml.safe_load(
            (REPO / ".github/workflows/frontend-dependency-security.yml").read_text()
        )
    )["pull_request"]
    assert "paths" not in (pr or {})


def test_audit_execution_failure_is_never_clean():
    fda = _load("frontend_dependency_audit", "tools/ci/frontend_dependency_audit.py")
    bad = fda.parse_audit_output("production", 1, "<html>registry down</html>", "")
    res = fda.evaluate_app("web", [bad, bad], [])
    assert res.status == fda.STATUS_UNVERIFIED


# 8. elevating workflow credentials
@pytest.mark.parametrize(
    "wf,fn,needle",
    [
        (
            "fg-required.yml",
            lambda d: d["jobs"]["fg-required"].__setitem__(
                "permissions", {"contents": "write"}
            ),
            "unapproved write permission",
        ),
        ("ci.yml", lambda d: d.__setitem__("permissions", "write-all"), "write-all"),
        (
            "fg-required.yml",
            lambda d: _on(d).__setitem__("pull_request_target", {}),
            "pull_request_target",
        ),
        ("fg-required.yml", lambda d: d.pop("permissions"), "no top-level permissions"),
        (
            "release-images.yml",
            lambda d: [
                s.__setitem__("uses", "docker/login-action@v3")
                for j in d["jobs"].values()
                for s in j.get("steps", [])
                if str(s.get("uses", "")).startswith("docker/login-action")
            ],
            "not SHA-pinned",
        ),
        (
            "fg-required.yml",
            lambda d: d["jobs"]["fg-required"]["steps"].append(
                {"run": "echo ${{ github.event.pull_request.title }}"}
            ),
            "untrusted expression",
        ),
        (
            "fg-required.yml",
            lambda d: d["jobs"]["fg-required"].__setitem__("runs-on", "self-hosted"),
            "self-hosted",
        ),
    ],
    ids=[
        "job-write",
        "write-all",
        "pull_request_target",
        "no-top-perms",
        "unpinned-action",
        "injection",
        "self-hosted",
    ],
)
def test_credential_elevation_is_rejected(fake, wf, fn, needle):
    _edit_yaml(_wf(fake, wf), fn)
    _expect(fake, needle)


def test_workflow_run_secret_trigger_requires_same_repo_push(fake):
    p = _wf(fake, "prod-auth-smoke.yml")
    p.write_text(
        p.read_text().replace(" && github.event.workflow_run.event == 'push'", "")
    )
    _expect(fake, "secret-bearing workflow_run")


def test_unmasked_generated_secrets_fail(fake):
    a = fake / ".github/actions/fg-secrets/action.yml"
    a.write_text(a.read_text().replace("::add-mask::", "masking-removed:"))
    _expect(fake, "without ::add-mask::")


def test_docker_relevance_list_must_match_push_paths(fake):
    p = _wf(fake, "docker-ci.yml")
    p.write_text(p.read_text().replace("            api/**\n", "", 1))
    _expect(fake, "DOCKER_PATHS")


# 9. bypass through a skipped job
def test_required_plain_job_with_if_condition_fails(fake):
    _edit_yaml(
        _wf(fake, "fg-required.yml"),
        lambda d: d["jobs"]["fg-required"].__setitem__("if", "github.actor != 'x'"),
    )
    _expect(fake, "skipped required check")


def test_aggregate_without_always_fails(fake):
    _edit_yaml(
        _wf(fake, "ci.yml"),
        lambda d: d["jobs"]["ci_required"].__setitem__("if", "success()"),
    )
    _expect(fake, "if: always()")


def _run_step(wf: str, job: str, env: dict[str, str]) -> int:
    d = yaml.safe_load((REPO / ".github/workflows" / wf).read_text())
    step = d["jobs"][job]["steps"][-1]
    script = step["run"]
    e = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
    e.update(
        {k: str(v) for k, v in (step.get("env") or {}).items() if "${{" not in str(v)}
    )
    e.update(env)
    return subprocess.run(
        ["bash", "-c", script], env=e, capture_output=True, text=True
    ).returncode


def _needs(**results: str) -> str:
    return json.dumps({k: {"result": v, "outputs": {}} for k, v in results.items()})


_ALL = json.loads((REPO / ".github/security/repository-policy.json").read_text())[
    "required_status_checks"
]["contexts"][0]["aggregate_needs"]


def _all(result: str = "success", **over: str) -> dict[str, str]:
    return {**{j: result for j in _ALL}, **over}


@pytest.mark.parametrize(
    "event,results,ok",
    [
        ("pull_request", _all(), True),
        (
            "pull_request",
            _all(unit="failure", integration="skipped", evidence="skipped"),
            False,
        ),
        ("pull_request", _all(integration="skipped"), False),
        ("pull_request", _all(migrations_replay="cancelled"), False),
        ("pull_request", _all(hardening="failure"), False),
        ("pull_request", {j: "success" for j in _ALL if j != "fg_guard"}, False),
        ("pull_request", {}, False),
        ("push", _all(console="skipped", portal="skipped"), True),
        ("push", _all(unit="failure"), False),
        ("push", _all(pt="cancelled"), False),
    ],
    ids=[
        "all-success",
        "upstream-failure",
        "unexpected-skip",
        "cancelled",
        "failure-or-timeout",
        "missing-job",
        "no-results",
        "push-skip-ok",
        "push-failure",
        "push-cancelled",
    ],
)
def test_ci_required_aggregate_semantics(event, results, ok):
    rc = _run_step(
        "ci.yml", "ci_required", {"NEEDS_JSON": _needs(**results), "EVENT_NAME": event}
    )
    assert (rc == 0) is ok


def test_ci_required_expected_jobs_must_match_policy(fake):
    p = _wf(fake, "ci.yml")
    p.write_text(
        p.read_text().replace("EXPECTED_JOBS: fg_guard,", "EXPECTED_JOBS: ", 1)
    )
    _expect(fake, "EXPECTED_JOBS")


@pytest.mark.parametrize(
    "changes,relevant,validate,ok",
    [
        ("success", "false", "skipped", True),
        ("success", "true", "success", True),
        ("success", "true", "failure", False),
        ("success", "true", "skipped", False),
        ("success", "true", "cancelled", False),
        ("failure", "", "skipped", False),
        ("success", "", "skipped", False),
    ],
    ids=[
        "irrelevant",
        "validated",
        "validation-failed",
        "validation-skipped",
        "cancelled",
        "detector-failed",
        "no-output",
    ],
)
def test_docker_compose_gate_semantics(changes, relevant, validate, ok):
    rc = _run_step(
        "docker-ci.yml",
        "docker-gate",
        {"CHANGES_RESULT": changes, "RELEVANT": relevant, "VALIDATE_RESULT": validate},
    )
    assert (rc == 0) is ok


# 10. removing or weakening the guard itself
def test_guard_runs_repository_policy_check():
    src = (REPO / "tools/ci/check_security_regression_gates.py").read_text()
    main_body = src[src.index("def main()") :]
    assert "check_repository_security_policy(failures)" in main_body
    ci = yaml.safe_load((REPO / ".github/workflows/ci.yml").read_text())
    runs = [s.get("run", "") for s in ci["jobs"]["fg_guard"]["steps"]]
    assert any("check_security_regression_gates.py" in r for r in runs)


@pytest.mark.parametrize(
    "rel",
    [
        ".github/security/repository-policy.json",
        ".github/security/main-ruleset.json",
        ".github/workflows/repo-security-drift.yml",
    ],
)
def test_guard_reports_missing_policy_assets(tmp_path, monkeypatch, rel):
    guard = _load(
        "check_security_regression_gates", "tools/ci/check_security_regression_gates.py"
    )
    shutil.copytree(REPO / ".github", tmp_path / ".github")
    (tmp_path / "tools/ci").mkdir(parents=True)
    shutil.copy(REPO / "tools/ci/check_github_repo_security.py", tmp_path / "tools/ci/")
    (tmp_path / rel).unlink()
    monkeypatch.setattr(guard, "REPO", tmp_path)
    failures: list[str] = []
    guard.check_repository_security_policy(failures)
    assert any(rel in f for f in failures), failures


# --- live drift evaluation ---------------------------------------------------


def _policy():
    pol = json.loads((REPO / ".github/security/repository-policy.json").read_text())
    rs = json.loads((REPO / ".github/security/main-ruleset.json").read_text())
    return pol, rs


def _compliant_obs() -> dict:
    pol, rs = _policy()
    A = chk.ApiResult
    rules = [
        {"type": r["type"], "parameters": r.get("parameters", {})} for r in rs["rules"]
    ]
    return {
        "repo": A(
            200,
            {
                "permissions": {"admin": True},
                "visibility": "public",
                "owner": {"type": "User"},
                "allow_merge_commit": False,
                "allow_rebase_merge": False,
                "allow_squash_merge": True,
                "allow_auto_merge": False,
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            },
        ),
        "branch_rules": A(200, rules),
        "rulesets": A(200, [{"id": 1, "name": "main-protection"}]),
        "ruleset_detail": A(200, {"bypass_actors": [], "enforcement": "active"}),
        "vulnerability_alerts": A(204, None),
        "automated_security_fixes": A(200, {"enabled": True, "paused": False}),
        "private_vulnerability_reporting": A(200, {"enabled": True}),
        "workflow_permissions": A(
            200,
            {
                "default_workflow_permissions": "read",
                "can_approve_pull_request_reviews": False,
            },
        ),
        "runners": A(200, {"total_count": 0}),
    }


def test_live_fully_configured_is_compliant():
    pol, rs = _policy()
    controls = chk.evaluate_live(pol, rs, _compliant_obs())
    assert chk.overall(controls) == chk.COMPLIANT, [
        c for c in controls if c.status != chk.COMPLIANT
    ]


def test_live_unprotected_main_is_drift_with_plan():
    pol, rs = _policy()
    obs = _compliant_obs()
    obs["branch_rules"] = chk.ApiResult(200, [])
    obs["rulesets"] = chk.ApiResult(200, [])
    obs.pop("ruleset_detail")
    controls = chk.evaluate_live(pol, rs, obs)
    assert chk.overall(controls) == chk.DRIFT
    assert "rulesets --input .github/security/main-ruleset.json" in chk.render(
        controls, chk.DRIFT
    )


def test_live_missing_required_check_is_drift():
    pol, rs = _policy()
    obs = _compliant_obs()
    for r in obs["branch_rules"].body:
        if r["type"] == "required_status_checks":
            r["parameters"]["required_status_checks"] = r["parameters"][
                "required_status_checks"
            ][:-1]
    assert chk.overall(chk.evaluate_live(pol, rs, obs)) == chk.DRIFT


def test_live_access_denied_is_never_compliant():
    pol, rs = _policy()
    obs = _compliant_obs()
    obs["repo"] = chk.ApiResult(
        200, {**obs["repo"].body, "permissions": {"admin": False}}
    )
    obs["ruleset_detail"] = chk.ApiResult(403, {"message": "denied"})
    controls = {c.control: c.status for c in chk.evaluate_live(pol, rs, obs)}
    for ctrl in (
        "security.vulnerability_alerts",
        "security.dependabot_security_updates",
        "security.private_vulnerability_reporting",
        "main.ruleset.bypass_actors",
    ):
        assert controls[ctrl] == chk.NOT_VERIFIED, ctrl
    all_denied = {k: chk.ApiResult(403, None) for k in _compliant_obs()}
    assert chk.overall(chk.evaluate_live(pol, rs, all_denied)) == chk.NOT_VERIFIED


def test_live_bypass_actor_is_drift():
    pol, rs = _policy()
    obs = _compliant_obs()
    obs["ruleset_detail"] = chk.ApiResult(
        200, {"bypass_actors": [{"actor_id": 5}], "enforcement": "active"}
    )
    assert chk.overall(chk.evaluate_live(pol, rs, obs)) == chk.DRIFT


@pytest.mark.parametrize("status", [0, 401, 403, 500, 502])
def test_live_api_failure_is_not_verified_not_compliant(status):
    pol, rs = _policy()
    obs = {k: chk.ApiResult(status, None) for k in _compliant_obs()}
    controls = chk.evaluate_live(pol, rs, obs)
    assert chk.overall(controls) == chk.NOT_VERIFIED
    assert not any(c.status == chk.COMPLIANT for c in controls)


def test_live_genuinely_disabled_alerts_is_drift_for_admin():
    pol, rs = _policy()
    obs = _compliant_obs()
    obs["vulnerability_alerts"] = chk.ApiResult(
        404, {"message": "Vulnerability alerts are disabled."}
    )
    controls = {c.control: c.status for c in chk.evaluate_live(pol, rs, obs)}
    assert controls["security.vulnerability_alerts"] == chk.DRIFT
