#!/usr/bin/env python3
"""P0-REPO-SECURITY-ENFORCEMENT-001 — repository security policy checker.

Two modes, both READ-ONLY:

``workflows`` (offline, runs in the Guard job via
``check_security_regression_gates.py``) proves the required status checks
declared in ``.github/security/repository-policy.json`` cannot silently fail
open:

* every required context is a real job (name == context) in a workflow that
  runs on *every* pull request (no ``paths``/``paths-ignore``);
* required jobs carry no ``continue-on-error`` and no skip condition — only
  aggregates may use ``if: always()``;
* aggregates ``needs:`` exactly the declared mandatory jobs, and every
  non-advisory ``ci.yml`` job is a member (adding or removing a job without
  updating the aggregate fails);
* the ruleset payload requires exactly the policy contexts, bound to the
  GitHub Actions app, with no bypass actors;
* no ``pull_request_target``, no ``write-all``, write scopes only where
  allow-listed, third-party actions SHA-pinned, no untrusted
  ``github.event`` text interpolated into ``run:`` scripts, secret-bearing
  ``workflow_run`` triggers restricted to same-repo pushes, generated CI
  secrets masked.

``live`` reads the actual GitHub configuration (``gh api``; no token is
stored or printed) and compares it with the desired state.  Each control is
COMPLIANT, DRIFT_DETECTED, NOT_VERIFIED (API denied/unavailable — never
assumed compliant) or UNSUPPORTED.  ``--plan`` prints the exact settings
mutations needed; nothing is ever applied by this tool.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
POLICY_PATH = ".github/security/repository-policy.json"
WORKFLOW_DIR = ".github/workflows"
ADVISORY_CI_JOBS = {"coverage", "ci_required"}
# Hard floor: removing one of these from the policy (and ruleset) is itself a
# failure, so the required set cannot be quietly narrowed in a PR.
MINIMUM_REQUIRED_CONTEXTS = {
    "CI Required",
    "fg-required",
    "Frontend Dependency Security",
    "Docker Compose Gate",
    "pr-fix-log-guard",
}
WRITE_SCOPE_ALLOWLIST = {
    ("release-images.yml", "build-and-push", "packages"),
    ("frontend-dependency-security.yml", "durable-finding", "issues"),
    ("repo-security-drift.yml", "record-drift", "issues"),
}
UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*github\.(?:head_ref|event\.(?:pull_request|issue|comment|review|"
    r"review_comment|head_commit|commits|discussion|pages|workflow_run)\.[a-z_.]*"
    r"(?:title|body|head_ref|ref|message|name|label|email|default_branch|"
    r"head_branch|display_title))\s*\}\}"
)

COMPLIANT = "COMPLIANT"
DRIFT = "DRIFT_DETECTED"
NOT_VERIFIED = "NOT_VERIFIED"
UNSUPPORTED = "UNSUPPORTED"


# ---------------------------------------------------------------------------
# Static workflow / policy enforcement
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict[Any, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _triggers(wf: dict[Any, Any]) -> dict[str, Any]:
    on = wf.get(True, wf.get("on"))  # PyYAML parses bare `on` as True
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {k: None for k in on}
    return on if isinstance(on, dict) else {}


def _needs(job: dict[str, Any]) -> list[str]:
    n = job.get("needs", [])
    return [n] if isinstance(n, str) else list(n or [])


def _is_always(cond: Any) -> bool:
    return (
        isinstance(cond, str)
        and re.fullmatch(r"\s*(\$\{\{\s*)?always\(\)(\s*\}\})?\s*", cond) is not None
    )


def check_workflows(repo: Path) -> list[str]:
    failures: list[str] = []
    try:
        policy = json.loads((repo / POLICY_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"policy unreadable: {POLICY_PATH}: {exc}"]
    rsc = policy.get("required_status_checks", {})
    contexts = rsc.get("contexts", [])
    if not contexts:
        failures.append("policy declares no required status checks")
    dropped = MINIMUM_REQUIRED_CONTEXTS - {c.get("context") for c in contexts}
    if dropped:
        failures.append(f"policy dropped mandatory required checks: {sorted(dropped)}")

    # Ruleset payload must match the policy exactly.
    ruleset_rel = policy.get("ruleset", {}).get("file", "")
    try:
        ruleset = json.loads((repo / ruleset_rel).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"ruleset unreadable: {ruleset_rel}: {exc}")
        ruleset = {}
    if ruleset:
        failures += _check_ruleset(ruleset, policy)

    wf_cache: dict[str, dict[str, Any]] = {}
    for ctx in contexts:
        name, wf_rel, job_id = ctx.get("context"), ctx.get("workflow"), ctx.get("job")
        path = repo / str(wf_rel)
        if not path.exists():
            failures.append(f"required check '{name}': workflow {wf_rel} missing")
            continue
        wf = wf_cache.setdefault(str(wf_rel), _load_yaml(path))
        trig = _triggers(wf)
        pr = trig.get("pull_request", "__absent__")
        if pr == "__absent__":
            failures.append(
                f"required check '{name}': {wf_rel} does not run on pull_request"
            )
        elif isinstance(pr, dict):
            for key in ("paths", "paths-ignore", "branches-ignore"):
                if key in pr:
                    failures.append(
                        f"required check '{name}': {wf_rel} pull_request has '{key}' "
                        "(the check would never report on some PRs)"
                    )
            if "branches" in pr and "main" not in (pr["branches"] or []):
                failures.append(
                    f"required check '{name}': pull_request branches exclude main"
                )
        job = (wf.get("jobs") or {}).get(job_id)
        if not isinstance(job, dict):
            failures.append(
                f"required check '{name}': job '{job_id}' missing from {wf_rel}"
            )
            continue
        if job.get("name", job_id) != name:
            failures.append(
                f"required check '{name}': job '{job_id}' is named "
                f"'{job.get('name', job_id)}' (context would never report)"
            )
        if "continue-on-error" in job:
            failures.append(f"required check '{name}': job has continue-on-error")
        for step in job.get("steps") or []:
            if isinstance(step, dict) and step.get("continue-on-error"):
                failures.append(
                    f"required check '{name}': a step has continue-on-error"
                )
        if ctx.get("kind") == "aggregate":
            if not _is_always(job.get("if")):
                failures.append(f"required aggregate '{name}': must use if: always()")
            declared = set(ctx.get("aggregate_needs") or [])
            actual = set(_needs(job))
            if declared != actual:
                failures.append(
                    f"required aggregate '{name}': needs {sorted(actual)} != "
                    f"policy {sorted(declared)}"
                )
            jobs_all = wf.get("jobs") or {}
            for member in sorted(actual):
                mjob = jobs_all.get(member)
                if not isinstance(mjob, dict):
                    failures.append(
                        f"required aggregate '{name}': member '{member}' missing"
                    )
                    continue
                if "continue-on-error" in mjob or any(
                    isinstance(st, dict) and st.get("continue-on-error")
                    for st in mjob.get("steps") or []
                ):
                    failures.append(
                        f"required aggregate '{name}': member '{member}' has "
                        "continue-on-error (a failure would report success)"
                    )
            if job_id == "ci_required":
                exp = ""
                for st in job.get("steps") or []:
                    if isinstance(st, dict):
                        exp = str((st.get("env") or {}).get("EXPECTED_JOBS", exp))
                if {j for j in exp.split(",") if j} != declared:
                    failures.append(
                        f"required aggregate '{name}': EXPECTED_JOBS {exp!r} != policy needs"
                    )
            body = json.dumps(job.get("steps") or [])
            if "success" not in body:
                failures.append(
                    f"required aggregate '{name}': no success evaluation step"
                )
        elif "if" in job:
            failures.append(
                f"required check '{name}': job has an 'if' condition "
                "(a skipped required check is reported as passing)"
            )
        if job.get("timeout-minutes") is None:
            failures.append(f"required check '{name}': no timeout-minutes")

    # Every non-advisory ci.yml job must be inside the CI aggregate.
    agg = next((c for c in contexts if c.get("job") == "ci_required"), None)
    ci_path = repo / WORKFLOW_DIR / "ci.yml"
    if agg is None:
        failures.append("policy is missing the 'CI Required' aggregate")
    elif ci_path.exists():
        jobs = set((_load_yaml(ci_path).get("jobs") or {}).keys())
        missing = jobs - ADVISORY_CI_JOBS - set(agg.get("aggregate_needs") or [])
        if missing:
            failures.append(
                f"ci.yml jobs not covered by 'CI Required': {sorted(missing)}"
            )

    failures += _check_workflow_hygiene(repo)
    failures += _check_docker_paths(repo)
    failures += _check_secret_masking(repo)
    return failures


def _check_ruleset(ruleset: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if ruleset.get("enforcement") != "active":
        out.append("ruleset enforcement is not 'active'")
    if ruleset.get("bypass_actors"):
        out.append("ruleset has bypass actors (policy: none)")
    rules = {r.get("type"): r for r in ruleset.get("rules", [])}
    for t in ("deletion", "non_fast_forward", "pull_request", "required_status_checks"):
        if t not in rules:
            out.append(f"ruleset missing rule '{t}'")
    rsc = rules.get("required_status_checks", {}).get("parameters", {})
    want = {
        (c["context"], policy["required_status_checks"]["integration_id"])
        for c in policy["required_status_checks"]["contexts"]
    }
    have = {
        (c.get("context"), c.get("integration_id"))
        for c in rsc.get("required_status_checks", [])
    }
    if want != have:
        out.append(f"ruleset required checks {sorted(have)} != policy {sorted(want)}")
    if rsc.get("strict_required_status_checks_policy") is not bool(
        policy["required_status_checks"].get("strict")
    ):
        out.append("ruleset strict status-check policy differs from policy")
    pr = rules.get("pull_request", {}).get("parameters", {})
    for key, val in policy.get("pull_request_review", {}).items():
        if key != "rationale" and pr.get(key) != val:
            out.append(f"ruleset pull_request.{key}={pr.get(key)!r} != policy {val!r}")
    return out


def _check_workflow_hygiene(repo: Path) -> list[str]:
    out: list[str] = []
    for path in sorted((repo / WORKFLOW_DIR).glob("*.y*ml")):
        src = path.read_text(encoding="utf-8")
        wf = _load_yaml(path)
        name = path.name
        trig = _triggers(wf)
        if "pull_request_target" in trig:
            out.append(f"{name}: pull_request_target is not allowed")
        if "permissions" not in wf:
            out.append(f"{name}: no top-level permissions (token would default)")
        if "write-all" in src:
            out.append(f"{name}: permissions write-all")
        for job_id, job in (wf.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            perms = job.get("permissions")
            scopes = [perms] if isinstance(perms, str) else []
            if isinstance(perms, dict):
                scopes = [k for k, v in perms.items() if v == "write"]
            top = wf.get("permissions")
            if perms is None and isinstance(top, dict):
                scopes = [k for k, v in top.items() if v == "write"]
            for scope in scopes:
                if (name, job_id, scope) not in WRITE_SCOPE_ALLOWLIST:
                    out.append(
                        f"{name}:{job_id}: unapproved write permission '{scope}'"
                    )
            if str(job.get("runs-on", "")).startswith("self-hosted"):
                out.append(f"{name}:{job_id}: self-hosted runner")
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))
                if uses and not uses.startswith(("./", "actions/", "docker://")):
                    if not re.search(r"@[0-9a-f]{40}$", uses):
                        out.append(
                            f"{name}:{job_id}: third-party action not SHA-pinned: {uses}"
                        )
                run = str(step.get("run", ""))
                for m in UNTRUSTED_EXPR.finditer(run):
                    out.append(
                        f"{name}:{job_id}: untrusted expression in run script: {m.group(0)} "
                        "(pass via env: instead)"
                    )
        if "workflow_run" in trig and "secrets." in src:
            if (
                "workflow_run.event == 'push'" not in src
                or "head_repository.full_name == github.repository" not in src
            ):
                out.append(
                    f"{name}: secret-bearing workflow_run must require a same-repository "
                    "push (fork PR branches named 'main' can trigger it)"
                )
    return out


def _check_docker_paths(repo: Path) -> list[str]:
    path = repo / WORKFLOW_DIR / "docker-ci.yml"
    if not path.exists():
        return []
    wf = _load_yaml(path)
    push = (_triggers(wf).get("push") or {}).get("paths") or []
    env = ((wf.get("jobs") or {}).get("changes") or {}).get("steps") or [{}]
    detect: dict[str, Any] = next(
        (s for s in env if isinstance(s, dict) and s.get("id") == "detect"), {}
    )
    listed = [
        p.strip()
        for p in str((detect.get("env") or {}).get("DOCKER_PATHS", "")).splitlines()
        if p.strip()
    ]
    if sorted(push) != sorted(listed):
        return ["docker-ci.yml: DOCKER_PATHS relevance list differs from push.paths"]
    return []


def _check_secret_masking(repo: Path) -> list[str]:
    out = []
    action = repo / ".github/actions/fg-secrets/action.yml"
    if action.exists() and "::add-mask::" not in action.read_text(encoding="utf-8"):
        out.append("fg-secrets action exports generated secrets without ::add-mask::")
    docker = repo / WORKFLOW_DIR / "docker-ci.yml"
    if docker.exists():
        src = docker.read_text(encoding="utf-8")
        if "GITHUB_ENV" in src and "::add-mask::" not in src:
            out.append("docker-ci.yml exports generated secrets without ::add-mask::")
    return out


# ---------------------------------------------------------------------------
# Live drift detection
# ---------------------------------------------------------------------------


@dataclass
class Control:
    control: str
    status: str
    desired: Any
    observed: Any
    detail: str = ""
    remediation: str = ""


@dataclass
class ApiResult:
    status: int  # HTTP status, 0 if the call could not be made
    body: Any


def gh_api(path: str) -> ApiResult:
    """Call ``gh api`` read-only. Returns status + parsed body, never raises."""
    try:
        proc = subprocess.run(
            ["gh", "api", "-i", path],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ApiResult(0, str(exc))
    raw = proc.stdout
    head, _, body = raw.partition("\r\n\r\n")
    if not body and "\n\n" in raw:
        head, _, body = raw.partition("\n\n")
    m = re.match(r"HTTP/\S+\s+(\d{3})", head)
    status = int(m.group(1)) if m else 0
    try:
        parsed: Any = json.loads(body) if body.strip() else None
    except json.JSONDecodeError:
        parsed = body.strip()
    return ApiResult(status, parsed)


def collect_observed(repo_slug: str, api=gh_api) -> dict[str, ApiResult]:
    r = f"repos/{repo_slug}"
    calls = {
        "repo": r,
        "branch_rules": f"{r}/rules/branches/main",
        "rulesets": f"{r}/rulesets?includes_parents=true",
        "classic_protection": f"{r}/branches/main/protection",
        "vulnerability_alerts": f"{r}/vulnerability-alerts",
        "automated_security_fixes": f"{r}/automated-security-fixes",
        "private_vulnerability_reporting": f"{r}/private-vulnerability-reporting",
        "workflow_permissions": f"{r}/actions/permissions/workflow",
        "fork_pr_approval": f"{r}/actions/permissions/fork-pr-contributor-approval",
        "runners": f"{r}/actions/runners",
    }
    obs = {k: api(v) for k, v in calls.items()}
    rs = obs["rulesets"]
    if rs.status == 200 and isinstance(rs.body, list):
        for item in rs.body:
            if item.get("name") == "main-protection" and item.get("id"):
                obs["ruleset_detail"] = api(f"{r}/rulesets/{item['id']}")
    return obs


def is_admin_ok(obs: dict[str, ApiResult]) -> bool:
    repo = obs.get("repo", ApiResult(0, None))
    return (
        repo.status == 200
        and isinstance(repo.body, dict)
        and (repo.body.get("permissions") or {}).get("admin") is True
    )


def _denied(res: ApiResult) -> bool:
    return res.status in (0, 401, 403) or res.status >= 500


def evaluate_live(
    policy: dict[str, Any], ruleset: dict[str, Any], obs: dict[str, ApiResult]
) -> list[Control]:
    out: list[Control] = []
    rsc = policy["required_status_checks"]
    want_checks = sorted((c["context"], rsc["integration_id"]) for c in rsc["contexts"])
    plan_ruleset = f"gh api -X POST repos/{policy['repository']}/rulesets --input {policy['ruleset']['file']}"

    br = obs.get("branch_rules", ApiResult(0, None))
    if _denied(br):
        out.append(
            Control(
                "main.rules", NOT_VERIFIED, "active ruleset", None, f"HTTP {br.status}"
            )
        )
    else:
        rules = br.body if isinstance(br.body, list) else []
        types = {x.get("type") for x in rules}
        for t in (
            "deletion",
            "non_fast_forward",
            "pull_request",
            "required_status_checks",
            "required_linear_history",
        ):
            out.append(
                Control(
                    f"main.rule.{t}",
                    COMPLIANT if t in types else DRIFT,
                    True,
                    t in types,
                    remediation="" if t in types else plan_ruleset,
                )
            )
        have = sorted(
            (c.get("context"), c.get("integration_id"))
            for x in rules
            if x.get("type") == "required_status_checks"
            for c in (x.get("parameters") or {}).get("required_status_checks", [])
        )
        missing = sorted(set(want_checks) - set(have))
        out.append(
            Control(
                "main.required_status_checks",
                COMPLIANT if not missing and have else DRIFT,
                want_checks,
                have,
                f"missing={missing}" if missing else "",
                "" if not missing and have else plan_ruleset,
            )
        )
        # Strictness (branch must be up to date) is part of the requirement:
        # the same check names with strict disabled are NOT compliant.
        strict_values = [
            bool(
                (x.get("parameters") or {}).get("strict_required_status_checks_policy")
            )
            for x in rules
            if x.get("type") == "required_status_checks"
        ]
        want_strict = bool(rsc.get("strict"))
        if strict_values:
            strict_ok = any(strict_values) if want_strict else True
            out.append(
                Control(
                    "main.required_status_checks.strict",
                    COMPLIANT if strict_ok else DRIFT,
                    want_strict,
                    strict_values,
                    ""
                    if strict_ok
                    else "strict_required_status_checks_policy disabled",
                    "" if strict_ok else plan_ruleset,
                )
            )
        else:
            out.append(
                Control(
                    "main.required_status_checks.strict",
                    DRIFT,
                    want_strict,
                    None,
                    "no required_status_checks rule",
                    plan_ruleset,
                )
            )
        prs = [
            x.get("parameters") or {} for x in rules if x.get("type") == "pull_request"
        ]
        if prs:
            mism = {
                k: prs[0].get(k)
                for k, v in policy["pull_request_review"].items()
                if k != "rationale" and k in prs[0] and prs[0].get(k) != v
            }
            out.append(
                Control(
                    "main.pull_request_params",
                    DRIFT if mism else COMPLIANT,
                    policy["pull_request_review"],
                    prs[0],
                    json.dumps(mism) if mism else "",
                )
            )

    det = obs.get("ruleset_detail")
    if not is_admin_ok(obs):
        out.append(
            Control(
                "main.ruleset.bypass_actors",
                NOT_VERIFIED,
                [],
                None,
                "admin readback required",
            )
        )
    elif det is None:
        out.append(
            Control(
                "main.ruleset.bypass_actors",
                NOT_VERIFIED
                if _denied(obs.get("rulesets", ApiResult(0, None)))
                else DRIFT,
                [],
                None,
                "ruleset 'main-protection' not found",
                plan_ruleset,
            )
        )
    elif _denied(det) or "bypass_actors" not in (det.body or {}):
        out.append(
            Control(
                "main.ruleset.bypass_actors",
                NOT_VERIFIED,
                [],
                None,
                f"HTTP {det.status}; bypass list needs admin read",
            )
        )
    else:
        bypass = det.body.get("bypass_actors") or []
        enf = det.body.get("enforcement")
        out.append(
            Control(
                "main.ruleset.bypass_actors",
                COMPLIANT if not bypass else DRIFT,
                [],
                bypass,
            )
        )
        out.append(
            Control(
                "main.ruleset.enforcement",
                COMPLIANT if enf == "active" else DRIFT,
                "active",
                enf,
            )
        )

    repo_res = obs.get("repo", ApiResult(0, None))
    is_admin = (
        repo_res.status == 200
        and isinstance(repo_res.body, dict)
        and (repo_res.body.get("permissions") or {}).get("admin") is True
    )

    def flag(
        ctrl: str, res: ApiResult, want: bool, observed: bool | None, plan: str
    ) -> None:
        # These endpoints answer 404 to non-admin callers, which is
        # indistinguishable from "disabled": only an admin readback counts.
        if not is_admin:
            out.append(
                Control(ctrl, NOT_VERIFIED, want, None, "admin readback required")
            )
            return
        if observed is None:
            out.append(Control(ctrl, NOT_VERIFIED, want, None, f"HTTP {res.status}"))
        else:
            out.append(
                Control(
                    ctrl,
                    COMPLIANT if observed == want else DRIFT,
                    want,
                    observed,
                    remediation="" if observed == want else plan,
                )
            )

    slug = policy["repository"]
    va = obs.get("vulnerability_alerts", ApiResult(0, None))
    flag(
        "security.vulnerability_alerts",
        va,
        True,
        {204: True, 404: False}.get(va.status),
        f"gh api -X PUT repos/{slug}/vulnerability-alerts",
    )
    asf = obs.get("automated_security_fixes", ApiResult(0, None))
    flag(
        "security.dependabot_security_updates",
        asf,
        True,
        (asf.body or {}).get("enabled") if asf.status == 200 else None,
        f"gh api -X PUT repos/{slug}/automated-security-fixes",
    )
    pvr = obs.get("private_vulnerability_reporting", ApiResult(0, None))
    flag(
        "security.private_vulnerability_reporting",
        pvr,
        True,
        (pvr.body or {}).get("enabled") if pvr.status == 200 else None,
        f"gh api -X PUT repos/{slug}/private-vulnerability-reporting",
    )

    repo = obs.get("repo", ApiResult(0, None))
    if repo.status == 200 and isinstance(repo.body, dict):
        saa = repo.body.get("security_and_analysis") or {}
        for key in ("secret_scanning", "secret_scanning_push_protection"):
            st = (saa.get(key) or {}).get("status")
            out.append(
                Control(
                    f"security.{key}",
                    NOT_VERIFIED
                    if st is None
                    else (COMPLIANT if st == "enabled" else DRIFT),
                    "enabled",
                    st,
                )
            )
        m = policy["merge"]
        for api_key, pol_key in (
            ("allow_merge_commit", "repository_allow_merge_commit"),
            ("allow_rebase_merge", "repository_allow_rebase_merge"),
            ("allow_squash_merge", "repository_allow_squash_merge"),
            ("allow_auto_merge", "repository_allow_auto_merge"),
        ):
            val = repo.body.get(api_key)
            out.append(
                Control(
                    f"repo.{api_key}",
                    NOT_VERIFIED
                    if val is None
                    else (COMPLIANT if val == m[pol_key] else DRIFT),
                    m[pol_key],
                    val,
                    remediation=f"gh api -X PATCH repos/{slug} -F {api_key}={str(m[pol_key]).lower()}",
                )
            )
        if (
            repo.body.get("visibility") not in ("public",)
            and not (repo.body.get("owner") or {}).get("type") == "Organization"
        ):
            out.append(
                Control(
                    "repo.rulesets_supported",
                    UNSUPPORTED,
                    "public or paid plan",
                    repo.body.get("visibility"),
                    "private personal repos on Free lack rulesets",
                )
            )
    else:
        out.append(
            Control("repo.settings", NOT_VERIFIED, None, None, f"HTTP {repo.status}")
        )

    wp = obs.get("workflow_permissions", ApiResult(0, None))
    if wp.status == 200 and isinstance(wp.body, dict):
        out.append(
            Control(
                "actions.default_workflow_permissions",
                COMPLIANT
                if wp.body.get("default_workflow_permissions") == "read"
                else DRIFT,
                "read",
                wp.body.get("default_workflow_permissions"),
            )
        )
        out.append(
            Control(
                "actions.can_approve_pull_request_reviews",
                COMPLIANT
                if wp.body.get("can_approve_pull_request_reviews") is False
                else DRIFT,
                False,
                wp.body.get("can_approve_pull_request_reviews"),
            )
        )
    else:
        out.append(
            Control(
                "actions.workflow_permissions",
                NOT_VERIFIED,
                "read",
                None,
                f"HTTP {wp.status}",
            )
        )
    run = obs.get("runners", ApiResult(0, None))
    if run.status == 200 and isinstance(run.body, dict):
        n = run.body.get("total_count", 0)
        out.append(
            Control("actions.self_hosted_runners", COMPLIANT if n == 0 else DRIFT, 0, n)
        )
    else:
        out.append(
            Control(
                "actions.self_hosted_runners",
                NOT_VERIFIED,
                0,
                None,
                f"HTTP {run.status}",
            )
        )
    return out


def overall(controls: list[Control]) -> str:
    states = {c.status for c in controls}
    if DRIFT in states:
        return DRIFT
    if NOT_VERIFIED in states or not controls:
        return NOT_VERIFIED
    return COMPLIANT


def render(controls: list[Control], status: str) -> str:
    lines = [
        f"## Repository security drift — {status}",
        "",
        "| Control | Status | Desired | Observed |",
        "|---|---|---|---|",
    ]
    for c in controls:
        lines.append(
            f"| {c.control} | {c.status} | `{json.dumps(c.desired)[:60]}` | `{json.dumps(c.observed)[:60]}` |"
        )
    plan = sorted(
        {c.remediation for c in controls if c.status == DRIFT and c.remediation}
    )
    if plan:
        lines += [
            "",
            "### Activation plan (NOT applied — requires founder authorization)",
            "",
        ]
        lines += [f"- `{p}`" for p in plan]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("workflows", help="offline static enforcement (CI)")
    lv = sub.add_parser("live", help="read-only drift readback via gh api")
    lv.add_argument("--out", help="write machine-readable result JSON here")
    lv.add_argument("--plan", action="store_true", help="print activation plan")
    args = ap.parse_args(argv)

    if args.cmd == "workflows":
        failures = check_workflows(REPO)
        if failures:
            print("repository security policy (workflows): FAILED")
            for f in failures:
                print(f" - {f}")
            return 1
        print("repository security policy (workflows): OK")
        return 0

    policy = json.loads((REPO / POLICY_PATH).read_text(encoding="utf-8"))
    ruleset = json.loads((REPO / policy["ruleset"]["file"]).read_text(encoding="utf-8"))
    obs = collect_observed(policy["repository"])
    controls = evaluate_live(policy, ruleset, obs)
    status = overall(controls)
    md = render(controls, status)
    print(md)
    if args.out:
        Path(args.out).write_text(
            json.dumps(
                {
                    "schema": "fg.github_repository_security_drift.v1",
                    "repository": policy["repository"],
                    "status": status,
                    "controls": [asdict(c) for c in controls],
                    "observed_http_status": {k: v.status for k, v in obs.items()},
                },
                indent=2,
                sort_keys=True,
                default=str,
            )
            + "\n",
            encoding="utf-8",
        )
    return {COMPLIANT: 0, DRIFT: 1}.get(status, 2)


if __name__ == "__main__":
    sys.exit(main())
