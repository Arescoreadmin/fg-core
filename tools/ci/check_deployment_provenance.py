#!/usr/bin/env python3
"""P0-PORTAL-DEPLOY-RECOVERY-001 — production deployment provenance and freshness.

Answers one question with evidence: *what is the production alias actually
serving, and is it at least as new as the approved security baseline and the
latest relevant commit on the production branch?*

It never trusts CI status, commit statuses, or "latest deployment". A Vercel
status of ``success`` is emitted even for a CANCELED (ignored) build, so the
only authority is the deployment the production **alias** resolves to.

Statuses: PASS (exit 0) · DRIFT (exit 1) · NOT_VERIFIED (exit 2).

Read-only. Live mode issues GET requests through ``vercel api`` (the operator's
existing CLI login) and never prints environment values: only allow-listed
deployment fields enter the evidence.

  python tools/ci/check_deployment_provenance.py --project portal \
      [--out evidence.json]                       # live, read-only
  python tools/ci/check_deployment_provenance.py --project portal \
      --fixture DIR                                # offline (alias.json,
                                                   # events.json, attempts.json)

A git SHA proves which source tree Vercel cloned. It does not attest the
installed dependency graph; the framework version is cross-checked between the
build log and the lockfile at that SHA, and recorded as exactly that.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / ".github/security/deployment-provenance-policy.json"
SCHEMA = "fg.deployment_provenance/v1"
PASS, DRIFT, NOT_VERIFIED = "PASS", "DRIFT", "NOT_VERIFIED"
EXIT = {PASS: 0, DRIFT: 1, NOT_VERIFIED: 2}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
NEXT_RE = re.compile(r"Detected Next\.js version:\s*([0-9][\w.\-+]*)")
CLONE_RE = re.compile(
    r"Cloning github\.com/([\w.-]+/[\w.-]+) \(Branch: ([^,]+), Commit: ([0-9a-f]+)\)"
)


class FetchError(RuntimeError):
    """A read could not be completed; the affected control is NOT_VERIFIED."""


@dataclass
class Result:
    project: str
    controls: list[dict[str, str]] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)

    def add(self, control: str, status: str, detail: str) -> None:
        self.controls.append({"control": control, "status": status, "detail": detail})

    @property
    def status(self) -> str:
        states = {c["status"] for c in self.controls}
        if DRIFT in states:
            return DRIFT
        if NOT_VERIFIED in states or not self.controls:
            return NOT_VERIFIED
        return PASS


class Git:
    """Minimal read-only git queries against a local clone."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            capture_output=True,
            text=True,
            timeout=60,
        )

    def commit_exists(self, sha: str) -> bool:
        return self._run("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0

    def is_shallow(self) -> bool:
        r = self._run("rev-parse", "--is-shallow-repository")
        return r.returncode != 0 or r.stdout.strip() != "false"

    def is_ancestor(self, older: str, newer: str) -> bool | None:
        """True/False, or None when unknowable.

        In a shallow clone a missing ancestry link may be truncation, not
        absence, so "not an ancestor" is only trusted with full history.
        """
        rc = self._run("merge-base", "--is-ancestor", older, newer).returncode
        if rc == 0:
            return True
        if rc == 1 and not self.is_shallow():
            return False
        return None

    def latest_touching(self, ref: str, paths: list[str]) -> str | None:
        r = self._run("log", "-1", "--format=%H", ref, "--", *paths)
        out = r.stdout.strip()
        return out if r.returncode == 0 and SHA_RE.match(out) else None

    def commits_between(self, older: str, newer: str, paths: list[str]) -> list[str]:
        r = self._run("log", "--format=%h %s", f"{older}..{newer}", "--", *paths)
        return r.stdout.strip().splitlines() if r.returncode == 0 else []

    def show(self, sha: str, path: str) -> str | None:
        r = self._run("show", f"{sha}:{path}")
        return r.stdout if r.returncode == 0 else None


def _lockfile_version(text: str | None, package: str) -> str | None:
    if not text:
        return None
    try:
        pkgs = json.loads(text).get("packages", {})
    except (json.JSONDecodeError, AttributeError):
        return None
    v = (pkgs.get(f"node_modules/{package}") or {}).get("version")
    return v if isinstance(v, str) else None


def _event_lines(events: Any) -> list[str]:
    lines: list[str] = []
    for e in events if isinstance(events, list) else []:
        if isinstance(e, dict):
            text = (e.get("payload") or {}).get("text") or e.get("text")
            if isinstance(text, str):
                lines.append(text)
    return lines


def evaluate(
    project: str,
    policy: dict[str, Any],
    deployment: dict[str, Any] | None,
    events: Any,
    attempts: list[dict[str, Any]] | None,
    git: Git,
    branch_ref: str,
) -> Result:
    res = Result(project=project)
    if not isinstance(deployment, dict) or not deployment.get("id"):
        res.add(
            "deployment_resolved",
            NOT_VERIFIED,
            f"alias {policy['production_alias']} did not resolve to a deployment",
        )
        return res
    meta = deployment.get("meta") or {}
    git_src = deployment.get("gitSource") or {}
    sha = str(meta.get("githubCommitSha") or git_src.get("sha") or "")
    ref = str(meta.get("githubCommitRef") or git_src.get("ref") or "")
    repo = (
        f"{meta.get('githubCommitOrg') or meta.get('githubOrg') or ''}/"
        f"{meta.get('githubCommitRepo') or meta.get('githubRepo') or ''}"
    )
    aliases = [a for a in deployment.get("alias") or [] if isinstance(a, str)]
    res.observed = {
        "deployment_id": deployment.get("id"),
        "deployment_url": deployment.get("url"),
        "project_id": deployment.get("projectId"),
        "project_name": deployment.get("name"),
        "target": deployment.get("target"),
        "ready_state": deployment.get("readyState"),
        "build_skipped": deployment.get("buildSkipped"),
        "source": deployment.get("source"),
        "created_at": _iso(deployment.get("createdAt")),
        "ready_at": _iso(deployment.get("ready")),
        "alias_assigned": deployment.get("aliasAssigned"),
        "aliases": sorted(aliases),
        "git_repo": repo,
        "git_ref": ref,
        "git_sha": sha or None,
    }
    res.add(
        "deployment_resolved",
        PASS,
        f"{policy['production_alias']} -> {deployment.get('id')}",
    )

    if deployment.get("projectId") == policy["project_id"]:
        res.add("project_identity", PASS, policy["project_id"])
    else:
        res.add(
            "project_identity",
            DRIFT,
            f"alias served by project {deployment.get('projectId')!r}, expected {policy['project_id']}",
        )

    if (
        policy["production_alias"] in aliases
        and deployment.get("aliasAssigned") is True
    ):
        res.add("production_alias", PASS, f"{policy['production_alias']} assigned")
    else:
        res.add(
            "production_alias",
            DRIFT,
            f"{policy['production_alias']} not among assigned aliases {sorted(aliases)}",
        )

    if deployment.get("target") == "production":
        res.add("target_production", PASS, "production target")
    else:
        res.add(
            "target_production",
            DRIFT,
            f"alias serves a {deployment.get('target') or 'preview'} deployment, not production",
        )

    if deployment.get("readyState") == "READY" and not deployment.get("buildSkipped"):
        res.add("build_outcome", PASS, "READY")
    else:
        res.add(
            "build_outcome",
            DRIFT,
            f"readyState={deployment.get('readyState')} buildSkipped={deployment.get('buildSkipped')}"
            " — a canceled, failed or skipped build is never current",
        )

    # Git provenance. A CLI upload has no git SHA: unverifiable, not compliant.
    if deployment.get("source") != "git" or not SHA_RE.match(sha):
        res.add(
            "git_source",
            NOT_VERIFIED,
            f"source={deployment.get('source')!r}, sha={sha or 'none'}: deployment has no verifiable git commit",
        )
        return _attempts(res, attempts, deployment)
    if repo != policy["git_repo"] or ref != policy["production_branch"]:
        res.add(
            "git_source",
            DRIFT,
            f"built from {repo}@{ref}, expected {policy['git_repo']}@{policy['production_branch']}",
        )
    else:
        res.add("git_source", PASS, f"{repo}@{ref} {sha[:12]}")

    if not git.commit_exists(sha):
        res.add(
            "commit_known",
            NOT_VERIFIED,
            f"{sha[:12]} not in local history (fetch {branch_ref} first)",
        )
        return _attempts(res, attempts, deployment)
    res.add("commit_known", PASS, sha[:12])

    base = policy["security_baseline_commit"]
    anc = git.is_ancestor(base, sha) if git.commit_exists(base) else None
    if anc is True:
        res.add("security_baseline", PASS, f"includes baseline {base[:12]}")
    elif anc is False:
        res.add(
            "security_baseline",
            DRIFT,
            f"production {sha[:12]} predates security baseline {base[:12]} ({policy.get('security_baseline_reason', '')})",
        )
    else:
        res.add(
            "security_baseline",
            NOT_VERIFIED,
            f"baseline {base[:12]} not resolvable locally",
        )

    latest = git.latest_touching(branch_ref, policy["watch_paths"])
    if latest is None:
        res.add(
            "freshness",
            NOT_VERIFIED,
            f"cannot resolve latest relevant commit on {branch_ref}",
        )
    else:
        fresh = git.is_ancestor(latest, sha)
        behind = (
            git.commits_between(sha, latest, policy["watch_paths"])
            if fresh is False
            else []
        )
        res.observed["latest_relevant_commit"] = latest
        res.observed["relevant_commits_not_deployed"] = behind
        if fresh is True:
            res.add(
                "freshness",
                PASS,
                f"includes latest relevant {branch_ref} commit {latest[:12]}",
            )
        elif fresh is False:
            res.add(
                "freshness",
                DRIFT,
                f"{len(behind)} relevant commit(s) on {branch_ref} not deployed; latest {latest[:12]}",
            )
        else:
            res.add(
                "freshness",
                NOT_VERIFIED,
                "ancestry unknowable (shallow history or git error)",
            )

    lines = _event_lines(events)
    log_version = next(
        (m.group(1) for line in lines if (m := NEXT_RE.search(line))), None
    )
    clone = next((m.groups() for line in lines if (m := CLONE_RE.search(line))), None)
    lock_version = _lockfile_version(
        git.show(sha, policy["framework_lockfile"]), policy["framework_package"]
    )
    res.observed["framework_version_build_log"] = log_version
    res.observed["framework_version_lockfile_at_sha"] = lock_version
    if clone is not None:
        res.observed["build_log_clone"] = {
            "repo": clone[0],
            "branch": clone[1],
            "commit": clone[2],
        }
        if not sha.startswith(clone[2]):
            res.add(
                "build_log_commit",
                DRIFT,
                f"build log cloned {clone[2]}, metadata says {sha[:12]}",
            )
        else:
            res.add("build_log_commit", PASS, f"build log cloned {clone[2]}")
    if log_version and lock_version:
        if log_version == lock_version:
            res.add(
                "framework_version",
                PASS,
                f"{policy['framework_package']} {log_version} (build log == lockfile)",
            )
        else:
            res.add(
                "framework_version",
                DRIFT,
                f"build log {log_version} != lockfile {lock_version}",
            )
    else:
        res.add(
            "framework_version",
            NOT_VERIFIED,
            f"build log={log_version or 'unavailable'}, lockfile={lock_version or 'unavailable'}",
        )
    return _attempts(res, attempts, deployment)


def _attempts(
    res: Result, attempts: list[dict[str, Any]] | None, live: dict[str, Any]
) -> Result:
    """Record newer production attempts that never became current (evidence only)."""
    if attempts is None:
        return res
    created = live.get("createdAt") or 0
    newer = [
        {
            "id": a.get("uid") or a.get("id"),
            "state": a.get("state") or a.get("readyState"),
            "created_at": _iso(a.get("created") or a.get("createdAt")),
            "sha": ((a.get("meta") or {}).get("githubCommitSha") or "")[:12] or None,
        }
        for a in attempts
        if (a.get("created") or a.get("createdAt") or 0) > created
        and a.get("target") == "production"
    ]
    res.observed["newer_production_attempts_not_current"] = newer
    return res


def _iso(ms: Any) -> str | None:
    if not isinstance(ms, (int, float)) or ms <= 0:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def vercel_get(path: str, scope: str) -> Any:
    try:
        p = subprocess.run(
            ["vercel", "api", path, "--scope", scope],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FetchError(f"vercel api unavailable: {exc}") from exc
    if p.returncode != 0:
        raise FetchError(f"vercel api {path.split('?')[0]} exited {p.returncode}")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise FetchError(f"vercel api {path.split('?')[0]} returned non-JSON") from exc


def collect_live(
    policy: dict[str, Any], scope: str, get: Callable[[str, str], Any] = vercel_get
) -> tuple[dict[str, Any] | None, Any, list[dict[str, Any]] | None, list[str]]:
    errors: list[str] = []
    deployment: dict[str, Any] | None = None
    events: Any = None
    attempts: list[dict[str, Any]] | None = None
    try:
        d = get(f"/v13/deployments/{policy['production_alias']}", scope)
        deployment = d if isinstance(d, dict) else None
    except FetchError as exc:
        errors.append(str(exc))
    if deployment and deployment.get("id"):
        try:
            events = get(f"/v3/deployments/{deployment['id']}/events?limit=-1", scope)
        except FetchError as exc:
            errors.append(str(exc))
    try:
        a = get(
            f"/v6/deployments?projectId={policy['project_id']}&target=production&limit=20",
            scope,
        )
        attempts = a.get("deployments") if isinstance(a, dict) else None
    except FetchError as exc:
        errors.append(str(exc))
    return deployment, events, attempts, errors


def _read_fixture(d: Path, name: str) -> Any:
    f = d / name
    return json.loads(f.read_text()) if f.exists() else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project", required=True)
    ap.add_argument("--policy", type=Path, default=POLICY)
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument(
        "--branch-ref", default=None, help="default origin/<production_branch>"
    )
    ap.add_argument(
        "--fixture",
        type=Path,
        help="offline: dir with alias.json, events.json, attempts.json",
    )
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    try:
        doc = json.loads(args.policy.read_text())
        policy = doc["deployments"][args.project]
        scope = doc["vercel_scope"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(
            f"deployment-provenance: NOT_VERIFIED: policy unreadable for {args.project!r}: {exc}",
            file=sys.stderr,
        )
        return EXIT[NOT_VERIFIED]
    branch_ref = args.branch_ref or f"origin/{policy['production_branch']}"
    errors: list[str] = []
    if args.fixture:
        deployment = _read_fixture(args.fixture, "alias.json")
        events = _read_fixture(args.fixture, "events.json")
        att = _read_fixture(args.fixture, "attempts.json")
        attempts = att.get("deployments") if isinstance(att, dict) else att
        mode = "fixture"
    else:
        deployment, events, attempts, errors = collect_live(policy, scope)
        mode = "live"
    res = evaluate(
        args.project, policy, deployment, events, attempts, Git(args.repo), branch_ref
    )
    for e in errors:
        res.add("read_errors", NOT_VERIFIED, e)
    evidence = {
        "schema": SCHEMA,
        "project": args.project,
        "mode": mode,
        "observed_at": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        "status": res.status,
        "policy": {
            k: policy[k]
            for k in (
                "project_id",
                "production_alias",
                "production_branch",
                "git_repo",
                "security_baseline_commit",
                "watch_paths",
            )
        },
        "branch_ref": branch_ref,
        "observed": res.observed,
        "controls": res.controls,
        "attestation_limits": "git SHA identifies the cloned source tree only; dependency graph "
        "is not attested beyond the framework version cross-check.",
    }
    text = json.dumps(evidence, indent=2) + "\n"
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    for c in res.controls:
        print(f"  {c['status']:<12} {c['control']:<20} {c['detail']}", file=sys.stderr)
    print(f"deployment-provenance[{args.project}]: {res.status}", file=sys.stderr)
    return EXIT[res.status]


if __name__ == "__main__":
    raise SystemExit(main())
