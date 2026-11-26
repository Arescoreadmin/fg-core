#!/usr/bin/env python3
"""FG-855-REPAIR-001 — keep Agent and assessment/security tests in required CI.

Issue #855 found ``agent/tests/`` in no CI lane, and the required fast lane
selects tests by marker (``smoke or contract or security``), so unmarked
assessment and security regression tests outside ``tests/security/`` only ran
in the conditional, non-required ``fg-full`` shards. This checker is READ-ONLY
and fails closed if any of these groups can silently fall out again.

Modes:

``--print-paths regression``
    Print the test files run by ``make ci-assessment-security`` (one per
    line). The Make target calls this mode, so the selection rule below is the
    single source of truth: a new ``*assessment*``/``*security*`` test file is
    picked up automatically.

(default) check
    * ``make agent-unit`` runs ``tests/agent`` and ``agent/tests`` (whole
      directories, no ``-m``/``-k``/``--deselect``) with the per-test timeout
      plugin enabled, and ``agent/tests`` still holds every one of its files;
    * ``make ci-assessment-security`` takes its paths from this script and
      applies no selection filters;
    * the regression selection is non-empty and not below the recorded floor;
    * files excluded from the selection because another required target runs
      them are still named by that target;
    * in ``ci.yml`` the ``agent_linux`` job runs ``make agent-unit``, a job runs
      ``make ci-assessment-security``, both jobs are members of ``CI Required``
      and neither the jobs nor those steps use ``continue-on-error`` or an
      ``if`` condition.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]

AGENT_TARGET = "agent-unit"
REGRESSION_TARGET = "ci-assessment-security"
AGENT_DIRS = ("tests/agent", "agent/tests")
TIMEOUT_PLUGIN = "tools.testing.harness.pytest_per_test_timeout"
TIMEOUT_OPTION = "--fg-per-test-timeout="

# Test files whose path names assessment or security work.
REGRESSION_PATTERN = re.compile(r"assessment|security", re.IGNORECASE)
# Already required as a whole directory (Hardening job: `pytest tests/security`).
REGRESSION_EXCLUDED_DIRS = ("tests/security/",)
# Already run by another required Make target in the same CI job; listed here
# so they are not executed twice. The check proves the target still names them.
REGRESSION_EXCLUDED_FILES = {
    "tests/test_security_hardening.py": "ci-pt",
    "tests/test_security_middleware.py": "ci-pt",
}
# Floors recorded by FG-855-REPAIR-001 (2026-11-26). Lowering one is a
# deliberate, reviewed change; a silent drop below it fails closed.
REGRESSION_MIN_FILES = 21
AGENT_TESTS_MIN_FILES = 14

FORBIDDEN_SELECTORS = ("-m ", "-m=", "-k ", "-k=", "--deselect", "--ignore")


def regression_paths(repo: Path = REPO) -> list[str]:
    """Return the sorted test files selected for ``ci-assessment-security``."""
    found: list[str] = []
    for path in sorted((repo / "tests").rglob("test_*.py")):
        rel = path.relative_to(repo).as_posix()
        if "__pycache__" in rel or any(
            rel.startswith(d) for d in REGRESSION_EXCLUDED_DIRS
        ):
            continue
        if rel in REGRESSION_EXCLUDED_FILES:
            continue
        if REGRESSION_PATTERN.search(rel):
            found.append(rel)
    return found


def make_recipe(makefile_text: str, target: str) -> str:
    """Return the joined recipe lines of a Makefile target ('' if absent)."""
    lines = makefile_text.splitlines()
    head = re.compile(rf"^{re.escape(target)}\s*:(?!=)")
    for i, line in enumerate(lines):
        if head.match(line):
            body: list[str] = []
            for nxt in lines[i + 1 :]:
                if nxt.startswith("\t"):
                    body.append(nxt.strip())
                elif nxt.strip() == "" and body and body[-1].endswith("\\"):
                    continue
                else:
                    break
            return " ".join(body)
    return ""


def _job_runs(job: dict[str, Any], command: str) -> list[dict[str, Any]]:
    steps = [s for s in job.get("steps") or [] if isinstance(s, dict)]
    return [s for s in steps if command in str(s.get("run", ""))]


def check(repo: Path = REPO) -> list[str]:
    failures: list[str] = []
    makefile = (repo / "Makefile").read_text(encoding="utf-8")

    agent = make_recipe(makefile, AGENT_TARGET)
    if not agent:
        failures.append(f"Makefile target '{AGENT_TARGET}' is missing")
    else:
        for d in AGENT_DIRS:
            if not re.search(rf"(^|\s){re.escape(d)}/?(\s|$)", agent):
                failures.append(
                    f"'{AGENT_TARGET}' does not run the whole '{d}' directory"
                )
        if TIMEOUT_PLUGIN not in agent or TIMEOUT_OPTION not in agent:
            failures.append(
                f"'{AGENT_TARGET}' does not enable the per-test timeout plugin"
            )
        for sel in FORBIDDEN_SELECTORS:
            if sel in agent:
                failures.append(f"'{AGENT_TARGET}' uses selector '{sel.strip()}'")

    agent_files = sorted((repo / "agent" / "tests").glob("test_*.py"))
    if len(agent_files) < AGENT_TESTS_MIN_FILES:
        failures.append(
            f"agent/tests holds {len(agent_files)} test files, below the recorded "
            f"floor {AGENT_TESTS_MIN_FILES}"
        )

    regression = make_recipe(makefile, REGRESSION_TARGET)
    if not regression:
        failures.append(f"Makefile target '{REGRESSION_TARGET}' is missing")
    else:
        if "check_required_ci_coverage.py --print-paths regression" not in regression:
            failures.append(
                f"'{REGRESSION_TARGET}' must take its paths from "
                "check_required_ci_coverage.py --print-paths regression"
            )
        for sel in FORBIDDEN_SELECTORS:
            if sel in regression:
                failures.append(f"'{REGRESSION_TARGET}' uses selector '{sel.strip()}'")

    selected = regression_paths(repo)
    if len(selected) < REGRESSION_MIN_FILES:
        failures.append(
            f"regression selection holds {len(selected)} files, below the recorded "
            f"floor {REGRESSION_MIN_FILES}"
        )
    for rel, target in sorted(REGRESSION_EXCLUDED_FILES.items()):
        if (repo / rel).exists() and rel not in make_recipe(makefile, target):
            failures.append(
                f"'{rel}' is excluded as run by '{target}', which no longer runs it"
            )

    ci_path = repo / ".github" / "workflows" / "ci.yml"
    wf = yaml.safe_load(ci_path.read_text(encoding="utf-8")) or {}
    jobs: dict[str, Any] = wf.get("jobs") or {}
    agg = jobs.get("ci_required") or {}
    agg_needs = agg.get("needs") or []
    agg_needs = [agg_needs] if isinstance(agg_needs, str) else list(agg_needs)

    def _require(job_id: str | None, command: str) -> None:
        if job_id is None:
            failures.append(f"ci.yml: no job runs '{command}'")
            return
        job = jobs[job_id]
        if job_id not in agg_needs:
            failures.append(
                f"ci.yml: job '{job_id}' ('{command}') is not in CI Required"
            )
        if "continue-on-error" in job:
            failures.append(f"ci.yml: job '{job_id}' has continue-on-error")
        for step in _job_runs(job, command):
            if "continue-on-error" in step or "if" in step:
                failures.append(
                    f"ci.yml: step running '{command}' in '{job_id}' has "
                    "continue-on-error or an if condition"
                )

    agent_job = (
        "agent_linux"
        if _job_runs(jobs.get("agent_linux") or {}, f"make {AGENT_TARGET}")
        else None
    )
    _require(agent_job, f"make {AGENT_TARGET}")
    reg_job = next(
        (
            j
            for j, body in jobs.items()
            if isinstance(body, dict) and _job_runs(body, f"make {REGRESSION_TARGET}")
        ),
        None,
    )
    _require(reg_job, f"make {REGRESSION_TARGET}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--print-paths", choices=["regression"])
    parser.add_argument("--repo", type=Path, default=REPO)
    args = parser.parse_args(argv)
    if args.print_paths:
        paths = regression_paths(args.repo)
        if not paths:
            print("ERROR: empty regression selection", file=sys.stderr)
            return 1
        print("\n".join(paths))
        return 0
    failures = check(args.repo)
    if failures:
        for f in failures:
            print(f"❌ {f}")
        return 1
    print(
        f"required-ci-coverage: OK (agent dirs {', '.join(AGENT_DIRS)}; "
        f"{len(regression_paths(args.repo))} assessment/security files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
