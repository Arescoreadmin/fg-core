#!/usr/bin/env python3
"""FG-CI-NIGHTLY-REPAIR-001 — fail-closed verdict for a testing-module run.

Run by the ``testing-module-verdict`` job with ``toJSON(needs)``. It decides,
from the event and the dispatch ``suite`` input, which jobs had to succeed,
and fails if any of them was skipped, cancelled, failed or is absent. A
job-level timeout is reported by GitHub as ``cancelled``, so a timed-out lane
can never read as a green run.

When fg-security had to run, the verdict also opens its JUnit
(``fg-security.xml`` from the uploaded artifact) and requires at least
``--security-min-tests`` tests with zero failures and errors, so the security
lane cannot pass by running nothing.

Standard library only: the verdict job does not install the project venv.

Exit codes: 0 = verdict PASS, 1 = verdict FAIL, 2 = bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

CORE_JOBS = ("detect-high-risk-paths", "fg-fast", "fg-contract")
SECURITY_JOBS = ("fg-security",)
FULL_JOBS = ("fg-full-gates", "fg-full-shard", "fg-full-complete", "fg-flake-detect")
ALL_JOBS = CORE_JOBS + SECURITY_JOBS + FULL_JOBS

EVENTS = ("schedule", "workflow_dispatch", "pull_request")
SUITES = ("all", "security", "full")
SECURITY_JUNIT_NAME = "fg-security.xml"


def expectations(event: str, suite: str) -> dict[str, str]:
    """Map each job to 'required', 'optional' (success or skipped) or 'absent'.

    ``suite`` only applies to workflow_dispatch; schedule and pull_request
    always behave as ``all``.
    """
    if event not in EVENTS:
        raise ValueError(f"unsupported event {event!r}")
    if suite not in SUITES:
        raise ValueError(f"unsupported suite {suite!r}")
    if event != "workflow_dispatch":
        suite = "all"

    exp = {job: "required" for job in CORE_JOBS}
    exp["fg-security"] = "absent" if suite == "full" else "required"
    if suite == "security":
        full = "absent"
    elif event == "pull_request":
        # Full suite on PRs is conditional on high-risk paths/branch names.
        full = "optional"
    else:
        full = "required"
    for job in FULL_JOBS:
        exp[job] = full
    return exp


def _security_junit_stats(artifacts_dir: Path | None) -> tuple[dict[str, Any], str]:
    if artifacts_dir is None or not artifacts_dir.is_dir():
        return {}, f"fg-security artifacts not found at {artifacts_dir}"
    found = sorted(artifacts_dir.rglob(SECURITY_JUNIT_NAME))
    if len(found) != 1:
        return {}, (
            f"expected exactly one {SECURITY_JUNIT_NAME} under {artifacts_dir}, "
            f"found {len(found)}"
        )
    try:
        root = ET.parse(found[0]).getroot()
    except ET.ParseError as exc:
        return {}, f"{found[0]}: unparseable JUnit ({exc})"
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if not suites:
        return {}, f"{found[0]}: no <testsuite> element"
    stats = {
        key: sum(int(s.get(key, 0)) for s in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }
    stats["path"] = str(found[0])
    return stats, ""


def evaluate(
    needs: dict[str, Any],
    event: str,
    suite: str,
    security_artifacts: Path | None,
    security_min_tests: int,
) -> dict[str, Any]:
    exp = expectations(event, suite)
    errors: list[str] = []

    unknown = sorted(set(needs) - set(ALL_JOBS))
    if unknown:
        errors.append(f"unexpected jobs in needs (update the verdict): {unknown}")

    jobs: dict[str, dict[str, str]] = {}
    for job in ALL_JOBS:
        result = str((needs.get(job) or {}).get("result", "missing"))
        want = exp[job]
        jobs[job] = {"expected": want, "result": result}
        if want == "required" and result != "success":
            errors.append(f"{job}: required to succeed, got {result!r}")
        elif want == "optional" and result not in ("success", "skipped"):
            errors.append(f"{job}: got {result!r}")
        elif want == "absent" and result != "skipped":
            errors.append(f"{job}: not selected by suite={suite!r} but got {result!r}")

    # On PRs the full suite is all-or-nothing: once its first job ran, a
    # skipped later stage is a silent gap, not a legitimate opt-out.
    if (
        exp["fg-full-gates"] == "optional"
        and jobs["fg-full-gates"]["result"] != "skipped"
    ):
        for job in FULL_JOBS[1:]:
            if jobs[job]["result"] != "success":
                errors.append(
                    f"{job}: full suite started but got {jobs[job]['result']!r}"
                )

    security: dict[str, Any] = {}
    if exp["fg-security"] == "required" and jobs["fg-security"]["result"] == "success":
        security, problem = _security_junit_stats(security_artifacts)
        if problem:
            errors.append(f"fg-security evidence: {problem}")
        else:
            if security["tests"] < security_min_tests:
                errors.append(
                    f"fg-security ran {security['tests']} tests "
                    f"< minimum {security_min_tests}"
                )
            if security["failures"] or security["errors"]:
                errors.append(
                    f"fg-security JUnit reports {security['failures']} failure(s), "
                    f"{security['errors']} error(s)"
                )

    return {
        "event": event,
        "suite": suite if event == "workflow_dispatch" else "all",
        "jobs": jobs,
        "security_junit": security,
        "security_min_tests": security_min_tests,
        "errors": errors,
        "result": "FAIL" if errors else "PASS",
    }


def _summary_markdown(verdict: dict[str, Any]) -> str:
    lines = [
        f"## testing-module verdict: {verdict['result']}",
        "",
        f"event `{verdict['event']}`, suite `{verdict['suite']}`",
        "",
        "| Job | Expected | Result |",
        "|---|---|---|",
    ]
    for job, info in verdict["jobs"].items():
        lines.append(f"| {job} | {info['expected']} | {info['result']} |")
    sec = verdict["security_junit"]
    if sec:
        lines += [
            "",
            f"fg-security JUnit: {sec['tests']} tests, {sec['failures']} failures, "
            f"{sec['errors']} errors, {sec['skipped']} skipped",
        ]
    if verdict["errors"]:
        lines += ["", "### Errors", *[f"- {e}" for e in verdict["errors"]]]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--needs-json", type=Path, required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--suite", default="all")
    parser.add_argument("--security-artifacts", type=Path, default=None)
    parser.add_argument("--security-min-tests", type=int, required=True)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--summary", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        needs = json.loads(args.needs_json.read_text())
        if not isinstance(needs, dict):
            raise ValueError("needs JSON must be an object")
        verdict = evaluate(
            needs,
            args.event,
            args.suite or "all",
            args.security_artifacts,
            args.security_min_tests,
        )
    except (OSError, ValueError) as exc:
        print(f"testing-module-verdict: bad input: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(verdict, indent=2)
    print(text)
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(text + "\n")
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as fh:
            fh.write(_summary_markdown(verdict))

    if verdict["errors"]:
        print("testing-module-verdict: FAIL", file=sys.stderr)
        for err in verdict["errors"]:
            print(f"  ERROR: {err}", file=sys.stderr)
        return 1
    print("testing-module-verdict: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
