#!/usr/bin/env python3
"""FG-CI-NIGHTLY-REPAIR-001 — keep scheduled security + full-suite runs reachable.

Audit gap 011: every scheduled ``testing-module`` run from 2026-11-14 was
cancelled when ``fg-security`` hit its 25-minute job timeout, and because the
full-suite shards needed ``fg-security`` to succeed they never ran. This
checker is READ-ONLY and fails closed if the workflow drifts back to any shape
that lets a lane be cancelled, skipped or lost without failing the run:

* triggers: a ``schedule`` cron, and ``workflow_dispatch`` with a ``suite``
  choice of exactly ``all``/``security``/``full``;
* concurrency: only ``pull_request`` runs cancel in progress; scheduled and
  manual runs use a per-run group (``github.run_id``);
* ``fg-security`` keeps at least ``SECURITY_MIN_TIMEOUT`` minutes (and at most
  the timeout-hierarchy ceiling) and is not a prerequisite of the full suite;
* full-suite shards: ``fail-fast: false``, a matrix of exactly
  ``0..TOTAL_SHARDS-1``, the same shard count in validate/aggregate, and the
  aggregate runs ``--require-collection`` with a test floor;
* ``make fg-full-shard`` writes ``shard-collection.json`` and both nightly
  pytest targets take the opt-in per-test timeout, enabled in those jobs;
* no job or step uses ``continue-on-error``; every ``upload-artifact`` step
  runs ``if: always()`` and retains for at least ``MIN_RETENTION_DAYS``;
* ``testing-module-verdict`` runs ``if: always()``, needs every other job, and
  its job list matches ``tools/ci/testing_module_verdict.py``;
* evidence provenance (Codex review): fg-security and every shard write
  ``evidence-provenance.json`` before upload; consumers resolve the producing
  attempt (``tools/ci/testing_module_evidence.py``), download by artifact id
  only (never a name, pattern or ``run_attempt``) and verify before use.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from tools.ci.check_required_ci_coverage import make_recipe  # noqa: E402
from tools.ci.testing_module_verdict import ALL_JOBS as VERDICT_JOBS  # noqa: E402

WORKFLOW = Path(".github/workflows/testing-module.yml")
SUITE_OPTIONS = ["all", "security", "full"]
SECURITY_MIN_TIMEOUT = 40
# check_timeout_hierarchy.py: fg-security job timeout <= 2800 s.
SECURITY_MAX_TIMEOUT = 2800 // 60
SHARD_MIN_TIMEOUT = 60
MIN_TEST_FLOOR = 25000
MIN_RETENTION_DAYS = 30
VERDICT_JOB = "testing-module-verdict"
TIMEOUT_TARGETS = ("fg-security-pytest", "fg-full-shard")
TIMEOUT_JOBS = ("fg-security", "fg-full-shard")


def _on(data: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML (YAML 1.1) loads the bare key `on` as boolean True.
    on = data.get("on", data.get(True))
    return on if isinstance(on, dict) else {}


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in job.get("steps") or [] if isinstance(s, dict)]


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def _int_arg(text: str, flag: str) -> int | None:
    m = re.search(rf"{re.escape(flag)}[ =](\d+)", text)
    return int(m.group(1)) if m else None


def check(repo: Path = REPO) -> list[str]:
    errors: list[str] = []
    data = yaml.safe_load((repo / WORKFLOW).read_text())
    jobs: dict[str, dict[str, Any]] = data.get("jobs") or {}
    on = _on(data)

    # Triggers
    if not (on.get("schedule") or [{}])[0].get("cron"):
        errors.append("on.schedule: a cron entry is required")
    suite = ((on.get("workflow_dispatch") or {}).get("inputs") or {}).get("suite") or {}
    if suite.get("type") != "choice" or suite.get("options") != SUITE_OPTIONS:
        errors.append(
            f"workflow_dispatch.inputs.suite must be a choice of {SUITE_OPTIONS}"
        )
    if suite.get("default") != "all":
        errors.append("workflow_dispatch.inputs.suite default must be 'all'")

    # Concurrency
    conc = data.get("concurrency") or {}
    cancel = conc.get("cancel-in-progress")
    if cancel is True or "github.event_name == 'pull_request'" not in str(cancel):
        errors.append(
            "concurrency.cancel-in-progress must be limited to pull_request events"
        )
    if "github.run_id" not in str(conc.get("group", "")):
        errors.append(
            "concurrency.group must be per-run (github.run_id) for non-PR events"
        )

    # continue-on-error and artifact retention everywhere
    for jid, job in jobs.items():
        if job.get("continue-on-error"):
            errors.append(f"{jid}: continue-on-error is not allowed")
        for step in _steps(job):
            name = step.get("name", step.get("uses", "?"))
            if step.get("continue-on-error"):
                errors.append(f"{jid}/{name}: continue-on-error is not allowed")
            if str(step.get("uses", "")).startswith("actions/upload-artifact"):
                if "always()" not in str(step.get("if", "")):
                    errors.append(
                        f"{jid}/{name}: upload-artifact must run if: always()"
                    )
                days = (step.get("with") or {}).get("retention-days")
                if not isinstance(days, int) or days < MIN_RETENTION_DAYS:
                    errors.append(
                        f"{jid}/{name}: retention-days must be >= {MIN_RETENTION_DAYS}"
                    )

    # fg-security
    sec = jobs.get("fg-security") or {}
    timeout = sec.get("timeout-minutes")
    if not isinstance(timeout, int) or not (
        SECURITY_MIN_TIMEOUT <= timeout <= SECURITY_MAX_TIMEOUT
    ):
        errors.append(
            f"fg-security: timeout-minutes must be {SECURITY_MIN_TIMEOUT}..{SECURITY_MAX_TIMEOUT}"
        )
    if not any("make fg-security" in str(s.get("run", "")) for s in _steps(sec)):
        errors.append("fg-security: must run `make fg-security`")

    # Full suite must not depend on security
    gates = jobs.get("fg-full-gates") or {}
    if "fg-security" in _needs(gates) or "needs.fg-security" in str(
        gates.get("if", "")
    ):
        errors.append(
            "fg-full-gates: must not depend on fg-security (its timeout skipped every shard)"
        )

    # Shards
    shard = jobs.get("fg-full-shard") or {}
    strategy = shard.get("strategy") or {}
    total = str((shard.get("env") or {}).get("TOTAL_SHARDS", ""))
    if strategy.get("fail-fast") is not False:
        errors.append("fg-full-shard: strategy.fail-fast must be false")
    if not total.isdigit() or int(total) < 1:
        errors.append("fg-full-shard: env.TOTAL_SHARDS must be a positive integer")
    else:
        n = int(total)
        if (strategy.get("matrix") or {}).get("shard_index") != list(range(n)):
            errors.append(
                f"fg-full-shard: matrix.shard_index must be exactly 0..{n - 1}"
            )
        gate_runs = " ".join(str(s.get("run", "")) for s in _steps(gates))
        if _int_arg(gate_runs, "--total-shards") != n:
            errors.append(
                f"fg-full-gates: shard validation must use --total-shards {n}"
            )
    stimeout = shard.get("timeout-minutes")
    if not isinstance(stimeout, int) or stimeout < SHARD_MIN_TIMEOUT:
        errors.append(f"fg-full-shard: timeout-minutes must be >= {SHARD_MIN_TIMEOUT}")
    if not any("make fg-full-shard" in str(s.get("run", "")) for s in _steps(shard)):
        errors.append("fg-full-shard: must run `make fg-full-shard`")

    # Aggregate
    complete = jobs.get("fg-full-complete") or {}
    if "always()" not in str(complete.get("if", "")):
        errors.append(
            "fg-full-complete: must run if: always() so failed shards are reported"
        )
    agg = " ".join(
        str(s.get("run", ""))
        for s in _steps(complete)
        if "fg_full_aggregate.py" in str(s.get("run", ""))
    )
    if not agg:
        errors.append("fg-full-complete: must run tools/ci/fg_full_aggregate.py")
    else:
        if "--require-collection" not in agg:
            errors.append("fg-full-complete: aggregate must pass --require-collection")
        if total.isdigit() and _int_arg(agg, "--total-shards") != int(total):
            errors.append(
                f"fg-full-complete: aggregate must use --total-shards {total}"
            )
        floor = _int_arg(agg, "--expected-min-tests")
        if floor is None or floor < MIN_TEST_FLOOR:
            errors.append(
                f"fg-full-complete: --expected-min-tests must be >= {MIN_TEST_FLOOR}"
            )

    # Makefile: collection record + opt-in per-test timeout
    makefile = (repo / "Makefile").read_text()
    if "shard-collection.json" not in make_recipe(makefile, "fg-full-shard"):
        errors.append("Makefile fg-full-shard: must write shard-collection.json")
    for target in TIMEOUT_TARGETS:
        if "$(NIGHTLY_TIMEOUT_ARGS)" not in make_recipe(makefile, target):
            errors.append(f"Makefile {target}: must pass $(NIGHTLY_TIMEOUT_ARGS)")
    for jid in TIMEOUT_JOBS:
        value = str(
            ((jobs.get(jid) or {}).get("env") or {}).get(
                "NIGHTLY_TEST_TIMEOUT_SECONDS", "0"
            )
        )
        if not value.isdigit() or int(value) <= 0:
            errors.append(f"{jid}: env.NIGHTLY_TEST_TIMEOUT_SECONDS must be > 0")

    # Verdict
    verdict = jobs.get(VERDICT_JOB)
    if not verdict:
        errors.append(f"{VERDICT_JOB}: job is required")
    else:
        if str(verdict.get("if", "")).replace(" ", "") != "${{always()}}":
            errors.append(f"{VERDICT_JOB}: must run if: ${{{{ always() }}}}")
        others = sorted(j for j in jobs if j != VERDICT_JOB)
        if sorted(_needs(verdict)) != others:
            errors.append(f"{VERDICT_JOB}: needs must list every other job {others}")
        if sorted(VERDICT_JOBS) != others:
            errors.append(
                "tools/ci/testing_module_verdict.py ALL_JOBS must match the workflow jobs"
            )
        if not any(
            "testing_module_verdict.py" in str(s.get("run", ""))
            for s in _steps(verdict)
        ):
            errors.append(f"{VERDICT_JOB}: must run tools/ci/testing_module_verdict.py")
    errors.extend(_check_evidence_provenance(jobs, total))
    return errors


def _step_index(steps: list[dict[str, Any]], pred: Any) -> int:
    return next((i for i, s in enumerate(steps) if pred(s)), -1)


def _is_upload(step: dict[str, Any]) -> bool:
    return str(step.get("uses", "")).startswith("actions/upload-artifact")


def _is_download(step: dict[str, Any]) -> bool:
    return str(step.get("uses", "")).startswith("actions/download-artifact")


def _check_evidence_provenance(
    jobs: dict[str, dict[str, Any]], total: str
) -> list[str]:
    """Codex review of #925: evidence is bound to its producing attempt.

    After "Re-run failed jobs" the jobs that were not re-run keep their earlier
    attempt's result, outputs and artifacts while run_attempt increments, so
    no consumer may fetch evidence by name, pattern or run_attempt.
    """
    errors: list[str] = []
    for jid, job in jobs.items():
        for step in _steps(job):
            if not _is_download(step):
                continue
            with_ = step.get("with") or {}
            if "name" in with_ or "pattern" in with_ or "artifact-ids" not in with_:
                errors.append(
                    f"{jid}: download-artifact must use artifact-ids only "
                    "(no name/pattern; never the run_attempt)"
                )
            elif "run_attempt" in str(with_):
                errors.append(f"{jid}: download-artifact must not use run_attempt")

    producers = {"fg-security": "--kind security", "fg-full-shard": "--kind shard"}
    for jid, kind in producers.items():
        steps = _steps(jobs.get(jid) or {})
        w = _step_index(
            steps,
            lambda s, k=kind: (
                "testing_module_evidence.py write" in str(s.get("run", ""))
                and k in str(s.get("run", ""))
            ),
        )
        u = _step_index(steps, _is_upload)
        if w < 0 or "always()" not in str(steps[w].get("if", "")):
            errors.append(
                f"{jid}: must write evidence provenance ({kind}) with if: always()"
            )
        elif u < 0 or w > u:
            errors.append(f"{jid}: evidence provenance must be written before upload")
    sec_steps = _steps(jobs.get("fg-security") or {})
    up = [s for s in sec_steps if _is_upload(s)]
    if not up or str((up[0].get("with") or {}).get("path", "")).strip() != (
        "artifacts/evidence/fg-security/"
    ):
        errors.append(
            "fg-security: upload exactly the provenance-staged artifacts/evidence/fg-security/"
        )
    sec_output = ((jobs.get("fg-security") or {}).get("outputs") or {}).get(
        "security_artifact_id", ""
    )
    if "steps.upload_security.outputs.artifact-id" not in str(sec_output):
        errors.append(
            "fg-security: outputs.security_artifact_id must expose the upload's artifact-id"
        )

    consumers = {
        VERDICT_JOB: (
            "--kind security",
            "needs.fg-security.outputs.security_artifact_id",
        ),
        "fg-full-complete": ("--kind shard", None),
    }
    for jid, (kind, output_ref) in consumers.items():
        job = jobs.get(jid) or {}
        steps = _steps(job)
        if (job.get("permissions") or {}).get("actions") != "read":
            errors.append(f"{jid}: needs permissions.actions: read to resolve evidence")
        r = _step_index(
            steps,
            lambda s, k=kind: (
                "testing_module_evidence.py resolve" in str(s.get("run", ""))
                and k in str(s.get("run", ""))
            ),
        )
        d = _step_index(
            steps,
            lambda s: (
                _is_download(s)
                and "outputs.artifact_ids"
                in str((s.get("with") or {}).get("artifact-ids", ""))
            ),
        )
        v = _step_index(
            steps,
            lambda s, k=kind: (
                "testing_module_evidence.py verify" in str(s.get("run", ""))
                and k in str(s.get("run", ""))
            ),
        )
        if not (0 <= r < d < v):
            errors.append(
                f"{jid}: must resolve ({kind}), download by the resolved artifact ids, "
                "then verify provenance, in that order"
            )
            continue
        rid = steps[r].get("id")
        if not rid or f"steps.{rid}.outputs.artifact_ids" not in str(
            steps[d].get("with")
        ):
            errors.append(f"{jid}: download must use the resolve step's artifact_ids")
        resolve_text = str(steps[r].get("run", "")) + str(steps[r].get("env", ""))
        if output_ref and (
            "--artifact-id" not in resolve_text or output_ref not in resolve_text
        ):
            errors.append(
                f"{jid}: resolve must cross-check fg-security's artifact-id output"
            )
        if kind == "--kind shard" and total.isdigit():
            if _int_arg(resolve_text, "--total-shards") != int(total):
                errors.append(f"{jid}: resolve must use --total-shards {total}")
        agg = _step_index(
            steps, lambda s: "fg_full_aggregate.py" in str(s.get("run", ""))
        )
        if jid == "fg-full-complete" and agg >= 0 and agg < v:
            errors.append(
                "fg-full-complete: aggregate must run after provenance verify"
            )
        evaluate = _step_index(
            steps, lambda s: "testing_module_verdict.py" in str(s.get("run", ""))
        )
        if jid == VERDICT_JOB and evaluate >= 0 and evaluate < v:
            errors.append(f"{VERDICT_JOB}: verdict must run after provenance verify")
    return errors


def main() -> int:
    errors = check()
    if errors:
        print("testing-module workflow check: FAILED", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("testing-module workflow check: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
