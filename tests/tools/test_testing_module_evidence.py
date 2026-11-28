"""FG-CI-NIGHTLY-REPAIR-001 — evidence provenance for testing-module artifacts.

Codex review of #925: after "Re-run failed jobs" a job that was not re-run
keeps its earlier attempt's result, outputs and artifact while
``run_attempt`` increments. These tests prove that
``tools/ci/testing_module_evidence.py`` resolves each evidence artifact to the
attempt that produced it, and rejects missing, duplicated, foreign, stale,
mismatched or corrupted evidence.

The job-listing shape is the one GitHub returned for fg-core run 46065775550
(a real "Re-run failed jobs"): jobs that were not re-run are listed again
under attempt 2 with a new job id but the original ``started_at``,
``completed_at`` and ``runner_name``.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.ci import testing_module_evidence as ev

pytestmark = pytest.mark.contract

REPO = Path(__file__).resolve().parents[2]
RUN = 46000000001
SHA = "a" * 40
TREE = "b" * 40
SHARDS = 10


# --- fixtures ---------------------------------------------------------------


def _job(
    name: str, attempt: int, started: str, runner: str = "GitHub Actions 1"
) -> dict[str, Any]:
    return {
        "id": hash((name, attempt)) & 0xFFFFFFF,
        "run_id": RUN,
        "name": name,
        "run_attempt": attempt,
        "started_at": started,
        "completed_at": started.replace("T01", "T02"),
        "runner_name": runner,
    }


def _carried(job: dict[str, Any], attempt: int) -> dict[str, Any]:
    """GitHub's copy of a job that was not re-run (same execution identity)."""
    return {**job, "id": job["id"] + 1, "run_attempt": attempt}


def _artifact(
    name: str, art_id: int, run_id: int = RUN, sha: str = SHA, expired: bool = False
) -> dict[str, Any]:
    return {
        "id": art_id,
        "name": name,
        "expired": expired,
        "workflow_run": {"id": run_id, "head_sha": sha},
    }


def _first_attempt() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    jobs = [_job("fg-security", 1, "2026-11-27T01:00:00Z")]
    arts = [_artifact("fg-security-artifacts-1", 101)]
    for i in range(SHARDS):
        jobs.append(_job(f"fg-full-shard ({i})", 1, f"2026-11-27T01:{i:02d}:00Z"))
        arts.append(_artifact(f"fg-full-shard-{i}-1", 200 + i))
    return jobs, arts


def _rerun_failed(
    failed: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Attempt 2 of "Re-run failed jobs": ``failed`` re-execute, others carried."""
    jobs, arts = _first_attempt()
    for job in list(jobs):
        if job["name"] in failed:
            jobs.append(
                _job(job["name"], 2, "2026-11-27T05:00:00Z", runner="GitHub Actions 9")
            )
        else:
            jobs.append(_carried(job, 2))
    for name in failed:
        if name == "fg-security":
            arts.append(_artifact("fg-security-artifacts-2", 102))
        else:
            i = int(name.split("(")[1].rstrip(")"))
            arts.append(_artifact(f"fg-full-shard-{i}-2", 300 + i))
    return jobs, arts


def _resolve(kind: str, jobs: Any, arts: Any, **kw: Any) -> list[dict[str, Any]]:
    args: dict[str, Any] = {
        "run_id": RUN,
        "head_sha": SHA,
        "current_attempt": 2,
        "total_shards": SHARDS if kind == "shard" else None,
        "output_artifact_id": "101" if kind == "security" else None,
    }
    args.update(kw)
    return ev.resolve(kind, {"artifacts": arts}, {"jobs": jobs}, **args)


# --- resolve: producing attempt --------------------------------------------


def test_first_attempt_resolves_every_artifact() -> None:
    jobs, arts = _first_attempt()
    shards = _resolve("shard", jobs, arts, current_attempt=1)
    assert [r["artifact_id"] for r in shards] == [200 + i for i in range(SHARDS)]
    assert {r["run_attempt"] for r in shards} == {1}
    sec = _resolve("security", jobs, arts, current_attempt=1)
    assert sec == [
        {
            "artifact_id": 101,
            "name": "fg-security-artifacts-1",
            "run_attempt": 1,
            "shard_index": None,
        }
    ]


def test_carried_over_security_resolves_to_its_producing_attempt() -> None:
    """The Codex scenario: fg-security passed in attempt 1, a shard is re-run."""
    jobs, arts = _rerun_failed({"fg-full-shard (3)"})
    sec = _resolve("security", jobs, arts, output_artifact_id="101")
    assert sec[0]["name"] == "fg-security-artifacts-1"
    assert sec[0]["artifact_id"] == 101


def test_partial_rerun_mixes_attempts_per_shard_exactly() -> None:
    jobs, arts = _rerun_failed({"fg-full-shard (3)", "fg-full-shard (7)"})
    by_shard = {r["shard_index"]: r for r in _resolve("shard", jobs, arts)}
    assert by_shard[3]["name"] == "fg-full-shard-3-2"
    assert by_shard[7]["name"] == "fg-full-shard-7-2"
    assert {i for i, r in by_shard.items() if r["run_attempt"] == 1} == set(
        range(SHARDS)
    ) - {3, 7}


def test_rerun_security_resolves_to_the_new_attempt() -> None:
    jobs, arts = _rerun_failed({"fg-security"})
    sec = _resolve("security", jobs, arts, output_artifact_id="102")
    assert sec[0]["name"] == "fg-security-artifacts-2"


def test_rerun_whose_upload_is_missing_does_not_fall_back_to_stale_evidence() -> None:
    jobs, arts = _rerun_failed({"fg-full-shard (3)"})
    arts = [a for a in arts if a["name"] != "fg-full-shard-3-2"]
    with pytest.raises(ev.EvidenceError, match="fg-full-shard-3-2"):
        _resolve("shard", jobs, arts)


def test_pre_fix_attempt_lookup_would_have_missed_carried_jobs() -> None:
    """Negative control: naming by the consumer's run_attempt finds nothing."""
    jobs, arts = _rerun_failed({"fg-full-shard (3)"})
    names = {a["name"] for a in arts}
    assert "fg-security-artifacts-2" not in names
    assert sum(f"fg-full-shard-{i}-2" in names for i in range(SHARDS)) == 1


# --- resolve: rejections ----------------------------------------------------


def _reject(kind: str, jobs: Any, arts: Any, match: str, **kw: Any) -> None:
    with pytest.raises(ev.EvidenceError, match=match):
        _resolve(kind, jobs, arts, **kw)


@pytest.mark.parametrize("bad", ["", None, "0", "12a", "*", "101,102"])
def test_security_output_id_missing_or_not_a_single_id(bad: Any) -> None:
    # An empty artifact-ids input would make download-artifact fetch every
    # artifact of the run.
    jobs, arts = _first_attempt()
    _reject("security", jobs, arts, "artifact-id output", output_artifact_id=bad)


def test_security_output_id_for_another_artifact_is_rejected() -> None:
    jobs, arts = _first_attempt()
    arts.append(_artifact("unrelated", 999))
    _reject("security", jobs, arts, "does not match", output_artifact_id="999")


def test_missing_artifact_is_rejected() -> None:
    jobs, arts = _first_attempt()
    arts = [a for a in arts if a["name"] != "fg-full-shard-5-1"]
    _reject("shard", jobs, arts, "found 0", current_attempt=1)


def test_duplicate_artifact_identity_is_rejected() -> None:
    jobs, arts = _first_attempt()
    arts.append(_artifact("fg-full-shard-5-1", 555))
    _reject("shard", jobs, arts, "found 2", current_attempt=1)


def test_artifact_from_another_run_is_rejected() -> None:
    jobs, arts = _first_attempt()
    arts[0] = _artifact("fg-security-artifacts-1", 101, run_id=RUN + 1)
    _reject("security", jobs, arts, "belongs to run", current_attempt=1)


def test_artifact_for_another_commit_is_rejected() -> None:
    jobs, arts = _first_attempt()
    arts[0] = _artifact("fg-security-artifacts-1", 101, sha="c" * 40)
    _reject("security", jobs, arts, "head_sha", current_attempt=1)


@pytest.mark.parametrize("expired", [True, None])
def test_expired_or_unknown_state_artifact_is_rejected(expired: Any) -> None:
    jobs, arts = _first_attempt()
    arts[0]["expired"] = expired
    _reject("security", jobs, arts, "expired", current_attempt=1)


def test_missing_producing_job_is_rejected() -> None:
    jobs, arts = _first_attempt()
    jobs = [j for j in jobs if j["name"] != "fg-full-shard (9)"]
    _reject("shard", jobs, arts, "no job named", current_attempt=1)


def test_unexpected_extra_shard_job_is_rejected() -> None:
    jobs, arts = _first_attempt()
    jobs.append(_job("fg-full-shard (10)", 1, "2026-11-27T01:30:00Z"))
    _reject("shard", jobs, arts, "unexpected shard jobs", current_attempt=1)


def test_duplicate_job_in_one_attempt_is_rejected() -> None:
    jobs, arts = _first_attempt()
    jobs.append(_job("fg-security", 1, "2026-11-27T01:44:00Z"))
    _reject("security", jobs, arts, "ambiguous", current_attempt=1)


@pytest.mark.parametrize("key", ["started_at", "completed_at", "runner_name"])
def test_incomplete_execution_identity_is_rejected(key: str) -> None:
    jobs, arts = _first_attempt()
    jobs[0][key] = None
    _reject("security", jobs, arts, "execution identity", current_attempt=1)


def test_producing_attempt_after_current_attempt_is_rejected() -> None:
    jobs, arts = _rerun_failed({"fg-security"})
    _reject(
        "security",
        jobs,
        arts,
        "> current attempt",
        current_attempt=1,
        output_artifact_id="102",
    )


def test_job_from_another_run_is_ignored() -> None:
    jobs, arts = _first_attempt()
    for j in jobs:
        if j["name"] == "fg-full-shard (2)":
            j["run_id"] = RUN + 1
    _reject(
        "shard", jobs, arts, "no job named 'fg-full-shard \\(2\\)'", current_attempt=1
    )


# --- write + verify ---------------------------------------------------------


ENV = {
    "GITHUB_RUN_ID": str(RUN),
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_SHA": SHA,
    "GITHUB_JOB": "fg-full-shard",
    "GITHUB_WORKFLOW": "testing-module",
}


def _shard_tree(
    root: Path, attempts: dict[int, int] | None = None
) -> list[dict[str, Any]]:
    resolved = []
    for i in range(SHARDS):
        d = root / f"shard-{i}"
        d.mkdir(parents=True)
        (d / f"junit-shard-{i}.xml").write_text(
            f'<testsuite tests="{10 + i}" failures="0"/>'
        )
        (d / "shard-collection.json").write_text(
            json.dumps({"collected_tests": 10 + i})
        )
        attempt = (attempts or {}).get(i, 1)
        ev.write_provenance(
            d, "shard", i, {**ENV, "GITHUB_RUN_ATTEMPT": str(attempt)}, SHA, TREE
        )
        resolved.append(
            {
                "artifact_id": 200 + i,
                "name": f"fg-full-shard-{i}-{attempt}",
                "run_attempt": attempt,
                "shard_index": i,
            }
        )
    return resolved


def _security_tree(root: Path, attempt: int = 1) -> list[dict[str, Any]]:
    (root / "ci" / "junit").mkdir(parents=True)
    (root / "ci" / "junit" / "fg-security.xml").write_text('<testsuite tests="1676"/>')
    ev.write_provenance(
        root,
        "security",
        None,
        {**ENV, "GITHUB_JOB": "fg-security", "GITHUB_RUN_ATTEMPT": str(attempt)},
        SHA,
        TREE,
    )
    return [
        {
            "artifact_id": 101,
            "name": f"fg-security-artifacts-{attempt}",
            "run_attempt": attempt,
            "shard_index": None,
        }
    ]


def test_round_trip_shards_with_mixed_attempts(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path, {3: 2})
    records = ev.verify("shard", tmp_path, resolved, RUN, SHA)
    assert [r["shard_index"] for r in records] == list(range(SHARDS))
    assert records[3]["run_attempt"] == 2
    assert records[0]["git_tree"] == TREE
    assert set(records[0]["files"]) == {"junit-shard-0.xml", "shard-collection.json"}


def test_round_trip_security(tmp_path: Path) -> None:
    resolved = _security_tree(tmp_path)
    (rec,) = ev.verify("security", tmp_path, resolved, RUN, SHA)
    assert rec["files"]["ci/junit/fg-security.xml"]["bytes"] > 0


def _verify_rejects(tmp_path: Path, match: str, kind: str = "shard", **kw: Any) -> None:
    resolved = kw.pop("resolved")
    with pytest.raises(ev.EvidenceError, match=match):
        ev.verify(kind, tmp_path, resolved, kw.get("run_id", RUN), kw.get("sha", SHA))


def test_tampered_junit_is_rejected(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    (tmp_path / "shard-4" / "junit-shard-4.xml").write_text(
        '<testsuite tests="99999" failures="0"/>'
    )
    _verify_rejects(tmp_path, "SHA-256", resolved=resolved)


def test_truncated_junit_is_rejected(tmp_path: Path) -> None:
    resolved = _security_tree(tmp_path)
    p = tmp_path / "ci" / "junit" / "fg-security.xml"
    p.write_bytes(p.read_bytes()[:-3])
    _verify_rejects(tmp_path, "SHA-256|size", kind="security", resolved=resolved)


def test_removed_file_is_rejected(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    (tmp_path / "shard-2" / "shard-collection.json").unlink()
    _verify_rejects(
        tmp_path, "missing \\['shard-collection.json'\\]", resolved=resolved
    )


def test_unlisted_file_is_rejected(tmp_path: Path) -> None:
    resolved = _security_tree(tmp_path)
    (tmp_path / "ci" / "junit" / "extra.xml").write_text("<testsuite tests='5000'/>")
    _verify_rejects(tmp_path, "unlisted", kind="security", resolved=resolved)


def test_symlink_in_evidence_is_rejected(tmp_path: Path) -> None:
    resolved = _security_tree(tmp_path)
    (tmp_path / "link.xml").symlink_to(tmp_path / "ci" / "junit" / "fg-security.xml")
    _verify_rejects(tmp_path, "symlink", kind="security", resolved=resolved)


def test_missing_provenance_is_rejected(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    (tmp_path / "shard-6" / ev.PROVENANCE).unlink()
    _verify_rejects(tmp_path, "provenance.json missing", resolved=resolved)


def test_corrupted_provenance_is_rejected(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    (tmp_path / "shard-6" / ev.PROVENANCE).write_text("{not json")
    _verify_rejects(tmp_path, "unreadable provenance", resolved=resolved)


def test_wrong_commit_is_rejected(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    _verify_rejects(tmp_path, "sha is", resolved=resolved, sha="c" * 40)


def test_evidence_from_another_run_is_rejected(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    _verify_rejects(tmp_path, "run_id is", resolved=resolved, run_id=RUN + 1)


def test_evidence_from_a_different_attempt_than_resolved_is_rejected(
    tmp_path: Path,
) -> None:
    resolved = _shard_tree(tmp_path)
    resolved[5]["run_attempt"] = 2
    _verify_rejects(tmp_path, "run_attempt is 1, expected 2", resolved=resolved)


def test_checked_out_head_must_equal_tested_sha(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    rec_path = tmp_path / "shard-1" / ev.PROVENANCE
    rec = json.loads(rec_path.read_text())
    rec["git_head"] = "d" * 40
    rec_path.write_text(json.dumps(rec))
    _verify_rejects(tmp_path, "git_head is", resolved=resolved)


def test_swapped_shard_directories_are_rejected(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    (tmp_path / "shard-1").rename(tmp_path / "tmp")
    (tmp_path / "shard-2").rename(tmp_path / "shard-1")
    (tmp_path / "tmp").rename(tmp_path / "shard-2")
    _verify_rejects(tmp_path, "shard_index is", resolved=resolved)


def test_wrong_kind_is_rejected(tmp_path: Path) -> None:
    sec = tmp_path / "sec"
    resolved = _security_tree(sec)
    with pytest.raises(ev.EvidenceError, match="kind is 'security'"):
        ev._verify_dir(sec, "shard", 0, RUN, SHA, resolved[0]["run_attempt"])


def test_missing_shard_directory_is_rejected(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    for f in (tmp_path / "shard-8").iterdir():
        f.unlink()
    (tmp_path / "shard-8").rmdir()
    _verify_rejects(tmp_path, "shard directories", resolved=resolved)


def test_unexpected_shard_directory_is_rejected(tmp_path: Path) -> None:
    resolved = _shard_tree(tmp_path)
    (tmp_path / "shard-10").mkdir()
    _verify_rejects(tmp_path, "shard directories", resolved=resolved)


def test_empty_evidence_is_rejected(tmp_path: Path) -> None:
    ev.write_provenance(
        tmp_path, "security", None, {**ENV, "GITHUB_JOB": "fg-security"}, SHA, TREE
    )
    resolved = [
        {"artifact_id": 101, "name": "x", "run_attempt": 1, "shard_index": None}
    ]
    _verify_rejects(
        tmp_path, "inventory missing or empty", kind="security", resolved=resolved
    )


def test_write_requires_run_identity(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="GITHUB_RUN_ATTEMPT"):
        ev.write_provenance(
            tmp_path,
            "security",
            None,
            {k: v for k, v in ENV.items() if k != "GITHUB_RUN_ATTEMPT"},
            SHA,
            TREE,
        )


# --- CLI as the workflow calls it -------------------------------------------


def _cli(
    *args: str, env: dict[str, str] | None = None, cwd: Path = REPO
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO / "tools/ci/testing_module_evidence.py"), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
    )


def test_cli_resolve_reads_gh_jsonl_and_writes_github_output(tmp_path: Path) -> None:
    jobs, arts = _rerun_failed({"fg-full-shard (3)"})
    (tmp_path / "arts.jsonl").write_text("\n".join(json.dumps(a) for a in arts) + "\n")
    (tmp_path / "jobs.jsonl").write_text("\n".join(json.dumps(j) for j in jobs) + "\n")
    out = tmp_path / "gh_output"
    proc = _cli(
        "resolve",
        "--kind",
        "shard",
        "--total-shards",
        str(SHARDS),
        "--run-id",
        str(RUN),
        "--head-sha",
        SHA,
        "--run-attempt",
        "2",
        "--artifacts-json",
        str(tmp_path / "arts.jsonl"),
        "--jobs-json",
        str(tmp_path / "jobs.jsonl"),
        "--out-json",
        str(tmp_path / "resolved.json"),
        "--github-output",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr
    ids = out.read_text().strip().removeprefix("artifact_ids=").split(",")
    assert ids == [str(303 if i == 3 else 200 + i) for i in range(SHARDS)]


def test_cli_rejection_exits_1_and_writes_no_output(tmp_path: Path) -> None:
    jobs, arts = _first_attempt()
    (tmp_path / "arts.json").write_text(json.dumps({"artifacts": arts[1:]}))
    (tmp_path / "jobs.json").write_text(json.dumps({"jobs": jobs}))
    out = tmp_path / "gh_output"
    proc = _cli(
        "resolve",
        "--kind",
        "security",
        "--run-id",
        str(RUN),
        "--head-sha",
        SHA,
        "--run-attempt",
        "1",
        "--artifact-id",
        "101",
        "--artifacts-json",
        str(tmp_path / "arts.json"),
        "--jobs-json",
        str(tmp_path / "jobs.json"),
        "--out-json",
        str(tmp_path / "resolved.json"),
        "--github-output",
        str(out),
    )
    assert proc.returncode == 1
    assert "REJECTED" in proc.stderr
    assert not out.exists()


def test_cli_write_binds_the_real_checkout(tmp_path: Path) -> None:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    shards = tmp_path / "shards"
    shard = shards / "shard-0"
    shard.mkdir(parents=True)
    (shard / "junit-shard-0.xml").write_text('<testsuite tests="1"/>')
    env = {"PATH": "/usr/bin:/bin", **ENV, "GITHUB_SHA": head}
    proc = _cli(
        "write", "--dir", str(shard), "--kind", "shard", "--shard-index", "0", env=env
    )
    assert proc.returncode == 0, proc.stderr
    rec = json.loads((shard / ev.PROVENANCE).read_text())
    assert (rec["git_head"], rec["git_tree"]) == (head, tree)
    resolved = [
        {
            "artifact_id": 1,
            "name": "fg-full-shard-0-1",
            "run_attempt": 1,
            "shard_index": 0,
        }
    ]
    (tmp_path / "resolved.json").write_text(json.dumps(resolved))
    ok = _cli(
        "verify",
        "--kind",
        "shard",
        "--dir",
        str(shards),
        "--resolved-json",
        str(tmp_path / "resolved.json"),
        "--run-id",
        str(RUN),
        "--sha",
        head,
    )
    assert ok.returncode == 0, ok.stderr
    bad = _cli(
        "verify",
        "--kind",
        "shard",
        "--dir",
        str(shards),
        "--resolved-json",
        str(tmp_path / "resolved.json"),
        "--run-id",
        str(RUN),
        "--sha",
        "0" * 40,
    )
    assert bad.returncode == 1 and "REJECTED" in bad.stderr
