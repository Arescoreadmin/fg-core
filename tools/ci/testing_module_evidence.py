#!/usr/bin/env python3
"""FG-CI-NIGHTLY-REPAIR-001 — provenance for testing-module evidence artifacts.

"Re-run failed jobs" increments ``github.run_attempt`` but keeps every job that
already succeeded, with its result, outputs and artifacts, from the earlier
attempt. A consumer that downloads ``<name>-${{ github.run_attempt }}`` (or a
wildcard) therefore either finds nothing or could pick up evidence from the
wrong attempt. This module binds each evidence artifact to the job execution
that produced it and lets consumers fetch exactly that artifact:

``write``
    Run by the producing job, ``if: always()``, just before its upload. Writes
    ``evidence-provenance.json`` into the evidence directory: run id, the
    job's own run attempt, workflow, job, ``GITHUB_SHA``, the checked-out
    commit and tree, and the SHA-256 and size of every file in the directory.

``resolve``
    Run by the consumer with the run's artifact and job listings (GitHub REST
    API). For each expected evidence item it finds the producing job's latest
    attempt and requires exactly one artifact named ``<prefix>-<attempt>`` in
    this run, unexpired, from this run id and head SHA. For fg-security it
    also requires that artifact's id to equal the job's ``artifact-id`` output.
    Prints the resolved ids (comma-separated) for ``download-artifact``'s
    ``artifact-ids``, never a name pattern.

``verify``
    Run after the download. Each evidence directory must hold a provenance
    file for this run, SHA, kind, shard index and the resolved attempt, and
    its file set and hashes must match exactly (nothing missing, added or
    altered). Unexpected shard directories are rejected.

Standard library only. Every check fails closed. Exit 0 = OK, 1 = rejected,
2 = bad input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PROVENANCE = "evidence-provenance.json"
SCHEMA = 1
KINDS = ("security", "shard")
SECURITY_JOB = "fg-security"
SECURITY_PREFIX = "fg-security-artifacts"
SHARD_JOB = "fg-full-shard ({index})"
SHARD_PREFIX = "fg-full-shard-{index}"
_ID = re.compile(r"^[1-9][0-9]*$")


class EvidenceError(Exception):
    """Evidence is missing, mismatched or corrupted."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _evidence_files(directory: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise EvidenceError(f"{path}: symlinks are not allowed in evidence")
        if path.is_file() and path.relative_to(directory).as_posix() != PROVENANCE:
            files[path.relative_to(directory).as_posix()] = path
    return files


def _git(*args: str) -> str:
    out = subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout
    return out.strip()


def write_provenance(
    directory: Path,
    kind: str,
    shard_index: int | None,
    env: dict[str, str],
    git_head: str,
    git_tree: str,
) -> dict[str, Any]:
    if kind not in KINDS:
        raise ValueError(f"unsupported kind {kind!r}")
    if (kind == "shard") != (shard_index is not None):
        raise ValueError("--shard-index is required for kind=shard and only for it")
    missing = [
        k
        for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_JOB")
        if not env.get(k)
    ]
    if missing:
        raise ValueError(f"missing environment: {missing}")
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": SCHEMA,
        "kind": kind,
        "shard_index": shard_index,
        "run_id": int(env["GITHUB_RUN_ID"]),
        "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
        "workflow": env.get("GITHUB_WORKFLOW", ""),
        "job": env["GITHUB_JOB"],
        "sha": env["GITHUB_SHA"],
        "git_head": git_head,
        "git_tree": git_tree,
        "files": {
            rel: {"sha256": _sha256(path), "bytes": path.stat().st_size}
            for rel, path in _evidence_files(directory).items()
        },
    }
    (directory / PROVENANCE).write_text(json.dumps(record, indent=2, sort_keys=True))
    return record


def _flatten(listing: Any, key: str) -> list[dict[str, Any]]:
    """Accept one API page, a list of pages (``gh api --paginate --slurp``) or a list."""
    pages = listing if isinstance(listing, list) else [listing]
    items: list[dict[str, Any]] = []
    for page in pages:
        if isinstance(page, dict) and key in page:
            page = page[key]
        if isinstance(page, dict):
            page = [page]
        if not isinstance(page, list):
            raise ValueError(f"{key} listing has an unexpected shape")
        items.extend(item for item in page if isinstance(item, dict))
    return items


_EXECUTION_KEYS = ("started_at", "completed_at", "runner_name")


def _producing_attempt(jobs: list[dict[str, Any]], name: str, run_id: int) -> int:
    """Return the attempt whose execution produced the job's current result.

    The jobs listing (``filter=all``) does not say this directly: after
    "Re-run failed jobs", GitHub lists every job that was *not* re-run again
    under the new attempt with a new job id but the original execution's
    ``started_at``, ``completed_at`` and ``runner_name`` (observed on
    fg-core run 46065775550). So the producing attempt is the earliest attempt
    sharing the latest record's execution identity; a re-executed job has a
    new identity and resolves to the new attempt.
    """
    records = [j for j in jobs if j.get("name") == name and j.get("run_id") == run_id]
    if not records:
        raise EvidenceError(f"no job named {name!r} in run {run_id}")
    if not all(
        isinstance(j.get("run_attempt"), int) and j["run_attempt"] >= 1 for j in records
    ):
        raise EvidenceError(f"{name!r}: invalid run_attempt in job listing")
    top = max(j["run_attempt"] for j in records)
    latest = [j for j in records if j["run_attempt"] == top]
    if len(latest) != 1:
        raise EvidenceError(
            f"{name!r}: {len(latest)} jobs in attempt {top}; identity is ambiguous"
        )
    identity = tuple(latest[0].get(k) for k in _EXECUTION_KEYS)
    if not all(isinstance(v, str) and v for v in identity):
        raise EvidenceError(
            f"{name!r}: latest job has no complete execution identity {dict(zip(_EXECUTION_KEYS, identity))}"
        )
    return min(
        j["run_attempt"]
        for j in records
        if tuple(j.get(k) for k in _EXECUTION_KEYS) == identity
    )


def _artifact_for(
    artifacts: list[dict[str, Any]], name: str, run_id: int, head_sha: str
) -> dict[str, Any]:
    matches = [a for a in artifacts if a.get("name") == name]
    if len(matches) != 1:
        raise EvidenceError(
            f"expected exactly one artifact {name!r}, found {len(matches)}"
        )
    art = matches[0]
    run = art.get("workflow_run") or {}
    if run.get("id") != run_id:
        raise EvidenceError(
            f"{name!r}: artifact belongs to run {run.get('id')}, not {run_id}"
        )
    if run.get("head_sha") != head_sha:
        raise EvidenceError(
            f"{name!r}: artifact head_sha {run.get('head_sha')!r} != {head_sha!r}"
        )
    if art.get("expired") is not False:
        raise EvidenceError(f"{name!r}: artifact is expired or its state is unknown")
    if not _ID.match(str(art.get("id", ""))):
        raise EvidenceError(f"{name!r}: invalid artifact id {art.get('id')!r}")
    return art


def resolve(
    kind: str,
    artifacts_listing: Any,
    jobs_listing: Any,
    run_id: int,
    head_sha: str,
    current_attempt: int,
    total_shards: int | None = None,
    output_artifact_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return [{"artifact_id", "name", "run_attempt", "shard_index"}] in order."""
    artifacts = _flatten(artifacts_listing, "artifacts")
    jobs = _flatten(jobs_listing, "jobs")
    if kind == "security":
        targets = [(None, SECURITY_JOB, SECURITY_PREFIX)]
        if not _ID.match(str(output_artifact_id or "")):
            raise EvidenceError(
                f"fg-security artifact-id output is missing or invalid: {output_artifact_id!r}"
            )
    elif kind == "shard":
        if not total_shards or total_shards < 1:
            raise ValueError("--total-shards is required for kind=shard")
        targets = [
            (i, SHARD_JOB.format(index=i), SHARD_PREFIX.format(index=i))
            for i in range(total_shards)
        ]
        extra = sorted(
            {
                str(j.get("name"))
                for j in jobs
                if str(j.get("name", "")).startswith("fg-full-shard (")
            }
            - {t[1] for t in targets}
        )
        if extra:
            raise EvidenceError(f"unexpected shard jobs in run: {extra}")
    else:
        raise ValueError(f"unsupported kind {kind!r}")

    resolved: list[dict[str, Any]] = []
    for index, job_name, prefix in targets:
        attempt = _producing_attempt(jobs, job_name, run_id)
        if attempt > current_attempt:
            raise EvidenceError(
                f"{job_name!r}: producing attempt {attempt} > current attempt {current_attempt}"
            )
        art = _artifact_for(artifacts, f"{prefix}-{attempt}", run_id, head_sha)
        if kind == "security" and str(art["id"]) != str(output_artifact_id):
            raise EvidenceError(
                f"fg-security artifact-id output {output_artifact_id} does not match "
                f"the producing attempt's artifact {art['id']}"
            )
        resolved.append(
            {
                "artifact_id": int(art["id"]),
                "name": art["name"],
                "run_attempt": attempt,
                "shard_index": index,
            }
        )
    return resolved


def _verify_dir(
    directory: Path,
    kind: str,
    shard_index: int | None,
    run_id: int,
    sha: str,
    attempt: int,
) -> dict[str, Any]:
    path = directory / PROVENANCE
    if not path.is_file():
        raise EvidenceError(f"{directory}: {PROVENANCE} missing")
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"{path}: unreadable provenance ({exc})") from exc
    if not isinstance(record, dict):
        raise EvidenceError(f"{path}: provenance must be an object")
    expected = {
        "schema": SCHEMA,
        "kind": kind,
        "shard_index": shard_index,
        "run_id": run_id,
        "run_attempt": attempt,
        "sha": sha,
        "git_head": sha,
    }
    for key, want in expected.items():
        if record.get(key) != want:
            raise EvidenceError(
                f"{path}: {key} is {record.get(key)!r}, expected {want!r}"
            )
    if not isinstance(record.get("git_tree"), str) or not re.fullmatch(
        r"[0-9a-f]{40}", record["git_tree"]
    ):
        raise EvidenceError(f"{path}: git_tree missing or invalid")
    listed = record.get("files")
    if not isinstance(listed, dict) or not listed:
        raise EvidenceError(f"{path}: file inventory missing or empty")
    actual = _evidence_files(directory)
    if set(listed) != set(actual):
        raise EvidenceError(
            f"{directory}: files differ from provenance "
            f"(missing {sorted(set(listed) - set(actual))}, "
            f"unlisted {sorted(set(actual) - set(listed))})"
        )
    for rel, meta in listed.items():
        if not isinstance(meta, dict) or meta.get("sha256") != _sha256(actual[rel]):
            raise EvidenceError(f"{directory}/{rel}: SHA-256 does not match provenance")
        if meta.get("bytes") != actual[rel].stat().st_size:
            raise EvidenceError(f"{directory}/{rel}: size does not match provenance")
    return record


def verify(
    kind: str,
    root: Path,
    resolved: list[dict[str, Any]],
    run_id: int,
    sha: str,
) -> list[dict[str, Any]]:
    if not root.is_dir():
        raise EvidenceError(f"evidence directory {root} not found")
    if kind == "security":
        if len(resolved) != 1:
            raise EvidenceError(
                "security evidence must resolve to exactly one artifact"
            )
        return [_verify_dir(root, kind, None, run_id, sha, resolved[0]["run_attempt"])]
    want = {f"shard-{r['shard_index']}": r for r in resolved}
    found = {
        p.name for p in root.iterdir() if p.is_dir() and p.name.startswith("shard-")
    }
    if found != set(want):
        raise EvidenceError(
            f"shard directories {sorted(found)} != expected {sorted(want)}"
        )
    return [
        _verify_dir(root / name, kind, r["shard_index"], run_id, sha, r["run_attempt"])
        for name, r in sorted(want.items(), key=lambda kv: kv[1]["shard_index"])
    ]


def _load_json(path: Path) -> Any:
    """A JSON document, or JSON Lines (``gh api --paginate --jq '.items[]'``)."""
    text = path.read_text()
    try:
        return json.loads(text)
    except ValueError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("write")
    w.add_argument("--dir", type=Path, required=True)
    w.add_argument("--kind", choices=KINDS, required=True)
    w.add_argument("--shard-index", type=int)

    for name in ("resolve", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--kind", choices=KINDS, required=True)
        p.add_argument("--run-id", type=int, required=True)
        if name == "resolve":
            p.add_argument("--artifacts-json", type=Path, required=True)
            p.add_argument("--jobs-json", type=Path, required=True)
            p.add_argument("--head-sha", required=True)
            p.add_argument("--run-attempt", type=int, required=True)
            p.add_argument("--total-shards", type=int)
            p.add_argument("--artifact-id")
            p.add_argument("--out-json", type=Path, required=True)
            p.add_argument("--github-output", type=Path)
        else:
            p.add_argument("--dir", type=Path, required=True)
            p.add_argument("--resolved-json", type=Path, required=True)
            p.add_argument("--sha", required=True)
    args = parser.parse_args(argv)

    try:
        if args.cmd == "write":
            record = write_provenance(
                args.dir,
                args.kind,
                args.shard_index,
                dict(os.environ),
                _git("rev-parse", "HEAD"),
                _git("rev-parse", "HEAD^{tree}"),
            )
            print(
                f"evidence provenance: {args.dir}/{PROVENANCE} "
                f"(attempt {record['run_attempt']}, {len(record['files'])} files)"
            )
            return 0
        if args.cmd == "resolve":
            resolved = resolve(
                args.kind,
                _load_json(args.artifacts_json),
                _load_json(args.jobs_json),
                args.run_id,
                args.head_sha,
                args.run_attempt,
                args.total_shards,
                args.artifact_id,
            )
            args.out_json.parent.mkdir(parents=True, exist_ok=True)
            args.out_json.write_text(json.dumps(resolved, indent=2))
            ids = ",".join(str(r["artifact_id"]) for r in resolved)
            if args.github_output:
                with args.github_output.open("a", encoding="utf-8") as fh:
                    fh.write(f"artifact_ids={ids}\n")
            for r in resolved:
                print(f"resolved {r['name']} -> artifact {r['artifact_id']}")
            return 0
        records = verify(
            args.kind,
            args.dir,
            _load_json(args.resolved_json),
            args.run_id,
            args.sha,
        )
        for rec in records:
            print(
                f"verified {rec['kind']} shard={rec['shard_index']} "
                f"attempt={rec['run_attempt']} files={len(rec['files'])} tree={rec['git_tree']}"
            )
        return 0
    except EvidenceError as exc:
        print(f"testing-module evidence: REJECTED: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"testing-module evidence: bad input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
