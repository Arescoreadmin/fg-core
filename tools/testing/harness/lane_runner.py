#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

TOOL_VERSION = "1.0.0"
ARTIFACT_ROOT = "artifacts/testing"
COMMAND_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class CommandSpec:
    argv: tuple[str, ...]
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS


ALLOWED_LANES: dict[str, tuple[CommandSpec, ...]] = {
    "fg-fast": (
        CommandSpec((sys.executable, "tools/testing/harness/required_tests_gate.py")),
        CommandSpec(("make", "fg-contract")),
        CommandSpec(("make", "fg-security")),
        CommandSpec((".venv/bin/pytest", "-q", "tests/test_gap_audit.py")),
    ),
    "fg-contract": (
        CommandSpec(("make", "fg-contract")),
        CommandSpec((sys.executable, "tools/testing/contracts/check_contract_drift.py")),
    ),
    "fg-security": (
        CommandSpec(("make", "fg-security")),
        CommandSpec((sys.executable, "tools/testing/security/check_security_invariants.py")),
    ),
    "fg-full": (CommandSpec(("make", "fg-full"), timeout_seconds=1800),),
}


def _safe_env() -> dict[str, str]:
    allow_keys = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONPATH",
        "PYTHONHASHSEED",
        "TZ",
        "FG_ENV",
        "GITHUB_SHA",
        "GITHUB_REF",
        "GITHUB_RUN_ID",
        "GITHUB_ACTIONS",
        "CI",
    }
    env = {k: v for k, v in os.environ.items() if k in allow_keys}
    env.setdefault("PYTHONHASHSEED", "0")
    env.setdefault("TZ", "UTC")
    return env


def _json_dumps(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sanitize_log(text: str) -> str:
    redaction_tokens = ["FG_API_KEY", "POSTGRES_PASSWORD", "NATS_AUTH_TOKEN", "FG_WEBHOOK_SECRET"]
    lines: list[str] = []
    for line in text.splitlines():
        sanitized = line
        for token in redaction_tokens:
            if token in sanitized:
                sanitized = sanitized.replace(token, f"{token}=<redacted>")
        lines.append(sanitized)
    return "\n".join(lines)


def _run_command(command: CommandSpec, cwd: Path, log_file: Path) -> int:
    proc = subprocess.run(
        list(command.argv),
        cwd=cwd,
        check=False,
        text=True,
        capture_output=True,
        env=_safe_env(),
        shell=False,
        timeout=command.timeout_seconds,
    )
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"$ {' '.join(command.argv)}\n")
        if proc.stdout:
            handle.write(_sanitize_log(proc.stdout))
            handle.write("\n")
        if proc.stderr:
            handle.write(_sanitize_log(proc.stderr))
            handle.write("\n")
    return int(proc.returncode)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _artifact_dir(repo_root: Path, out_dir: str) -> Path:
    root = (repo_root / ARTIFACT_ROOT).resolve()
    requested = (repo_root / out_dir).resolve()
    if requested != root and root not in requested.parents:
        raise SystemExit(f"out-dir must be under {ARTIFACT_ROOT}")
    requested.mkdir(parents=True, exist_ok=True)
    return requested


def main() -> int:
    parser = argparse.ArgumentParser(description="Run allowlisted test lane commands")
    parser.add_argument("--lane", required=True, choices=sorted(ALLOWED_LANES))
    parser.add_argument("--out-dir", default=ARTIFACT_ROOT)
    parser.add_argument("--actor", default="ci")
    parser.add_argument("--commit", default=os.getenv("GITHUB_SHA", "local"))
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[3]
    out_dir = _artifact_dir(repo_root, args.out_dir)
    log_file = out_dir / f"{args.lane}.log"
    metadata_file = out_dir / f"{args.lane}.metadata.json"

    started_iso = _iso_now()
    status = "passed"
    for command in ALLOWED_LANES[args.lane]:
        try:
            code = _run_command(command, cwd=repo_root, log_file=log_file)
        except subprocess.TimeoutExpired:
            status = "failed"
            with log_file.open("a", encoding="utf-8") as handle:
                handle.write(f"[timeout] {' '.join(command.argv)}\n")
            break
        if code != 0:
            status = "failed"
            break

    ended_iso = _iso_now()
    metadata = {
        "artifact_sha256": _sha256(log_file),
        "actor": args.actor,
        "commit_sha": args.commit,
        "ended_at": ended_iso,
        "lane": args.lane,
        "started_at": started_iso,
        "status": status,
        "tool_version": TOOL_VERSION,
    }
    metadata_file.write_text(_json_dumps(metadata) + "\n", encoding="utf-8")
    print(_json_dumps(metadata))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
