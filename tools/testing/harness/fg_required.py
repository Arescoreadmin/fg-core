#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.testing.harness.triage_report import _classify
from tools.testing.harness.quarantine_policy import pytest_addopts_for_lane

ARTIFACT_ROOT = REPO_ROOT / "artifacts/testing"
GLOBAL_BUDGET_SECONDS = 480
DEFAULT_LANE_TIMEOUT_SECONDS = 480
BUDGET_SAFETY_MARGIN_SECONDS = 10
MAX_LOG_BYTES = 2 * 1024 * 1024

LANES: tuple[str, ...] = (
    "policy-validate",
    "required-tests-gate",
    "fg-fast",
    "fg-contract",
    "fg-security",
)

LANE_COMMANDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "policy-validate": (("make", "policy-validate"),),
    "required-tests-gate": (("make", "required-tests-gate"),),
    "fg-fast": (("make", "fg-fast"),),
    "fg-contract": (
        ("make", "fg-contract"),
        ("python", "tools/testing/contracts/check_contract_drift.py"),
    ),
    "fg-security": (
        ("make", "fg-security"),
        ("python", "tools/testing/security/check_security_invariants.py"),
    ),
}

ALWAYS_REQUIRED_FILES = (
    "fg-required-summary.json",
    "fg-required-summary.md",
)
BLOCKED_COMMANDS = {"env", "printenv", "set"}
BLOCKED_COMMAND_PATTERNS = (
    re.compile(r"(^|\s)(cat|sed|awk|grep)\s+[^\n]*\.env(\.[^\s]+)?(\s|$)"),
)


@dataclass(frozen=True)
class LaneResult:
    lane: str
    status: str
    duration_seconds: int
    timeout: bool
    error: str | None = None
    artifact_paths: dict[str, str] | None = None


def _safe_env() -> dict[str, str]:
    allow = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONPATH",
        "PYTHONHASHSEED",
        "TZ",
        "CI",
        "GITHUB_ACTIONS",
        "GITHUB_BASE_REF",
        "GITHUB_EVENT_PATH",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
    }
    env = {k: v for k, v in os.environ.items() if k in allow}
    env.setdefault("PYTHONHASHSEED", "0")
    env.setdefault("TZ", "UTC")
    return env


def _secret_values() -> list[str]:
    values: set[str] = set()
    for key, value in os.environ.items():
        if len(value) < 6:
            continue
        upper = key.upper()
        if any(tok in upper for tok in ("TOKEN", "SECRET", "PASSWORD", "KEY", "AUTH")):
            values.add(value)
    return sorted(values)


def _sanitize(text: str, secrets: list[str]) -> str:
    cleaned = text.replace("\r", "")
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)
    two_group_patterns = [
        r"(Authorization:\s*Bearer\s+)(\S+)",
        r"(password\s*[=:]\s*)(\S+)",
        r"(token\s*[=:]\s*)(\S+)",
        r"(FG_API_KEY\s*[=:]\s*)(\S+)",
    ]
    for pattern in two_group_patterns:
        cleaned = re.sub(pattern, r"\1[REDACTED]", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'(\"api_key\"\s*:\s*\")(.*?)(\")', r"\1[REDACTED]\3", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'(\"token\"\s*:\s*\")(.*?)(\")', r"\1[REDACTED]\3", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\beyJ[a-zA-Z0-9._-]+\b", "[REDACTED]", cleaned)
    for secret in secrets:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _check_working_tree_clean(stage: str) -> None:
    proc = subprocess.run(
        ["git", "status", "--porcelain"], cwd=REPO_ROOT, text=True, capture_output=True, check=False, shell=False
    )
    if proc.returncode != 0:
        raise SystemExit(f"unable to verify working tree at {stage}")
    dirty = proc.stdout.strip()
    if dirty:
        sanitized = _sanitize(dirty, _secret_values())
        raise SystemExit(f"working tree mutated at {stage}:\n{sanitized}")


def _is_blocked_command(command: tuple[str, ...]) -> bool:
    if command[0] in BLOCKED_COMMANDS:
        return True
    joined = " ".join(command)
    return any(p.search(joined) for p in BLOCKED_COMMAND_PATTERNS)


def _validate_lane_commands() -> None:
    for lane in LANES:
        commands = LANE_COMMANDS.get(lane)
        if commands is None:
            raise SystemExit(f"lane missing command mapping: {lane}")
        for command in commands:
            if not command:
                raise SystemExit(f"empty command in lane={lane}")
            if _is_blocked_command(command):
                raise SystemExit(f"blocked command in lane={lane}: {' '.join(command)}")


def _append_capped_log(log_file: Path, content: str) -> None:
    current = log_file.stat().st_size if log_file.exists() else 0
    if current >= MAX_LOG_BYTES:
        return
    remaining = MAX_LOG_BYTES - current
    payload = content.encode("utf-8")
    if len(payload) > remaining:
        truncated = payload[:remaining].decode("utf-8", errors="ignore")
        payload = (truncated + "\n[truncated: max log size reached]\n").encode("utf-8")
    with log_file.open("ab") as handle:
        handle.write(payload)


def _write_lane_triage(lane_dir: Path, log_file: Path) -> Path:
    lines = []
    if log_file.exists():
        lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    triage = _classify(lines)
    triage_path = lane_dir / "lane.triage.json"
    _write_json(triage_path, triage)
    return triage_path


def _run_lane(lane: str, lane_timeout: int, remaining_budget: int, secrets: list[str], dry_run: bool) -> LaneResult:
    started = time.monotonic()
    lane_dir = ARTIFACT_ROOT / "lanes" / lane
    lane_dir.mkdir(parents=True, exist_ok=True)
    log_file = lane_dir / "lane.log"

    if dry_run:
        _append_capped_log(log_file, "[dry-run] commands skipped\n")
        triage_path = _write_lane_triage(lane_dir, log_file)
        return LaneResult(lane=lane, status="passed", duration_seconds=0, timeout=False, artifact_paths={"lane_log": str(log_file), "lane_triage": str(triage_path)})

    for command in LANE_COMMANDS[lane]:
        timeout = min(lane_timeout, remaining_budget)
        if timeout <= 0:
            _append_capped_log(log_file, "[budget-exhausted]\n")
            triage_path = _write_lane_triage(lane_dir, log_file)
            return LaneResult(lane=lane, status="failed", duration_seconds=int(time.monotonic() - started), timeout=True, error="global_budget_exhausted", artifact_paths={"lane_log": str(log_file), "lane_triage": str(triage_path)})
        try:
            env = _safe_env()
            addopts = pytest_addopts_for_lane(lane)
            if addopts:
                existing = env.get("PYTEST_ADDOPTS", "").strip()
                env["PYTEST_ADDOPTS"] = f"{existing} {addopts}".strip()
            proc = subprocess.run(
                list(command),
                cwd=REPO_ROOT,
                env=env,
                check=False,
                shell=False,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            _append_capped_log(log_file, f"$ {' '.join(command)}\n[timeout]\n")
            triage_path = _write_lane_triage(lane_dir, log_file)
            return LaneResult(lane=lane, status="failed", duration_seconds=int(time.monotonic() - started), timeout=True, error="lane_timeout", artifact_paths={"lane_log": str(log_file), "lane_triage": str(triage_path)})

        _append_capped_log(log_file, f"$ {' '.join(command)}\n")
        if proc.stdout:
            _append_capped_log(log_file, _sanitize(proc.stdout, secrets) + "\n")
        if proc.stderr:
            _append_capped_log(log_file, _sanitize(proc.stderr, secrets) + "\n")

        if proc.returncode != 0:
            triage_path = _write_lane_triage(lane_dir, log_file)
            return LaneResult(lane=lane, status="failed", duration_seconds=int(time.monotonic() - started), timeout=False, error=f"exit_{proc.returncode}", artifact_paths={"lane_log": str(log_file), "lane_triage": str(triage_path)})

    triage_path = _write_lane_triage(lane_dir, log_file)
    return LaneResult(lane=lane, status="passed", duration_seconds=int(time.monotonic() - started), timeout=False, artifact_paths={"lane_log": str(log_file), "lane_triage": str(triage_path)})


def _write_lane_reports(results: list[LaneResult]) -> tuple[dict[str, str], list[str]]:
    report_specs = {
        "required-tests-gate": "required-tests-gate.json",
        "fg-contract": "contract-drift.json",
        "fg-security": "security-invariants.json",
    }
    hashes: dict[str, str] = {}
    generated: list[str] = []
    for lane, report_name in report_specs.items():
        if not any(r.lane == lane for r in results):
            continue
        payload = {"lane": lane, "status": next((r.status for r in results if r.lane == lane), "failed")}
        path = ARTIFACT_ROOT / report_name
        _write_json(path, payload)
        hashes[report_name] = _sha256(path)
        generated.append(report_name)
    return hashes, generated


def _write_summary(results: list[LaneResult], overall_status: str, budget_seconds: int, elapsed_seconds: int, artifact_hashes: dict[str, str]) -> None:
    payload = {
        "artifact_hashes": artifact_hashes,
        "budget_seconds": budget_seconds,
        "elapsed_seconds": elapsed_seconds,
        "lanes": [
            {
                "artifact_paths": r.artifact_paths or {},
                "duration_seconds": r.duration_seconds,
                "error": r.error,
                "name": r.lane,
                "status": r.status,
                "timeout": r.timeout,
            }
            for r in results
        ],
        "overall_status": overall_status,
    }
    _write_json(ARTIFACT_ROOT / "fg-required-summary.json", payload)

    lines = [
        "# fg-required summary",
        "",
        f"- overall_status: {overall_status}",
        f"- budget_seconds: {budget_seconds}",
        f"- elapsed_seconds: {elapsed_seconds}",
        "",
        "## lanes",
    ]
    for lane in payload["lanes"]:
        suffix = f" - {lane['error']}" if lane["error"] else ""
        lines.append(f"- {lane['name']}: {lane['status']} ({lane['duration_seconds']}s){suffix}")
    (ARTIFACT_ROOT / "fg-required-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _verify_required_files(results: list[LaneResult], generated_reports: list[str], strict: bool) -> None:
    if not strict:
        return
    required = set(ALWAYS_REQUIRED_FILES)
    required.update(generated_reports)
    for result in results:
        if result.artifact_paths is None:
            raise SystemExit(f"missing lane artifacts metadata for lane={result.lane}")
        required.add(Path(result.artifact_paths["lane_log"]).relative_to(ARTIFACT_ROOT).as_posix())
        required.add(Path(result.artifact_paths["lane_triage"]).relative_to(ARTIFACT_ROOT).as_posix())
    missing = [name for name in sorted(required) if not (ARTIFACT_ROOT / name).exists()]
    if missing:
        raise SystemExit(f"missing required artifacts: {','.join(missing)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run fg-required deterministic hard gate")
    parser.add_argument("--global-budget-seconds", type=int, default=GLOBAL_BUDGET_SECONDS)
    parser.add_argument("--lane-timeout-seconds", type=int, default=DEFAULT_LANE_TIMEOUT_SECONDS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--strict", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()

    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    if args.strict:
        _check_working_tree_clean("start")
    _validate_lane_commands()

    started = time.monotonic()
    secrets = _secret_values()
    results: list[LaneResult] = []
    overall_status = "passed"

    for lane in LANES:
        elapsed = int(time.monotonic() - started)
        remaining = args.global_budget_seconds - elapsed - BUDGET_SAFETY_MARGIN_SECONDS
        lane_timeout = min(args.lane_timeout_seconds, remaining)
        if remaining <= 0:
            lane_dir = ARTIFACT_ROOT / "lanes" / lane
            lane_dir.mkdir(parents=True, exist_ok=True)
            log_path = lane_dir / "lane.log"
            _append_capped_log(log_path, "[global budget exceeded before lane start]\n")
            _append_capped_log(
                log_path,
                f"[budget] elapsed={elapsed}s remaining={remaining}s next_lane={lane} recommendation=optimize lane runtime or move deep checks to fg-full\n",
            )
            triage_path = _write_lane_triage(lane_dir, log_path)
            results.append(
                LaneResult(
                    lane=lane,
                    status="failed",
                    duration_seconds=0,
                    timeout=True,
                    error="global_budget_exceeded",
                    artifact_paths={"lane_log": str(log_path), "lane_triage": str(triage_path)},
                )
            )
            overall_status = "failed"
            break

        lane_result = _run_lane(lane=lane, lane_timeout=lane_timeout, remaining_budget=remaining, secrets=secrets, dry_run=args.dry_run)
        results.append(lane_result)
        if lane_result.status != "passed":
            overall_status = "failed"
            break
        if args.strict:
            _check_working_tree_clean(f"after-lane:{lane}")

    elapsed_seconds = int(time.monotonic() - started)
    hashes, generated_reports = _write_lane_reports(results)
    _write_summary(results, overall_status, args.global_budget_seconds, elapsed_seconds, hashes)
    _verify_required_files(results, generated_reports, strict=args.strict)
    return 0 if overall_status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
