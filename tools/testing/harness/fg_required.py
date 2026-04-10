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

# Uses repo’s classifier (requested). Fallback is intentionally conservative.
try:
    from tools.testing.harness.triage_report import _classify  # noqa: E402
    from tools.testing.harness.quarantine_policy import pytest_addopts_for_lane  # noqa: E402
except Exception:  # pragma: no cover

    def _classify(lines: list[str], lane: str = "unknown") -> dict[str, Any]:  # type: ignore[misc]
        text = "\n".join(lines[-200:])
        return {
            "classifier": "fallback",
            "summary": "triage_report._classify import failed",
            "tail": text,
        }

    def pytest_addopts_for_lane(lane: str) -> str:
        # Conservative fallback: no extra pytest options.
        return ""


from tools.testing.harness.quarantine_policy import pytest_addopts_for_lane  # noqa: E402

# Put artifacts where humans actually look.
ARTIFACT_ROOT = REPO_ROOT / "artifacts" / "fg-required"

DEFAULT_GLOBAL_BUDGET_SECONDS = 2800
DEFAULT_LANE_TIMEOUT_SECONDS = 2800
BUDGET_SAFETY_MARGIN_SECONDS = 10
MAX_LOG_BYTES = 2 * 1024 * 1024

LANES: tuple[str, ...] = (
    "policy-validate",
    "required-tests-gate",
    "fg-fast",
    "fg-contract",
    "fg-security",
)

# Always prefer venv python (sys.executable) for repo scripts.
PY = sys.executable

LANE_COMMANDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "policy-validate": (("make", "policy-validate"),),
    "required-tests-gate": (("make", "required-tests-gate"),),
    "fg-fast": (("make", "fg-fast"),),
    "fg-contract": (
        ("make", "fg-contract"),
        (PY, "tools/testing/contracts/check_contract_drift.py"),
    ),
    "fg-security": (
        ("make", "fg-security"),
        (PY, "tools/testing/security/check_security_invariants.py"),
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

# Keep secrets out of logs.
REDACT_PATTERNS_2G = [
    r"(Authorization:\s*Bearer\s+)(\S+)",
    r"(password\s*[=:]\s*)(\S+)",
    r"(token\s*[=:]\s*)(\S+)",
    r"(FG_API_KEY\s*[=:]\s*)(\S+)",
]
REDACT_JSON_KV = [
    r"(\"api_key\"\s*:\s*\")(.*?)(\")",
    r"(\"token\"\s*:\s*\")(.*?)(\")",
]


@dataclass(frozen=True)
class LaneResult:
    lane: str
    status: str  # "passed"|"failed"
    duration_seconds: int
    timeout: bool
    error: str | None = None
    artifact_paths: dict[str, str] | None = None


def _safe_env() -> dict[str, str]:
    """
    Deterministic but not suicidal: preserve routing/proxy/pip vars so CI runners
    in locked networks don’t randomly fail.
    """
    allow_exact = {
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
        # Tooling / networking in restricted runners:
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PIP_TRUSTED_HOST",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
    }

    env = {k: v for k, v in os.environ.items() if k in allow_exact}

    # Determinism defaults.
    env.setdefault("PYTHONHASHSEED", "0")
    env.setdefault("TZ", "UTC")

    # Make sure repo modules resolve (without depending on caller shell).
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


def _secret_values() -> list[str]:
    values: set[str] = set()
    for key, value in os.environ.items():
        if not value or len(value) < 6:
            continue
        upper = key.upper()
        if any(tok in upper for tok in ("TOKEN", "SECRET", "PASSWORD", "KEY", "AUTH")):
            values.add(value)
    return sorted(values)


def _sanitize(text: str, secrets: list[str]) -> str:
    cleaned = text.replace("\r", "")
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)
    for pattern in REDACT_PATTERNS_2G:
        cleaned = re.sub(pattern, r"\1[REDACTED]", cleaned, flags=re.IGNORECASE)
    for pattern in REDACT_JSON_KV:
        cleaned = re.sub(pattern, r"\1[REDACTED]\3", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\beyJ[a-zA-Z0-9._-]+\b", "[REDACTED]", cleaned)  # JWT-ish
    for secret in secrets:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _write_json(path: Path, payload: Any) -> None:
    _atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dirty_paths() -> list[str]:
    proc = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit("unable to verify working tree")
    lines = [line.rstrip("\n") for line in proc.stdout.splitlines() if line.strip()]
    paths: list[str] = []
    for line in lines:
        entry = line[3:] if len(line) >= 4 else line
        if " -> " in entry:
            entry = entry.split(" -> ", 1)[1]
        paths.append(entry.strip())
    return paths


def _print_dirty_diagnostics(paths: list[str]) -> None:
    print("\n---- GIT STATUS ----", flush=True)
    subprocess.run(["git", "status", "--short"], cwd=REPO_ROOT, check=False)

    focus = "artifacts/platform_inventory.det.json"
    if focus in paths:
        print("\n---- DIFF platform_inventory.det.json ----", flush=True)
        subprocess.run(
            ["git", "diff", "--", focus],
            cwd=REPO_ROOT,
            check=False,
        )

        print("\n---- SHA platform_inventory.det.json ----", flush=True)
        subprocess.run(
            ["sha256sum", focus],
            cwd=REPO_ROOT,
            check=False,
        )

        print("\n---- INPUT SHAS ----", flush=True)
        subprocess.run(
            [
                "sha256sum",
                "tools/ci/plane_registry_snapshot.json",
                "tools/ci/route_inventory.json",
                "tools/ci/contract_routes.json",
                "tools/ci/topology.sha256",
            ],
            cwd=REPO_ROOT,
            check=False,
        )


def _attempt_platform_inventory_self_heal(stage: str, paths: list[str]) -> bool:
    target = "artifacts/platform_inventory.det.json"
    if stage != "after-lane:fg-fast":
        return False
    if paths != [target]:
        return False

    env = _safe_env()
    proc = subprocess.run(
        [PY, "scripts/generate_platform_inventory.py", "--allow-gaps"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n", flush=True)
    if proc.stderr:
        print(proc.stderr, end="" if proc.stderr.endswith("\n") else "\n", flush=True)

    healed_paths = _dirty_paths()
    return not healed_paths


def _check_working_tree_clean(stage: str) -> None:
    paths = _dirty_paths()
    if not paths:
        return

    if _attempt_platform_inventory_self_heal(stage, paths):
        print(
            f"[fg-required] self-healed deterministic artifact drift at {stage}",
            flush=True,
        )
        return

    _print_dirty_diagnostics(paths)
    raise SystemExit(f"working tree mutated at {stage}:\n" + "\n".join(paths))


def _is_blocked_command(command: tuple[str, ...]) -> bool:
    if not command:
        return True
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
            if _is_blocked_command(command):
                raise SystemExit(f"blocked command in lane={lane}: {' '.join(command)}")


def _append_capped_log(log_file: Path, content: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    current = log_file.stat().st_size if log_file.exists() else 0
    if current >= MAX_LOG_BYTES:
        return
    remaining = MAX_LOG_BYTES - current
    payload = content.encode("utf-8")
    if len(payload) > remaining:
        payload = payload[:remaining] + b"\n[truncated: max log size reached]\n"
    with log_file.open("ab") as handle:
        handle.write(payload)


def _write_lane_triage(lane_dir: Path, log_file: Path) -> Path:
    lines: list[str] = []
    if log_file.exists():
        lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    triage = _classify(lines)
    triage_path = lane_dir / "lane.triage.json"
    _write_json(triage_path, triage)
    return triage_path


def _run_one_command(
    lane: str,
    command: tuple[str, ...],
    timeout: int,
    secrets: list[str],
    verbose: bool,
) -> subprocess.CompletedProcess[str]:
    env = _safe_env()
    addopts = pytest_addopts_for_lane(lane)
    if addopts:
        existing = env.get("PYTEST_ADDOPTS", "").strip()
        env["PYTEST_ADDOPTS"] = f"{existing} {addopts}".strip()

    if verbose:
        print(f"[lane={lane}] $ {' '.join(command)}", flush=True)

    return subprocess.run(
        list(command),
        cwd=REPO_ROOT,
        env=env,
        check=False,
        shell=False,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _run_lane(
    lane: str,
    lane_timeout: int,
    remaining_budget: int,
    secrets: list[str],
    dry_run: bool,
    verbose: bool,
) -> LaneResult:
    started = time.monotonic()
    lane_dir = ARTIFACT_ROOT / "lanes" / lane
    lane_dir.mkdir(parents=True, exist_ok=True)
    log_file = lane_dir / "lane.log"

    if dry_run:
        _append_capped_log(log_file, "[dry-run] commands skipped\n")
        triage_path = _write_lane_triage(lane_dir, log_file)
        return LaneResult(
            lane=lane,
            status="passed",
            duration_seconds=0,
            timeout=False,
            artifact_paths={"lane_log": str(log_file), "lane_triage": str(triage_path)},
        )

    for command in LANE_COMMANDS[lane]:
        timeout = min(lane_timeout, remaining_budget)
        if timeout <= 0:
            _append_capped_log(log_file, "[budget-exhausted]\n")
            triage_path = _write_lane_triage(lane_dir, log_file)
            return LaneResult(
                lane=lane,
                status="failed",
                duration_seconds=int(time.monotonic() - started),
                timeout=True,
                error="global_budget_exhausted",
                artifact_paths={
                    "lane_log": str(log_file),
                    "lane_triage": str(triage_path),
                },
            )

        try:
            proc = _run_one_command(lane, command, timeout, secrets, verbose)
        except subprocess.TimeoutExpired:
            _append_capped_log(log_file, f"$ {' '.join(command)}\n[timeout]\n")
            triage_path = _write_lane_triage(lane_dir, log_file)
            return LaneResult(
                lane=lane,
                status="failed",
                duration_seconds=int(time.monotonic() - started),
                timeout=True,
                error="lane_timeout",
                artifact_paths={
                    "lane_log": str(log_file),
                    "lane_triage": str(triage_path),
                },
            )

        _append_capped_log(log_file, f"$ {' '.join(command)}\n")
        if proc.stdout:
            _append_capped_log(log_file, _sanitize(proc.stdout, secrets) + "\n")
        if proc.stderr:
            _append_capped_log(log_file, _sanitize(proc.stderr, secrets) + "\n")

        if proc.returncode != 0:
            triage_path = _write_lane_triage(lane_dir, log_file)
            return LaneResult(
                lane=lane,
                status="failed",
                duration_seconds=int(time.monotonic() - started),
                timeout=False,
                error=f"exit_{proc.returncode}",
                artifact_paths={
                    "lane_log": str(log_file),
                    "lane_triage": str(triage_path),
                },
            )

    triage_path = _write_lane_triage(lane_dir, log_file)
    return LaneResult(
        lane=lane,
        status="passed",
        duration_seconds=int(time.monotonic() - started),
        timeout=False,
        artifact_paths={"lane_log": str(log_file), "lane_triage": str(triage_path)},
    )


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
        payload = {
            "lane": lane,
            "status": next((r.status for r in results if r.lane == lane), "failed"),
        }
        path = ARTIFACT_ROOT / report_name
        _write_json(path, payload)
        hashes[report_name] = _sha256(path)
        generated.append(report_name)
    return hashes, generated


def _write_summary(
    results: list[LaneResult],
    overall_status: str,
    budget_seconds: int,
    elapsed_seconds: int,
    artifact_hashes: dict[str, str],
) -> None:
    lane_summaries: list[dict[str, object]] = [
        {
            "artifact_paths": r.artifact_paths or {},
            "duration_seconds": r.duration_seconds,
            "error": r.error,
            "name": r.lane,
            "status": r.status,
            "timeout": r.timeout,
        }
        for r in results
    ]
    payload = {
        "artifact_hashes": artifact_hashes,
        "budget_seconds": budget_seconds,
        "elapsed_seconds": elapsed_seconds,
        "lanes": lane_summaries,
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
    for lane in lane_summaries:
        suffix = f" - {lane['error']}" if lane["error"] else ""
        lines.append(
            f"- {lane['name']}: {lane['status']} ({lane['duration_seconds']}s){suffix}"
        )
    _atomic_write_text(
        ARTIFACT_ROOT / "fg-required-summary.md", "\n".join(lines) + "\n"
    )


def _verify_required_files(
    results: list[LaneResult], generated_reports: list[str], strict: bool
) -> None:
    if not strict:
        return
    required = set(ALWAYS_REQUIRED_FILES)
    required.update(generated_reports)
    for result in results:
        if result.artifact_paths is None:
            raise SystemExit(f"missing lane artifacts metadata for lane={result.lane}")
        required.add(
            Path(result.artifact_paths["lane_log"])
            .relative_to(ARTIFACT_ROOT)
            .as_posix()
        )
        required.add(
            Path(result.artifact_paths["lane_triage"])
            .relative_to(ARTIFACT_ROOT)
            .as_posix()
        )
    missing = [name for name in sorted(required) if not (ARTIFACT_ROOT / name).exists()]
    if missing:
        raise SystemExit(f"missing required artifacts: {','.join(missing)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run fg-required deterministic hard gate"
    )
    parser.add_argument(
        "--global-budget-seconds", type=int, default=DEFAULT_GLOBAL_BUDGET_SECONDS
    )
    parser.add_argument(
        "--lane-timeout-seconds", type=int, default=DEFAULT_LANE_TIMEOUT_SECONDS
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--strict", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument(
        "--keep-going",
        dest="keep_going",
        action="store_true",
        help="Continue running lanes after a failure",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)

    secrets = _secret_values()
    _validate_lane_commands()

    if args.strict:
        _check_working_tree_clean("start")

    started = time.monotonic()
    results: list[LaneResult] = []
    overall_status = "passed"

    try:
        for lane in LANES:
            elapsed = int(time.monotonic() - started)
            remaining = (
                args.global_budget_seconds - elapsed - BUDGET_SAFETY_MARGIN_SECONDS
            )
            lane_timeout = min(args.lane_timeout_seconds, remaining)

            if remaining <= 0:
                lane_dir = ARTIFACT_ROOT / "lanes" / lane
                lane_dir.mkdir(parents=True, exist_ok=True)
                log_path = lane_dir / "lane.log"
                _append_capped_log(
                    log_path, "[global budget exceeded before lane start]\n"
                )
                _append_capped_log(
                    log_path,
                    f"[budget] elapsed={elapsed}s remaining={remaining}s next_lane={lane}\n",
                )
                triage_path = _write_lane_triage(lane_dir, log_path)
                results.append(
                    LaneResult(
                        lane=lane,
                        status="failed",
                        duration_seconds=0,
                        timeout=True,
                        error="global_budget_exceeded",
                        artifact_paths={
                            "lane_log": str(log_path),
                            "lane_triage": str(triage_path),
                        },
                    )
                )
                overall_status = "failed"
                break

            lane_result = _run_lane(
                lane=lane,
                lane_timeout=lane_timeout,
                remaining_budget=remaining,
                secrets=secrets,
                dry_run=args.dry_run,
                verbose=args.verbose,
            )
            results.append(lane_result)

            if lane_result.status != "passed":
                overall_status = "failed"
                # Print something useful immediately.
                lp = (
                    lane_result.artifact_paths["lane_log"]
                    if lane_result.artifact_paths
                    else "<missing>"
                )
                print(
                    f"[fg-required] FAIL lane={lane} error={lane_result.error} log={lp}",
                    flush=True,
                )
                if not args.keep_going:
                    break

            if args.strict and lane_result.status == "passed":
                _check_working_tree_clean(f"after-lane:{lane}")

    finally:
        elapsed_seconds = int(time.monotonic() - started)
        hashes, generated_reports = _write_lane_reports(results)
        _write_summary(
            results, overall_status, args.global_budget_seconds, elapsed_seconds, hashes
        )
        # Verify last so summary is always present even on verify failure.
        _verify_required_files(results, generated_reports, strict=args.strict)

    return 0 if overall_status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
