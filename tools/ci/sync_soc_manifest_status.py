from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST_PATH = REPO_ROOT / "tools/ci/soc_findings_manifest.json"
DEFAULT_TIMEOUT_SECONDS = 180
DEFAULT_TAIL_LINES = 60
DEFAULT_JOBS = 1

NON_FINAL_STATUSES = {"open", "todo", "partial", "unknown"}


@dataclass(frozen=True)
class FindingRef:
    index: int
    finding_id: str


@dataclass(frozen=True)
class GateResult:
    gate: str
    ok: bool
    return_code: int
    output: str
    timed_out: bool


class ManifestValidationError(ValueError):
    pass


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sync_soc_manifest_status.py",
        description="Verify or sync SOC findings manifest statuses from gate/evidence state.",
    )
    parser.add_argument(
        "--mode",
        choices=("verify", "sync"),
        default="verify",
        help="verify checks manifest and exits non-zero on unresolved issues; sync updates eligible statuses.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help=f"Path to findings manifest (default: {DEFAULT_MANIFEST_PATH}).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-gate timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--tail-lines",
        type=int,
        default=DEFAULT_TAIL_LINES,
        help=f"Failure output lines to print from each gate (default: {DEFAULT_TAIL_LINES}).",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=DEFAULT_JOBS,
        help=f"Parallel gate jobs (default: {DEFAULT_JOBS}).",
    )
    parser.add_argument(
        "--fail-on-unresolved-p0",
        action="store_true",
        help="Fail when non-final P0 findings remain (verify mode already enforces this; useful to make sync strict).",
    )
    return parser.parse_args(argv)


def load_manifest(path: Path) -> tuple[Any, bool]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ManifestValidationError(f"manifest file not found: {path}") from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ManifestValidationError(f"invalid JSON: {path} ({exc})") from exc

    return payload, raw_text.endswith("\n")


def normalize_manifest(payload: Any) -> tuple[list[dict[str, Any]], bool]:
    if isinstance(payload, dict):
        findings = payload.get("findings")
        if not isinstance(findings, list):
            raise ManifestValidationError(
                "manifest object must include 'findings' as a list"
            )
        return findings, False

    if isinstance(payload, list):
        return payload, True

    raise ManifestValidationError(
        "manifest must be either an object with 'findings' or a list"
    )


def normalize_string(value: Any) -> str:
    return str(value).strip().lower()


def validate_finding(finding: dict[str, Any], index: int) -> None:
    finding_id = finding.get("id")
    label = (
        finding_id if isinstance(finding_id, str) and finding_id else f"index {index}"
    )

    def fail(field: str, message: str) -> None:
        raise ManifestValidationError(f"finding {label}: field '{field}' {message}")

    if not isinstance(finding_id, str) or not finding_id.strip():
        fail("id", "must be a non-empty string")

    severity = finding.get("severity")
    if not isinstance(severity, str) or not severity.strip():
        fail("severity", "must be a non-empty string")

    status = finding.get("status")
    if not isinstance(status, str) or not status.strip():
        fail("status", "must be a non-empty string")

    gate = finding.get("gate")
    if not isinstance(gate, str):
        fail("gate", "must be a string (empty string allowed)")

    evidence = finding.get("evidence")
    if not isinstance(evidence, list):
        fail("evidence", "must be a list of strings")
    for idx, item in enumerate(evidence):
        if not isinstance(item, str):
            fail("evidence", f"item {idx} must be a string")


def validate_manifest(findings: list[dict[str, Any]]) -> None:
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ManifestValidationError(f"finding index {index}: must be an object")
        validate_finding(finding, index)


def evidence_missing_paths(finding: dict[str, Any], repo_root: Path) -> list[str]:
    missing: list[str] = []
    for path_text in finding["evidence"]:
        candidate = repo_root / path_text
        if not candidate.exists():
            missing.append(path_text)
    return missing


def tail_lines(text: str, count: int) -> str:
    if count <= 0:
        return ""
    parts = text.splitlines()
    if len(parts) <= count:
        return text
    return "\n".join(parts[-count:])


def run_gate(gate: str, timeout: int, tail_count: int, repo_root: Path) -> GateResult:
    env = dict(os.environ)
    env.setdefault("PYTHONHASHSEED", "0")
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("LC_ALL", "C")
    env.setdefault("LANG", "C")
    try:
        proc = subprocess.run(
            ["make", gate],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        output = tail_lines(f"{stdout}{stderr}".strip(), tail_count)
        return GateResult(
            gate=gate,
            ok=False,
            return_code=124,
            output=output,
            timed_out=True,
        )

    combined = f"{proc.stdout or ''}{proc.stderr or ''}".strip()
    return GateResult(
        gate=gate,
        ok=proc.returncode == 0,
        return_code=proc.returncode,
        output=tail_lines(combined, tail_count),
        timed_out=False,
    )


def run_gates(
    gates: list[str],
    *,
    jobs: int,
    timeout: int,
    tail_count: int,
    repo_root: Path,
) -> dict[str, GateResult]:
    if not gates:
        return {}

    if jobs <= 1 or len(gates) == 1:
        return {
            gate: run_gate(
                gate, timeout=timeout, tail_count=tail_count, repo_root=repo_root
            )
            for gate in gates
        }

    results: dict[str, GateResult] = {}
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures: dict[Future[GateResult], str] = {
            executor.submit(
                run_gate,
                gate,
                timeout,
                tail_count,
                repo_root,
            ): gate
            for gate in gates
        }
        for future in as_completed(futures):
            gate = futures[future]
            results[gate] = future.result()

    return results


def write_manifest_atomic(path: Path, payload: Any, trailing_newline: bool) -> None:
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    if trailing_newline:
        encoded += "\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(tmp_path, path)


def manifest_with_updates(original_payload: Any, findings: list[dict[str, Any]]) -> Any:
    if isinstance(original_payload, dict):
        updated = dict(original_payload)
        updated["findings"] = findings
        return updated
    return findings


def finding_id(finding: dict[str, Any], index: int) -> str:
    value = finding.get("id")
    if isinstance(value, str) and value:
        return value
    return f"index-{index}"


def execute(argv: list[str], *, repo_root: Path = REPO_ROOT) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        return 2 if code != 0 else 0

    if args.timeout <= 0:
        print("usage/config error: --timeout must be > 0", file=sys.stderr)
        return 2
    if args.jobs <= 0:
        print("usage/config error: --jobs must be > 0", file=sys.stderr)
        return 2
    if args.tail_lines < 0:
        print("usage/config error: --tail-lines must be >= 0", file=sys.stderr)
        return 2

    started = time.perf_counter()
    updated_count = 0
    gates_executed = 0

    try:
        manifest_payload, trailing_newline = load_manifest(args.manifest)
        findings, _ = normalize_manifest(manifest_payload)
        validate_manifest(findings)
    except ManifestValidationError as exc:
        elapsed = time.perf_counter() - started
        print(f"ERROR: {exc}")
        print(
            f"SUMMARY mode={args.mode} updated=0 gates_executed=0 elapsed={elapsed:.2f}s"
        )
        return 2

    ordered_indices = sorted(
        range(len(findings)),
        key=lambda idx: finding_id(findings[idx], idx),
    )

    missing_evidence: dict[str, list[str]] = {}
    gate_to_refs: dict[str, list[FindingRef]] = {}

    for idx in ordered_indices:
        finding = findings[idx]
        fid = finding_id(finding, idx)
        missing = evidence_missing_paths(finding, repo_root)
        if missing:
            missing_evidence[fid] = missing
        gate_name = finding["gate"].strip()
        if gate_name:
            gate_to_refs.setdefault(gate_name, []).append(
                FindingRef(index=idx, finding_id=fid)
            )

    gates = sorted(gate_to_refs)
    gate_results = run_gates(
        gates,
        jobs=args.jobs,
        timeout=args.timeout,
        tail_count=args.tail_lines,
        repo_root=repo_root,
    )
    gates_executed = len(gate_results)

    gate_failures: dict[str, list[str]] = {}
    for gate in gates:
        result = gate_results[gate]
        refs = gate_to_refs[gate]
        if not result.ok:
            gate_failures[gate] = sorted(ref.finding_id for ref in refs)
            continue

        if args.mode != "sync":
            continue

        for ref in refs:
            finding = findings[ref.index]
            if missing_evidence.get(ref.finding_id):
                continue
            status_before = normalize_string(finding["status"])
            if status_before in NON_FINAL_STATUSES:
                finding["status"] = "mitigated"
                updated_count += 1

    unresolved_p0s: list[str] = []
    for idx in ordered_indices:
        finding = findings[idx]
        if normalize_string(finding["severity"]) != "p0":
            continue
        status_value = normalize_string(finding["status"])
        if status_value in NON_FINAL_STATUSES:
            unresolved_p0s.append(
                f"{finding_id(finding, idx)} (gate={finding['gate'] or '<none>'}, status={finding['status']})"
            )

    verify_failed = bool(missing_evidence or gate_failures)
    enforce_unresolved_p0 = args.mode == "verify" or args.fail_on_unresolved_p0
    if enforce_unresolved_p0:
        verify_failed = verify_failed or bool(unresolved_p0s)

    if args.mode == "sync":
        updated_payload = manifest_with_updates(manifest_payload, findings)
        original_json = json.dumps(manifest_payload, indent=2, sort_keys=True)
        updated_json = json.dumps(updated_payload, indent=2, sort_keys=True)
        if updated_json != original_json:
            write_manifest_atomic(args.manifest, updated_payload, trailing_newline)

    if verify_failed:
        if missing_evidence:
            print("Missing evidence:")
            for fid in sorted(missing_evidence):
                missing_paths = ", ".join(sorted(missing_evidence[fid]))
                print(f"  - {fid}: {missing_paths}")

        if gate_failures:
            print("Gate failures:")
            for gate in sorted(gate_failures):
                result = gate_results[gate]
                reason = "timeout" if result.timed_out else f"rc={result.return_code}"
                ids = ", ".join(gate_failures[gate])
                print(f"  - {gate} ({reason}) -> {ids}")
                if result.output:
                    print(f"    tail ({args.tail_lines} lines):")
                    for line in result.output.splitlines():
                        print(f"      {line}")

        if unresolved_p0s:
            print("Unresolved P0s:")
            for item in unresolved_p0s:
                print(f"  - {item}")

    elapsed = time.perf_counter() - started
    print(
        f"SUMMARY mode={args.mode} updated={updated_count} gates_executed={gates_executed} elapsed={elapsed:.2f}s"
    )

    return 1 if verify_failed else 0


def main(argv: list[str] | None = None) -> int:
    return execute(argv if argv is not None else sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
