#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from api.config.prod_invariants import ProdInvariantViolation, assert_prod_invariants
from scripts.prod_profile_check import ProductionProfileChecker

REPO = Path(__file__).resolve().parents[2]

ALLOWED_REDIRECT_FILES = {
    "api/security_alerts.py",
    "api/tripwires.py",
}
VALID_STATUSES = {"open", "partial", "mitigated"}
SOC_ID_PATTERN = re.compile(r"SOC-(P0|P1|HIGH)-\d{3}")
EXCLUDED_PATH_SEGMENTS = {
    ".venv",
    "site-packages",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    "dist",
    "build",
}


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _is_excluded_path(path: Path) -> bool:
    return any(segment in EXCLUDED_PATH_SEGMENTS for segment in path.parts)


def _git_ls_files_under(prefixes: tuple[str, ...]) -> list[Path]:
    cmd = ["git", "ls-files", "--", *prefixes]
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return []

    files: list[Path] = []
    for raw in proc.stdout.splitlines():
        rel = raw.strip()
        if not rel.endswith(".py"):
            continue
        path = REPO / rel
        if not path.exists() or _is_excluded_path(path):
            continue
        files.append(path)
    return sorted(files)


def _iter_owned_python_files() -> list[Path]:
    tracked = _git_ls_files_under(("api", "admin_gateway"))
    if tracked:
        return tracked

    fallback: list[Path] = []
    for base in (REPO / "api", REPO / "admin_gateway"):
        if not base.exists():
            continue
        for py in base.rglob("*.py"):
            if _is_excluded_path(py):
                continue
            fallback.append(py)
    return sorted(fallback)


def _normalize_evidence(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    return []


def _check_manifest(failures: list[str]) -> dict[str, object]:
    data = json.loads(_read("tools/ci/soc_findings_manifest.json"))
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        failures.append("SOC manifest: findings must be a list")
        return {"findings": []}

    ids: set[str] = set()
    makefile_body = _read("Makefile")
    gates = {
        str(item.get("gate", ""))
        for item in findings
        if isinstance(item, dict) and item.get("gate")
    }

    for finding in findings:
        if not isinstance(finding, dict):
            failures.append("SOC manifest contains non-object finding entry")
            continue
        fid = str(finding.get("id", ""))
        status = str(finding.get("status", ""))
        gate = str(finding.get("gate", ""))
        evidence = _normalize_evidence(finding.get("evidence"))
        ids.add(fid)

        if not SOC_ID_PATTERN.fullmatch(fid):
            failures.append(f"Invalid finding id format in manifest: {fid}")
        if status not in VALID_STATUSES:
            failures.append(f"Invalid status for {fid}: {status}")
        if not gate or gate not in makefile_body:
            failures.append(f"Manifest gate for {fid} not found in Makefile: {gate}")

        if status == "mitigated":
            if not evidence:
                failures.append(f"Mitigated finding {fid} must include evidence")
                continue

            valid_evidence_link = False
            for path in evidence:
                full = REPO / path
                if not full.exists():
                    failures.append(
                        f"Mitigated finding {fid} references missing evidence file: {path}"
                    )
                    continue
                if path.startswith("tests/") or path.startswith("tools/ci/"):
                    valid_evidence_link = True
                if any(gate_name and gate_name in path for gate_name in gates):
                    valid_evidence_link = True

            if not valid_evidence_link:
                failures.append(
                    f"Mitigated finding {fid} evidence must reference at least one CI gate/test path"
                )

    for required in (
        "SOC-P0-001",
        "SOC-P0-002",
        "SOC-P0-003",
        "SOC-P0-004",
        "SOC-P0-005",
        "SOC-P0-006",
        "SOC-P0-007",
    ):
        if required not in ids:
            failures.append(f"SOC manifest missing required P0 id: {required}")

    return data


def _check_prod_profile_invariants(failures: list[str]) -> None:
    checker = ProductionProfileChecker()
    checker.check_compose_file(REPO / "docker-compose.yml")
    if checker.errors:
        for error in checker.errors:
            failures.append(f"prod-profile invariant failure: {error}")


def _check_runtime_enforcement_mode(failures: list[str]) -> None:
    for env_name in ("prod", "staging"):
        valid = {
            "FG_ENV": env_name,
            "FG_AUTH_ENABLED": "1",
            "FG_DB_URL": "postgresql://example",
            "FG_DB_BACKEND": "postgres",
            "FG_ENFORCEMENT_MODE": "enforce",
        }
        try:
            assert_prod_invariants(valid)
        except Exception as exc:  # noqa: BLE001
            failures.append(
                f"runtime invariant unexpectedly failed for {env_name}/enforce: {exc}"
            )

        invalid = dict(valid)
        invalid["FG_ENFORCEMENT_MODE"] = "observe"
        try:
            assert_prod_invariants(invalid)
            failures.append(f"runtime invariant failed open for {env_name}/observe")
        except ProdInvariantViolation:
            pass


def _check_fallback_import_patterns(failures: list[str]) -> None:
    banned_patterns = [
        re.compile(r"from\s+.+fallback.+\s+import\s+", re.IGNORECASE),
        re.compile(r"import\s+.+fallback", re.IGNORECASE),
    ]
    for py in _iter_owned_python_files():
        rel = py.relative_to(REPO).as_posix()
        text = py.read_text(encoding="utf-8")
        for pat in banned_patterns:
            if pat.search(text):
                failures.append(f"{rel} imports fallback module pattern: {pat.pattern}")


def _check_redirect_clients(failures: list[str]) -> None:
    pattern = re.compile(
        r"(httpx\.(Client|AsyncClient)\([^\)]*follow_redirects\s*=\s*True|"
        r"requests\.[a-z]+\([^\)]*allow_redirects\s*=\s*True)"
    )
    for py in _iter_owned_python_files():
        rel = py.relative_to(REPO).as_posix()
        if rel in ALLOWED_REDIRECT_FILES:
            continue
        text = py.read_text(encoding="utf-8")
        if pattern.search(text):
            failures.append(
                f"{rel} uses redirect-following client without approved wrapper"
            )


def main() -> int:
    failures: list[str] = []
    _check_manifest(failures)
    _check_prod_profile_invariants(failures)
    _check_runtime_enforcement_mode(failures)
    _check_fallback_import_patterns(failures)
    _check_redirect_clients(failures)

    if failures:
        print("soc invariants: FAILED")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("soc invariants: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
