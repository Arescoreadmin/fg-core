#!/usr/bin/env python3
"""BP-D-000 gate: Brand Token Enforcement Gate.

Invariant: No raw color literals in dashboard UI code.
Forbidden patterns in UI source files:
- Hex colors: #RGB, #RRGGBB, #RRGGBBAA
- rgb(), rgba()
- hsl(), hsla()

Allowed exact repo-relative exceptions:
- ui/theme.css
- brand/BRAND.json

Fail-closed behavior:
- Missing required files
- Missing or malformed align map
- Read/parse errors

Output report: artifacts/gates/bp_d_000_report.json
Exit code: 0 on pass, 1 on fail.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

GATE_ID = "BP-D-000"
EXPECTED_ALIGN_VALUE = "make bp-d-000-gate"

ALIGN_MAP_PATH = Path("tools/align_score_map.json")
THEME_PATH = Path("ui/theme.css")
BRAND_JSON_PATH = Path("brand/BRAND.json")
ALLOWLIST = {THEME_PATH.as_posix(), BRAND_JSON_PATH.as_posix()}

SCAN_DIRS = ("ui", "dashboard", "frontend")
SCAN_EXTS = {".ts", ".tsx", ".js", ".jsx", ".css", ".scss", ".sass", ".html", ".vue"}

HEX_RE = re.compile(r"(?i)#(?:[0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})\b")
RGB_RE = re.compile(r"(?i)\brgba?\s*\(")
HSL_RE = re.compile(r"(?i)\bhsla?\s*\(")


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def repo_rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def check_align_map(repo_root: Path, errors: list[str]) -> None:
    align_map = repo_root / ALIGN_MAP_PATH
    if not align_map.exists():
        errors.append(
            "Missing required file tools/align_score_map.json; add BP-D-000 mapping to make bp-d-000-gate"
        )
        return
    try:
        data = json.loads(align_map.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(
            f"Unable to parse tools/align_score_map.json: {exc}; fix JSON and set BP-D-000 mapping"
        )
        return
    actual = data.get(GATE_ID)
    if actual != EXPECTED_ALIGN_VALUE:
        errors.append(
            f"tools/align_score_map.json has {GATE_ID}={actual!r}; expected {EXPECTED_ALIGN_VALUE!r}"
        )


def gather_ui_files(repo_root: Path, errors: list[str]) -> list[Path]:
    files: list[Path] = []
    for dirname in SCAN_DIRS:
        base = repo_root / dirname
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() in SCAN_EXTS:
                rel = repo_rel(path, repo_root)
                if rel not in ALLOWLIST:
                    files.append(path)

    required = [THEME_PATH, BRAND_JSON_PATH]
    for req in required:
        if not (repo_root / req).exists():
            errors.append(
                f"Missing required file {req.as_posix()}; create it to satisfy BP-D-000 allowlist"
            )
    return files


def scan_file(
    path: Path, root: Path, findings: list[dict[str, object]], errors: list[str]
) -> None:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(
            f"Unable to read {repo_rel(path, root)}: {exc}; ensure UTF-8 readable source"
        )
        return

    rel = repo_rel(path, root)
    for line_no, line in enumerate(content.splitlines(), start=1):
        snippet = line.strip()[:200]
        for regex, finding_type in ((HEX_RE, "hex"), (RGB_RE, "rgb"), (HSL_RE, "hsl")):
            for _ in regex.finditer(line):
                findings.append(
                    {
                        "file": rel,
                        "line": line_no,
                        "type": finding_type,
                        "snippet": snippet,
                    }
                )


def run_gate(repo_root: Path | None = None) -> tuple[int, dict[str, object]]:
    root = (repo_root or Path.cwd()).resolve()
    errors: list[str] = []
    findings: list[dict[str, object]] = []

    check_align_map(root, errors)
    files = gather_ui_files(root, errors)
    for path in files:
        scan_file(path, root, findings, errors)

    checked_files = [
        ALIGN_MAP_PATH.as_posix(),
        THEME_PATH.as_posix(),
        "allowlist:ui/theme.css",
        "allowlist:brand/BRAND.json",
    ]

    passed = not errors and not findings
    report: dict[str, object] = {
        "gate_id": GATE_ID,
        "passed": passed,
        "generated_at_utc": utc_now_iso(),
        "invariant": "No raw color literals are allowed in UI source files outside the explicit allowlist.",
        "checked_files": checked_files,
        "files_scanned": [repo_rel(p, root) for p in files],
        "findings": findings,
        "errors": errors,
    }

    out = root / "artifacts" / "gates" / "bp_d_000_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if passed:
        print(f"{GATE_ID}: PASS ({len(files)} files scanned)")
        return 0, report

    print(
        f"{GATE_ID}: FAIL ({len(findings)} findings, {len(errors)} errors). "
        f"See {out.as_posix()}"
    )
    return 1, report


def main() -> int:
    code, _ = run_gate()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
