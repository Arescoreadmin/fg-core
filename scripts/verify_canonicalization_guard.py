#!/usr/bin/env python3
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET_GLOBS = [
    "services/audit_engine/**/*.py",
    "services/compliance_registry/**/*.py",
    "scripts/verify_*chain*.py",
]


def _iter_target_files() -> list[Path]:
    files: set[Path] = set()
    for glob in TARGET_GLOBS:
        for p in ROOT.glob(glob):
            if p.is_file() and p.suffix == ".py":
                files.add(p)
    return sorted(files)


def _json_dump_calls(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    json_aliases: set[str] = set()
    dumps_aliases: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "json":
                    json_aliases.add(alias.asname or "json")
        elif isinstance(node, ast.ImportFrom) and node.module == "json":
            for alias in node.names:
                if alias.name == "dumps":
                    dumps_aliases.add(alias.asname or alias.name)

    lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.attr == "dumps" and func.value.id in json_aliases:
                lines.append(node.lineno)
        elif isinstance(func, ast.Name) and func.id in dumps_aliases:
            lines.append(node.lineno)
    return sorted(lines)


def main() -> int:
    violations: list[str] = []
    for path in _iter_target_files():
        rel = path.relative_to(ROOT).as_posix()
        for line in _json_dump_calls(path):
            violations.append(
                f"{rel}:{line}: direct json.dumps in signed/chain-sensitive path; use services.canonical.canonical_json_bytes"
            )

    if violations:
        print("❌ canonicalization guard failed")
        for violation in violations:
            print(violation)
        return 1

    print(
        "✅ canonicalization guard: direct json.dumps disallowed in signed/chain-sensitive paths"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
