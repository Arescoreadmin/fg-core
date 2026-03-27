#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Safer next-pass files only.
TARGETS = [
    "api/tenant_usage.py",
    "api/token_useage.py",
    "api/auth_scopes/validation.py",
    "api/auth_scopes/resolution.py",
    "api/auth_scopes/definitions.py",
]

# Explicitly skipped for now.
SKIP = [
    "api/security_alerts.py",
    "api/security_audit.py",
    "api/auth_scopes/mapping.py",
]

# Line-level substitutions that are relatively safe.
PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # def foo(tenant_id: Optional[str]) -> ...
    (
        re.compile(r"tenant_id:\s*Optional\[str\](?=\s*[),])"),
        "tenant_id: str",
    ),
    # def foo(..., tenant_id: Optional[str] = None, ...)
    (
        re.compile(r"tenant_id:\s*Optional\[str\]\s*=\s*None(?=\s*[),])"),
        "tenant_id: str",
    ),
]

# Leave these alone for now.
IGNORE_LINE_PATTERNS = [
    re.compile(r"last_tenant_id:\s*Optional\[str\]\s*=\s*None"),
    re.compile(r"Optional\[str\]\s*=\s*None,\s*$"),  # broad fallback for state-like lines
]

@dataclass
class Change:
    path: str
    line_no: int
    old: str
    new: str

def should_ignore(line: str) -> bool:
    return any(p.search(line) for p in IGNORE_LINE_PATTERNS)

def process_file(path: Path, apply: bool) -> list[Change]:
    original = path.read_text(encoding="utf-8").splitlines()
    updated = list(original)
    changes: list[Change] = []

    for i, line in enumerate(original):
        if should_ignore(line):
            continue

        new_line = line
        for pattern, replacement in PATTERNS:
            new_line = pattern.sub(replacement, new_line)

        if new_line != line:
            changes.append(
                Change(
                    path=str(path.relative_to(ROOT)),
                    line_no=i + 1,
                    old=line,
                    new=new_line,
                )
            )
            updated[i] = new_line

    if apply and changes:
        path.write_text("\n".join(updated) + "\n", encoding="utf-8")

    return changes

def main() -> int:
    parser = argparse.ArgumentParser(description="Tenant hardening codemod v3")
    parser.add_argument("--apply", action="store_true", help="Write changes to disk")
    args = parser.parse_args()

    print("TARGETS:")
    for t in TARGETS:
        print(f"- {t}")

    print("\nSKIP:")
    for s in SKIP:
        print(f"- {s}")

    total_changes = 0
    files_changed = 0

    for rel in TARGETS:
        path = ROOT / rel
        if not path.exists():
            print(f"SKIP missing {rel}")
            continue

        changes = process_file(path, apply=args.apply)
        if changes:
            files_changed += 1
            print(f"\nUPDATED {rel}")
            for c in changes:
                total_changes += 1
                print(f"  L{c.line_no}:")
                print(f"    OLD: {c.old}")
                print(f"    NEW: {c.new}")
        else:
            print(f"\nUNCHANGED {rel}")

    print(f"\nFILES_CHANGED={files_changed}")
    print(f"TOTAL_CHANGES={total_changes}")
    print(f"MODE={'APPLY' if args.apply else 'DRY_RUN'}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())