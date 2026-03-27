#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SAFE_TARGETS = [
    "api/admin.py",
    "api/config_control.py",
    "api/key_rotation.py",
    "api/middleware/dos_guard.py",
    "api/dev_events.py",
    "api/decisions.py",
    "api/ingest.py",
    "api/keys.py",
    "api/ui_dashboards.py",
    "api/control_plane_v2.py",
]

# Files intentionally excluded because blind conversion is risky.
SKIP_TARGETS = [
    "api/security_audit.py",
    "api/security_alerts.py",
    "api/auth_scopes/definitions.py",
    "api/auth_scopes/mapping.py",
    "api/auth_scopes/resolution.py",
    "api/auth_scopes/validation.py",
    "api/tenant_usage.py",
    "api/token_useage.py",
]

OPTIONAL_TYPE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # tenant_id: Optional[str] = None,  -> tenant_id: str,
    (
        re.compile(
            r"(?P<indent>\s*)tenant_id:\s*Optional\[str\]\s*=\s*None(?P<tail>\s*,?)"
        ),
        r"\g<indent>tenant_id: str\g<tail>",
    ),
    # tenant_id: Optional[str], -> tenant_id: str,
    (
        re.compile(r"(?P<indent>\s*)tenant_id:\s*Optional\[str\](?P<tail>\s*,?)"),
        r"\g<indent>tenant_id: str\g<tail>",
    ),
    # x_tenant_id: Optional[str] = None, -> x_tenant_id: str,
    (
        re.compile(
            r"(?P<indent>\s*)x_tenant_id:\s*Optional\[str\]\s*=\s*None(?P<tail>\s*,?)"
        ),
        r"\g<indent>x_tenant_id: str\g<tail>",
    ),
    # x_tenant_id: Optional[str], -> x_tenant_id: str,
    (
        re.compile(r"(?P<indent>\s*)x_tenant_id:\s*Optional\[str\](?P<tail>\s*,?)"),
        r"\g<indent>x_tenant_id: str\g<tail>",
    ),
]

HELPER_SIGNATURE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"def _resolve_tenant\((?P<prefix>[^)]*?),\s*tenant_id:\s*Optional\[str\]\) -> str:"
        ),
        r"def _resolve_tenant(\g<prefix>, tenant_id: str) -> str:",
    ),
    (
        re.compile(
            r"def _rl_key\(\s*tenant_id:\s*Optional\[str\],\s*endpoint:\s*str\s*\)\s*->\s*str:"
        ),
        r"def _rl_key(tenant_id: str, endpoint: str) -> str:",
    ),
]


@dataclass
class FileResult:
    path: str
    changed: bool
    replacements: int


def process_text(text: str) -> tuple[str, int]:
    replacements = 0
    updated = text

    for pattern, repl in OPTIONAL_TYPE_PATTERNS:
        updated, n = pattern.subn(repl, updated)
        replacements += n

    for pattern, repl in HELPER_SIGNATURE_PATTERNS:
        updated, n = pattern.subn(repl, updated)
        replacements += n

    return updated, replacements


def process_file(path: Path, apply: bool) -> FileResult:
    original = path.read_text(encoding="utf-8")
    updated, replacements = process_text(original)
    changed = updated != original

    if changed and apply:
        path.write_text(updated, encoding="utf-8")

    return FileResult(
        path=str(path.relative_to(ROOT)),
        changed=changed,
        replacements=replacements,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Tenant hardening codemod v2")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes to disk. Default is dry-run.",
    )
    args = parser.parse_args()

    print("SAFE_TARGETS:")
    for p in SAFE_TARGETS:
        print(f"- {p}")

    print("\nSKIP_TARGETS:")
    for p in SKIP_TARGETS:
        print(f"- {p}")

    results: list[FileResult] = []
    for rel in SAFE_TARGETS:
        path = ROOT / rel
        if not path.exists():
            print(f"SKIP missing {rel}")
            continue
        results.append(process_file(path, apply=args.apply))

    changed_files = [r for r in results if r.changed]
    total_replacements = sum(r.replacements for r in results)

    print("\nRESULTS:")
    for r in results:
        status = "UPDATED" if r.changed else "UNCHANGED"
        print(f"{status} {r.path} replacements={r.replacements}")

    print(f"\nFILES_CHANGED={len(changed_files)}")
    print(f"TOTAL_REPLACEMENTS={total_replacements}")
    print(f"MODE={'APPLY' if args.apply else 'DRY_RUN'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
