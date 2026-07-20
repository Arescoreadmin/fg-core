"""CI gate: only api/credential_authority.py may write tenant_credentials or credential_slots.

Scans all Python source files (excluding migration files and the authority module itself)
for direct INSERT or UPDATE statements targeting these tables.  Exits non-zero if any
violation is found.

Allows:
  - api/credential_authority.py  — the one authority
  - migrations/postgres/*.sql    — schema bootstrap only, never in Python
  - tests/*                      — test-only DB setup helpers (fixture schema DDL)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

_AUTHORITY_MODULE = REPO / "api" / "credential_authority.py"

# Tables that only the authority module may mutate.
_PROTECTED_TABLES = frozenset({"tenant_credentials", "credential_slots"})

# Matches INSERT INTO <table> or UPDATE <table> in a Python string literal or SQL call.
# We look for the table name anywhere in the source line — false-positives are reviewed
# manually if the gate fires.
_WRITE_PATTERN = re.compile(
    r"""(?ix)
    \b(?:INSERT\s+INTO|UPDATE)\s+
    (?P<table>tenant_credentials|credential_slots)
    \b
    """,
)

# Directories and file-name patterns whose Python files may contain these strings.
_ALLOWED_PATHS: tuple[Path, ...] = (
    _AUTHORITY_MODULE,
)

_ALLOWED_PATH_PREFIXES: tuple[str, ...] = (
    "tests/",           # fixture schema helpers (DDL, not DML mutations)
    "migrations/",      # SQL files — not scanned (Python only)
)


def _is_allowed(path: Path) -> bool:
    if path == _AUTHORITY_MODULE:
        return True
    rel = path.relative_to(REPO).as_posix()
    return any(rel.startswith(p) for p in _ALLOWED_PATH_PREFIXES)


def main() -> int:
    violations: list[str] = []

    for py_file in sorted(REPO.rglob("*.py")):
        if _is_allowed(py_file):
            continue
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for lineno, line in enumerate(source.splitlines(), start=1):
            m = _WRITE_PATTERN.search(line)
            if m:
                rel = py_file.relative_to(REPO)
                violations.append(
                    f"  {rel}:{lineno}: direct write to {m.group('table')!r}\n"
                    f"    {line.strip()}"
                )

    if violations:
        print(
            "❌ check-credential-authority: direct writes to protected tables "
            "detected outside api/credential_authority.py\n",
            file=sys.stderr,
        )
        for v in violations:
            print(v, file=sys.stderr)
        print(
            "\nOnly api/credential_authority.py may INSERT or UPDATE "
            "tenant_credentials or credential_slots.",
            file=sys.stderr,
        )
        return 1

    table_list = ", ".join(sorted(_PROTECTED_TABLES))
    print(f"✓ check-credential-authority: {table_list} — write authority verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
