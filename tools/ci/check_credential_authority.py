"""CI gate: only api/credential_authority.py may write to credential tables.

Scans all Python source files (excluding migration files and the authority module itself)
for direct INSERT or UPDATE statements targeting these tables.  Exits non-zero if any
violation is found.

Also asserts (R4.4) that api/credential_authority.py imports TenantRepository — the
canonical lifecycle source — so a future refactor cannot silently drop it.

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
_PROTECTED_TABLES = frozenset(
    {"tenant_credentials", "credential_slots", "tenant_credential_events"}
)

# Matches INSERT INTO <table> or UPDATE <table> in a Python string literal or SQL call.
# We look for the table name anywhere in the source line — false-positives are reviewed
# manually if the gate fires.
_WRITE_PATTERN = re.compile(
    r"""(?ix)
    \b(?:INSERT\s+INTO|UPDATE)\s+
    (?P<table>tenant_credentials|credential_slots|tenant_credential_events)
    \b
    """,
)

# Directories and file-name patterns whose Python files may contain these strings.
_ALLOWED_PATHS: tuple[Path, ...] = (_AUTHORITY_MODULE,)

_ALLOWED_PATH_PREFIXES: tuple[str, ...] = (
    "tests/",  # fixture schema helpers (DDL, not DML mutations)
    "migrations/",  # SQL files — not scanned (Python only)
    ".claude/",  # local dev worktrees — not present in CI
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

    # R4.4: positive assertion — TenantRepository must be the lifecycle source.
    authority_source = _AUTHORITY_MODULE.read_text(encoding="utf-8")
    if "from api.tenant_repository import TenantRepository" not in authority_source:
        print(
            "❌ check-credential-authority: api/credential_authority.py does not import "
            "TenantRepository.\n"
            "  Tenant lifecycle state must be read via TenantRepository, not raw SQL.\n"
            "  Add: from api.tenant_repository import TenantRepository",
            file=sys.stderr,
        )
        return 1

    table_list = ", ".join(sorted(_PROTECTED_TABLES))
    print(
        f"✓ check-credential-authority: {table_list} — write authority verified; "
        "TenantRepository import confirmed"
    )

    # R4.8: block resurrection of legacy credential modules
    _RETIRED_MODULES = ("api.credentials", "api.key_rotation", "api.db.api_keys_store")
    for py_file in sorted(REPO.rglob("*.py")):
        relative_file = py_file.relative_to(REPO).as_posix()
        if any(
            relative_file.startswith(prefix)
            for prefix in ("migrations/", "tests/", "tools/ci/", ".claude/")
        ):
            continue
        try:
            src = py_file.read_text(encoding="utf-8")
        except OSError:
            continue
        for mod in _RETIRED_MODULES:
            if f"from {mod} import" in src or f"import {mod}" in src:
                print(
                    f"❌ check-credential-authority: {relative_file} imports retired module {mod}",
                    file=sys.stderr,
                )
                return 1

    # R4.8: block direct api_keys writes outside allowed paths.
    # Pre-existing writers below are grandfathered; any NEW file not in this list
    # that adds api_keys DML will fail this gate.
    _LEGACY_WRITE_RE = re.compile(
        r"\b(?:INSERT\s+INTO|UPDATE)\s+api_keys\b", re.IGNORECASE
    )
    _LEGACY_WRITE_ALLOWED = frozenset(
        {
            "migrations/",
            "tests/",
            "tools/ci/",
            ".claude/",  # local dev worktrees — not present in CI
            # Pre-R4.8 writers not retired in this PR (cleaned up separately)
            # api/auth_scopes/mapping.py: mint_key / revoke_api_key / _update_key_usage
            # write to the legacy api_keys table (SQLite + Postgres paths).  These
            # functions are still called at runtime by api/keys.py and api/admin.py
            # for the legacy key-minting surface.  Retirement tracked separately.
            "api/auth_scopes/mapping.py",
            "api/auth_scopes/resolution.py",
            "api/auth_scopes/store.py",
            "api/keys.py",
            "api/tenant_rbac.py",
            "api/tripwires.py",
            "tools/seed/",
            "tools/scripts/",
            "tools/patch_chain_and_ui_single_use.py",
            "scripts/",
        }
    )
    for py_file in sorted(REPO.rglob("*.py")):
        relative_file = py_file.relative_to(REPO).as_posix()
        if any(relative_file.startswith(prefix) for prefix in _LEGACY_WRITE_ALLOWED):
            continue
        try:
            src = py_file.read_text(encoding="utf-8")
        except OSError:
            continue
        if _LEGACY_WRITE_RE.search(src):
            print(
                f"❌ check-credential-authority: {relative_file} writes directly to api_keys table",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
