"""AST-based guard: detect prohibited module-level environment mutation in test files.

Runs as part of the fast required CI gate. Exit 0 = clean. Exit 1 = violations found.

## What is checked

Module-scope statements (outside any function or class) that mutate os.environ:
  - os.environ.setdefault(...)
  - os.environ[...] = ...       (direct assignment)
  - os.environ.update(...)
  - os.putenv(...)
  - os.environ.pop(...)         (destructive — removes a key)
  - os.environ.clear()          (destructive — wipes all env vars)

These execute during pytest *collection*, before any fixture isolation runs.
A mutation in one collected module can contaminate all subsequently-collected
tests in the same worker process — even if those tests use monkeypatch correctly.

## What is allowed

  - Any of the above *inside* a function, method, or class body (fixture-scoped).
  - os.environ reads (os.environ.get, os.environ[...] as rvalue, etc.)
  - monkeypatch.setenv / monkeypatch.delenv (fixture-scoped, properly restored).
  - patch.dict(os.environ, ...) inside a function.

## Allowlist design

PERMITTED_COLLECTION_VARS — variable names whose module-scope setdefault() calls
are classified as safe, with documented justification:

  FG_ENV              — Runtime tier identifier. conftest.py already sets "test";
                        redundant setdefaults in individual test files are harmless.
  FG_ACKNOWLEDGMENT_KEY — Crypto key read lazily inside _master_key() function in
                          services/connectors/msgraph/acknowledgment.py; NOT read
                          at import time. Belt-and-suspenders; harmless.
  FG_REPORT_SIGNING_KEY — Read lazily in api/reports_engine.py and
                          api/config/startup_validation.py; NOT at import time.
  FG_API_KEY          — conftest.py already sets ci-test-key; redundant.
  FG_KEY_PEPPER       — conftest.py already sets ci-test-pepper; redundant.
  FG_RL_ENABLED       — Rate-limiting toggle; no effect on auth/tenant isolation.
  FG_COMPLIANCE_HMAC_KEY_ID_CURRENT — Compliance module key version; no auth effect.
  FG_MSAL_CLIENT_ID   — MSAL OAuth client ID; read lazily in auth modules.

HARD-FAIL variables — never permitted at module scope (any value):

  FG_AUTH_ENABLED     — Explicitly overrides _resolve_auth_enabled_from_env(),
                        silencing FG_API_KEY presence. A module-scope "0" disables
                        auth for every test collected afterward in the same worker.
                        Caused 8 confirmed failures in test_membership_versioning.py
                        (POST-789-COLLECTION-ENV-LEAK-001, SHARD2-COLLECTION-ISOLATION-002).

CONFTEST ALLOWLIST — conftest.py files are exempt:

  tests/conftest.py        — central test-session defaults; reviewed.
  backend/tests/conftest.py — same.

Usage:
  python tools/ci/check_collection_purity.py [--repo REPO] [--verbose]
  Exit 0 = no violations. Exit 1 = violations found.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# conftest files are the canonical home for test-session defaults.
_CONFTEST_ALLOWLIST: frozenset[str] = frozenset(
    [
        "tests/conftest.py",
        "backend/tests/conftest.py",
    ]
)

# Variable names whose module-scope setdefault() is classified as safe.
# See module docstring for per-variable justification.
_PERMITTED_COLLECTION_VARS: frozenset[str] = frozenset(
    [
        "FG_ENV",
        "FG_ACKNOWLEDGMENT_KEY",
        "FG_REPORT_SIGNING_KEY",
        "FG_API_KEY",
        "FG_KEY_PEPPER",
        "FG_RL_ENABLED",
        "FG_COMPLIANCE_HMAC_KEY_ID_CURRENT",
        "FG_COMPLIANCE_HMAC_KEY_CURRENT",
        "FG_MSAL_CLIENT_ID",
    ]
)


def _extract_setdefault_var(call: ast.Call) -> str | None:
    """Return the variable name from os.environ.setdefault(VAR, ...) or None."""
    if not call.args:
        return None
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _check_statement(node: ast.stmt) -> str | None:
    """Return a violation description if the statement is a prohibited env mutation, else None."""
    # os.environ[key] = value  (Assign with Subscript target on os.environ)
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Attribute)
                and isinstance(target.value.value, ast.Name)
                and target.value.value.id == "os"
                and target.value.attr == "environ"
            ):
                return "os.environ[...] = ... (direct assignment at module scope)"

    if not isinstance(node, ast.Expr):
        return None
    call = node.value
    if not isinstance(call, ast.Call):
        return None

    func = call.func

    # os.putenv(...)
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "os"
        and func.attr == "putenv"
    ):
        return "os.putenv(...) at module scope"

    # os.environ.<method>(...)
    if not (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Attribute)
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id == "os"
        and func.value.attr == "environ"
    ):
        return None

    method = func.attr

    if method == "setdefault":
        var_name = _extract_setdefault_var(call)
        if var_name in _PERMITTED_COLLECTION_VARS:
            return None  # explicitly permitted
        return f"os.environ.setdefault({var_name!r}, ...) at module scope — not in PERMITTED_COLLECTION_VARS"

    if method == "update":
        return "os.environ.update(...) at module scope"

    if method == "clear":
        return "os.environ.clear() at module scope"

    if method == "pop":
        return "os.environ.pop(...) at module scope"

    return None


def check_file(path: Path) -> list[tuple[int, str]]:
    """Return list of (line, description) for module-scope violations."""
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    violations: list[tuple[int, str]] = []
    # Only examine top-level statements (module scope)
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if not isinstance(node, ast.stmt):
            continue
        desc = _check_statement(node)
        if desc:
            violations.append((node.lineno, desc))
    return violations


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Check test files for collection-time env mutations"
    )
    parser.add_argument("--repo", default=".", help="Path to repository root")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    test_roots = [repo / "tests", repo / "backend" / "tests"]

    all_violations: list[tuple[Path, int, str]] = []
    file_count = 0

    for root in test_roots:
        if not root.exists():
            continue
        for py_file in sorted(root.rglob("*.py")):
            rel = py_file.relative_to(repo)
            if str(rel) in _CONFTEST_ALLOWLIST:
                continue
            file_count += 1
            violations = check_file(py_file)
            for lineno, desc in violations:
                all_violations.append((py_file, lineno, desc))
                if args.verbose:
                    print(f"  VIOLATION {rel}:{lineno} — {desc}")

    if all_violations:
        print(
            f"collection-purity: FAIL — {len(all_violations)} violation(s) in "
            f"{file_count} files scanned"
        )
        for path, lineno, desc in all_violations:
            rel = path.relative_to(repo)
            print(f"  {rel}:{lineno}: {desc}")
        print()
        print(
            "Fix: move mutations into function-scoped pytest fixtures using monkeypatch."
        )
        print(
            "To permit a new variable, add it to _PERMITTED_COLLECTION_VARS in "
            "tools/ci/check_collection_purity.py with explicit justification."
        )
        return 1

    print(f"collection-purity: OK — {file_count} test files scanned, 0 violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
