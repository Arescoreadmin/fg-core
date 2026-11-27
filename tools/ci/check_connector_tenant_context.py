#!/usr/bin/env python3
"""FG-ASSESSMENT-CONNECTOR-RLS-001 — synchronous connector tenant-context guard.

``set_config('app.tenant_id', ..., true)`` is transaction-local: a
``db.commit()`` or ``db.rollback()`` clears the binding, and further work in
the same request then runs with no tenant under forced RLS (reads see no rows,
writes fail WITH CHECK). The original defect left durable jobs queued and lost
their failure records. This READ-ONLY checker fails closed if a synchronous
connector route drifts back to that shape.

A synchronous connector route is a function in ``api/field_assessment.py``
that creates a scan job (``_c6_create_scan_job``), completes it inline
(``_c6_update_job_status(..., status="complete")``) and does not hand the work
to ``background_tasks.add_task``. For each such route, and for the shared
helpers in ``HELPERS``:

1. After a ``db.commit()`` / ``db.rollback()`` statement that is followed by
   more ``db`` work in the same block, the very next statement must be
   ``set_tenant_context(db, <name>)``. The tenant must be a plain local name
   (the server-resolved tenant), never an attribute or call on request data.
2. No job-transition result may be ignored: a bare ``_c6_update_job_status``
   or ``durable_job_svc.mark_*`` statement fails (compare-and-swap results
   must be checked).
3. Discovery must find at least ``EXPECTED_ROUTES``, so the guard can never
   pass by covering nothing.
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterator
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOURCE = Path("api/field_assessment.py")
EXPECTED_ROUTES = frozenset(
    {
        "run_ai_data_access_mapping",
        "run_external_ai_risk_register",
        "run_ai_vendor_governance",
    }
)
HELPERS = frozenset({"_c6_sync_connector_record_failure"})
TRANSITION_CALLS = frozenset({"_c6_update_job_status"})
SERVICE_TRANSITIONS = frozenset(
    {"mark_running", "mark_complete", "mark_failed", "terminate_stale_running"}
)

Func = ast.FunctionDef | ast.AsyncFunctionDef


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
    return ""


def _kw(call: ast.Call, name: str) -> object:
    for k in call.keywords:
        if k.arg == name and isinstance(k.value, ast.Constant):
            return k.value.value
    return None


def is_sync_connector(func: Func) -> bool:
    calls = [n for n in ast.walk(func) if isinstance(n, ast.Call)]
    names = {_call_name(c) for c in calls}
    completes = any(
        _call_name(c) in TRANSITION_CALLS and _kw(c, "status") == "complete"
        for c in calls
    )
    background = "add_task" in names
    return "_c6_create_scan_job" in names and completes and not background


def _is_db_txn_end(stmt: ast.stmt) -> str:
    if (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Attribute)
        and isinstance(stmt.value.func.value, ast.Name)
        and stmt.value.func.value.id == "db"
        and stmt.value.func.attr in ("commit", "rollback")
    ):
        return stmt.value.func.attr
    return ""


def _is_rebind(stmt: ast.stmt) -> bool:
    if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
        return False
    call = stmt.value
    return (
        _call_name(call) == "set_tenant_context"
        and len(call.args) == 2
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "db"
        and isinstance(call.args[1], ast.Name)
    )


def _uses_db(stmts: list[ast.stmt]) -> bool:
    return any(
        isinstance(n, ast.Name) and n.id == "db"
        for stmt in stmts
        for n in ast.walk(stmt)
    )


def _child_blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    for field in ("body", "orelse", "finalbody"):
        block = getattr(node, field, None)
        if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
            yield block
    for handler in getattr(node, "handlers", []) or []:
        yield handler.body
    for case in getattr(node, "cases", []) or []:
        yield case.body


def _blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    """Every statement list in ``node``, at any depth (incl. except handlers)."""
    for block in _child_blocks(node):
        yield block
        for stmt in block:
            yield from _blocks(stmt)


def check_function(func: Func) -> list[str]:
    errors: list[str] = []
    seen: set[int] = set()
    for block in _blocks(func):
        if id(block) in seen:
            continue
        seen.add(id(block))
        for i, stmt in enumerate(block):
            kind = _is_db_txn_end(stmt)
            if kind and _uses_db(block[i + 1 :]):
                nxt = block[i + 1]
                if not _is_rebind(nxt):
                    errors.append(
                        f"{func.name}:{stmt.lineno}: db.{kind}() is followed by more "
                        "database work without set_tenant_context(db, <tenant>) on the "
                        "next line (the tenant binding is transaction-local)"
                    )
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                name = _call_name(stmt.value)
                svc = (
                    isinstance(stmt.value.func, ast.Attribute)
                    and isinstance(stmt.value.func.value, ast.Name)
                    and stmt.value.func.value.id == "durable_job_svc"
                    and name in SERVICE_TRANSITIONS
                )
                if name in TRANSITION_CALLS or svc:
                    errors.append(
                        f"{func.name}:{stmt.lineno}: result of {name}() is ignored "
                        "(compare-and-swap transitions must be checked)"
                    )
    return errors


def check_source(text: str, filename: str = str(SOURCE)) -> tuple[list[str], set[str]]:
    tree = ast.parse(text, filename=filename)
    funcs = [
        n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    routes = {f.name for f in funcs if is_sync_connector(f)}
    errors: list[str] = []
    for func in funcs:
        if func.name in routes or func.name in HELPERS:
            errors.extend(check_function(func))
    return errors, routes


def check(repo: Path = REPO) -> list[str]:
    errors, routes = check_source((repo / SOURCE).read_text(encoding="utf-8"))
    missing = sorted(EXPECTED_ROUTES - routes)
    if missing:
        errors.append(
            f"synchronous connector routes not found (guard would cover nothing): {missing}"
        )
    text = (repo / SOURCE).read_text(encoding="utf-8")
    tree = ast.parse(text)
    defined = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    for helper in sorted(HELPERS - defined):
        errors.append(f"required helper {helper} is missing")
    return errors


def main() -> int:
    errors = check()
    if errors:
        print("connector tenant-context check: FAILED", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("connector tenant-context check: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
