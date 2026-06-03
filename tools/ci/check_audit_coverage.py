#!/usr/bin/env python3
"""H13.5 Audit Coverage Validator — mandatory CI gate.

Exit codes:
  0 — all mutation routes are audited or have valid approved exceptions
  1 — coverage violation (unaudited route without valid exception)
  2 — configuration error (malformed exceptions registry or bad args)

Auto-discovers mutation routes via AST and checks each function body for a
direct call to one of the recognized audit functions. Routes without a direct
call must appear in the exceptions registry (tools/ci/audit_exceptions.yaml)
with a non-expired expiration_date and all required fields present.
"""

from __future__ import annotations

import ast
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml  # PyYAML — already in dev deps

REPO = Path(__file__).resolve().parents[2]

AUDIT_FUNCTIONS = frozenset(
    {
        "emit_engagement_audit_event",
        "audit_atomicity_svc",
        "_c6_write_audit_event",
    }
)

MUTATION_METHODS = frozenset({"post", "put", "patch", "delete"})

SCANNED_FILES = [
    "api/field_assessment.py",
    "api/portal.py",
]

EXCEPTIONS_FILE = REPO / "tools" / "ci" / "audit_exceptions.yaml"
REPORT_FILE = REPO / "artifacts" / "audit_coverage_report.json"
EXCEPTION_REPORT_FILE = REPO / "artifacts" / "audit_exception_report.json"

# Optional debt-tracking fields — not required, but included in the exception report
# and flagged as missing so the debt picture stays visible every CI run.
EXCEPTION_DEBT_FIELDS = (
    "jira_ticket",
    "business_justification",
    "approval_date",
    "approved_by",
)

EXCEPTION_REQUIRED_FIELDS = frozenset(
    {
        "id",
        "function_name",
        "file",
        "reason",
        "owner",
        "expiration_date",
        "approval_reference",
    }
)


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _has_audit_call(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in AUDIT_FUNCTIONS:
            return True
        if isinstance(func, ast.Attribute):
            if func.attr in AUDIT_FUNCTIONS:
                return True
            if isinstance(func.value, ast.Name) and func.value.id in AUDIT_FUNCTIONS:
                return True
    return False


def _scan_mutation_routes(rel_path: str) -> list[dict[str, Any]]:
    path = REPO / rel_path
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=rel_path)

    routes: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            func = deco.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr not in MUTATION_METHODS:
                continue
            routes.append(
                {
                    "file": rel_path,
                    "function_name": node.name,
                    "method": func.attr.upper(),
                    "line": node.lineno,
                    "audited": _has_audit_call(node),
                }
            )
    return routes


# ---------------------------------------------------------------------------
# Exceptions registry
# ---------------------------------------------------------------------------


def _load_exceptions() -> tuple[dict[str, dict[str, Any]], list[str]]:
    errors: list[str] = []
    if not EXCEPTIONS_FILE.exists():
        errors.append(f"exceptions registry not found: {EXCEPTIONS_FILE}")
        return {}, errors

    try:
        raw = yaml.safe_load(EXCEPTIONS_FILE.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        errors.append(f"YAML parse error in {EXCEPTIONS_FILE}: {exc}")
        return {}, errors

    if not isinstance(raw, dict) or "exceptions" not in raw:
        errors.append(f"{EXCEPTIONS_FILE} must have top-level 'exceptions' key")
        return {}, errors

    registry: dict[str, dict[str, Any]] = {}
    today = date.today()

    for entry in raw["exceptions"]:
        missing = EXCEPTION_REQUIRED_FIELDS - set(entry.keys())
        if missing:
            errors.append(
                f"exception '{entry.get('id', '?')}' missing required fields: {sorted(missing)}"
            )
            continue

        exp_raw = entry["expiration_date"]
        try:
            exp_date = (
                exp_raw
                if isinstance(exp_raw, date)
                else date.fromisoformat(str(exp_raw))
            )
        except ValueError:
            errors.append(
                f"exception '{entry['id']}' has invalid expiration_date: {exp_raw!r}"
            )
            continue

        key = f"{entry['file']}::{entry['function_name']}"
        registry[key] = {
            **entry,
            "expiration_date": exp_date,
            "expired": exp_date < today,
        }

    return registry, errors


# ---------------------------------------------------------------------------
# Core validation
# ---------------------------------------------------------------------------


def run(*, write_report: bool = True) -> int:
    all_routes: list[dict[str, Any]] = []
    for rel_path in SCANNED_FILES:
        try:
            all_routes.extend(_scan_mutation_routes(rel_path))
        except FileNotFoundError:
            print(f"[audit-coverage] SKIP (not found): {rel_path}", file=sys.stderr)
        except SyntaxError as exc:
            print(
                f"[audit-coverage] SYNTAX ERROR in {rel_path}: {exc}", file=sys.stderr
            )
            return 2

    exceptions, cfg_errors = _load_exceptions()
    if cfg_errors:
        for err in cfg_errors:
            print(f"[audit-coverage] CONFIG ERROR: {err}", file=sys.stderr)
        return 2

    violations: list[dict[str, Any]] = []
    expired_exceptions: list[dict[str, Any]] = []
    covered: list[dict[str, Any]] = []
    excepted: list[dict[str, Any]] = []

    for route in all_routes:
        key = f"{route['file']}::{route['function_name']}"
        if route["audited"]:
            covered.append(route)
            continue

        exception_record = exceptions.get(key)
        if exception_record is None:
            violations.append(route)
        elif exception_record["expired"]:
            expired_exceptions.append({**route, "exception": exception_record})
        else:
            excepted.append({**route, "exception": exception_record})

    total = len(all_routes)
    audited_count = len(covered) + len(excepted)
    coverage_pct = round(100 * audited_count / total, 1) if total else 0.0

    report: dict[str, Any] = {
        "generated_at": date.today().isoformat(),
        "total_mutation_routes": total,
        "audited": len(covered),
        "excepted": len(excepted),
        "expired_exceptions": len(expired_exceptions),
        "violations": len(violations),
        "coverage_pct": coverage_pct,
        "violation_list": violations,
        "expired_exception_list": expired_exceptions,
        "excepted_list": excepted,
        "covered_list": covered,
    }

    if write_report:
        REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
        REPORT_FILE.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )

    _generate_exception_report(exceptions, write_report=write_report)
    _print_summary(report)

    if violations or expired_exceptions:
        return 1
    return 0


def _generate_exception_report(
    registry: dict[str, dict[str, Any]], *, write_report: bool = True
) -> dict[str, Any]:
    today = date.today()
    entries = []
    for exc in registry.values():
        exp_date = exc["expiration_date"]
        days_remaining = (exp_date - today).days
        entries.append(
            {
                "id": exc["id"],
                "function_name": exc["function_name"],
                "file": exc["file"],
                "owner": exc["owner"],
                "expiration_date": exp_date.isoformat(),
                "days_remaining": days_remaining,
                "expired": exc["expired"],
                "jira_ticket": exc.get("jira_ticket"),
                "business_justification": exc.get("business_justification"),
                "approval_date": exc.get("approval_date"),
                "approved_by": exc.get("approved_by"),
            }
        )

    entries.sort(key=lambda e: e["days_remaining"])

    missing_jira = sum(1 for e in entries if not e["jira_ticket"])
    missing_approved_by = sum(1 for e in entries if not e["approved_by"])

    report: dict[str, Any] = {
        "generated_at": today.isoformat(),
        "total_exceptions": len(entries),
        "expiring_in_30_days": sum(
            1 for e in entries if 0 <= e["days_remaining"] <= 30
        ),
        "expiring_in_60_days": sum(
            1 for e in entries if 0 <= e["days_remaining"] <= 60
        ),
        "expiring_in_90_days": sum(
            1 for e in entries if 0 <= e["days_remaining"] <= 90
        ),
        "expired": sum(1 for e in entries if e["expired"]),
        "missing_jira_ticket": missing_jira,
        "missing_approved_by": missing_approved_by,
        "exceptions": entries,
    }

    if write_report:
        EXCEPTION_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
        EXCEPTION_REPORT_FILE.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )

    return report


def _print_summary(report: dict[str, Any]) -> None:
    total = report["total_mutation_routes"]
    pct = report["coverage_pct"]
    print(
        f"[audit-coverage] {total} mutation routes | "
        f"audited={report['audited']} excepted={report['excepted']} "
        f"expired={report['expired_exceptions']} violations={report['violations']} | "
        f"coverage={pct}%"
    )

    for v in report["violation_list"]:
        print(
            f"  ❌ VIOLATION  {v['file']}:{v['line']}  {v['method']} {v['function_name']}  "
            f"— no audit call and no approved exception",
            file=sys.stderr,
        )

    for e in report["expired_exception_list"]:
        exc = e["exception"]
        print(
            f"  ⚠️  EXPIRED    {e['file']}:{e['line']}  {e['method']} {e['function_name']}  "
            f"— exception '{exc['id']}' expired {exc['expiration_date']}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-report", action="store_true", help="skip writing the JSON report"
    )
    args = parser.parse_args()
    sys.exit(run(write_report=not args.no_report))
