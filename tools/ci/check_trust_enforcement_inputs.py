#!/usr/bin/env python3
"""P0-6B Trust Enforcement Input Guardrail — mandatory CI gate.

Verifies that calls to the three primary trust enforcement functions pass
explicit chain_valid, link_valid, and replay_valid kwargs derived from the
engagement's provenance chain. Default-True trust inputs are not permitted
at these call sites.

Exit codes:
  0 — all checked call sites pass explicit required kwargs
  1 — one or more call sites use implicit (default) trust inputs
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# (file, function_name, required_explicit_kwargs)
ENFORCEMENT_CALL_SITES: list[tuple[str, str, frozenset[str]]] = [
    (
        "api/reports_engine.py",
        "enforce_report_finalization",
        frozenset({"chain_valid", "link_valid", "replay_valid"}),
    ),
    (
        "api/field_assessment.py",
        "enforce_evidence_approval",
        frozenset({"chain_valid", "link_valid", "replay_valid"}),
    ),
    (
        "api/field_assessment.py",
        "enforce_report_export",
        frozenset({"chain_valid", "link_valid", "replay_valid"}),
    ),
]


def _find_calls(tree: ast.AST, fn_name: str) -> list[ast.Call]:
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == fn_name:
                calls.append(node)
            elif isinstance(func, ast.Attribute) and func.attr == fn_name:
                calls.append(node)
    return calls


def _check_site(file: str, fn_name: str, required: frozenset[str]) -> list[str]:
    path = REPO / file
    if not path.exists():
        return [f"MISSING FILE: {file}"]

    source = path.read_text()
    try:
        tree = ast.parse(source, filename=file)
    except SyntaxError as e:
        return [f"SYNTAX ERROR in {file}: {e}"]

    calls = _find_calls(tree, fn_name)
    if not calls:
        return [f"NO CALLS FOUND: {fn_name} not called in {file}"]

    errors: list[str] = []
    for call in calls:
        provided = {kw.arg for kw in call.keywords if kw.arg is not None}
        missing = required - provided
        if missing:
            lineno = call.lineno
            errors.append(
                f"{file}:{lineno}: {fn_name}() missing explicit kwargs: "
                + ", ".join(sorted(missing))
            )
    return errors


def main() -> int:
    all_errors: list[str] = []
    for file, fn_name, required in ENFORCEMENT_CALL_SITES:
        all_errors.extend(_check_site(file, fn_name, required))

    if all_errors:
        print("TRUST ENFORCEMENT INPUT GUARDRAIL FAILED", file=sys.stderr)
        for err in all_errors:
            print(f"  {err}", file=sys.stderr)
        print(
            "\nAll trust enforcement calls must pass chain_valid, link_valid, and "
            "replay_valid derived from derive_engagement_trust_inputs().",
            file=sys.stderr,
        )
        return 1

    print(
        f"trust-enforcement-inputs: OK ({len(ENFORCEMENT_CALL_SITES)} call sites verified)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
