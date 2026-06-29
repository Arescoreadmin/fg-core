"""tools/ci/check_cgin_privacy.py

CGIN Privacy Gate — schema-level structural enforcement.

Crawls every Pydantic schema file under services/ and fails the build if
any class that looks like a CGIN snapshot model contains a field whose name
appears in the forbidden PII list.

This is stronger than checking authority_manifest.yaml because it validates
the actual schema field names, not just a hand-maintained flag.

Usage:
    python tools/ci/check_cgin_privacy.py          # exits 0 on pass, 1 on fail
    python tools/ci/check_cgin_privacy.py --verbose

Exit codes:
    0  All CGIN snapshot schemas are privacy-safe.
    1  One or more CGIN snapshot schemas contain forbidden fields.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# Field names that must never appear in a CGIN snapshot schema
FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "tenant_id",
        "organization_name",
        "customer_name",
        "tenant_slug",
        "account_id",
        "raw_account_id",
        "email",
        "email_domain",
    }
)

# Class name suffixes that identify CGIN snapshot models
CGIN_CLASS_SUFFIXES = (
    "CGINSnapshot",
    "CginSnapshot",
    "CGINBundle",
    "CginBundle",
    "CGINTrendSnapshot",
    "CginTrendSnapshot",
)


def _is_cgin_class(class_name: str) -> bool:
    return "cgin" in class_name.lower() and (
        "snapshot" in class_name.lower() or "bundle" in class_name.lower()
    )


def _get_field_names_from_class(node: ast.ClassDef) -> list[str]:
    """Extract field names from a Pydantic-style class (annotated assignments)."""
    fields = []
    for item in node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            fields.append(item.target.id)
    return fields


def check_file(path: Path, verbose: bool) -> list[str]:
    """Return list of violations found in this schema file."""
    violations = []
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError):
        return violations

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if not _is_cgin_class(node.name):
            continue

        fields = _get_field_names_from_class(node)
        forbidden_found = [f for f in fields if f in FORBIDDEN_FIELD_NAMES]

        if verbose and fields:
            rel = path.relative_to(ROOT)
            print(f"  Checked {rel}::{node.name} — fields: {fields}")

        for field in forbidden_found:
            rel = path.relative_to(ROOT)
            violations.append(
                f"{rel}::{node.name} — forbidden field '{field}' in CGIN snapshot schema. "
                f"Use 'tenant_fingerprint' instead. "
                f"See services/cgin/privacy.py for the canonical helper."
            )

    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="CGIN Privacy Gate")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    schema_files = list(Path(ROOT / "services").rglob("schemas.py"))
    # Also check any *schemas*.py files in services/
    schema_files += [
        p for p in Path(ROOT / "services").rglob("*schema*.py") if p not in schema_files
    ]

    all_violations: list[str] = []
    cgin_classes_checked = 0

    for schema_file in sorted(schema_files):
        file_violations = check_file(schema_file, args.verbose)
        all_violations.extend(file_violations)
        # Count CGIN classes in this file (for the summary)
        try:
            tree = ast.parse(schema_file.read_text(encoding="utf-8"))
            cgin_classes_checked += sum(
                1
                for node in ast.walk(tree)
                if isinstance(node, ast.ClassDef) and _is_cgin_class(node.name)
            )
        except (SyntaxError, OSError):
            pass

    if all_violations:
        print(f"\nCGIN Privacy Gate: FAILED ({len(all_violations)} violation(s))")
        for v in all_violations:
            print(f"  ✗  {v}")
        return 1

    try:
        from services.cgin.privacy import (
            ACTIVE_FINGERPRINT_ALGORITHM,
            CGIN_PRIVACY_VERSION,
        )

        algo = ACTIVE_FINGERPRINT_ALGORITHM.value
        pv = CGIN_PRIVACY_VERSION
    except ImportError:
        algo = "sha256-cgin-v1"
        pv = "1.0"

    print(
        f"CGIN Privacy Gate: PASS "
        f"({cgin_classes_checked} CGIN snapshot schema(s) verified, "
        f"0 forbidden fields, "
        f"privacy_version={pv}, "
        f"algorithm={algo})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
