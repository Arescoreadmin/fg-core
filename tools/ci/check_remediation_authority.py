#!/usr/bin/env python3
"""tools/ci/check_remediation_authority.py

Gate: verify the Enterprise Remediation Authority (PR 18.3) is correctly
wired and internally consistent.

Checks (12):
  1. All expected service module files exist
  2. engine.py declares RemediationAuthorityEngine class
  3. models.py declares all required enums
  4. schemas.py declares all required exception classes
  5. API router file exists and declares routes under /remediation-authority/
  6. ORM models file exists and declares required table classes
  7. Migration file exists
  8. No duplicate business logic (no trust/signing helpers in this module)
  9. remediation_authority is registered in authority_manifest.yaml
  10. State machine transitions are defined
  11. Timeline is append-only (ORM guards + PG rules present)
  12. set_tenant_context is called in every route handler

Exits 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

SERVICE_DIR = ROOT / "services" / "remediation_authority"
API_ROUTER = ROOT / "api" / "remediation_authority.py"
DB_MODELS = ROOT / "api" / "db_models_remediation_authority.py"
MIGRATION = ROOT / "migrations" / "postgres" / "0144_remediation_authority.sql"
AUTHORITY_MANIFEST = ROOT / "authority_manifest.yaml"


REQUIRED_SERVICE_FILES: list[str] = [
    "__init__.py",
    "engine.py",
    "models.py",
    "schemas.py",
    "workflow.py",
    "state_machine.py",
    "assignment.py",
    "verification.py",
    "dependencies.py",
    "effectiveness.py",
    "risk.py",
    "sla.py",
    "forecast.py",
    "history.py",
    "timeline.py",
    "notifications.py",
    "statistics.py",
    "validators.py",
    "health.py",
    "repository.py",
]


REQUIRED_ENGINE_CLASS = "RemediationAuthorityEngine"

REQUIRED_ENUMS = [
    "RemediationPlanState",
    "RemediationTaskState",
    "RemediationPriority",
    "RemediationVerificationState",
    "AssignmentRole",
    "SlaStatus",
    "DependencyType",
]

REQUIRED_EXCEPTIONS = [
    "RemediationAuthorityError",
    "RemediationNotFound",
    "RemediationTenantViolation",
    "RemediationConflict",
    "RemediationInvalidTransition",
    "RemediationImmutableState",
    "RemediationDependencyError",
    "RemediationAssignmentError",
    "RemediationVerificationError",
    "RemediationValidationError",
]

REQUIRED_ORM_CLASSES = [
    "RemAuthPlan",
    "RemAuthTask",
    "RemAuthTimeline",
    "RemAuthAssignment",
    "RemAuthDependency",
    "RemAuthVerification",
    "RemAuthEvidenceLink",
]

REQUIRED_ROUTE_PREFIX = "/remediation-authority"
MINIMUM_ROUTE_COUNT = 15

# Forbidden patterns (no local signing / crypto)
FORBIDDEN_PATTERNS = [
    (r"\bhmac\.new\b", "HMAC signing must be delegated to Trust Authority"),
    (r"\bsign_payload\b", "Signing must be delegated to Trust Authority"),
    (r"\bimport\s+ed25519\b", "Signing must be delegated to Trust Authority"),
]


_CLASS_RE = re.compile(r"^\s*class\s+(\w+)", re.MULTILINE)
_FUNC_OR_CLASS_RE = re.compile(r"^\s*(?:class|def|async\s+def)\s+(\w+)", re.MULTILINE)
_ROUTE_STR_RE = re.compile(r'@router\.\w+\(\s*["\']([^"\']+)["\']', re.MULTILINE)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _declared_classes(text: str) -> set[str]:
    return set(_CLASS_RE.findall(text))


def _declared_names(text: str) -> set[str]:
    return set(_FUNC_OR_CLASS_RE.findall(text))


def _extract_routes(text: str) -> list[str]:
    return _ROUTE_STR_RE.findall(text)


def _iter_handler_bodies(text: str) -> list[str]:
    """Return the source of each @router.<method> handler."""
    lines = text.splitlines()
    bodies: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("@router."):
            # Advance to the def
            j = i
            while j < len(lines) and not (
                lines[j].lstrip().startswith("def ")
                or lines[j].lstrip().startswith("async def ")
            ):
                j += 1
            if j >= len(lines):
                break
            # Collect until dedent to column 0 or another decorator/def at col 0
            k = j + 1
            body_start = k
            while k < len(lines):
                stripped = lines[k]
                if stripped and not stripped.startswith((" ", "\t")):
                    break
                k += 1
            bodies.append("\n".join(lines[body_start:k]))
            i = k
            continue
        i += 1
    return bodies


def main() -> int:
    parser = argparse.ArgumentParser(description="Remediation Authority Gate")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []

    def fail(msg: str) -> None:
        failures.append(msg)

    def vprint(msg: str) -> None:
        if args.verbose:
            print(msg)

    # ------------------------------------------------------------------
    # Check 1: All expected service module files exist
    # ------------------------------------------------------------------
    vprint("Check 1: service module files")
    for fname in REQUIRED_SERVICE_FILES:
        fpath = SERVICE_DIR / fname
        if not fpath.exists():
            fail(f"Missing service file: services/remediation_authority/{fname}")
        else:
            vprint(f"  + {fname}")

    # ------------------------------------------------------------------
    # Check 2: engine.py declares RemediationAuthorityEngine
    # ------------------------------------------------------------------
    vprint("Check 2: engine.py declares RemediationAuthorityEngine")
    engine_path = SERVICE_DIR / "engine.py"
    if engine_path.exists():
        text = _read(engine_path) or ""
        if REQUIRED_ENGINE_CLASS not in _declared_classes(text):
            fail(
                "services/remediation_authority/engine.py: "
                f"missing class {REQUIRED_ENGINE_CLASS!r}"
            )
        else:
            vprint(f"  + class {REQUIRED_ENGINE_CLASS}")

    # ------------------------------------------------------------------
    # Check 3: models.py declares all required enums
    # ------------------------------------------------------------------
    vprint("Check 3: models.py declares required enums")
    models_path = SERVICE_DIR / "models.py"
    if models_path.exists():
        text = _read(models_path) or ""
        declared = _declared_names(text)
        for enum_name in REQUIRED_ENUMS:
            if enum_name not in declared:
                fail(
                    "services/remediation_authority/models.py: "
                    f"missing enum {enum_name!r}"
                )
            else:
                vprint(f"  + {enum_name}")

    # ------------------------------------------------------------------
    # Check 4: schemas.py declares all required exceptions
    # ------------------------------------------------------------------
    vprint("Check 4: schemas.py declares required exceptions")
    schemas_path = SERVICE_DIR / "schemas.py"
    if schemas_path.exists():
        text = _read(schemas_path) or ""
        declared = _declared_names(text)
        for exc_name in REQUIRED_EXCEPTIONS:
            if exc_name not in declared:
                fail(
                    "services/remediation_authority/schemas.py: "
                    f"missing exception {exc_name!r}"
                )
            else:
                vprint(f"  + {exc_name}")

    # ------------------------------------------------------------------
    # Check 5: API router file exists and declares routes
    # ------------------------------------------------------------------
    vprint("Check 5: API router file and route prefixes")
    if not API_ROUTER.exists():
        fail(f"Missing: {API_ROUTER.relative_to(ROOT)}")
    else:
        text = _read(API_ROUTER) or ""
        routes = _extract_routes(text)
        matching = [
            r
            for r in routes
            if r == REQUIRED_ROUTE_PREFIX or r.startswith(REQUIRED_ROUTE_PREFIX)
        ]
        if len(matching) < MINIMUM_ROUTE_COUNT:
            fail(
                f"{API_ROUTER.relative_to(ROOT)}: expected at least "
                f"{MINIMUM_ROUTE_COUNT} routes under {REQUIRED_ROUTE_PREFIX!r}, "
                f"found {len(matching)}: {matching}"
            )
        else:
            vprint(f"  + {len(matching)} route(s)")

    # ------------------------------------------------------------------
    # Check 6: ORM models file exists and declares required table classes
    # ------------------------------------------------------------------
    vprint("Check 6: ORM models file and table classes")
    if not DB_MODELS.exists():
        fail(f"Missing: {DB_MODELS.relative_to(ROOT)}")
    else:
        text = _read(DB_MODELS) or ""
        classes = _declared_classes(text)
        for cls_name in REQUIRED_ORM_CLASSES:
            if cls_name not in classes:
                fail(f"{DB_MODELS.relative_to(ROOT)}: missing ORM class {cls_name!r}")
            else:
                vprint(f"  + {cls_name}")

    # ------------------------------------------------------------------
    # Check 7: Migration file exists
    # ------------------------------------------------------------------
    vprint("Check 7: migration file exists")
    if not MIGRATION.exists():
        fail(f"Missing migration: {MIGRATION.relative_to(ROOT)}")
    else:
        migration_text = _read(MIGRATION) or ""
        # Replay-safe patterns
        if "CREATE TABLE IF NOT EXISTS" not in migration_text:
            fail(
                f"{MIGRATION.relative_to(ROOT)}: expected "
                "'CREATE TABLE IF NOT EXISTS' idempotent pattern"
            )
        if "BEGIN;" in migration_text or "COMMIT;" in migration_text:
            fail(
                f"{MIGRATION.relative_to(ROOT)}: BEGIN;/COMMIT; is not allowed "
                "(migration runner owns the transaction)"
            )
        vprint(f"  + {MIGRATION.relative_to(ROOT)}")

    # ------------------------------------------------------------------
    # Check 8: No duplicate business logic (no trust/signing in this module)
    # ------------------------------------------------------------------
    vprint("Check 8: no forbidden signing/crypto helpers")
    for py_file in SERVICE_DIR.glob("*.py"):
        text = _read(py_file) or ""
        for pattern, message in FORBIDDEN_PATTERNS:
            if re.search(pattern, text):
                fail(
                    f"{py_file.relative_to(ROOT)}: forbidden pattern "
                    f"{pattern!r} - {message}"
                )

    # ------------------------------------------------------------------
    # Check 9: remediation_authority is registered in authority_manifest.yaml
    # ------------------------------------------------------------------
    vprint("Check 9: authority_manifest.yaml registration")
    if not AUTHORITY_MANIFEST.exists():
        fail(f"Missing: {AUTHORITY_MANIFEST.relative_to(ROOT)}")
    else:
        text = _read(AUTHORITY_MANIFEST) or ""
        if "remediation_authority" not in text:
            fail(
                f"{AUTHORITY_MANIFEST.relative_to(ROOT)}: "
                "'remediation_authority' entry not found"
            )
        else:
            vprint("  + remediation_authority found")

    # ------------------------------------------------------------------
    # Check 10: State machine transitions are defined
    # ------------------------------------------------------------------
    vprint("Check 10: state machine transitions defined")
    sm_path = SERVICE_DIR / "state_machine.py"
    if sm_path.exists():
        text = _read(sm_path) or ""
        for symbol in (
            "VALID_TRANSITIONS",
            "validate_transition",
            "is_immutable_state",
        ):
            if symbol not in text:
                fail(f"state_machine.py: missing symbol {symbol!r}")

    # ------------------------------------------------------------------
    # Check 11: Timeline is append-only (ORM guards + PG rules)
    # ------------------------------------------------------------------
    vprint("Check 11: timeline append-only enforcement")
    orm_text = _read(DB_MODELS) or ""
    if "before_update" not in orm_text or "before_delete" not in orm_text:
        fail(
            f"{DB_MODELS.relative_to(ROOT)}: expected ORM before_update/"
            "before_delete guards on RemAuthTimeline"
        )
    if "RemAuthTimeline" not in orm_text:
        fail(f"{DB_MODELS.relative_to(ROOT)}: missing RemAuthTimeline class")
    migration_text = _read(MIGRATION) or ""
    if "fa_rem_timeline_no_update" not in migration_text:
        fail(
            f"{MIGRATION.relative_to(ROOT)}: missing "
            "'fa_rem_timeline_no_update' PG rule"
        )
    if "fa_rem_timeline_no_delete" not in migration_text:
        fail(
            f"{MIGRATION.relative_to(ROOT)}: missing "
            "'fa_rem_timeline_no_delete' PG rule"
        )

    # ------------------------------------------------------------------
    # Check 12: set_tenant_context called in all route handlers
    # ------------------------------------------------------------------
    vprint("Check 12: set_tenant_context called in every route handler")
    router_text = _read(API_ROUTER) or ""
    handlers = _iter_handler_bodies(router_text)
    for idx, body in enumerate(handlers):
        # Every handler that opens a Session must also call set_tenant_context
        if "Session(" in body and "set_tenant_context" not in body:
            fail(
                f"{API_ROUTER.relative_to(ROOT)}: handler #{idx} opens a "
                "Session but does not call set_tenant_context"
            )

    # ------------------------------------------------------------------
    # Result
    # ------------------------------------------------------------------
    if failures:
        print(f"\nRemediation Authority Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  x  {f}")
        return 1

    print("Remediation Authority Gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
