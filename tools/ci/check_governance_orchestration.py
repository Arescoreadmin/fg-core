#!/usr/bin/env python3
"""tools/ci/check_governance_orchestration.py

Gate: verify the Continuous Governance Orchestration Authority (PR 18.4) is
correctly wired and internally consistent.

Checks (12+):
  1. All expected service module files exist
  2. engine.py declares GovernanceOrchestrationEngine class
  3. models.py declares all required enums
  4. schemas.py declares all required exception classes
  5. API router file exists and declares routes under /governance-orchestration/
  6. ORM models file exists and declares required table classes
  7. Migration file (0145) exists
  8. No duplicate business logic (no trust/signing helpers in this module)
  9. governance_orchestration is registered in authority_manifest.yaml
  10. Policy engine functions are pure (no DB calls)
  11. Timeline tables are append-only (ORM guards + PG rules)
  12. set_tenant_context called in every route handler

Exits 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent.parent

SERVICE_DIR = ROOT / "services" / "governance_orchestration"
API_ROUTER = ROOT / "api" / "governance_orchestration.py"
DB_MODELS = ROOT / "api" / "db_models_governance_orchestration.py"
MIGRATION = ROOT / "migrations" / "postgres" / "0145_governance_orchestration.sql"
AUTHORITY_MANIFEST = ROOT / "authority_manifest.yaml"
POLICY_ENGINE = SERVICE_DIR / "policy_engine.py"


REQUIRED_SERVICE_FILES: list[str] = [
    "__init__.py",
    "engine.py",
    "models.py",
    "schemas.py",
    "repository.py",
    "policy_engine.py",
    "trigger_engine.py",
    "workflow.py",
    "reassessment.py",
    "scheduler.py",
    "change_detection.py",
    "impact_analysis.py",
    "playbooks.py",
    "maintenance_windows.py",
    "approvals.py",
    "rollback.py",
    "governance_loop.py",
    "statistics.py",
    "timeline.py",
    "notifications.py",
    "health.py",
    "validators.py",
]


REQUIRED_ENGINE_CLASS = "GovernanceOrchestrationEngine"

REQUIRED_ENUMS = [
    "GovernanceOrchestrationState",
    "TriggerType",
    "PolicyRiskLevel",
    "WorkflowState",
    "ReassessmentState",
    "ApprovalState",
    "MaintenanceWindowState",
    "SimulationState",
    "PlaybookType",
    "ImpactLevel",
    "ChangeType",
]

REQUIRED_EXCEPTIONS = [
    "GovernanceOrchestrationError",
    "GovernanceOrchestrationNotFound",
    "GovernanceOrchestrationTenantViolation",
    "GovernanceOrchestrationConflict",
    "GovernanceOrchestrationInvalidTransition",
    "GovernanceOrchestrationPolicyViolation",
    "GovernanceOrchestrationValidationError",
    "GovernanceOrchestrationSimulationError",
    "GovernanceOrchestrationApprovalError",
    "GovernanceOrchestrationWorkflowError",
]

REQUIRED_ORM_CLASSES = [
    "GovOrchPolicy",
    "GovOrchPolicyVersion",
    "GovOrchPlaybook",
    "GovOrchWorkflow",
    "GovOrchReassessment",
    "GovOrchTrigger",
    "GovOrchTriggerTimeline",
    "GovOrchSimulation",
    "GovOrchApproval",
    "GovOrchMaintenanceWindow",
    "GovOrchChangeDetection",
    "GovOrchTimeline",
]

REQUIRED_ROUTE_PREFIX = "/governance-orchestration"
MINIMUM_ROUTE_COUNT = 30

FORBIDDEN_PATTERNS = [
    (r"\bhmac\.new\b", "HMAC signing must be delegated to Trust Authority"),
    (r"\bsign_payload\b", "Signing must be delegated to Trust Authority"),
    (r"\bimport\s+ed25519\b", "Signing must be delegated to Trust Authority"),
]

# Regexes
_CLASS_RE = re.compile(r"^\s*class\s+(\w+)", re.MULTILINE)
_FUNC_OR_CLASS_RE = re.compile(
    r"^\s*(?:class|def|async\s+def)\s+(\w+)", re.MULTILINE
)
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
    lines = text.splitlines()
    bodies: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("@router."):
            j = i
            while j < len(lines) and not (
                lines[j].lstrip().startswith("def ")
                or lines[j].lstrip().startswith("async def ")
            ):
                j += 1
            if j >= len(lines):
                break
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
    parser = argparse.ArgumentParser(description="Governance Orchestration Gate")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []

    def fail(msg: str) -> None:
        failures.append(msg)

    def vprint(msg: str) -> None:
        if args.verbose:
            print(msg)

    # 1. Service files exist
    vprint("Check 1: service module files")
    for fname in REQUIRED_SERVICE_FILES:
        if not (SERVICE_DIR / fname).exists():
            fail(f"Missing service file: services/governance_orchestration/{fname}")

    # 2. engine.py declares GovernanceOrchestrationEngine
    vprint("Check 2: engine.py declares GovernanceOrchestrationEngine")
    engine_path = SERVICE_DIR / "engine.py"
    if engine_path.exists():
        text = _read(engine_path) or ""
        if REQUIRED_ENGINE_CLASS not in _declared_classes(text):
            fail(f"engine.py: missing class {REQUIRED_ENGINE_CLASS!r}")

    # 3. models.py declares required enums
    vprint("Check 3: models.py enums")
    models_path = SERVICE_DIR / "models.py"
    if models_path.exists():
        text = _read(models_path) or ""
        declared = _declared_names(text)
        for name in REQUIRED_ENUMS:
            if name not in declared:
                fail(f"models.py: missing enum {name!r}")

    # 4. schemas.py declares required exceptions
    vprint("Check 4: schemas.py exceptions")
    schemas_path = SERVICE_DIR / "schemas.py"
    if schemas_path.exists():
        text = _read(schemas_path) or ""
        declared = _declared_names(text)
        for name in REQUIRED_EXCEPTIONS:
            if name not in declared:
                fail(f"schemas.py: missing exception {name!r}")

    # 5. API router exists with routes
    vprint("Check 5: API router file")
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
                f"found {len(matching)}"
            )

    # 6. ORM models
    vprint("Check 6: ORM models")
    if not DB_MODELS.exists():
        fail(f"Missing: {DB_MODELS.relative_to(ROOT)}")
    else:
        text = _read(DB_MODELS) or ""
        classes = _declared_classes(text)
        for name in REQUIRED_ORM_CLASSES:
            if name not in classes:
                fail(f"{DB_MODELS.relative_to(ROOT)}: missing ORM class {name!r}")

    # 7. Migration file
    vprint("Check 7: migration file")
    if not MIGRATION.exists():
        fail(f"Missing migration: {MIGRATION.relative_to(ROOT)}")
    else:
        migration_text = _read(MIGRATION) or ""
        if "CREATE TABLE IF NOT EXISTS" not in migration_text:
            fail(
                f"{MIGRATION.relative_to(ROOT)}: expected replay-safe "
                "'CREATE TABLE IF NOT EXISTS'"
            )
        if "BEGIN;" in migration_text or "COMMIT;" in migration_text:
            fail(f"{MIGRATION.relative_to(ROOT)}: BEGIN;/COMMIT; not allowed")

    # 8. No forbidden signing/crypto helpers
    vprint("Check 8: no forbidden crypto helpers")
    for py_file in SERVICE_DIR.glob("*.py"):
        text = _read(py_file) or ""
        for pattern, message in FORBIDDEN_PATTERNS:
            if re.search(pattern, text):
                fail(
                    f"{py_file.relative_to(ROOT)}: forbidden pattern "
                    f"{pattern!r} - {message}"
                )

    # 9. authority_manifest entry
    vprint("Check 9: authority_manifest")
    if not AUTHORITY_MANIFEST.exists():
        fail(f"Missing: {AUTHORITY_MANIFEST.relative_to(ROOT)}")
    else:
        text = _read(AUTHORITY_MANIFEST) or ""
        if "governance_orchestration:" not in text:
            fail(
                f"{AUTHORITY_MANIFEST.relative_to(ROOT)}: "
                "'governance_orchestration:' entry not found"
            )

    # 10. policy_engine functions are pure (no DB calls)
    vprint("Check 10: policy_engine purity")
    if POLICY_ENGINE.exists():
        text = _read(POLICY_ENGINE) or ""
        for bad in ("sqlalchemy", "Session(", "db.execute", "db.query"):
            if bad in text:
                fail(f"policy_engine.py: forbidden pattern {bad!r} (must be pure)")

    # 11. Timeline append-only (ORM guards + PG rules)
    vprint("Check 11: timeline append-only")
    orm_text = _read(DB_MODELS) or ""
    if "before_update" not in orm_text or "before_delete" not in orm_text:
        fail(
            f"{DB_MODELS.relative_to(ROOT)}: expected ORM guards on "
            "trigger_timeline / timeline"
        )
    migration_text = _read(MIGRATION) or ""
    for rule in (
        "fa_gov_orch_trigger_timeline_no_update",
        "fa_gov_orch_trigger_timeline_no_delete",
        "fa_gov_orch_timeline_no_update",
        "fa_gov_orch_timeline_no_delete",
    ):
        if rule not in migration_text:
            fail(f"{MIGRATION.relative_to(ROOT)}: missing PG rule {rule!r}")

    # 12. set_tenant_context in every route handler
    vprint("Check 12: set_tenant_context in every route handler")
    router_text = _read(API_ROUTER) or ""
    handlers = _iter_handler_bodies(router_text)
    for idx, body in enumerate(handlers):
        if "Session(" in body and "set_tenant_context" not in body:
            fail(
                f"{API_ROUTER.relative_to(ROOT)}: handler #{idx} opens a "
                "Session but does not call set_tenant_context"
            )

    if failures:
        print(
            f"\nGovernance Orchestration Gate: FAILED ({len(failures)} violation(s))"
        )
        for f in failures:
            print(f"  x  {f}")
        return 1

    print("Governance Orchestration Gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
