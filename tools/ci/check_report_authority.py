#!/usr/bin/env python3
"""tools/ci/check_report_authority.py

Gate: verify the Report Authority is correctly wired and internally consistent.

Checks:
  1. All expected service module files exist
  2. engine.py declares ReportAuthorityEngine class
  3. models.py declares all required enums
  4. schemas.py declares all required exception classes
  5. API router file exists and declares correct endpoints
  6. ORM models file exists and declares required table classes
  7. Migration file exists
  8. Manifest integrity: hashing uses sort_keys + deterministic JSON
  9. No duplicate scoring logic (no score computation in renderer_pdf/html/json)
  10. report_authority is registered in authority_manifest.yaml

Exits 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SERVICE_DIR = ROOT / "services" / "report_authority"
API_ROUTER = ROOT / "api" / "report_authority.py"
DB_MODELS = ROOT / "api" / "db_models_report_authority.py"
MIGRATION = ROOT / "migrations" / "postgres" / "0142_report_authority.sql"
HASHING_MODULE = SERVICE_DIR / "hashing.py"
MANIFEST_MODULE = SERVICE_DIR / "manifest.py"
AUTHORITY_MANIFEST = ROOT / "authority_manifest.yaml"

RENDERER_FILES = [
    SERVICE_DIR / "renderer_pdf.py",
    SERVICE_DIR / "renderer_html.py",
    SERVICE_DIR / "renderer_json.py",
]

# ---------------------------------------------------------------------------
# Check 1: Required service module files
# ---------------------------------------------------------------------------

REQUIRED_SERVICE_FILES: list[str] = [
    "__init__.py",
    "engine.py",
    "models.py",
    "schemas.py",
    "repository.py",
    "hashing.py",
    "manifest.py",
    "signature.py",
    "export.py",
    "renderer_pdf.py",
    "renderer_html.py",
    "renderer_json.py",
    "versioning.py",
    "statistics.py",
    "validators.py",
    "metadata.py",
]

# ---------------------------------------------------------------------------
# Check 2-4: Required symbols
# ---------------------------------------------------------------------------

REQUIRED_ENGINE_CLASS = "ReportAuthorityEngine"

REQUIRED_ENUMS = [
    "ReportLifecycleState",
    "ReportType",
    "ReportFormat",
    "ReportSectionType",
    "ExportBundleState",
    "FindingSeverity",
]

REQUIRED_EXCEPTIONS = [
    "ReportAuthorityError",
    "ReportNotFound",
    "ReportTenantViolation",
    "ReportConflict",
    "ReportGenerationError",
]

# ---------------------------------------------------------------------------
# Check 6: Required ORM classes
# ---------------------------------------------------------------------------

REQUIRED_ORM_CLASSES = [
    "FaReport",
    "FaReportAuditEvent",
    "FaReportBundle",
]

# ---------------------------------------------------------------------------
# Check 5: Required route prefixes (at least 3 routes under /reports)
# ---------------------------------------------------------------------------

REQUIRED_ROUTE_PREFIX = "/reports"
MINIMUM_ROUTE_COUNT = 3

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CLASS_RE = re.compile(r"^\s*class\s+(\w+)", re.MULTILINE)
_FUNC_OR_CLASS_RE = re.compile(r"^\s*(?:class|def|async\s+def)\s+(\w+)", re.MULTILINE)
_ROUTE_STR_RE = re.compile(
    r'@router\.\w+\(\s*["\']([^"\']+)["\']', re.MULTILINE
)
_SORT_KEYS_RE = re.compile(r"sort_keys\s*=\s*True")
_JSON_DUMPS_RE = re.compile(r"json\.dumps\s*\(")
_QUALITY_SCORE_ASSIGN_RE = re.compile(r"\bquality_score\s*=")


def _read(path: Path) -> str | None:
    """Read file text; return None and record nothing (caller appends failure)."""
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Report Authority Gate")
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
            fail(f"Missing service file: services/report_authority/{fname}")
        else:
            vprint(f"  + services/report_authority/{fname}")

    # ------------------------------------------------------------------
    # Check 2: engine.py declares ReportAuthorityEngine
    # ------------------------------------------------------------------
    vprint("Check 2: engine.py declares ReportAuthorityEngine")
    engine_path = SERVICE_DIR / "engine.py"
    if engine_path.exists():
        text = _read(engine_path)
        if text is None:
            fail(f"Cannot read {engine_path.relative_to(ROOT)}")
        else:
            classes = _declared_classes(text)
            if REQUIRED_ENGINE_CLASS not in classes:
                fail(
                    f"services/report_authority/engine.py: "
                    f"missing class '{REQUIRED_ENGINE_CLASS}'"
                )
            else:
                vprint(f"  + class {REQUIRED_ENGINE_CLASS}")
    # (missing file already reported in check 1)

    # ------------------------------------------------------------------
    # Check 3: models.py declares all required enums
    # ------------------------------------------------------------------
    vprint("Check 3: models.py declares required enums")
    models_path = SERVICE_DIR / "models.py"
    if models_path.exists():
        text = _read(models_path)
        if text is None:
            fail(f"Cannot read {models_path.relative_to(ROOT)}")
        else:
            names = _declared_names(text)
            for enum_name in REQUIRED_ENUMS:
                if enum_name not in names:
                    fail(
                        f"services/report_authority/models.py: "
                        f"missing enum '{enum_name}'"
                    )
                else:
                    vprint(f"  + {enum_name}")

    # ------------------------------------------------------------------
    # Check 4: schemas.py declares all required exception classes
    # ------------------------------------------------------------------
    vprint("Check 4: schemas.py declares required exceptions")
    schemas_path = SERVICE_DIR / "schemas.py"
    if schemas_path.exists():
        text = _read(schemas_path)
        if text is None:
            fail(f"Cannot read {schemas_path.relative_to(ROOT)}")
        else:
            names = _declared_names(text)
            for exc_name in REQUIRED_EXCEPTIONS:
                if exc_name not in names:
                    fail(
                        f"services/report_authority/schemas.py: "
                        f"missing exception class '{exc_name}'"
                    )
                else:
                    vprint(f"  + {exc_name}")

    # ------------------------------------------------------------------
    # Check 5: API router file exists and declares correct endpoints
    # ------------------------------------------------------------------
    vprint("Check 5: API router file and route prefixes")
    if not API_ROUTER.exists():
        fail(f"Missing: {API_ROUTER.relative_to(ROOT)}")
    else:
        text = _read(API_ROUTER)
        if text is None:
            fail(f"Cannot read {API_ROUTER.relative_to(ROOT)}")
        else:
            routes = _extract_routes(text)
            vprint(f"  routes found: {routes}")
            matching = [r for r in routes if r == REQUIRED_ROUTE_PREFIX or r.startswith(REQUIRED_ROUTE_PREFIX)]
            if len(matching) < MINIMUM_ROUTE_COUNT:
                fail(
                    f"{API_ROUTER.relative_to(ROOT)}: "
                    f"expected at least {MINIMUM_ROUTE_COUNT} routes under "
                    f"'{REQUIRED_ROUTE_PREFIX}', found {len(matching)}: {matching}"
                )
            else:
                vprint(f"  + {len(matching)} route(s) under '{REQUIRED_ROUTE_PREFIX}'")

    # ------------------------------------------------------------------
    # Check 6: ORM models file exists and declares required table classes
    # ------------------------------------------------------------------
    vprint("Check 6: ORM models file and table classes")
    if not DB_MODELS.exists():
        fail(f"Missing: {DB_MODELS.relative_to(ROOT)}")
    else:
        text = _read(DB_MODELS)
        if text is None:
            fail(f"Cannot read {DB_MODELS.relative_to(ROOT)}")
        else:
            classes = _declared_classes(text)
            for cls_name in REQUIRED_ORM_CLASSES:
                if cls_name not in classes:
                    fail(
                        f"{DB_MODELS.relative_to(ROOT)}: "
                        f"missing ORM class '{cls_name}'"
                    )
                else:
                    vprint(f"  + {cls_name}")

    # ------------------------------------------------------------------
    # Check 7: Migration file exists
    # ------------------------------------------------------------------
    vprint("Check 7: migration file exists")
    if not MIGRATION.exists():
        fail(f"Missing migration: {MIGRATION.relative_to(ROOT)}")
    else:
        vprint(f"  + {MIGRATION.relative_to(ROOT)}")

    # ------------------------------------------------------------------
    # Check 8: Manifest integrity — hashing uses sort_keys + deterministic JSON
    # ------------------------------------------------------------------
    vprint("Check 8: manifest integrity (sort_keys=True in hashing/manifest)")
    for mod_path in (HASHING_MODULE, MANIFEST_MODULE):
        rel = mod_path.relative_to(ROOT)
        if mod_path.exists():
            text = _read(mod_path)
            if text is None:
                fail(f"Cannot read {rel}")
            else:
                has_json_dumps = bool(_JSON_DUMPS_RE.search(text))
                has_sort_keys = bool(_SORT_KEYS_RE.search(text))
                if has_json_dumps and not has_sort_keys:
                    fail(
                        f"{rel}: calls json.dumps() but does not pass sort_keys=True "
                        f"— manifest hashing must be deterministic"
                    )
                elif args.verbose:
                    if has_json_dumps:
                        vprint(f"  + {rel}: json.dumps with sort_keys=True")
                    else:
                        vprint(f"  + {rel}: no json.dumps calls (ok)")

    # ------------------------------------------------------------------
    # Check 9: No duplicate scoring logic in renderer files
    # ------------------------------------------------------------------
    vprint("Check 9: no quality_score assignment in renderer files")
    for renderer in RENDERER_FILES:
        rel = renderer.relative_to(ROOT)
        if renderer.exists():
            text = _read(renderer)
            if text is None:
                fail(f"Cannot read {rel}")
            else:
                if _QUALITY_SCORE_ASSIGN_RE.search(text):
                    fail(
                        f"{rel}: contains quality_score assignment — "
                        f"score computation must live in engine.py, not renderers"
                    )
                else:
                    vprint(f"  + {rel}: no quality_score assignment (ok)")

    # ------------------------------------------------------------------
    # Check 10: report_authority is registered in authority_manifest.yaml
    # ------------------------------------------------------------------
    vprint("Check 10: authority_manifest.yaml registration")
    if not AUTHORITY_MANIFEST.exists():
        fail(f"Missing: {AUTHORITY_MANIFEST.relative_to(ROOT)}")
    else:
        manifest_text = _read(AUTHORITY_MANIFEST)
        if manifest_text is None:
            fail(f"Cannot read {AUTHORITY_MANIFEST.relative_to(ROOT)}")
        else:
            if "report_authority" not in manifest_text:
                fail(
                    f"{AUTHORITY_MANIFEST.relative_to(ROOT)}: "
                    f"'report_authority' entry not found — "
                    f"add it under the 'authorities:' key"
                )
            else:
                vprint("  + report_authority found in authority_manifest.yaml")

    # ------------------------------------------------------------------
    # Result
    # ------------------------------------------------------------------
    if failures:
        print(f"\nReport Authority Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  x  {f}")
        return 1

    print("Report Authority Gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
