#!/usr/bin/env python3
"""tools/ci/check_authority_integration.py

Gate: verify every governance authority is fully wired before it can ship.

Usage:
  python tools/ci/check_authority_integration.py          # verify (CI default)
  python tools/ci/check_authority_integration.py --write  # regenerate manifest

Checks (verify mode):
  1. Every service with engine.py is declared in authority_manifest.yaml
     (or listed under library_services — services consumed as libraries, no own routes)
  2. All declared files exist on disk
  3. All db_models_* files are registered in api/db.py
  4. Every authority api_file router is included in api/main.py
  5. Each authority has at least one test file that exists on disk
  6. If cgin_snapshot: true, the api_file must contain a /cgin/ route
  7. If cgin_anonymized: false and cgin_snapshot: true, flag the authority
     (acknowledged debt — does not fail, but is reported)

Write mode:
  Scans services/ for engine.py files and api/db_models_* files.
  Writes discovered structure into authority_manifest.yaml.
  Consumers, events, reports, and cgin_anonymized must be filled in by hand.
  Safe to re-run: preserves hand-written fields that auto-discovery cannot derive.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "authority_manifest.yaml"
DB_PY = ROOT / "api" / "db.py"
MAIN_PY = ROOT / "api" / "main.py"
SERVICES_DIR = ROOT / "services"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _registered_db_models() -> set[str]:
    """Return set of 'api.db_models_*' module names imported in api/db.py."""
    txt = _read_text(DB_PY)
    return set(
        re.findall(
            r'importlib\.import_module\(\s*["\']'
            r"(api\.db_models[^\"']+)"
            r'["\']',
            txt,
            re.MULTILINE,
        )
    )


def _routers_in_main() -> set[str]:
    """Return set of api module names whose router is included in api/main.py."""
    # Collapse whitespace so multi-line imports match single-line patterns
    txt = re.sub(r"\s+", " ", _read_text(MAIN_PY))
    # from api.X import router
    imported = set(re.findall(r"from api\.(\w+) import router\b", txt))
    # from api.X import ( router as Y_router )  or  from api.X import router as Y
    aliased = set(re.findall(r"from api\.(\w+) import\s*\(?\s*router as \w+", txt))
    return imported | aliased


def _tables_in_db_models(db_models_path: Path) -> list[str]:
    txt = _read_text(db_models_path)
    return re.findall(r'__tablename__\s*=\s*["\'](\w+)["\']', txt)


def _services_with_engine() -> list[str]:
    return sorted(p.parent.name for p in SERVICES_DIR.glob("*/engine.py"))


def _api_module_name(api_file: str) -> str:
    """'api/foo_bar.py' → 'foo_bar'"""
    return Path(api_file).stem


def _db_module_name(db_models_file: str) -> str:
    """'api/db_models_foo.py' → 'api.db_models_foo'"""
    return "api." + Path(db_models_file).stem


# ---------------------------------------------------------------------------
# Verify mode
# ---------------------------------------------------------------------------


def verify(manifest: dict) -> int:
    errors: list[str] = []
    warnings: list[str] = []

    library_services: list[str] = manifest.get("library_services", [])
    authorities: dict = manifest.get("authorities", {})
    declared_services = set(authorities.keys()) | set(library_services)

    registered_db = _registered_db_models()
    routers_in_main = _routers_in_main()

    # -----------------------------------------------------------------------
    # Check 1: every service with engine.py must be declared
    # -----------------------------------------------------------------------
    for svc in _services_with_engine():
        if svc not in declared_services:
            errors.append(
                f"UNDECLARED SERVICE: services/{svc}/engine.py exists but '{svc}' "
                f"is not in authority_manifest.yaml. "
                f"Run: python tools/ci/check_authority_integration.py --write"
            )

    # -----------------------------------------------------------------------
    # Check 2–7: per-authority checks
    # -----------------------------------------------------------------------
    for name, auth in authorities.items():
        prefix = f"[{name}]"

        # skip_checks allows older authorities to acknowledge gaps without failing CI.
        # Accepted values: db_registration, tables, tests, router
        # Each skipped check is a documented gap, not a silent exclusion.
        skip = set(auth.get("skip_checks", []))

        # 2a. engine directory exists (engine.py required unless no_engine_py: true)
        engine_dir = ROOT / auth.get("engine", f"services/{name}")
        if not engine_dir.is_dir():
            errors.append(
                f"{prefix} engine dir not found: {engine_dir.relative_to(ROOT)}"
            )
        elif not auth.get("no_engine_py") and not (engine_dir / "engine.py").exists():
            errors.append(
                f"{prefix} engine.py not found in {engine_dir.relative_to(ROOT)}. "
                f"Set no_engine_py: true in manifest if this authority pre-dates the pattern."
            )

        # 2b. api_file exists
        api_file = auth.get("api_file")
        if api_file:
            api_path = ROOT / api_file
            if not api_path.exists():
                errors.append(f"{prefix} api_file not found: {api_file}")

            # Check 4: router included in main.py
            module_name = _api_module_name(api_file)
            if module_name not in routers_in_main:
                if "router" in skip:
                    warnings.append(
                        f"{prefix} SKIPPED(router): '{api_file}' not in main.py — "
                        f"acknowledged gap"
                    )
                else:
                    errors.append(
                        f"{prefix} router from '{api_file}' is not included in api/main.py"
                    )

        # 2c. db_models file exists and is registered in db.py
        db_models_file = auth.get("db_models")
        if db_models_file:
            db_path = ROOT / db_models_file
            if not db_path.exists():
                errors.append(f"{prefix} db_models not found: {db_models_file}")
            else:
                # Check 3: registered in db.py
                mod_name = _db_module_name(db_models_file)
                if mod_name not in registered_db:
                    if "db_registration" in skip:
                        warnings.append(
                            f"{prefix} SKIPPED(db_registration): '{mod_name}' "
                            f"not in api/db.py — acknowledged gap"
                        )
                    else:
                        errors.append(
                            f"{prefix} db_models '{db_models_file}' is not registered "
                            f"in api/db.py via importlib.import_module('{mod_name}')"
                        )

                # Cross-check declared tables vs actual ORM models
                # tables: null in manifest means "not yet cataloged — skip check"
                declared_tables_raw = auth.get("tables")
                if declared_tables_raw is not None and "tables" not in skip:
                    declared_tables = set(declared_tables_raw)
                    actual_tables = set(_tables_in_db_models(db_path))
                    missing = declared_tables - actual_tables
                    extra = actual_tables - declared_tables
                    if missing:
                        errors.append(
                            f"{prefix} tables declared in manifest but not in db_models: "
                            f"{sorted(missing)}"
                        )
                    if extra:
                        errors.append(
                            f"{prefix} tables in db_models not declared in manifest: "
                            f"{sorted(extra)}. Run --write to update."
                        )
                elif "tables" in skip:
                    warnings.append(
                        f"{prefix} SKIPPED(tables): table cross-check waived — "
                        f"populate manifest when tables are stable"
                    )

        # Check 5: at least one test file exists
        test_files = auth.get("tests")
        if "tests" in skip:
            warnings.append(
                f"{prefix} SKIPPED(tests): no tests — acknowledged gap; add tests"
            )
        elif not test_files:
            errors.append(
                f"{prefix} no tests declared. Add at least one test file to manifest, "
                f"or add 'tests' to skip_checks to acknowledge the gap."
            )
        else:
            existing = [t for t in test_files if (ROOT / t).exists()]
            if not existing:
                errors.append(f"{prefix} no test files exist on disk: {test_files}")
            missing_tests = [t for t in test_files if not (ROOT / t).exists()]
            if missing_tests:
                errors.append(
                    f"{prefix} declared test files missing from disk: {missing_tests}"
                )

        # Check 6: if cgin_snapshot: true, api_file must have a /cgin/ route
        if auth.get("cgin_snapshot") and api_file:
            api_path = ROOT / api_file
            if api_path.exists():
                txt = _read_text(api_path)
                if "/cgin/" not in txt:
                    errors.append(
                        f"{prefix} cgin_snapshot: true but no '/cgin/' route found "
                        f"in {api_file}"
                    )

        # Check 7: CGIN anonymization — FAIL if not anonymized
        if auth.get("cgin_snapshot") and not auth.get("cgin_anonymized"):
            errors.append(
                f"{prefix} CGIN snapshot uses raw tenant_id (cgin_anonymized: false). "
                "All CGIN-producing authorities must use tenant_fingerprint. "
                "Import from services.cgin.privacy and set cgin_anonymized: true in authority_manifest.yaml."
            )

        # Check 8: declared consumer files exist
        for consumer in auth.get("consumers", []):
            if not (ROOT / consumer).exists():
                errors.append(
                    f"{prefix} declared consumer not found on disk: {consumer}"
                )

    # -----------------------------------------------------------------------
    # Structural check: every api/db_models_*.py must be registered in db.py
    # (independent of manifest — catches orphan db_models files)
    # -----------------------------------------------------------------------
    all_db_model_files = list((ROOT / "api").glob("db_models_*.py"))
    # Some db_models files are known non-authority stubs — allow explicit exclusions
    known_exclusions = {
        "api.db_models_billing",  # standalone billing integration layer
        "api.db_models_subscriptions",  # standalone subscription management
        "api.db_models_governance_event",  # legacy event ledger (H14)
    }
    for db_file in sorted(all_db_model_files):
        mod = "api." + db_file.stem
        if mod in known_exclusions:
            continue
        if mod not in registered_db:
            errors.append(
                f"ORPHAN DB_MODELS: {db_file.relative_to(ROOT)} exists but is not "
                f"imported in api/db.py and is not in the exclusion list. "
                f"Add: importlib.import_module('{mod}')"
            )

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------
    if warnings:
        print("Warnings (acknowledged tech debt):")
        for w in warnings:
            print(f"  ⚠  {w}")

    if errors:
        print(f"\nAuthority integration gate: FAILED ({len(errors)} error(s))")
        for e in errors:
            print(f"  ✗  {e}")
        return 1

    n = len(authorities)
    print(
        f"Authority integration gate: OK "
        f"({n} authorit{'ies' if n != 1 else 'y'} verified, "
        f"{len(warnings)} warning(s))"
    )
    return 0


# ---------------------------------------------------------------------------
# Write mode — auto-discover and regenerate manifest
# ---------------------------------------------------------------------------


def _find_api_file(svc_name: str) -> str | None:
    """Best-effort mapping from service name to api/*.py file."""
    candidates = [
        ROOT / "api" / f"{svc_name}.py",
        ROOT / "api" / f"{svc_name.replace('_authority', '')}.py",
    ]
    for c in candidates:
        if c.exists():
            return str(c.relative_to(ROOT))
    return None


def _find_db_models_file(svc_name: str) -> str | None:
    candidates = [
        ROOT / "api" / f"db_models_{svc_name}.py",
    ]
    for c in candidates:
        if c.exists():
            return str(c.relative_to(ROOT))
    return None


def _find_tests(svc_name: str) -> list[str]:
    patterns = [
        f"tests/test_{svc_name}.py",
        f"tests/test_h*_{svc_name}.py",
        f"tests/test_h*_{svc_name.replace('_authority', '')}.py",
    ]
    found: list[str] = []
    for pat in patterns:
        hits = sorted(ROOT.glob(pat))
        found.extend(str(h.relative_to(ROOT)) for h in hits)
    return sorted(set(found))


def _extract_route_prefixes(api_file_path: str) -> list[str]:
    path = ROOT / api_file_path
    if not path.exists():
        return []
    txt = _read_text(path)
    # Find router prefix
    prefixes = re.findall(r'APIRouter\([^)]*prefix\s*=\s*["\']([^"\']+)["\']', txt)
    if prefixes:
        return prefixes
    # Derive from first few unique base paths
    routes = re.findall(r'@router\.\w+\(\s*["\'](/[^"\'/{]+)', txt)
    return sorted(set(routes))[:3]


def write_manifest(existing_manifest: dict | None) -> None:
    """Regenerate authority_manifest.yaml from code structure.

    Preserves hand-written fields (consumers, events, reports, cgin_anonymized)
    from the existing manifest where they exist.
    """
    existing_authorities: dict = (existing_manifest or {}).get("authorities", {})
    existing_library: list = (existing_manifest or {}).get("library_services", [])

    services = _services_with_engine()
    registered_db = _registered_db_models()
    routers_in_main = _routers_in_main()

    # Determine which services are library-only (no api file found)
    library_services: list[str] = []
    authority_services: list[str] = []
    for svc in services:
        api_file = _find_api_file(svc)
        if api_file is None:
            library_services.append(svc)
        else:
            authority_services.append(svc)

    # Preserve hand-curated library_services from existing manifest
    for lib in existing_library:
        if lib not in library_services:
            library_services.append(lib)

    authorities: dict = {}
    for svc in authority_services:
        existing = existing_authorities.get(svc, {})

        api_file = _find_api_file(svc)
        db_models_file = _find_db_models_file(svc)

        tables: list[str] = []
        if db_models_file:
            db_path = ROOT / db_models_file
            tables = sorted(_tables_in_db_models(db_path))

        tests = _find_tests(svc)
        route_prefixes = _extract_route_prefixes(api_file) if api_file else []

        has_cgin = False
        if api_file:
            api_path = ROOT / api_file
            if api_path.exists() and "/cgin/" in _read_text(api_path):
                has_cgin = True

        is_registered_in_db = (
            _db_module_name(db_models_file) in registered_db if db_models_file else None
        )
        is_in_main = _api_module_name(api_file) in routers_in_main if api_file else None

        entry: dict = {
            "engine": f"services/{svc}",
            "api_file": api_file,
            "db_models": db_models_file,
            "route_prefixes": existing.get("route_prefixes") or route_prefixes,
            "tables": existing.get("tables") or tables,
            "tests": existing.get("tests") or tests or [],
            "cgin_snapshot": has_cgin,
            # Preserve hand-written fields — auto-discovery cannot derive these
            "cgin_anonymized": existing.get("cgin_anonymized", False),
            "consumers": existing.get("consumers", []),
        }

        # Preserve no_engine_py and skip_checks if set in existing manifest
        if existing.get("no_engine_py"):
            entry["no_engine_py"] = True
        if existing.get("skip_checks"):
            entry["skip_checks"] = existing["skip_checks"]

        if is_registered_in_db is False and "db_registration" not in set(
            existing.get("skip_checks", [])
        ):
            entry["_warn_db_not_registered"] = True
        if is_in_main is False and "router" not in set(existing.get("skip_checks", [])):
            entry["_warn_not_in_main"] = True

        authorities[svc] = entry

    # Build final manifest
    manifest: dict = {
        "manifest_version": "1.0",
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "library_services": sorted(set(library_services)),
        "authorities": authorities,
    }

    header = """\
# authority_manifest.yaml
# Machine-verifiable declaration of every governance authority's integration surface.
#
# Maintained by: humans (consumers, events, reports, cgin_anonymized)
# Verified by:   python tools/ci/check_authority_integration.py
# Regenerate:    python tools/ci/check_authority_integration.py --write
#
# Fields auto-discovered by --write:
#   engine, api_file, db_models, tables, route_prefixes, tests, cgin_snapshot
# Fields requiring human input after --write:
#   consumers, cgin_anonymized (set true only when sha256 fingerprinting is used)
#   _warn_db_not_registered / _warn_not_in_main — fix these before committing

"""
    MANIFEST_PATH.write_text(
        header + yaml.dump(manifest, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    print(f"Wrote {MANIFEST_PATH.relative_to(ROOT)}")
    print(
        f"  {len(authority_services)} authorit{'ies' if len(authority_services) != 1 else 'y'} discovered"
    )
    print(f"  {len(library_services)} library service(s) declared")
    print(
        "Review _warn_* fields and fill in consumers/cgin_anonymized before committing."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="Regenerate authority_manifest.yaml from code structure",
    )
    args = parser.parse_args()

    if not MANIFEST_PATH.exists() and not args.write:
        print(
            f"ERROR: {MANIFEST_PATH.relative_to(ROOT)} not found. "
            "Run: python tools/ci/check_authority_integration.py --write",
            file=sys.stderr,
        )
        return 1

    manifest: dict | None = None
    if MANIFEST_PATH.exists():
        with MANIFEST_PATH.open(encoding="utf-8") as f:
            manifest = yaml.safe_load(f)

    if args.write:
        write_manifest(manifest)
        return 0

    if manifest is None:
        print("ERROR: empty manifest", file=sys.stderr)
        return 1

    return verify(manifest)


if __name__ == "__main__":
    sys.exit(main())
