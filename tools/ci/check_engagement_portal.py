#!/usr/bin/env python3
"""tools/ci/check_engagement_portal.py

Gate: verify the Engagement Portal Authority (PR 18.2) is correctly wired
and internally consistent.

Checks:
  1.  services/engagement_portal/engine.py exists
  2.  EngagementPortalEngine class is declared
  3.  api/engagement_portal.py exists
  4.  /portal/engagement/health route present
  5.  /portal/engagement/dashboard route present
  6.  api/db_models_engagement_portal.py exists
  7.  PortalEngagementActivity ORM class declared
  8.  engagement_portal entry in authority_manifest.yaml
  9.  /portal/engagement prefix registered in services/plane_registry/registry.py
  10. portal_engagement_activity table created in migration 0143
  11. No inline cross-authority SQL (engine.py must not embed text SQL targeting
      fa_evidence/fa_engagements/fa_report tables — it accesses authorities via
      SQLAlchemy ORM only, not raw text)
  12. Tenant isolation: require_bound_tenant is imported in API file

Exits 0 on success, 1 on failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SERVICE_DIR = ROOT / "services" / "engagement_portal"
ENGINE_FILE = SERVICE_DIR / "engine.py"
API_FILE = ROOT / "api" / "engagement_portal.py"
DB_MODELS_FILE = ROOT / "api" / "db_models_engagement_portal.py"
MIGRATION_FILE = ROOT / "migrations" / "postgres" / "0143_engagement_portal.sql"
AUTHORITY_MANIFEST = ROOT / "authority_manifest.yaml"
PLANE_REGISTRY = ROOT / "services" / "plane_registry" / "registry.py"

_ROUTE_RE = re.compile(r'@router\.\w+\(\s*["\']([^"\']+)["\']', re.MULTILINE)
_CLASS_RE = re.compile(r"^\s*class\s+(\w+)", re.MULTILINE)
# Matches text SQL like sqlalchemy.text("select ... from fa_evidence ...")
_RAW_SQL_RE = re.compile(
    r'(?:text|execute)\s*\(\s*["\'][^"\']*\b(fa_evidence|fa_engagements|fa_report)\b',
    re.IGNORECASE,
)

FAILURES: list[str] = []


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        FAILURES.append(f"{name}: {detail}" if detail else name)


def main() -> int:
    # 1. engine.py exists
    check(
        "engine.py exists",
        ENGINE_FILE.exists(),
        f"missing {ENGINE_FILE.relative_to(ROOT)}",
    )

    # 2. EngagementPortalEngine class declared
    engine_text = _read(ENGINE_FILE)
    classes = set(_CLASS_RE.findall(engine_text))
    check(
        "EngagementPortalEngine class declared",
        "EngagementPortalEngine" in classes,
        "class not found in services/engagement_portal/engine.py",
    )

    # 3. api/engagement_portal.py exists
    check(
        "api/engagement_portal.py exists",
        API_FILE.exists(),
        f"missing {API_FILE.relative_to(ROOT)}",
    )

    api_text = _read(API_FILE)
    routes = set(_ROUTE_RE.findall(api_text))

    # 4. /portal/engagement/health route present
    check(
        "/portal/engagement/health route present",
        "/portal/engagement/health" in routes,
        "route declaration not found",
    )

    # 5. /portal/engagement/dashboard route present
    check(
        "/portal/engagement/dashboard route present",
        "/portal/engagement/dashboard" in routes,
        "route declaration not found",
    )

    # 6. db_models file exists
    check(
        "api/db_models_engagement_portal.py exists",
        DB_MODELS_FILE.exists(),
        f"missing {DB_MODELS_FILE.relative_to(ROOT)}",
    )

    # 7. PortalEngagementActivity declared
    db_text = _read(DB_MODELS_FILE)
    db_classes = set(_CLASS_RE.findall(db_text))
    check(
        "PortalEngagementActivity ORM class declared",
        "PortalEngagementActivity" in db_classes,
        "class not found in api/db_models_engagement_portal.py",
    )

    # 8. engagement_portal in authority_manifest.yaml
    manifest_text = _read(AUTHORITY_MANIFEST)
    check(
        "engagement_portal in authority_manifest.yaml",
        "engagement_portal:" in manifest_text,
        "entry not found under 'authorities:'",
    )

    # 9. /portal/engagement registered in plane registry
    registry_text = _read(PLANE_REGISTRY)
    check(
        "/portal/engagement in plane registry route_prefixes",
        '"/portal/engagement"' in registry_text,
        "prefix not registered in services/plane_registry/registry.py",
    )

    # 10. portal_engagement_activity table in migration 0143
    migration_text = _read(MIGRATION_FILE)
    check(
        "portal_engagement_activity table in migration 0143",
        "portal_engagement_activity" in migration_text,
        f"table not found in {MIGRATION_FILE.relative_to(ROOT)}",
    )

    # 11. No inline cross-authority text SQL in engine.py
    check(
        "No inline SQL targeting fa_evidence/fa_engagements/fa_report in engine.py",
        _RAW_SQL_RE.search(engine_text) is None,
        "engine.py must access authorities via ORM, not text SQL",
    )

    # 12. Tenant isolation: require_bound_tenant used in API
    check(
        "require_bound_tenant imported in api/engagement_portal.py",
        "require_bound_tenant" in api_text,
        "API file must import and use require_bound_tenant",
    )

    if FAILURES:
        print(f"FAIL ({len(FAILURES)} check(s)):")
        for f in FAILURES:
            print(f"  - {f}")
        return 1

    print("OK (12 checks passed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
