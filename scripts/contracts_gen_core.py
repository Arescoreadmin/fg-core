#!/usr/bin/env python3
from __future__ import annotations

# =============================================================================
# Core OpenAPI contract generation (NO admin routes)
# =============================================================================

import json
import os
from pathlib import Path
from typing import Any, Dict

CORE_OUTPUT_PATH = Path("contracts/core/openapi.json")
SCHEMA_OPENAPI_MIRROR_PATH = Path("schemas/api/openapi.json")

SCHEMA_REGISTRY_DIR = Path("schemas/api")
HEALTH_SCHEMA_PATH = SCHEMA_REGISTRY_DIR / "health.schema.json"
HEALTH_SCHEMA_REF = "schemas/api/health.schema.json"


# -----------------------
# Rendering / normalization
# -----------------------


def _render_openapi(payload: Dict[str, Any]) -> str:
    """
    Canonical JSON rendering for OpenAPI artifacts.
    Must be deterministic for diff-based contract checks.
    """
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


# Back-compat: contracts_diff_core imports render_openapi
def render_openapi(payload: Dict[str, Any]) -> str:
    return _render_openapi(payload)


# -----------------------
# Filtering / invariants
# -----------------------


def _filter_admin_paths(openapi: Dict[str, Any]) -> Dict[str, Any]:
    paths = openapi.get("paths", {})
    if isinstance(paths, dict):
        openapi["paths"] = {
            p: spec for p, spec in paths.items() if not str(p).startswith("/admin/")
        }

    tags = openapi.get("tags")
    if isinstance(tags, list):
        openapi["tags"] = [
            t for t in tags if isinstance(t, dict) and t.get("name") != "admin"
        ]

    return openapi


def _assert_no_admin_leak(openapi: Dict[str, Any]) -> None:
    paths = openapi.get("paths", {})
    if not isinstance(paths, dict):
        return

    leaked = sorted(p for p in paths if str(p).startswith("/admin/"))
    if leaked:
        sample = "\n".join(leaked[:20])
        raise SystemExit(
            "ERROR: core OpenAPI contract contains /admin/* routes.\n"
            "This breaks contracts/core/openapi.json invariants.\n"
            f"Leaked paths (first 20):\n{sample}\n"
            "Fix: ensure admin router is not mounted in core contract mode."
        )


# -----------------------
# Schema injection (BP-C-003 support)
# -----------------------


def _inject_schema_refs(openapi: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure the canonical core OpenAPI includes at least one stable $ref into
    schemas/api/ so schema validation gates are verifiable.

    This must happen *during generation* so BP-C-002 (regen drift) remains strict.
    """
    # If schemas/api exists, we require the referenced file to exist too.
    if SCHEMA_REGISTRY_DIR.exists() and not HEALTH_SCHEMA_PATH.exists():
        raise SystemExit(
            "ERROR: schemas/api exists but schemas/api/health.schema.json is missing.\n"
            "BP-C-003 requires referenced schemas to exist.\n"
            "Fix: add schemas/api/health.schema.json (Draft 2020-12) or change injected ref."
        )

    if not SCHEMA_REGISTRY_DIR.exists():
        return openapi

    components = openapi.setdefault("components", {})
    if not isinstance(components, dict):
        raise SystemExit("ERROR: OpenAPI components is not a dict")

    schemas = components.setdefault("schemas", {})
    if not isinstance(schemas, dict):
        raise SystemExit("ERROR: OpenAPI components.schemas is not a dict")

    # Deterministic: only add if absent
    schemas.setdefault("Health", {"$ref": HEALTH_SCHEMA_REF})

    return openapi


# -----------------------
# Environment freeze
# -----------------------


def _freeze_contract_env() -> None:
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    os.environ["FG_CONTRACT_SPEC"] = "prod"
    os.environ["FG_ENV"] = "prod"
    os.environ["FG_ADMIN_ENABLED"] = "0"
    os.environ.setdefault("FG_DEV_EVENTS_ENABLED", "0")
    os.environ.setdefault("FG_AUTH_ENABLED", "1")
    os.environ.setdefault("FG_UI_ENABLED", "0")
    os.environ.setdefault("FG_UI_TOKEN_GET_ENABLED", "0")
    os.environ.setdefault("FG_FORENSICS_ENABLED", "0")
    os.environ.setdefault("FG_GOVERNANCE_ENABLED", "1")
    os.environ.setdefault("FG_MISSION_ENVELOPE_ENABLED", "1")
    os.environ.setdefault("FG_RING_ROUTER_ENABLED", "1")
    os.environ.setdefault("FG_ROE_ENGINE_ENABLED", "1")


# -----------------------
# Generation
# -----------------------


def generate_openapi() -> Dict[str, Any]:
    _freeze_contract_env()

    from api.main import build_app  # delayed import by design

    app = build_app(auth_enabled=True)
    openapi = app.openapi()

    openapi = _filter_admin_paths(openapi)
    openapi = _inject_schema_refs(openapi)
    _assert_no_admin_leak(openapi)

    return openapi


def main() -> None:
    spec = generate_openapi()
    rendered = _render_openapi(spec)

    CORE_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_OPENAPI_MIRROR_PATH.parent.mkdir(parents=True, exist_ok=True)

    CORE_OUTPUT_PATH.write_text(rendered, encoding="utf-8")
    SCHEMA_OPENAPI_MIRROR_PATH.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
