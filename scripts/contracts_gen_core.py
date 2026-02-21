#!/usr/bin/env python3
from __future__ import annotations

# =============================================================================
# Core OpenAPI contract generation (NO admin routes)
# =============================================================================

from dataclasses import dataclass
import os
import warnings
from pathlib import Path
from typing import Any, Dict

from scripts.openapi_canonical import normalize_openapi, render_openapi

CORE_OUTPUT_PATH = Path("contracts/core/openapi.json")
SCHEMA_OPENAPI_MIRROR_PATH = Path("schemas/api/openapi.json")

SCHEMA_REGISTRY_DIR = Path("schemas/api")
HEALTH_SCHEMA_PATH = SCHEMA_REGISTRY_DIR / "health.schema.json"
HEALTH_SCHEMA_REF = "schemas/api/health.schema.json"


# -----------------------
# Rendering / normalization
# -----------------------


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
# Generation
# -----------------------


@dataclass(frozen=True)
class ContractSettings:
    title: str = "frostgate-core"
    version: str = "0.8.0"
    servers: tuple[dict[str, str], ...] = ()


def generate_openapi(settings: ContractSettings | None = None) -> Dict[str, Any]:
    from api.main import build_contract_app  # delayed import by design

    effective = settings or ContractSettings()
    prior_env = os.environ.get("FG_ENV")
    os.environ["FG_ENV"] = "prod"
    try:
        app = build_contract_app(settings=effective)
    finally:
        if prior_env is None:
            os.environ.pop("FG_ENV", None)
        else:
            os.environ["FG_ENV"] = prior_env
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        openapi = normalize_openapi(app.openapi())

    openapi = _filter_admin_paths(openapi)
    openapi = _inject_schema_refs(openapi)
    _assert_no_admin_leak(openapi)

    return normalize_openapi(openapi)


def main() -> None:
    spec = generate_openapi()
    rendered = render_openapi(spec)

    CORE_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_OPENAPI_MIRROR_PATH.parent.mkdir(parents=True, exist_ok=True)

    CORE_OUTPUT_PATH.write_text(rendered, encoding="utf-8")
    SCHEMA_OPENAPI_MIRROR_PATH.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
