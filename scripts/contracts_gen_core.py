from __future__ import annotations

# =============================================================================
# Core OpenAPI contract generation (NO admin routes)
# =============================================================================

import json
import os
from pathlib import Path
from typing import Any, Dict

OUTPUT_PATH = Path("contracts/core/openapi.json")

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
# Environment freeze
# -----------------------


def _freeze_contract_env() -> None:
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    os.environ.setdefault("FG_CONTRACT_SPEC", "prod")
    os.environ.setdefault("FG_ENV", "prod")
    os.environ.setdefault("FG_DEV_EVENTS_ENABLED", "0")
    os.environ.setdefault("FG_AUTH_ENABLED", "1")
    os.environ.setdefault("FG_UI_ENABLED", "0")
    os.environ.setdefault("FG_UI_TOKEN_GET_ENABLED", "0")
    os.environ.setdefault("FG_FORENSICS_ENABLED", "0")
    os.environ.setdefault("FG_GOVERNANCE_ENABLED", "1")
    os.environ.setdefault("FG_MISSION_ENVELOPE_ENABLED", "1")
    os.environ.setdefault("FG_RING_ROUTER_ENABLED", "1")
    os.environ.setdefault("FG_ROE_ENGINE_ENABLED", "1")
    os.environ.setdefault("FG_ADMIN_ENABLED", "0")  # critical


# -----------------------
# Generation
# -----------------------


def generate_openapi() -> Dict[str, Any]:
    _freeze_contract_env()

    from api.main import build_app  # delayed import by design

    app = build_app(auth_enabled=True)
    openapi = app.openapi()

    openapi = _filter_admin_paths(openapi)
    _assert_no_admin_leak(openapi)

    return openapi


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    spec = generate_openapi()
    OUTPUT_PATH.write_text(_render_openapi(spec), encoding="utf-8")


if __name__ == "__main__":
    main()
