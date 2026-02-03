#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

OUTPUT_PATH = Path("contracts/core/openapi.json")


def render_openapi(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _freeze_contract_env() -> None:
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_DEV_EVENTS_ENABLED", "0")
    os.environ.setdefault("FG_AUTH_ENABLED", "0")
    os.environ.setdefault("FG_UI_TOKEN_GET_ENABLED", "0")
    os.environ.setdefault("FG_FORENSICS_ENABLED", "0")
    os.environ.setdefault("FG_GOVERNANCE_ENABLED", "0")
    os.environ.setdefault("FG_MISSION_ENVELOPES_ENABLED", "0")
    os.environ.setdefault("FG_RING_ROUTER_ENABLED", "0")
    os.environ.setdefault("FG_ROE_ENGINE_ENABLED", "0")


def _filter_admin_paths(openapi: Dict[str, Any]) -> Dict[str, Any]:
    paths = openapi.get("paths", {})
    if isinstance(paths, dict):
        openapi["paths"] = {
            path: spec
            for path, spec in paths.items()
            if not str(path).startswith("/admin/")
        }

    tags = openapi.get("tags")
    if isinstance(tags, list):
        openapi["tags"] = [tag for tag in tags if tag.get("name") != "admin"]
    return openapi


def generate_openapi() -> Dict[str, Any]:
    _freeze_contract_env()

    from api.main import build_app

    app = build_app(auth_enabled=False)
    openapi = app.openapi()
    return _filter_admin_paths(openapi)


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    openapi = generate_openapi()
    OUTPUT_PATH.write_text(render_openapi(openapi), encoding="utf-8")


if __name__ == "__main__":
    main()
