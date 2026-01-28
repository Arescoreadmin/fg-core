#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Type

from pydantic import BaseModel

from contracts.admin import schemas


OUTPUT_DIR = Path("contracts/admin")

MODELS: Dict[str, Type[BaseModel]] = {
    "health": schemas.HealthResponse,
    "version": schemas.VersionResponse,
    "audit": schemas.AuditLogEntry,
}


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    os.environ.setdefault("FG_CONTRACTS_GEN", "1")
    from admin_gateway.main import build_app

    app = build_app()
    openapi = app.openapi()
    _write_json(OUTPUT_DIR / "openapi.json", openapi)

    for name, model in MODELS.items():
        schema = model.model_json_schema()
        schema.setdefault("$schema", "https://json-schema.org/draft/2020-12/schema")
        _write_json(OUTPUT_DIR / f"{name}.json", schema)


if __name__ == "__main__":
    main()
