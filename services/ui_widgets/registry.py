from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from api.config.env import is_production_env
from services.dashboard_contracts import (
    ContractLoadError,
    load_json_contract,
    validate_widget_contract,
)

_WIDGET_ROOT = Path("contracts/dashboard").resolve()
_WIDGET_DIR = _WIDGET_ROOT / "widgets"
_WIDGET_SCHEMA = _WIDGET_ROOT / "schema" / "widget.schema.json"


class WidgetContractError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_widget_contracts() -> dict[str, dict[str, Any]]:
    widgets: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    _ = load_json_contract(_WIDGET_SCHEMA, root=_WIDGET_ROOT)
    if not _WIDGET_DIR.exists():
        return widgets
    for path in sorted(_WIDGET_DIR.glob("*.json")):
        try:
            payload = load_json_contract(path, root=_WIDGET_ROOT)
        except ContractLoadError as exc:
            errors.append(str(exc))
            continue
        for err in validate_widget_contract(payload):
            errors.append(f"{path}: {err}")
        widget_id = str(payload.get("id") or "").strip()
        if not widget_id:
            errors.append(f"{path}: missing widget id")
            continue
        widgets[widget_id] = payload

    if errors:
        message = "Invalid widget contracts: " + "; ".join(errors)
        if is_production_env() or (os.getenv("FG_ENV", "").lower() == "staging"):
            raise WidgetContractError(message)
        print(f"[ui-widgets] warning: {message}")
    return widgets


def get_widget_contract(widget_id: str) -> dict[str, Any] | None:
    return load_widget_contracts().get(widget_id)
