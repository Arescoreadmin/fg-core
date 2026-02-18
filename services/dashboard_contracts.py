from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ContractLoadError(RuntimeError):
    pass


def load_json_contract(
    path: Path,
    *,
    root: Path,
    max_bytes: int = 256 * 1024,
    refuse_symlink: bool = True,
    refuse_hardlink: bool = True,
) -> dict[str, Any]:
    if ".." in path.parts:
        raise ContractLoadError(f"path traversal denied: {path}")

    resolved_root = root.resolve()
    resolved_path = path.resolve(strict=True)
    if resolved_root not in resolved_path.parents and resolved_path != resolved_root:
        raise ContractLoadError(f"path outside allowed root: {path}")

    if refuse_symlink and (path.is_symlink() or resolved_path.is_symlink()):
        raise ContractLoadError(f"symlink contract denied: {path}")

    st = resolved_path.stat()
    size = st.st_size
    if size > max_bytes:
        raise ContractLoadError(f"contract too large: {path} ({size} > {max_bytes})")
    if refuse_hardlink and getattr(st, "st_nlink", 1) > 1:
        raise ContractLoadError(f"hardlink contract denied: {path}")

    try:
        return json.loads(resolved_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ContractLoadError(f"invalid json in {path}: {exc}") from exc


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_views_contract(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    dashboards = payload.get("dashboards")
    if not isinstance(dashboards, list):
        return ["dashboards must be an array"]
    for i, dashboard in enumerate(dashboards):
        if not isinstance(dashboard, dict):
            errors.append(f"dashboards[{i}] must be an object")
            continue
        if not _is_non_empty_string(dashboard.get("id")):
            errors.append(f"dashboards[{i}].id must be a non-empty string")
        if not _is_non_empty_string(dashboard.get("title")):
            errors.append(f"dashboards[{i}].title must be a non-empty string")
        widgets = dashboard.get("widgets")
        if not isinstance(widgets, list) or any(not isinstance(w, str) for w in widgets):
            errors.append(f"dashboards[{i}].widgets must be an array of strings")
        persona = dashboard.get("persona")
        if not isinstance(persona, dict) or not isinstance(persona.get("allowed"), list):
            errors.append(f"dashboards[{i}].persona.allowed must be an array")
    return errors


def validate_widget_contract(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("id", "version", "data_provider"):
        if not _is_non_empty_string(payload.get(field)):
            errors.append(f"{field} must be a non-empty string")

    permissions = payload.get("permissions")
    if not isinstance(permissions, dict):
        errors.append("permissions must be an object")
    else:
        scopes = permissions.get("scopes")
        if not isinstance(scopes, list) or any(not isinstance(s, str) for s in scopes):
            errors.append("permissions.scopes must be an array of strings")
        for field in ("admin_override_allowed", "tenant_safe"):
            if not isinstance(permissions.get(field), bool):
                errors.append(f"permissions.{field} must be a boolean")

    refresh_policy = payload.get("refresh_policy")
    if not isinstance(refresh_policy, dict):
        errors.append("refresh_policy must be an object")
    else:
        interval = refresh_policy.get("interval_seconds")
        if not isinstance(interval, int) or interval < 1:
            errors.append("refresh_policy.interval_seconds must be an integer >= 1")

    if not isinstance(payload.get("degrade_ok"), bool):
        errors.append("degrade_ok must be a boolean")
    if not isinstance(payload.get("render_hints"), dict):
        errors.append("render_hints must be an object")
    return errors


def validate_theme_contract(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("brand_name", "logo_url"):
        if not _is_non_empty_string(payload.get(field)):
            errors.append(f"{field} must be a non-empty string")
    if not isinstance(payload.get("palette"), dict):
        errors.append("palette must be an object")
    if not isinstance(payload.get("title_suffix"), str):
        errors.append("title_suffix must be a string")
    css = payload.get("css_overrides")
    if css is not None and not isinstance(css, str):
        errors.append("css_overrides must be a string or null")
    return errors
