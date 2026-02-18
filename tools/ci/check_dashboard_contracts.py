from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _validate(schema_path: Path, payload_path: Path) -> list[str]:
    schema = _read(schema_path)
    payload = _read(payload_path)
    v = Draft202012Validator(schema)
    return [f"{payload_path}: {e.message}" for e in v.iter_errors(payload)]


def main() -> int:
    errors: list[str] = []
    views_path = ROOT / "contracts/dashboard/views.json"
    views_schema = ROOT / "contracts/dashboard/schema/views.schema.json"
    widget_schema = ROOT / "contracts/dashboard/schema/widget.schema.json"
    theme_schema = ROOT / "contracts/dashboard/schema/theme.schema.json"

    errors.extend(_validate(views_schema, views_path))

    widgets: set[str] = set()
    for path in sorted((ROOT / "contracts/dashboard/widgets").glob("*.json")):
        errors.extend(_validate(widget_schema, path))
        payload = _read(path)
        wid = payload.get("id")
        if isinstance(wid, str):
            widgets.add(wid)

    views = _read(views_path)
    for dashboard in views.get("dashboards", []):
        did = dashboard.get("id")
        for wid in dashboard.get("widgets", []):
            if wid not in widgets:
                errors.append(f"dashboard {did} references unknown widget {wid}")

    for path in sorted((ROOT / "contracts/dashboard/themes").glob("*.json")):
        errors.extend(_validate(theme_schema, path))

    policy_path = ROOT / "contracts/dashboard/widget_runtime_policy.json"
    policy = _read(policy_path) if policy_path.exists() else {"disabled": []}
    if not isinstance(policy, dict):
        errors.append("widget_runtime_policy must be object")
    else:
        disabled = policy.get("disabled", [])
        if not isinstance(disabled, list):
            errors.append("widget_runtime_policy disabled must be list")
        else:
            for entry in disabled:
                if not isinstance(entry, dict):
                    errors.append("widget_runtime_policy entry must be object")
                    continue
                wid = entry.get("widget_id")
                if isinstance(wid, str) and wid not in widgets:
                    errors.append(f"widget_runtime_policy references unknown widget {wid}")

        persona_overrides = policy.get("persona_overrides", {})
        if persona_overrides and not isinstance(persona_overrides, dict):
            errors.append("widget_runtime_policy persona_overrides must be object")

        tenant_overrides = policy.get("tenant_overrides", {})
        if tenant_overrides and not isinstance(tenant_overrides, dict):
            errors.append("widget_runtime_policy tenant_overrides must be object")

        feature_flags = policy.get("feature_flag_overrides", [])
        if feature_flags and not isinstance(feature_flags, list):
            errors.append("widget_runtime_policy feature_flag_overrides must be list")
        elif isinstance(feature_flags, list):
            for item in feature_flags:
                if not isinstance(item, dict):
                    errors.append("widget_runtime_policy feature_flag entry must be object")
                    continue
                wid = item.get("widget_id")
                if isinstance(wid, str) and wid not in widgets:
                    errors.append(f"widget_runtime_policy feature_flag references unknown widget {wid}")
    if errors:
        for err in errors:
            print(err)
        return 1
    print("dashboard contracts: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
