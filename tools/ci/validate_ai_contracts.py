from __future__ import annotations

import json
from pathlib import Path

from services.schema_validation import validate_payload_against_schema

ROOT = Path("contracts/ai")
KNOWN_PROVIDERS = {"simulated"}
FORBIDDEN_THEME_FIELDS = {"css", "raw_css", "script", "javascript"}


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _require_safe_theme(theme: dict) -> None:
    forbidden = sorted(FORBIDDEN_THEME_FIELDS.intersection(theme.keys()))
    if forbidden:
        raise SystemExit(
            f"theme {theme.get('id')} contains forbidden fields: {','.join(forbidden)}"
        )


def _require_policy_provider_integrity(policy: dict) -> None:
    providers = policy.get("allowed_providers") or []
    if not isinstance(providers, list) or not providers:
        raise SystemExit(f"policy {policy.get('id')} must define allowed_providers")
    bad = sorted({str(item) for item in providers if str(item) not in KNOWN_PROVIDERS})
    if bad:
        raise SystemExit(
            f"policy {policy.get('id')} includes unknown providers: {','.join(bad)}"
        )


def main() -> int:
    schemas = {
        "experiences": _load_json(ROOT / "schema" / "experience.schema.json"),
        "policies": _load_json(ROOT / "schema" / "policy.schema.json"),
        "themes": _load_json(ROOT / "schema" / "theme.schema.json"),
    }

    datasets: dict[str, list[dict]] = {}
    for folder, schema in schemas.items():
        records: list[dict] = []
        for path in sorted((ROOT / folder).glob("*.json")):
            payload = _load_json(path)
            validate_payload_against_schema(payload, schema)
            records.append(payload)
        if not records:
            raise SystemExit(f"{folder} contracts missing")
        datasets[folder] = records

    policy_ids = {item["id"] for item in datasets["policies"]}
    theme_ids = {item["id"] for item in datasets["themes"]}

    for policy in datasets["policies"]:
        _require_policy_provider_integrity(policy)

    for theme in datasets["themes"]:
        _require_safe_theme(theme)

    for experience in datasets["experiences"]:
        if experience["policy_id"] not in policy_ids:
            raise SystemExit(
                f"experience {experience['id']} references unknown policy {experience['policy_id']}"
            )
        if experience["theme_id"] not in theme_ids:
            raise SystemExit(
                f"experience {experience['id']} references unknown theme {experience['theme_id']}"
            )

    print("ai contracts validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
