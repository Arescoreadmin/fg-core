from __future__ import annotations

import json
import re
from pathlib import Path

from services.schema_validation import validate_payload_against_schema

ROOT = Path("contracts/connectors")
FORBIDDEN_FIELDS = {
    "secret",
    "client_secret",
    "access_token",
    "refresh_token",
    "password",
    "raw_secret",
    "script",
    "javascript",
    "exec",
    "eval",
    "code",
}
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
KNOWN_PROVIDERS = {"slack", "google"}
SCOPE_ALLOWLIST = {
    "slack": {"channels:history", "users:read"},
    "google": {"https://www.googleapis.com/auth/drive.readonly"},
}


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _contains_forbidden(obj: object) -> list[str]:
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in FORBIDDEN_FIELDS:
                hits.append(str(k))
            hits.extend(_contains_forbidden(v))
    elif isinstance(obj, list):
        for item in obj:
            hits.extend(_contains_forbidden(item))
    return hits


def _validate_connector_manifest(payload: dict, name: str) -> None:
    version = str(payload.get("version") or "")
    if not SEMVER_RE.match(version):
        raise SystemExit(f"connector {name} has non-semver version: {version}")

    provider = str(payload.get("provider") or "")
    if provider not in KNOWN_PROVIDERS:
        raise SystemExit(f"connector {name} has unknown provider: {provider}")

    allowed_scopes = SCOPE_ALLOWLIST.get(provider, set())
    required_scopes = {str(x) for x in (payload.get("required_scopes") or [])}
    bad_scopes = sorted(required_scopes - allowed_scopes)
    if bad_scopes:
        raise SystemExit(
            f"connector {name} contains provider-disallowed scopes: {','.join(bad_scopes)}"
        )


def main() -> int:
    connector_schema = _load_json(ROOT / "schema" / "connector.schema.json")
    policy_schema = _load_json(ROOT / "schema" / "policy.schema.json")

    connectors = []
    for path in sorted((ROOT / "connectors").glob("*.json")):
        payload = _load_json(path)
        validate_payload_against_schema(payload, connector_schema)
        _validate_connector_manifest(payload, path.name)
        forbidden = _contains_forbidden(payload)
        if forbidden:
            raise SystemExit(
                f"connector {path.name} contains forbidden secret/dynamic fields: {','.join(sorted(set(forbidden)))}"
            )
        connectors.append(payload)

    if not connectors:
        raise SystemExit("connector contracts missing")

    known_ids = {str(item["id"]) for item in connectors}

    for path in sorted((ROOT / "policies").glob("*.json")):
        policy = _load_json(path)
        validate_payload_against_schema(policy, policy_schema)
        forbidden = _contains_forbidden(policy)
        if forbidden:
            raise SystemExit(
                f"policy {path.name} contains forbidden secret/dynamic fields: {','.join(sorted(set(forbidden)))}"
            )

        refs = set(policy.get("enabled_connectors") or [])
        refs.update((policy.get("connector_scopes") or {}).keys())
        refs.update((policy.get("allowed_resources") or {}).keys())
        bad_refs = sorted({str(x) for x in refs if str(x) not in known_ids})
        if bad_refs:
            raise SystemExit(
                f"policy {path.name} references unknown connectors: {','.join(bad_refs)}"
            )

    print("connector contracts validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
