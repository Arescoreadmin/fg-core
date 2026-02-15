#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

FILES = [
    Path("docker-compose.yml"),
    Path("deploy/frostgate-core/values.yaml"),
    Path("deploy/helm/frostgatecore/values.yaml"),
]

UNSAFE_TRUE_FLAGS = (
    "fg_auth_db_fail_open",
    "fg_auth_allow_fallback",
    "fg_rl_fail_open",
    "fg_rl_allow_bypass_in_prod",
    "fg_contract_gen_context",
    "fg_webhook_allow_unsigned",
)

FORBIDDEN_OUTBOUND_BYPASS_KEYS = (
    "fg_alert_allow_private_destinations",
    "fg_tripwire_allow_private_destinations",
    "fg_outbound_url_bypass",
)

FORBIDDEN_MARKERS = (
    "contract generation context detected: allowing missing oidc configuration",
)


def _normalize(text: str) -> str:
    return "\n".join(line.strip().lower() for line in text.splitlines())


def _has_unsafe_true(body: str, key: str) -> bool:
    return f"{key}: true" in body or f'{key}: "true"' in body or f"{key}:-true" in body


def main() -> int:
    failures: list[str] = []
    for path in FILES:
        if not path.exists():
            continue
        body = _normalize(path.read_text(encoding="utf-8"))

        for key in UNSAFE_TRUE_FLAGS:
            if _has_unsafe_true(body, key):
                failures.append(f"{path}: {key}=true is forbidden")

        for marker in FORBIDDEN_MARKERS:
            if marker in body:
                failures.append(f"{path}: forbidden marker present: {marker}")

        if (
            'fg_env: "prod"' in body
            or "fg_env: prod" in body
            or path.name == "docker-compose.yml"
        ):
            if "fg_db_url" not in body:
                failures.append(f"{path}: prod-like manifest must set FG_DB_URL")
            if "sqlite" in body and "fg_db_url" in body:
                failures.append(
                    f"{path}: sqlite FG_DB_URL is forbidden for prod-like manifests"
                )
            if "fg_webhook_secret" not in body:
                failures.append(f"{path}: prod-like manifest must set FG_WEBHOOK_SECRET")

        for key in FORBIDDEN_OUTBOUND_BYPASS_KEYS:
            if key in body:
                failures.append(f"{path}: outbound URL bypass key is forbidden: {key}")

    if failures:
        print("prod unsafe config gate: FAILED")
        for item in failures:
            print(f" - {item}")
        return 1

    print("prod unsafe config gate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
