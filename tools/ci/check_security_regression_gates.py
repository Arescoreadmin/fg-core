#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


def check_no_placeholder_security_tests(failures: list[str]) -> None:
    for path in (REPO / "tests").rglob("test_*.py"):
        body = path.read_text(encoding="utf-8")
        if "assert True" in body and "security" in str(path):
            failures.append(f"{path.relative_to(REPO)} contains placeholder assert True")


def check_auth_middleware_enforces(failures: list[str]) -> None:
    body = _read("api/middleware/auth_gate.py")
    required_markers = [
        "verify_api_key_detailed(",
        "request.state.auth = result",
        "status_code=401",
    ]
    missing = [m for m in required_markers if m not in body]
    if missing:
        failures.append(
            "api/middleware/auth_gate.py missing auth enforcement markers: "
            + ", ".join(missing)
        )


def check_no_insecure_prod_overrides(failures: list[str]) -> None:
    body = _read("tools/ci/check_prod_unsafe_config.py")
    for marker in ("fg_auth_db_fail_open", "fg_auth_allow_fallback", "fg_rl_fail_open"):
        if marker not in body:
            failures.append(f"tools/ci/check_prod_unsafe_config.py missing unsafe marker {marker}")


def check_network_egress_policy(failures: list[str]) -> None:
    body = _read("api/security_alerts.py")
    if "_validate_alert_webhook_url" not in body:
        failures.append("api/security_alerts.py missing webhook egress validation")
    if "Blocked security alert webhook URL by egress policy" not in body:
        failures.append("api/security_alerts.py missing blocked egress audit log")


def check_stable_error_codes(failures: list[str]) -> None:
    body = _read("api/main.py")
    if "error_code" not in body:
        failures.append("api/main.py missing stable error_code response handling")




def check_ci_prod_webhook_secret_and_no_outbound_bypass(failures: list[str]) -> None:
    body = _read(".github/workflows/ci.yml")
    if "FG_ENV: prod" in body and "FG_WEBHOOK_SECRET" not in body:
        failures.append(".github/workflows/ci.yml prod job missing FG_WEBHOOK_SECRET")

    prod_gate = _read("tools/ci/check_prod_unsafe_config.py")
    for marker in (
        "fg_webhook_allow_unsigned",
        "FORBIDDEN_OUTBOUND_BYPASS_KEYS",
        "prod-like manifest must set FG_WEBHOOK_SECRET",
    ):
        if marker not in prod_gate:
            failures.append(
                "tools/ci/check_prod_unsafe_config.py missing required marker: "
                + marker
            )


def main() -> int:
    failures: list[str] = []
    check_no_placeholder_security_tests(failures)
    check_auth_middleware_enforces(failures)
    check_no_insecure_prod_overrides(failures)
    check_network_egress_policy(failures)
    check_stable_error_codes(failures)
    check_ci_prod_webhook_secret_and_no_outbound_bypass(failures)

    if failures:
        print("security regression gates: FAILED")
        for item in failures:
            print(f" - {item}")
        return 1

    print("security regression gates: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
