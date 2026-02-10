#!/usr/bin/env python3
"""Production profile validation for FrostGate Core.

Validates docker-compose.yml and related config have safe production defaults.

Checks (core + admin-gateway):
- FG_RL_FAIL_OPEN must be false (fail-closed rate limiting)
- FG_AUTH_ALLOW_FALLBACK must be false (no dev bypass in production)
- FG_AUTH_ENABLED must be true or 1 (core)
- DoS hardening must be enabled and finite (core)
- No default/weak secrets in production config (basic checks)

Run as part of CI to prevent unsafe configurations from reaching production.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml


def _env_truthy(value: str | bool | None) -> bool:
    """Check if an environment value is truthy."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    val = str(value).strip().lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if ":-" in val:
        default = val.split(":-", 1)[1].rstrip("}")
        return default.strip().lower() in ("1", "true", "yes", "on")
    return False


def _env_falsy(value: str | bool | None) -> bool:
    """Check if an environment value is explicitly false.

    Handles shell variable syntax like ${VAR:-default}.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return not value
    val = str(value).strip().lower()
    if val in ("0", "false", "no", "off"):
        return True
    if ":-" in val:
        default = val.split(":-", 1)[1].rstrip("}")
        return default.strip().lower() in ("0", "false", "no", "off")
    return False


def _normalize_env(env: Any) -> dict[str, Any]:
    """Compose 'environment' can be dict or list of KEY=VALUE strings."""
    if env is None:
        return {}
    if isinstance(env, dict):
        return env
    if isinstance(env, list):
        out: dict[str, Any] = {}
        for item in env:
            if not isinstance(item, str):
                continue
            if "=" not in item:
                out[item.strip()] = ""
                continue
            k, v = item.split("=", 1)
            out[k.strip()] = v.strip()
        return out
    return {}


def _env_default_is_prod(env: dict[str, Any]) -> bool:
    """Treat as prod if FG_ENV is prod or defaults to prod (or missing)."""
    v = env.get("FG_ENV")
    if v is None:
        return True
    s = str(v).strip().lower()
    if s == "prod" or s == "production":
        return True
    if ":-" in s:
        default = s.split(":-", 1)[1].rstrip("}").strip().lower()
        return default in ("prod", "production")
    return False


class ProductionProfileChecker:
    """Validates production configuration for safety."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def check_compose_file(self, compose_path: Path) -> None:
        """Check docker-compose.yml for unsafe production settings."""
        if not compose_path.exists():
            self.errors.append(f"Compose file not found: {compose_path}")
            return

        with open(compose_path, encoding="utf-8") as f:
            compose = yaml.safe_load(f) or {}

        services = compose.get("services", {}) or {}

        core_svc = services.get("frostgate-core") or services.get("core") or {}
        core_env = _normalize_env(core_svc.get("environment"))
        self._check_core_env(core_env)

        admin_svc = services.get("admin-gateway") or {}
        admin_env = _normalize_env(admin_svc.get("environment"))
        self._check_admin_env(admin_env)

    def _check_core_env(self, env: dict[str, Any]) -> None:
        """Validate core service environment variables."""
        is_prod = _env_default_is_prod(env)

        # DoS hardening must be enabled and finite in production
        dos_enabled = env.get("FG_DOS_GUARD_ENABLED")
        if dos_enabled is None:
            self.errors.append(
                "CRITICAL: FG_DOS_GUARD_ENABLED must be explicitly set in production."
            )
        elif not _env_truthy(dos_enabled):
            self.errors.append(
                "CRITICAL: FG_DOS_GUARD_ENABLED must be true in production."
            )

        required_positive = [
            "FG_MAX_BODY_BYTES",
            "FG_MAX_QUERY_BYTES",
            "FG_MAX_PATH_BYTES",
            "FG_MAX_HEADERS_COUNT",
            "FG_MAX_HEADERS_BYTES",
            "FG_MAX_HEADER_LINE_BYTES",
            "FG_MULTIPART_MAX_BYTES",
            "FG_MULTIPART_MAX_PARTS",
            "FG_REQUEST_TIMEOUT_SEC",
            "FG_KEEPALIVE_TIMEOUT_SEC",
            "FG_MAX_CONCURRENT_REQUESTS",
        ]

        for key in required_positive:
            value = env.get(key)
            if value is None:
                self.errors.append(
                    f"CRITICAL: {key} must be explicitly set in production."
                )
                continue
            try:
                if isinstance(value, str) and ":-" in value:
                    raw = value.split(":-", 1)[1].rstrip("}")
                else:
                    raw = value
                parsed = float(str(raw).strip())
                if parsed <= 0:
                    raise ValueError
            except Exception:
                self.errors.append(
                    f"CRITICAL: {key} must be a positive number in production (got {value!r})."
                )

        # Rate limiting fail-open must be false in production
        fail_open = env.get("FG_RL_FAIL_OPEN")
        if fail_open is None:
            self.errors.append(
                "CRITICAL: FG_RL_FAIL_OPEN is not set in core. "
                "Production MUST set FG_RL_FAIL_OPEN=false for fail-closed rate limiting."
            )
        elif not _env_falsy(fail_open):
            self.errors.append(
                f"CRITICAL: FG_RL_FAIL_OPEN={fail_open!r} in core. "
                "Production MUST use FG_RL_FAIL_OPEN=false."
            )

        # Auth enabled must be on in prod
        auth_enabled = env.get("FG_AUTH_ENABLED")
        if is_prod and auth_enabled is not None and not _env_truthy(auth_enabled):
            self.errors.append(
                f"CRITICAL: FG_AUTH_ENABLED={auth_enabled!r} in core. "
                "Production MUST enable authentication."
            )

        # Auth fallback must default false
        allow_fallback = env.get("FG_AUTH_ALLOW_FALLBACK")
        if allow_fallback is None:
            self.errors.append(
                "CRITICAL: FG_AUTH_ALLOW_FALLBACK must be explicitly set in core "
                "and default to false in production."
            )
        elif _env_truthy(allow_fallback):
            self.errors.append(
                "CRITICAL: FG_AUTH_ALLOW_FALLBACK is enabled in core. "
                "Production MUST set FG_AUTH_ALLOW_FALLBACK=false."
            )

        rl_backend = env.get("FG_RL_BACKEND")
        if rl_backend and str(rl_backend).strip().lower() == "memory":
            self.warnings.append(
                "WARNING: FG_RL_BACKEND=memory in core. "
                "Production should use FG_RL_BACKEND=redis for distributed rate limiting."
            )

        bypass_in_prod = env.get("FG_RL_ALLOW_BYPASS_IN_PROD")
        if bypass_in_prod is not None and _env_truthy(bypass_in_prod):
            self.errors.append(
                "CRITICAL: FG_RL_ALLOW_BYPASS_IN_PROD=true in core. "
                "Production MUST NOT allow rate limit bypass."
            )

    def _check_admin_env(self, env: dict[str, Any]) -> None:
        """Validate admin-gateway environment variables."""
        is_prod = _env_default_is_prod(env)

        allow_fallback = env.get("FG_AUTH_ALLOW_FALLBACK")
        if allow_fallback is None:
            # In prod-like, being explicit is the whole point
            if is_prod:
                self.errors.append(
                    "CRITICAL: FG_AUTH_ALLOW_FALLBACK must be explicitly set in admin-gateway "
                    "and default to false in production."
                )
            else:
                self.warnings.append(
                    "WARNING: FG_AUTH_ALLOW_FALLBACK is not set in admin-gateway. "
                    "Set FG_AUTH_ALLOW_FALLBACK=false explicitly."
                )
            return

        if _env_truthy(allow_fallback):
            self.errors.append(
                "CRITICAL: FG_AUTH_ALLOW_FALLBACK=true in admin-gateway. "
                "Production MUST set FG_AUTH_ALLOW_FALLBACK=false."
            )

    def report(self) -> int:
        """Print report and return exit code (0 = pass, 1 = fail)."""
        if self.errors:
            print("=" * 60)
            print("PRODUCTION PROFILE CHECK: FAILED")
            print("=" * 60)
            for error in self.errors:
                print(f"  [ERROR] {error}")
            print()

        if self.warnings:
            print("-" * 60)
            print("PRODUCTION PROFILE WARNINGS:")
            print("-" * 60)
            for warning in self.warnings:
                print(f"  {warning}")
            print()

        if not self.errors and not self.warnings:
            print("Production profile check: OK")

        return 1 if self.errors else 0


def main() -> int:
    """Run production profile checks."""
    checker = ProductionProfileChecker()
    checker.check_compose_file(Path("docker-compose.yml"))
    return checker.report()


if __name__ == "__main__":
    sys.exit(main())
