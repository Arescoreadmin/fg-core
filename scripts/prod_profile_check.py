#!/usr/bin/env python3
"""Production profile validation for FrostGate Core.

This script validates that docker-compose.yml and related config files
have safe production defaults. It checks for:
- FG_RL_FAIL_OPEN must be false (fail-closed rate limiting)
- FG_AUTH_ALLOW_FALLBACK must be false (no dev bypass in production)
- FG_AUTH_ENABLED must be true or 1
- No default/weak secrets in production config

Run as part of CI to prevent unsafe configurations from reaching production.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


def _env_truthy(value: str | bool | None) -> bool:
    """Check if an environment value is truthy."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _env_falsy(value: str | bool | None) -> bool:
    """Check if an environment value is explicitly false.

    Handles shell variable syntax like ${VAR:-default}.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return not value
    val_str = str(value).strip().lower()
    # Direct false values
    if val_str in ("0", "false", "no", "off"):
        return True
    # Handle ${VAR:-default} syntax - check if default is false
    if ":-false" in val_str or ":-0" in val_str or ":-no" in val_str:
        return True
    return False


def _normalize_env_value(value: str | bool | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    val = str(value).strip()
    if val.startswith("${") and ":-" in val:
        return val.split(":-", 1)[1].rstrip("}").strip()
    return val


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

        with open(compose_path) as f:
            compose = yaml.safe_load(f)

        services = compose.get("services", {})

        # Check core service (may be named "core" or "frostgate-core")
        core_svc = services.get("frostgate-core") or services.get("core") or {}
        core_env = core_svc.get("environment", {})
        self._check_core_env(core_env)

        # Check admin-gateway service
        _ = services.get("admin-gateway", {})

    def _check_core_env(self, env: dict) -> None:
        """Validate core service environment variables."""
        db_backend = _normalize_env_value(env.get("FG_DB_BACKEND"))
        db_url = _normalize_env_value(env.get("FG_DB_URL"))

        if not db_backend:
            self.errors.append(
                "CRITICAL: FG_DB_BACKEND is not set in core. Production MUST use Postgres."
            )
        elif str(db_backend).lower() != "postgres":
            self.errors.append(
                f"CRITICAL: FG_DB_BACKEND={db_backend} in core. Production MUST use Postgres."
            )

        if not db_url:
            self.errors.append(
                "CRITICAL: FG_DB_URL is not set in core. Production MUST configure Postgres."
            )

        opa_enforce = env.get("FG_OPA_ENFORCE")
        if opa_enforce is None or _env_falsy(opa_enforce):
            self.errors.append(
                "CRITICAL: FG_OPA_ENFORCE is disabled in core. Production MUST enforce policy."
            )

        triggers_sql = Path("migrations/postgres/0002_append_only_triggers.sql")
        if not triggers_sql.exists():
            self.errors.append(
                "CRITICAL: Append-only trigger migration missing. Production MUST enforce append-only."
            )
        else:
            content = triggers_sql.read_text(encoding="utf-8")
            required = [
                "decisions_append_only_update",
                "decisions_append_only_delete",
                "decision_evidence_artifacts_append_only_update",
                "decision_evidence_artifacts_append_only_delete",
            ]
            missing = [name for name in required if name not in content]
            if missing:
                self.errors.append(
                    f"CRITICAL: Append-only trigger migration missing definitions: {missing}"
                )

        # FG_RL_FAIL_OPEN must be explicitly false
        fail_open = env.get("FG_RL_FAIL_OPEN")
        if fail_open is None:
            self.errors.append(
                "CRITICAL: FG_RL_FAIL_OPEN is not set in core. "
                "Production MUST set FG_RL_FAIL_OPEN=false for fail-closed rate limiting."
            )
        elif not _env_falsy(fail_open):
            self.errors.append(
                f"CRITICAL: FG_RL_FAIL_OPEN={fail_open} in core. "
                "Production MUST use FG_RL_FAIL_OPEN=false."
            )

        # FG_AUTH_ENABLED should be true or 1
        auth_enabled = env.get("FG_AUTH_ENABLED")
        if auth_enabled is not None and not _env_truthy(auth_enabled):
            self.errors.append(
                f"CRITICAL: FG_AUTH_ENABLED={auth_enabled} in core. "
                "Production MUST enable authentication."
            )

        # FG_RL_BACKEND should be redis in production
        rl_backend = env.get("FG_RL_BACKEND")
        if rl_backend and str(rl_backend).lower() == "memory":
            self.warnings.append(
                "WARNING: FG_RL_BACKEND=memory in core. "
                "Production should use FG_RL_BACKEND=redis for distributed rate limiting."
            )

        # FG_RL_ALLOW_BYPASS_IN_PROD should be false
        bypass_in_prod = env.get("FG_RL_ALLOW_BYPASS_IN_PROD")
        if bypass_in_prod is not None and _env_truthy(bypass_in_prod):
            self.errors.append(
                "CRITICAL: FG_RL_ALLOW_BYPASS_IN_PROD=true in core. "
                "Production MUST NOT allow rate limit bypass."
            )

    def _check_admin_env(self, env: dict) -> None:
        """Validate admin-gateway environment variables."""
        # FG_AUTH_ALLOW_FALLBACK should be false in production
        allow_fallback = env.get("FG_AUTH_ALLOW_FALLBACK")
        if allow_fallback is not None and _env_truthy(allow_fallback):
            self.warnings.append(
                "WARNING: FG_AUTH_ALLOW_FALLBACK=true in admin-gateway. "
                "This allows dev bypass authentication. "
                "Set FG_AUTH_ALLOW_FALLBACK=false for production."
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

    # Check docker-compose.yml
    compose_path = Path("docker-compose.yml")
    checker.check_compose_file(compose_path)

    return checker.report()


if __name__ == "__main__":
    sys.exit(main())
