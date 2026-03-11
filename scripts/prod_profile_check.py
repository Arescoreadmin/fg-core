#!/usr/bin/env python3
"""
Validates docker-compose production profile safety for FrostGate Core.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
DEFAULT_COMPOSE = REPO / "docker-compose.yml"

REQUIRED_KEYS = [
    "FG_DOS_GUARD_ENABLED",
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
    "FG_RL_FAIL_OPEN",
]


@dataclass(frozen=True)
class Report:
    ok: bool
    errors: list[str]
    resolved_core_service: str


class ProductionProfileChecker:
    _DEFAULT_CORE_CANDIDATES = ("frostgate-core", "core")
    _COMPOSE_PLACEHOLDER_ENV: dict[str, str] = {
        "POSTGRES_PASSWORD": "ci-postgres-password",
        "REDIS_PASSWORD": "ci-redis-password",
        "NATS_AUTH_TOKEN": "ci-nats-token",
        "FG_API_KEY": "ci-api-key",
        "FG_AGENT_API_KEY": "ci-agent-api-key",
        "FG_WEBHOOK_SECRET": "ci-webhook-secret",
        "FG_ENCRYPTION_KEY": "ci-encryption-key-32-bytes-minimum",
        "FG_JWT_SECRET": "ci-jwt-secret-32-bytes-minimum",
    }

    def __init__(
        self,
        compose_path: Path | None = None,
        *,
        core_service_name: str | None = None,
    ) -> None:
        self.compose_path = Path(compose_path) if compose_path else DEFAULT_COMPOSE
        self.errors: list[str] = []
        self.core_service = (
            core_service_name or os.getenv("FG_CORE_SERVICE_NAME") or "frostgate-core"
        )
        self.resolved_core_service: str = "unknown"

    def check_compose_file(self, compose_path: Path) -> dict[str, Any]:
        self.compose_path = Path(compose_path)
        rep = self.check()
        return {
            "ok": rep.ok,
            "errors": rep.errors,
            "resolved_core_service": rep.resolved_core_service,
        }

    def _compose_profiles(self) -> list[str]:
        raw = (os.getenv("COMPOSE_PROFILES") or "").strip()
        if not raw:
            return ["core"]
        parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
        return parts or ["core"]

    def _compose_files(self) -> list[Path]:
        raw = (os.getenv("FG_PROD_PROFILE_COMPOSE_FILES") or "").strip()
        if raw:
            out: list[Path] = []
            for item in re.split(r"[,\s]+", raw):
                item = item.strip()
                if not item:
                    continue
                p = Path(item)
                if not p.is_absolute():
                    p = REPO / p
                out.append(p)
            return out or [self.compose_path]

        files = [self.compose_path]
        lockdown = REPO / "docker-compose.lockdown.yml"
        if lockdown.exists():
            files.append(lockdown)
        return files

    def _resolve_env_file(self) -> Path | None:
        explicit = (os.getenv("FG_ENV_FILE") or "").strip()
        if explicit:
            p = Path(explicit)
            if not p.is_absolute():
                p = REPO / p
            return p if p.exists() else None

        ci_env = REPO / ".env.ci"
        if ci_env.exists():
            return ci_env

        dot_env = REPO / ".env"
        if dot_env.exists():
            return dot_env

        return None

    def _compose_env(self) -> dict[str, str]:
        env = dict(os.environ)
        for key, fallback in self._COMPOSE_PLACEHOLDER_ENV.items():
            if not env.get(key):
                env[key] = fallback
        return env

    def _run_compose_config(self) -> dict[str, Any]:
        missing = [str(p) for p in self._compose_files() if not p.exists()]
        if missing:
            raise FileNotFoundError(
                "compose file(s) not found: " + ", ".join(sorted(missing))
            )

        cmd = ["docker", "compose", "--env-file", "/dev/null"]
        for compose_file in self._compose_files():
            cmd += ["-f", str(compose_file)]

        env_file = self._resolve_env_file()
        if env_file is not None:
            cmd += ["--env-file", str(env_file)]

        for profile in self._compose_profiles():
            cmd += ["--profile", profile]

        cmd += ["config"]

        try:
            proc = subprocess.run(
                cmd,
                cwd=REPO,
                env=self._compose_env(),
                text=True,
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            details = (e.stderr or e.stdout or "").strip()
            msg = (
                f"docker compose config failed: Command {cmd!r} returned non-zero "
                f"exit status {e.returncode}."
            )
            if details:
                msg += f"\nCaptured stderr/stdout:\n{details}"
            raise RuntimeError(msg) from e

        try:
            import yaml  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "PyYAML is required to parse docker compose config output"
            ) from e

        data = yaml.safe_load(proc.stdout)
        if not isinstance(data, dict):
            raise ValueError("docker compose config output must be a YAML object")
        return data

    def _service_env_map(
        self, service: dict[str, Any], service_name: str
    ) -> dict[str, str]:
        env = service.get("environment", {})
        if env is None:
            env = {}
        if not isinstance(env, dict):
            raise ValueError(
                f"compose.services[{service_name!r}].environment must be an object"
            )
        out: dict[str, str] = {}
        for k, v in env.items():
            if v is None:
                continue
            out[str(k)] = str(v)
        return out

    def _resolve_target_service(
        self, services: dict[str, Any]
    ) -> tuple[str, dict[str, str]]:
        candidates = [self.core_service]
        for name in self._DEFAULT_CORE_CANDIDATES:
            if name not in candidates:
                candidates.append(name)

        for name in candidates:
            svc = services.get(name)
            if isinstance(svc, dict):
                env = self._service_env_map(svc, name)
                self.resolved_core_service = name
                return name, env

        available = ", ".join(sorted(str(k) for k in services.keys()))
        raise RuntimeError(
            "compose is missing required core service "
            f"(tried {tuple(candidates)!r}). Available services: {available}"
        )

    def _collect_env(self) -> dict[str, str]:
        compose = self._run_compose_config()
        services = compose.get("services", {})
        if not isinstance(services, dict):
            raise ValueError("compose.services must be an object")
        _, env = self._resolve_target_service(services)
        return env

    def _require_explicit(self, env: dict[str, str], key: str) -> None:
        if key not in env:
            self.errors.append(
                f"[ERROR] CRITICAL: {key} must be explicitly set in production."
            )

    def _require_positive_int(self, env: dict[str, str], key: str) -> None:
        self._require_explicit(env, key)
        if key not in env:
            return
        try:
            val = int(str(env[key]).strip())
        except Exception:
            self.errors.append(f"[ERROR] CRITICAL: {key} must be an integer.")
            return
        if val <= 0:
            self.errors.append(f"[ERROR] CRITICAL: {key} must be > 0.")

    def _require_true(self, env: dict[str, str], key: str) -> None:
        self._require_explicit(env, key)
        if key not in env:
            return
        if str(env[key]).strip().lower() not in {"1", "true"}:
            self.errors.append(
                f"[ERROR] CRITICAL: {key} must be explicitly enabled in production."
            )

    def _require_fail_closed_rl(self, env: dict[str, str]) -> None:
        if "FG_RL_FAIL_OPEN" not in env:
            self.errors.append(
                "[ERROR] CRITICAL: FG_RL_FAIL_OPEN is not set in core. "
                "Production MUST set FG_RL_FAIL_OPEN=false for fail-closed rate limiting."
            )
            return
        if str(env["FG_RL_FAIL_OPEN"]).strip().lower() not in {"0", "false"}:
            self.errors.append(
                "[ERROR] CRITICAL: Production MUST set FG_RL_FAIL_OPEN=false for fail-closed rate limiting."
            )

    def check(self) -> Report:
        self.errors = []

        env = self._collect_env()

        self._require_true(env, "FG_DOS_GUARD_ENABLED")

        for key in (
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
        ):
            self._require_positive_int(env, key)

        self._require_fail_closed_rl(env)

        return Report(
            ok=not self.errors,
            errors=list(self.errors),
            resolved_core_service=self.resolved_core_service,
        )


def main() -> int:
    checker = ProductionProfileChecker()
    try:
        report = checker.check()
    except Exception as e:
        print("=" * 60)
        print("PRODUCTION PROFILE CHECK: FAILED (crash)")
        print("=" * 60)
        print(str(e))
        return 2

    if report.ok:
        print("=" * 60)
        print("PRODUCTION PROFILE CHECK: PASSED")
        print("=" * 60)
        return 0

    print("=" * 60)
    print("PRODUCTION PROFILE CHECK: FAILED")
    print("=" * 60)
    for err in report.errors:
        print(f"  {err}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
