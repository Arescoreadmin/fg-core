#!/usr/bin/env python3
"""
Validates docker-compose production profile safety for FrostGate Core.

What this gate enforces:
- DoS hardening must be explicitly enabled
- Request/headers/multipart limits must be explicitly set to finite positive values
- Timeouts and concurrency must be explicitly set to finite positive values
- Rate limiting must be fail-closed in production (FG_RL_FAIL_OPEN=false)

Design goals:
- deterministic
- loud on failure
- SOC compatibility preserved
- CI-safe: automatically prefers .env.ci when present, else .env
- supports compose profiles and optional compose-file overrides

SOC compatibility:
- tools/ci/check_soc_invariants.py imports ProductionProfileChecker
- It calls checker.check_compose_file(path)
- It checks checker.errors after running
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
    """
    Deterministic production profile checker.
    """

    _DEFAULT_CORE_CANDIDATES = ("core", "frostgate-core")

    def __init__(
        self,
        compose_path: Path | None = None,
        *,
        core_service_name: str | None = None,
    ) -> None:
        self.compose_path = Path(compose_path) if compose_path else DEFAULT_COMPOSE

        # SOC expects this attribute.
        self.errors: list[str] = []

        # Allow override (env > ctor), else resolve later.
        self.core_service = (
            core_service_name or os.getenv("FG_CORE_SERVICE_NAME") or "core"
        )

        # Exposed for debugging / SOC log usefulness.
        self.resolved_core_service: str = "unknown"

    # --- SOC compatibility shim ---
    def check_compose_file(self, compose_path: Path) -> dict[str, Any]:
        self.compose_path = Path(compose_path)
        rep = self.check()
        return {
            "ok": rep.ok,
            "errors": rep.errors,
            "resolved_core_service": rep.resolved_core_service,
        }

    def _compose_profiles(self) -> list[str]:
        """
        Compose profiles to include when rendering config.

        Behavior:
        - If COMPOSE_PROFILES is unset/empty -> default to ['core']
        - If set -> support comma and/or whitespace separated list
        """
        raw = (os.getenv("COMPOSE_PROFILES") or "").strip()
        if not raw:
            return ["core"]
        parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
        return parts or ["core"]

    def _compose_files(self) -> list[Path]:
        """
        Compose files to render.

        Override with FG_PROD_PROFILE_COMPOSE_FILES using comma/space-separated paths.
        Otherwise use only self.compose_path for stable behavior.
        """
        raw = (os.getenv("FG_PROD_PROFILE_COMPOSE_FILES") or "").strip()
        if not raw:
            return [self.compose_path]

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

    def _resolve_env_file(self) -> Path | None:
        """
        Pick the env-file for docker compose interpolation.

        Order:
        1) FG_ENV_FILE if explicitly set
        2) .env.ci if present
        3) .env if present
        4) None
        """
        explicit = (os.getenv("FG_ENV_FILE") or "").strip()
        if explicit:
            p = Path(explicit)
            if not p.is_absolute():
                p = REPO / p
            if not p.exists():
                raise FileNotFoundError(f"configured env file does not exist: {p}")
            return p

        ci_env = REPO / ".env.ci"
        if ci_env.exists():
            return ci_env

        dot_env = REPO / ".env"
        if dot_env.exists():
            return dot_env

        return None

    def _run_compose_config(self) -> dict[str, Any]:
        """
        Use docker compose to render the fully merged configuration.
        This is the only reliable way to resolve env-file layering + interpolation.
        """
        compose_files = self._compose_files()
        missing = [str(p) for p in compose_files if not p.exists()]
        if missing:
            raise FileNotFoundError(
                "compose file(s) not found: " + ", ".join(sorted(missing))
            )

        env_file = self._resolve_env_file()

        cmd = ["docker", "compose"]
        for compose_file in compose_files:
            cmd += ["-f", str(compose_file)]

        if env_file is not None:
            cmd += ["--env-file", str(env_file)]

        for prof in self._compose_profiles():
            cmd += ["--profile", prof]

        cmd += ["config"]

        try:
            proc = subprocess.run(
                cmd,
                cwd=REPO,
                text=True,
                capture_output=True,
                check=True,
            )
            out = proc.stdout
        except subprocess.CalledProcessError as e:
            details = (e.stderr or e.stdout or "").strip()
            msg = f"docker compose config failed: Command {cmd!r} returned non-zero exit status {e.returncode}."
            if details:
                msg += f"\nCaptured stderr/stdout:\n{details}"
            raise RuntimeError(msg) from e

        try:
            import yaml  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "PyYAML is required to parse docker compose config output"
            ) from e

        data = yaml.safe_load(out)
        if not isinstance(data, dict):
            raise ValueError("docker compose config output must be a YAML object")
        return data

    def _resolve_core_service_name(self, services: dict[str, Any]) -> str:
        """
        Resolve which service is the core API.

        Order:
        1) explicit core_service (env/ctor) if present
        2) known candidates: core, frostgate-core
        """
        if self.core_service in services:
            return self.core_service

        for name in self._DEFAULT_CORE_CANDIDATES:
            if name in services:
                return name

        available = ", ".join(sorted(services.keys()))
        raise KeyError(
            "compose is missing required core service "
            f"(tried {self.core_service!r} then {self._DEFAULT_CORE_CANDIDATES!r}). "
            f"Available services: {available}"
        )

    def _collect_env(self) -> dict[str, str]:
        compose = self._run_compose_config()
        services = compose.get("services", {})
        if not isinstance(services, dict):
            raise ValueError("compose.services must be an object")

        resolved = self._resolve_core_service_name(services)
        self.resolved_core_service = resolved

        svc = services.get(resolved, {})
        if not isinstance(svc, dict):
            raise ValueError(f"compose.services[{resolved!r}] must be an object")

        env = svc.get("environment", {})
        if env is None:
            env = {}
        if not isinstance(env, dict):
            raise ValueError(
                f"compose.services[{resolved!r}].environment must be an object"
            )

        out: dict[str, str] = {}
        for k, v in env.items():
            if v is None:
                continue
            out[str(k)] = str(v)

        return out

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

    def _require_boolish(self, env: dict[str, str], key: str) -> None:
        self._require_explicit(env, key)
        if key not in env:
            return
        s = str(env[key]).strip().lower()
        if s not in {"0", "1", "true", "false"}:
            self.errors.append(
                f"[ERROR] CRITICAL: {key} must be boolean-like (true/false/1/0)."
            )

    def _require_true(self, env: dict[str, str], key: str) -> None:
        self._require_boolish(env, key)
        if key not in env:
            return
        s = str(env[key]).strip().lower()
        if s not in {"1", "true"}:
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
        s = str(env["FG_RL_FAIL_OPEN"]).strip().lower()
        if s not in {"0", "false"}:
            self.errors.append(
                "[ERROR] CRITICAL: Production MUST set FG_RL_FAIL_OPEN=false for fail-closed rate limiting."
            )

    def check(self) -> Report:
        self.errors = []

        env = self._collect_env()

        # Explicit enablement toggle
        self._require_true(env, "FG_DOS_GUARD_ENABLED")

        # Size limits
        for key in (
            "FG_MAX_BODY_BYTES",
            "FG_MAX_QUERY_BYTES",
            "FG_MAX_PATH_BYTES",
            "FG_MAX_HEADERS_COUNT",
            "FG_MAX_HEADERS_BYTES",
            "FG_MAX_HEADER_LINE_BYTES",
            "FG_MULTIPART_MAX_BYTES",
            "FG_MULTIPART_MAX_PARTS",
        ):
            self._require_positive_int(env, key)

        # Timeouts / concurrency
        for key in (
            "FG_REQUEST_TIMEOUT_SEC",
            "FG_KEEPALIVE_TIMEOUT_SEC",
            "FG_MAX_CONCURRENT_REQUESTS",
        ):
            self._require_positive_int(env, key)

        # Rate limiting: must fail-closed
        self._require_fail_closed_rl(env)

        ok = len(self.errors) == 0
        return Report(
            ok=ok,
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
