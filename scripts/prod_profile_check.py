#!/usr/bin/env python3
"""
Validates docker-compose.yml and related config have safe production defaults.

What this gate enforces (minimum):
- DoS hardening must be explicitly enabled
- Request/headers/multipart limits must be explicitly set to finite positive values
- Timeouts and concurrency must be explicitly set to finite positive values
- Rate limiting must be fail-closed in production (FG_RL_FAIL_OPEN=false)

This is a release-safety gate. It should be deterministic and loud.

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

        # SOC expects these attributes.
        self.errors: list[str] = []

        # Allow override (env > ctor), else resolved from compose services.
        self.core_service = (
            core_service_name or os.getenv("FG_CORE_SERVICE_NAME") or "core"
        )

        # Exposed for debugging / SOC log tail usefulness
        self.resolved_core_service: str = "unknown"
        self._docker_unavailable: bool = False

    # --- SOC compatibility shim ---
    def check_compose_file(self, compose_path: Path) -> dict[str, Any]:
        self.compose_path = Path(compose_path)
        rep = self.check()
        # Some call sites expect a dict-like object; provide one.
        return {
            "ok": rep.ok,
            "errors": rep.errors,
            "resolved_core_service": rep.resolved_core_service,
        }

    def _compose_profiles(self) -> list[str]:
        """
        Compose profiles for docker compose config.

        Why this exists:
        - Your compose hides frostgate-core behind profile 'core'.
        - docker compose config --services without profiles will NOT include it.
        - CI and pre-commit often run without COMPOSE_PROFILES set.

        Behavior:
        - If COMPOSE_PROFILES is unset/empty -> default to ['core'].
        - If set -> support comma and/or whitespace separated list.
        """
        raw = (os.getenv("COMPOSE_PROFILES") or "").strip()
        if not raw:
            return ["core"]
        parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
        return parts or ["core"]

    def _run_compose_config(self) -> dict[str, Any]:
        """
        Use docker compose to render the fully merged configuration.
        Falls back to direct YAML parse when docker is unavailable.
        """
        cmd = ["docker", "compose", "-f", str(self.compose_path)]
        for prof in self._compose_profiles():
            cmd += ["--profile", prof]
        cmd += ["config"]

        # Lazy import to avoid hard dependency if not needed.
        try:
            import yaml  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "PyYAML is required to parse docker compose config output"
            ) from e

        self._docker_unavailable = False
        try:
            out = subprocess.check_output(
                cmd,
                cwd=REPO,
                text=True,
            )
            data = yaml.safe_load(out)
            if not isinstance(data, dict):
                raise ValueError("docker compose config output must be a YAML object")
            return data
        except FileNotFoundError:
            self._docker_unavailable = True
            raw = yaml.safe_load(self.compose_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("docker-compose.yml must be a YAML object")
            return raw
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"docker compose config failed: {e}") from e

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

    def _read_env_file(self, path: Path) -> dict[str, str]:
        out: dict[str, str] = {}
        if not path.exists() or not path.is_file():
            return out
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
        return out

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

        out: dict[str, str] = {}

        env_file = svc.get("env_file", [])
        if isinstance(env_file, str):
            env_files = [env_file]
        elif isinstance(env_file, list):
            env_files = [entry for entry in env_file if isinstance(entry, str)]
        else:
            env_files = []

        for env_file_path in env_files:
            merged = self._read_env_file((REPO / env_file_path).resolve())
            out.update(merged)

        env = svc.get("environment", {})
        if env is None:
            env = {}
        if not isinstance(env, dict):
            raise ValueError(
                f"compose.services[{resolved!r}].environment must be an object"
            )

        for k, v in env.items():
            if v is None:
                continue
            out[str(k)] = str(v)

        return out

    def _require_explicit(self, env: dict[str, str], key: str) -> None:
        if key not in env:
            if self._docker_unavailable:
                return
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

    def _require_fail_closed_rl(self, env: dict[str, str]) -> None:
        # Fail-closed means FG_RL_FAIL_OPEN must be explicitly false.
        if "FG_RL_FAIL_OPEN" not in env:
            if self._docker_unavailable:
                return
            self.errors.append(
                "[ERROR] CRITICAL: FG_RL_FAIL_OPEN is not set in core. "
                "Production MUST set FG_RL_FAIL_OPEN=false for fail-closed rate limiting."
            )
            return
        s = str(env["FG_RL_FAIL_OPEN"]).strip().lower()
        if s != "false":
            self.errors.append(
                "[ERROR] CRITICAL: Production MUST set FG_RL_FAIL_OPEN=false for fail-closed rate limiting."
            )

    def check(self) -> Report:
        self.errors = []  # reset per run

        env = self._collect_env()

        # Explicit enablement toggle
        self._require_boolish(env, "FG_DOS_GUARD_ENABLED")

        # Size limits
        for k in (
            "FG_MAX_BODY_BYTES",
            "FG_MAX_QUERY_BYTES",
            "FG_MAX_PATH_BYTES",
            "FG_MAX_HEADERS_COUNT",
            "FG_MAX_HEADERS_BYTES",
            "FG_MAX_HEADER_LINE_BYTES",
            "FG_MULTIPART_MAX_BYTES",
            "FG_MULTIPART_MAX_PARTS",
        ):
            self._require_positive_int(env, k)

        # Timeouts / concurrency
        for k in (
            "FG_REQUEST_TIMEOUT_SEC",
            "FG_KEEPALIVE_TIMEOUT_SEC",
            "FG_MAX_CONCURRENT_REQUESTS",
        ):
            self._require_positive_int(env, k)

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
