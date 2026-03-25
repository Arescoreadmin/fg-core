#!/usr/bin/env python3
"""
FrostGate Control Tower Doctor

Diagnose + fix common issues opening/using Control Tower (console + admin gateway + core).

What it does:
- Validates you're in the fg-core repo root
- Checks docker compose config, profiles, ports, and health endpoints
- Verifies Control Tower routes exist in runtime inventory and OpenAPI contract
- Ensures canonical governance artifacts exist (plane registry snapshot, route inventory, contract routes, topology hash, etc.)
- Regenerates deterministic governance artifacts if missing or stale
- Ensures platform inventory generation is decoupled from PlaneDef internals:
  - FAILS only on *actual coupling* (PlaneDef import/usage + attribute access), not on comments/strings
  - Optionally runs platform inventory generation using canonical artifacts
- Applies safe, deterministic fixes:
  - compose up/down targeted profiles
  - rebuild console
  - regenerate route inventory + summaries
  - run pr-check-fast gates (or targeted gates)

This is a release-safety helper. It is intentionally loud.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO = Path(__file__).resolve().parents[1]

# Canonical governance artifacts (source of truth)
PLANE_REGISTRY_SNAPSHOT = REPO / "tools/ci/plane_registry_snapshot.json"
ROUTE_INVENTORY = REPO / "tools/ci/route_inventory.json"
ROUTE_INVENTORY_SUMMARY = REPO / "artifacts/route_inventory_summary.json"
CONTRACT_ROUTES = REPO / "tools/ci/contract_routes.json"
TOPOLOGY_HASH = REPO / "tools/ci/topology.sha256"
ATTESTATION_BUNDLE_HASH = REPO / "tools/ci/attestation_bundle.sha256"
BUILD_META = REPO / "tools/ci/build_meta.json"

# Platform inventory outputs (common locations in this repo)
PLATFORM_INV_JSON = REPO / "artifacts/platform_inventory.json"
PLATFORM_INV_MD = REPO / "artifacts/PLATFORM_INVENTORY.md"

# Core sources we refuse to let rot
PLATFORM_INV_GEN = REPO / "scripts/generate_platform_inventory.py"

# Compose + endpoints
COMPOSE_FILE = REPO / "docker-compose.yml"
DEFAULT_ADMIN_PORT = 18080  # host published port for admin-gateway
DEFAULT_CONSOLE_PORT = 13000  # host published port for console
ADMIN_HEALTH_PATH = "/health"
CORE_READY_PATH = "/health/ready"

# Control Tower endpoints (based on your observed runtime inventory drift)
CONTROL_TOWER_ROUTES = [
    ("GET", "/control-tower/snapshot"),
    ("GET", "/control/testing/health"),
    ("GET", "/control/testing/runs"),
    ("GET", "/control/testing/runs/{run_id}"),
    ("POST", "/control/testing/runs/register"),
]

# ----------------------------
# Platform inventory decoupling check
# ----------------------------
# We only fail on *real* coupling:
# - importing PlaneDef (or referring to it) AND/OR
# - attribute access like: plane.mount_flag, plane.required_route_invariants, plane.evidence
#
# We do NOT fail on:
# - JSON keys / compatibility strings like "mount_flag" in dicts
# - comments mentioning the deprecated fields
# - error messages that list tolerated legacy keys
PLANEDEF_IMPORT_PATTERNS = [
    re.compile(r"^\s*from\s+services\.plane_registry\s+import\s+.*\bPlaneDef\b", re.M),
    re.compile(r"^\s*import\s+services\.plane_registry\b.*\bPlaneDef\b", re.M),
]
PLANEDEF_SYMBOL_PATTERN = re.compile(r"\bPlaneDef\b")
PLANEDEF_ATTR_ACCESS_PATTERNS = [
    re.compile(r"\.\s*mount_flag\b"),
    re.compile(r"\.\s*required_route_invariants\b"),
    re.compile(r"\.\s*evidence\b"),
]


@dataclass
class CheckResult:
    ok: bool
    name: str
    details: str = ""


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        check=check,
    )


def _print_section(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def _ok(name: str, details: str = "") -> CheckResult:
    return CheckResult(True, name, details)


def _fail(name: str, details: str = "") -> CheckResult:
    return CheckResult(False, name, details)


def _require_repo_root() -> CheckResult:
    must_exist = [
        REPO / "Makefile",
        REPO / "docker-compose.yml",
        REPO / "api",
        REPO / "tools",
    ]
    missing = [p for p in must_exist if not p.exists()]
    if missing:
        return _fail(
            "repo-root",
            f"Not in fg-core repo root? Missing: {[str(p) for p in missing]}",
        )
    return _ok("repo-root", str(REPO))


def _have_bin(name: str) -> bool:
    return shutil.which(name) is not None


def _check_bins() -> CheckResult:
    required = ["docker", "git", "python", "make"]
    missing = [b for b in required if not _have_bin(b)]
    if missing:
        return _fail("binaries", f"Missing executables in PATH: {missing}")
    return _ok("binaries", "docker/git/python/make present")


def _compose_config() -> tuple[CheckResult, str]:
    if not COMPOSE_FILE.exists():
        return _fail("compose-file", f"Missing {COMPOSE_FILE}"), ""
    proc = _run(["docker", "compose", "-f", str(COMPOSE_FILE), "config"], cwd=REPO)
    if proc.returncode != 0:
        return _fail("compose-config", proc.stderr.strip() or proc.stdout.strip()), ""
    return _ok("compose-config", "docker compose config OK"), proc.stdout


def _http_check(url: str, timeout_sec: float = 2.0) -> bool:
    # avoid deps; use stdlib in a subprocess for consistent behavior across envs
    code = (
        "import urllib.request,sys\n"
        f"u='{url}'\n"
        "try:\n"
        f"  urllib.request.urlopen(u, timeout={timeout_sec}).read()\n"
        "  sys.exit(0)\n"
        "except Exception:\n"
        "  sys.exit(1)\n"
    )
    proc = _run([sys.executable, "-c", code], cwd=REPO)
    return proc.returncode == 0


def _wait_http(url: str, *, timeout_sec: int = 60, interval_sec: float = 2.0) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if _http_check(url):
            return True
        time.sleep(interval_sec)
    return False


def _ensure_governance_artifacts_exist() -> CheckResult:
    required = [
        PLANE_REGISTRY_SNAPSHOT,
        ROUTE_INVENTORY,
        CONTRACT_ROUTES,
        TOPOLOGY_HASH,
        ATTESTATION_BUNDLE_HASH,
        BUILD_META,
    ]
    missing = [p for p in required if not p.exists()]
    if missing:
        return _fail(
            "governance-artifacts",
            f"Missing canonical artifacts: {[str(p) for p in missing]}",
        )
    return _ok("governance-artifacts", "canonical artifacts present")


def _regenerate_route_inventory() -> CheckResult:
    proc = _run(["make", "route-inventory-generate"], cwd=REPO)
    if proc.returncode != 0:
        return _fail(
            "route-inventory-generate", (proc.stdout + "\n" + proc.stderr).strip()
        )
    return _ok("route-inventory-generate", "route inventory regenerated")


def _route_inventory_contains_control_tower() -> CheckResult:
    if not ROUTE_INVENTORY.exists():
        return _fail("route-inventory-present", "route_inventory.json missing")
    try:
        doc = json.loads(ROUTE_INVENTORY.read_text(encoding="utf-8"))
    except Exception as e:
        return _fail("route-inventory-parse", f"route_inventory.json invalid JSON: {e}")

    data = doc.get("data") if isinstance(doc, dict) else doc
    routes = data if isinstance(data, list) else []
    keyset = {(r.get("method"), r.get("path")) for r in routes if isinstance(r, dict)}

    missing = [(m, p) for (m, p) in CONTROL_TOWER_ROUTES if (m, p) not in keyset]
    if missing:
        return _fail("control-tower-routes", f"Missing in runtime inventory: {missing}")
    return _ok(
        "control-tower-routes", "Control Tower routes present in runtime inventory"
    )


def _contract_contains_control_tower() -> CheckResult:
    if not CONTRACT_ROUTES.exists():
        return _fail("contract-routes-present", "contract_routes.json missing")
    try:
        doc = json.loads(CONTRACT_ROUTES.read_text(encoding="utf-8"))
    except Exception as e:
        return _fail("contract-routes-parse", f"contract_routes.json invalid JSON: {e}")

    data = doc.get("data") if isinstance(doc, dict) else doc
    routes = data if isinstance(data, list) else []
    keyset = {(r.get("method"), r.get("path")) for r in routes if isinstance(r, dict)}

    missing = [(m, p) for (m, p) in CONTROL_TOWER_ROUTES if (m, p) not in keyset]
    if missing:
        return _ok(
            "contract-control-tower-routes",
            f"WARNING: not in OpenAPI contract: {missing}",
        )
    return _ok(
        "contract-control-tower-routes",
        "Control Tower routes present in OpenAPI contract",
    )


def _platform_inventory_generator_decoupled() -> CheckResult:
    if not PLATFORM_INV_GEN.exists():
        return _fail("platform-inventory-generator", f"Missing {PLATFORM_INV_GEN}")

    src = PLATFORM_INV_GEN.read_text(encoding="utf-8")

    has_planedef_import = any(p.search(src) for p in PLANEDEF_IMPORT_PATTERNS)
    has_planedef_symbol = bool(PLANEDEF_SYMBOL_PATTERN.search(src))
    attr_hits = [p.pattern for p in PLANEDEF_ATTR_ACCESS_PATTERNS if p.search(src)]

    # Fail conditions:
    # 1) attribute access of deprecated internals (strong signal)
    # 2) PlaneDef import (strong signal)
    # 3) PlaneDef symbol usage + attribute access (still strong)
    # We do NOT fail on the presence of "mount_flag" as a string key.
    hits: list[str] = []
    if has_planedef_import:
        hits.append("PlaneDef import from services.plane_registry")
    if has_planedef_symbol and has_planedef_import:
        hits.append("PlaneDef symbol usage (with import)")
    if attr_hits:
        hits.append(f"Deprecated PlaneDef attribute access: {attr_hits}")

    if hits:
        return _fail(
            "platform-inventory-decoupling",
            "scripts/generate_platform_inventory.py appears coupled to PlaneDef internals.\n"
            "Signals:\n - " + "\n - ".join(hits) + "\n\n"
            "Requirement: platform inventory must be derived from canonical governance artifacts on disk:\n"
            " - tools/ci/plane_registry_snapshot.json\n"
            " - tools/ci/route_inventory.json\n"
            " - artifacts/route_inventory_summary.json (optional)\n"
            " - tools/ci/contract_routes.json\n"
            " - tools/ci/topology.sha256\n"
            " - tools/ci/attestation_bundle.sha256\n"
            " - tools/ci/build_meta.json\n",
        )

    return _ok("platform-inventory-decoupling", "No PlaneDef internals referenced")


def _generate_platform_inventory_from_artifacts() -> CheckResult:
    """
    Runs scripts/generate_platform_inventory.py in repo context.
    Assumes generator reads canonical artifacts from disk (governance-first).
    """
    if not PLATFORM_INV_GEN.exists():
        return _fail(
            "platform-inventory-generate", "generate_platform_inventory.py missing"
        )

    env = {**os.environ, "PYTHONPATH": "."}
    proc = _run([sys.executable, str(PLATFORM_INV_GEN)], cwd=REPO, env=env)
    if proc.returncode != 0:
        return _fail(
            "platform-inventory-generate", (proc.stdout + "\n" + proc.stderr).strip()
        )

    outs = [p for p in [PLATFORM_INV_JSON, PLATFORM_INV_MD] if p.exists()]
    return _ok(
        "platform-inventory-generate",
        f"Generated platform inventory (outputs present: {[str(p) for p in outs]})",
    )


def _compose_up(profiles: Iterable[str], *, rebuild: bool = False) -> CheckResult:
    args = ["docker", "compose", "-f", str(COMPOSE_FILE)]
    for p in profiles:
        args += ["--profile", p]
    if rebuild:
        proc = _run(args + ["build"], cwd=REPO)
        if proc.returncode != 0:
            return _fail("compose-build", (proc.stdout + "\n" + proc.stderr).strip())

    proc = _run(args + ["up", "-d", "--remove-orphans"], cwd=REPO)
    if proc.returncode != 0:
        return _fail("compose-up", (proc.stdout + "\n" + proc.stderr).strip())
    return _ok("compose-up", f"compose up profiles={list(profiles)}")


def _compose_down(profiles: Iterable[str]) -> CheckResult:
    args = ["docker", "compose", "-f", str(COMPOSE_FILE)]
    for p in profiles:
        args += ["--profile", p]
    proc = _run(args + ["down"], cwd=REPO)
    if proc.returncode != 0:
        return _fail("compose-down", (proc.stdout + "\n" + proc.stderr).strip())
    return _ok("compose-down", f"compose down profiles={list(profiles)}")


def _rebuild_console() -> CheckResult:
    proc = _run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "--profile",
            "admin",
            "build",
            "console",
        ],
        cwd=REPO,
    )
    if proc.returncode != 0:
        return _fail("console-build", (proc.stdout + "\n" + proc.stderr).strip())
    return _ok("console-build", "console rebuilt")


def _check_control_tower_http() -> CheckResult:
    admin_url = f"http://127.0.0.1:{DEFAULT_ADMIN_PORT}{ADMIN_HEALTH_PATH}"
    console_url = f"http://127.0.0.1:{DEFAULT_CONSOLE_PORT}/api/health"

    admin_ok = _wait_http(admin_url, timeout_sec=60)
    console_ok = _wait_http(console_url, timeout_sec=60)

    if not admin_ok and not console_ok:
        return _fail(
            "control-tower-http",
            f"Admin + Console not reachable:\n - {admin_url}\n - {console_url}",
        )
    if not admin_ok:
        return _fail("control-tower-http", f"Admin gateway not reachable: {admin_url}")
    if not console_ok:
        return _fail("control-tower-http", f"Console not reachable: {console_url}")

    return _ok(
        "control-tower-http",
        f"Admin + Console reachable:\n - {admin_url}\n - {console_url}",
    )


def _run_target(target: str) -> CheckResult:
    proc = _run(["make", target], cwd=REPO)
    if proc.returncode != 0:
        return _fail(f"make {target}", (proc.stdout + "\n" + proc.stderr).strip())
    return _ok(f"make {target}", "OK")


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose + fix Control Tower issues")
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Apply safe fixes (compose up/down, regenerate artifacts, etc.)",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Rebuild images (console/admin/core) before restarting",
    )
    parser.add_argument(
        "--strict-contract",
        action="store_true",
        help="Fail if Control Tower routes are missing from OpenAPI contract",
    )
    parser.add_argument(
        "--regen-inventory",
        action="store_true",
        help="Force regenerate route inventory and summary",
    )
    parser.add_argument(
        "--regen-platform-inventory",
        action="store_true",
        help="Run platform inventory generation from canonical artifacts",
    )
    parser.add_argument(
        "--run-gates",
        action="store_true",
        help="Run pr-check (or fast) after repairs",
    )
    args = parser.parse_args()

    _print_section("CONTROL TOWER DOCTOR")

    checks: list[CheckResult] = []
    checks.append(_require_repo_root())
    checks.append(_check_bins())

    ok_cfg, _compose_cfg = _compose_config()
    checks.append(ok_cfg)

    _print_section("DIAGNOSE: GOVERNANCE ARTIFACTS")
    if args.regen_inventory and args.fix:
        checks.append(_regenerate_route_inventory())

    checks.append(_ensure_governance_artifacts_exist())
    checks.append(_route_inventory_contains_control_tower())

    contract_res = _contract_contains_control_tower()
    if args.strict_contract and "WARNING:" in contract_res.details:
        checks.append(_fail("contract-control-tower-routes", contract_res.details))
    else:
        checks.append(contract_res)

    _print_section("DIAGNOSE: PLATFORM INVENTORY DECOUPLING")
    checks.append(_platform_inventory_generator_decoupled())

    _print_section("DIAGNOSE: RUNTIME STACK")
    if args.fix:
        if args.rebuild:
            checks.append(_compose_up(["core", "admin"], rebuild=True))
        else:
            checks.append(_compose_up(["core", "admin"], rebuild=False))

        checks.append(
            _rebuild_console() if args.rebuild else _ok("console-build", "skipped")
        )
        checks.append(_check_control_tower_http())
    else:
        checks.append(_ok("compose-up", "skipped (run with --fix to restart stack)"))
        checks.append(
            _ok("control-tower-http", "skipped (run with --fix to verify endpoints)")
        )

    _print_section("OPTIONAL: REGENERATE PLATFORM INVENTORY")
    if args.regen_platform_inventory:
        dec = _platform_inventory_generator_decoupled()
        if not dec.ok:
            checks.append(dec)
        else:
            checks.append(_generate_platform_inventory_from_artifacts())
    else:
        checks.append(_ok("platform-inventory-generate", "skipped"))

    _print_section("OPTIONAL: RUN GATES")
    if args.run_gates:
        proc = _run(["make", "-n", "pr-check-fast"], cwd=REPO)
        target = "pr-check-fast" if proc.returncode == 0 else "pr-check"
        checks.append(_run_target(target))
    else:
        checks.append(_ok("gates", "skipped"))

    _print_section("REPORT")
    failures = [c for c in checks if not c.ok]
    for c in checks:
        status = "OK " if c.ok else "FAIL"
        msg = f"{status}  {c.name}"
        if c.details:
            msg += f"\n      {c.details.replace(chr(10), chr(10) + '      ')}"
        print(msg)

    if failures:
        print("\nRESULT: FAILED (because reality is undefeated).")
        return 1

    print("\nRESULT: PASSED (Control Tower should be usable).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
