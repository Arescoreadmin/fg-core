"""tools/ci/check_cgin_key_management.py

CGIN Key Management Gate — static structural enforcement.

Validates that the key management module, registry, MemoryKeyProvider,
and API router are structurally correct by AST inspection and lightweight
import probing.

Usage:
    python tools/ci/check_cgin_key_management.py          # exits 0 on pass, 1 on fail
    python tools/ci/check_cgin_key_management.py --verbose

Exit codes:
    0  All CGIN key management structural checks pass.
    1  One or more checks failed.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

PROVIDER_MODULE = ROOT / "services" / "cgin" / "key_management" / "provider.py"
REGISTRY_MODULE = ROOT / "services" / "cgin" / "key_management" / "registry.py"
MEMORY_PROVIDER_MODULE = (
    ROOT / "services" / "cgin" / "key_management" / "providers" / "memory.py"
)
API_ROUTER = ROOT / "api" / "cgin_trust.py"

REQUIRED_PROVIDER_SYMBOLS = {
    "KeyProvider",
    "SigningAlgorithm",
    "ACTIVE_SIGNING_ALGORITHM",
    "ProviderHealth",
    "ProviderCapabilityManifest",
    "ProviderMetadata",
    "AuditEvent",
    "CryptoPolicy",
}

REQUIRED_REGISTRY_SYMBOLS = {
    "ProviderRegistry",
    "ACTIVE_PROVIDER_REGISTRY",
}

REQUIRED_MEMORY_SYMBOLS = {
    "MemoryKeyProvider",
}

REQUIRED_ROUTE_PREFIXES = {
    "/cgin/trust/providers",
    "/cgin/trust/providers/",
}


def _top_level_names(path: Path) -> set[str]:
    """Return all top-level names defined in a Python source file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, OSError) as exc:
        raise RuntimeError(f"Cannot parse {path}: {exc}") from exc

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
    return names


def _extract_route_strings(path: Path) -> list[str]:
    """Extract string literals from router decorator calls in an API file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, OSError):
        return []

    routes: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            is_router_method = (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "router"
            )
            if not is_router_method:
                continue
            for arg in decorator.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    routes.append(arg.value)
    return routes


def main() -> int:
    parser = argparse.ArgumentParser(description="CGIN Key Management Gate")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []

    # --- Check provider module ---
    if not PROVIDER_MODULE.exists():
        failures.append(f"Missing: {PROVIDER_MODULE.relative_to(ROOT)}")
    else:
        if args.verbose:
            print(f"  Checking {PROVIDER_MODULE.relative_to(ROOT)}")
        try:
            names = _top_level_names(PROVIDER_MODULE)
            for sym in sorted(REQUIRED_PROVIDER_SYMBOLS):
                if sym not in names:
                    failures.append(
                        f"{PROVIDER_MODULE.relative_to(ROOT)}: missing symbol '{sym}'"
                    )
                elif args.verbose:
                    print(f"    ✓ {sym}")
        except RuntimeError as exc:
            failures.append(str(exc))

    # --- Check registry module ---
    if not REGISTRY_MODULE.exists():
        failures.append(f"Missing: {REGISTRY_MODULE.relative_to(ROOT)}")
    else:
        if args.verbose:
            print(f"  Checking {REGISTRY_MODULE.relative_to(ROOT)}")
        try:
            names = _top_level_names(REGISTRY_MODULE)
            for sym in sorted(REQUIRED_REGISTRY_SYMBOLS):
                if sym not in names:
                    failures.append(
                        f"{REGISTRY_MODULE.relative_to(ROOT)}: missing symbol '{sym}'"
                    )
                elif args.verbose:
                    print(f"    ✓ {sym}")
        except RuntimeError as exc:
            failures.append(str(exc))

    # --- Check MemoryKeyProvider module ---
    if not MEMORY_PROVIDER_MODULE.exists():
        failures.append(f"Missing: {MEMORY_PROVIDER_MODULE.relative_to(ROOT)}")
    else:
        if args.verbose:
            print(f"  Checking {MEMORY_PROVIDER_MODULE.relative_to(ROOT)}")
        try:
            names = _top_level_names(MEMORY_PROVIDER_MODULE)
            for sym in sorted(REQUIRED_MEMORY_SYMBOLS):
                if sym not in names:
                    failures.append(
                        f"{MEMORY_PROVIDER_MODULE.relative_to(ROOT)}: missing symbol '{sym}'"
                    )
                elif args.verbose:
                    print(f"    ✓ {sym}")
        except RuntimeError as exc:
            failures.append(str(exc))

    # --- Check API router has provider routes ---
    if not API_ROUTER.exists():
        failures.append(f"Missing: {API_ROUTER.relative_to(ROOT)}")
    else:
        if args.verbose:
            print(f"  Checking {API_ROUTER.relative_to(ROOT)}")
        routes = _extract_route_strings(API_ROUTER)
        if args.verbose:
            print(f"    Routes found: {routes}")
        for prefix in sorted(REQUIRED_ROUTE_PREFIXES):
            matched = any(r == prefix or r.startswith(prefix) for r in routes)
            if not matched:
                failures.append(
                    f"{API_ROUTER.relative_to(ROOT)}: "
                    f"no route matching prefix '{prefix}'"
                )
            elif args.verbose:
                print(f"    ✓ route prefix '{prefix}'")

    if failures:
        print(f"\nCGIN Key Management Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  ✗  {f}")
        return 1

    # --- Runtime import checks ---
    try:
        import importlib

        sys.path.insert(0, str(ROOT))
        km_mod = importlib.import_module("services.cgin.key_management")

        # ACTIVE_PROVIDER_REGISTRY.active() works
        registry = km_mod.ACTIVE_PROVIDER_REGISTRY
        active = registry.active()

        # active provider health is READY
        health = active.health()
        if health != km_mod.ProviderHealth.READY:
            failures.append(
                f"ACTIVE_PROVIDER_REGISTRY.active().health() returned {health!r},"
                f" expected READY"
            )
        elif args.verbose:
            print(f"    ✓ active provider health={health.value}")

        # all providers satisfy KeyProvider protocol
        for p in registry.all():
            if not isinstance(p, km_mod.KeyProvider):
                failures.append(
                    f"Provider {p.provider_name!r} does not satisfy KeyProvider protocol"
                )
            elif args.verbose:
                print(f"    ✓ {p.provider_name} satisfies KeyProvider protocol")

        # no duplicate provider names
        names_list = [p.provider_name for p in registry.all()]
        if len(names_list) != len(set(names_list)):
            failures.append(
                f"Duplicate provider names in ACTIVE_PROVIDER_REGISTRY: {names_list}"
            )
        elif args.verbose:
            print(f"    ✓ no duplicate provider names: {names_list}")

    except Exception as exc:
        failures.append(f"Runtime import check failed: {exc}")

    if failures:
        print(f"\nCGIN Key Management Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  ✗  {f}")
        return 1

    print(
        "CGIN Key Management Gate: PASS (provider module verified, registry verified, MemoryKeyProvider verified, API router verified)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
