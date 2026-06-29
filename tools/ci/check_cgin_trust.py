"""tools/ci/check_cgin_trust.py

CGIN Trust Gate — static structural enforcement.

Validates that the trust module, manifest module, and API router are
structurally correct by AST inspection and lightweight import probing.

Usage:
    python tools/ci/check_cgin_trust.py          # exits 0 on pass, 1 on fail
    python tools/ci/check_cgin_trust.py --verbose

Exit codes:
    0  All CGIN trust structural checks pass.
    1  One or more checks failed.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

TRUST_MODULE = ROOT / "services" / "cgin" / "trust.py"
TRUST_MANIFEST_MODULE = ROOT / "services" / "cgin" / "trust_manifest.py"
API_ROUTER = ROOT / "api" / "cgin_trust.py"

REQUIRED_TRUST_SYMBOLS = {
    "SigningAlgorithm",
    "ACTIVE_SIGNING_ALGORITHM",
    "canonicalize_snapshot",
    "generate_digest",
    "build_trust_metadata",
    "verify_snapshot",
    "VerificationResult",
}

REQUIRED_MANIFEST_SYMBOLS = {
    "TrustManifest",
    "generate_trust_manifest",
    "verify_trust_manifest",
}

REQUIRED_ROUTE_PREFIXES = {
    "/cgin/trust/algorithms",
    "/cgin/trust/verify",
    "/cgin/trust/manifest/",
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


def _check_active_signing_algorithm_is_enum_member(path: Path) -> bool:
    """Return True if ACTIVE_SIGNING_ALGORITHM is assigned a SigningAlgorithm member."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, OSError):
        return False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not (
                isinstance(target, ast.Name) and target.id == "ACTIVE_SIGNING_ALGORITHM"
            ):
                continue
            val = node.value
            if (
                isinstance(val, ast.Attribute)
                and isinstance(val.value, ast.Name)
                and val.value.id == "SigningAlgorithm"
            ):
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="CGIN Trust Gate")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []

    # --- Check trust module exists ---
    if not TRUST_MODULE.exists():
        failures.append(f"Missing: {TRUST_MODULE.relative_to(ROOT)}")
    else:
        if args.verbose:
            print(f"  Checking {TRUST_MODULE.relative_to(ROOT)}")
        try:
            names = _top_level_names(TRUST_MODULE)
            for sym in sorted(REQUIRED_TRUST_SYMBOLS):
                if sym not in names:
                    failures.append(
                        f"{TRUST_MODULE.relative_to(ROOT)}: missing symbol '{sym}'"
                    )
                elif args.verbose:
                    print(f"    ✓ {sym}")
            if not _check_active_signing_algorithm_is_enum_member(TRUST_MODULE):
                failures.append(
                    f"{TRUST_MODULE.relative_to(ROOT)}: "
                    "ACTIVE_SIGNING_ALGORITHM must be assigned a SigningAlgorithm member, "
                    "not a raw string"
                )
            elif args.verbose:
                print("    ✓ ACTIVE_SIGNING_ALGORITHM is a SigningAlgorithm member")
        except RuntimeError as exc:
            failures.append(str(exc))

    # --- Check trust_manifest module exists ---
    if not TRUST_MANIFEST_MODULE.exists():
        failures.append(f"Missing: {TRUST_MANIFEST_MODULE.relative_to(ROOT)}")
    else:
        if args.verbose:
            print(f"  Checking {TRUST_MANIFEST_MODULE.relative_to(ROOT)}")
        try:
            names = _top_level_names(TRUST_MANIFEST_MODULE)
            for sym in sorted(REQUIRED_MANIFEST_SYMBOLS):
                if sym not in names:
                    failures.append(
                        f"{TRUST_MANIFEST_MODULE.relative_to(ROOT)}: missing symbol '{sym}'"
                    )
                elif args.verbose:
                    print(f"    ✓ {sym}")
        except RuntimeError as exc:
            failures.append(str(exc))

    # --- Check API router exists and has required routes ---
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
        print(f"\nCGIN Trust Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  ✗  {f}")
        return 1

    # Try lightweight import validation
    try:
        import importlib

        sys.path.insert(0, str(ROOT))
        trust_mod = importlib.import_module("services.cgin.trust")
        active = trust_mod.ACTIVE_SIGNING_ALGORITHM
        algo_cls = trust_mod.SigningAlgorithm
        if not isinstance(active, algo_cls):
            failures.append(
                "ACTIVE_SIGNING_ALGORITHM is not a SigningAlgorithm instance at runtime"
            )
        trust_version = trust_mod.CGIN_TRUST_VERSION
        canon_version = trust_mod.CGIN_CANONICALIZATION_VERSION
        if args.verbose:
            print(
                f"    trust_version={trust_version} "
                f"canonicalization_version={canon_version} "
                f"active_algorithm={active.value}"
            )
    except Exception as exc:
        failures.append(f"Runtime import check failed: {exc}")

    if failures:
        print(f"\nCGIN Trust Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  ✗  {f}")
        return 1

    print(
        f"CGIN Trust Gate: PASS "
        f"(trust module verified, manifest module verified, "
        f"API router verified, "
        f"active_algorithm={ACTIVE_SIGNING_ALGORITHM_VALUE})"
    )
    return 0


# Capture active algo value for summary line
try:
    sys.path.insert(0, str(ROOT))
    from services.cgin.trust import ACTIVE_SIGNING_ALGORITHM as _ASA

    ACTIVE_SIGNING_ALGORITHM_VALUE = _ASA.value
except Exception:
    ACTIVE_SIGNING_ALGORITHM_VALUE = "ed25519-v1"


if __name__ == "__main__":
    sys.exit(main())
