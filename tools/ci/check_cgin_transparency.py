"""tools/ci/check_cgin_transparency.py

CGIN Transparency Gate — static structural enforcement.

Validates that the transparency module, ledger, store, merkle tree, and API
router are structurally correct by AST inspection and lightweight import probing.

Usage:
    python tools/ci/check_cgin_transparency.py          # exits 0 on pass, 1 on fail
    python tools/ci/check_cgin_transparency.py --verbose

Exit codes:
    0  All CGIN transparency structural checks pass.
    1  One or more checks failed.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

ENTRY_MODULE = ROOT / "services" / "cgin" / "transparency" / "entry.py"
MERKLE_MODULE = ROOT / "services" / "cgin" / "transparency" / "merkle.py"
STORE_MODULE = ROOT / "services" / "cgin" / "transparency" / "store.py"
LEDGER_MODULE = ROOT / "services" / "cgin" / "transparency" / "ledger.py"
API_ROUTER = ROOT / "api" / "cgin_transparency.py"

REQUIRED_ENTRY_SYMBOLS = {
    "TransparencyEntry",
    "TRANSPARENCY_VERSION",
    "TRANSPARENCY_SCHEMA_VERSION",
}

REQUIRED_MERKLE_SYMBOLS = {
    "MerkleTree",
    "MembershipProof",
}

REQUIRED_STORE_SYMBOLS = {
    "TransparencyStore",
    "MemoryTransparencyStore",
}

REQUIRED_LEDGER_SYMBOLS = {
    "TransparencyLedger",
}

REQUIRED_ROUTE_PREFIXES = {
    "/cgin/transparency/",
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
    parser = argparse.ArgumentParser(description="CGIN Transparency Gate")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []

    # --- Check entry module ---
    _check_module(ENTRY_MODULE, REQUIRED_ENTRY_SYMBOLS, failures, args.verbose, ROOT)

    # --- Check merkle module ---
    _check_module(MERKLE_MODULE, REQUIRED_MERKLE_SYMBOLS, failures, args.verbose, ROOT)

    # --- Check store module ---
    _check_module(STORE_MODULE, REQUIRED_STORE_SYMBOLS, failures, args.verbose, ROOT)

    # --- Check ledger module ---
    _check_module(LEDGER_MODULE, REQUIRED_LEDGER_SYMBOLS, failures, args.verbose, ROOT)

    # --- Check API router ---
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
        print(f"\nCGIN Transparency Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  ✗  {f}")
        return 1

    # --- Runtime import checks ---
    try:
        import importlib

        sys.path.insert(0, str(ROOT))
        mod = importlib.import_module("services.cgin.transparency")

        # ACTIVE_TRANSPARENCY_LEDGER exists
        ledger = mod.ACTIVE_TRANSPARENCY_LEDGER
        if args.verbose:
            print(f"    ✓ ACTIVE_TRANSPARENCY_LEDGER = {ledger!r}")

        # MerkleTree determinism check
        merkle_mod = importlib.import_module("services.cgin.transparency.merkle")
        MerkleTree = merkle_mod.MerkleTree
        leaves = [b"alpha", b"beta", b"gamma"]
        root1 = MerkleTree(leaves).root()
        root2 = MerkleTree(leaves).root()
        if root1 != root2:
            failures.append(
                "MerkleTree determinism check failed: same input produced different roots"
            )
        elif args.verbose:
            print(f"    ✓ MerkleTree deterministic: {root1.hex()}")

        # Append-only check: duplicate entry_id raises
        store_mod = importlib.import_module("services.cgin.transparency.store")
        entry_mod = importlib.import_module("services.cgin.transparency.entry")
        MemoryTransparencyStore = store_mod.MemoryTransparencyStore
        TransparencyEntry = entry_mod.TransparencyEntry
        TRANSPARENCY_VERSION = entry_mod.TRANSPARENCY_VERSION
        TRANSPARENCY_SCHEMA_VERSION = entry_mod.TRANSPARENCY_SCHEMA_VERSION

        s = MemoryTransparencyStore()
        e = TransparencyEntry(
            entry_id="abc123",
            entry_type="test",
            authority_name="test",
            authority_version="1.0",
            artifact_digest="a" * 64,
            parent_digest=None,
            sequence_number=0,
            generated_at="2026-01-01T00:00:00+00:00",
            tenant_fingerprint="f" * 32,
            signature_algorithm="ed25519-v1",
            signature_provider="memory",
            schema_version=TRANSPARENCY_SCHEMA_VERSION,
            transparency_version=TRANSPARENCY_VERSION,
        )
        s.append_entry(e)
        raised = False
        try:
            s.append_entry(e)
        except ValueError:
            raised = True
        if not raised:
            failures.append(
                "MemoryTransparencyStore: duplicate entry_id did not raise ValueError"
            )
        elif args.verbose:
            print("    ✓ append-only: duplicate entry_id raises ValueError")

    except Exception as exc:
        failures.append(f"Runtime import check failed: {exc}")

    if failures:
        print(f"\nCGIN Transparency Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  ✗  {f}")
        return 1

    print(
        "CGIN Transparency Gate: PASS "
        "(entry module verified, merkle module verified, store module verified, "
        "ledger module verified, API router verified, "
        "MerkleTree determinism verified, append-only invariant verified)"
    )
    return 0


def _check_module(
    path: Path,
    required: set[str],
    failures: list[str],
    verbose: bool,
    root: Path,
) -> None:
    if not path.exists():
        failures.append(f"Missing: {path.relative_to(root)}")
        return
    if verbose:
        print(f"  Checking {path.relative_to(root)}")
    try:
        names = _top_level_names(path)
        for sym in sorted(required):
            if sym not in names:
                failures.append(f"{path.relative_to(root)}: missing symbol '{sym}'")
            elif verbose:
                print(f"    ✓ {sym}")
    except RuntimeError as exc:
        failures.append(str(exc))


if __name__ == "__main__":
    sys.exit(main())
