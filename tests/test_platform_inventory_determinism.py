from __future__ import annotations

import hashlib
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

from tools.ci import check_route_inventory


OUTPUT_FILES = [
    Path("artifacts/PLATFORM_INVENTORY.md"),
    Path("artifacts/PLATFORM_GAPS.md"),
    Path("artifacts/platform_inventory.json"),
]

GOVERNANCE_INPUTS = [
    Path("tools/ci/plane_registry_snapshot.json"),
    Path("tools/ci/route_inventory.json"),
    Path("tools/ci/route_inventory_summary.json"),
    Path("tools/ci/contract_routes.json"),
    Path("tools/ci/topology.sha256"),
    Path("tools/ci/attestation_bundle.sha256"),
    Path("tools/ci/build_meta.json"),
]

FILES_TO_PRESERVE = OUTPUT_FILES + GOVERNANCE_INPUTS


@contextmanager
def _preserve_files(paths: list[Path]):
    snapshots: dict[Path, bytes | None] = {}
    for path in paths:
        snapshots[path] = path.read_bytes() if path.exists() else None
    try:
        yield
    finally:
        for path, content in snapshots.items():
            if content is None:
                if path.exists():
                    path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)


def _hashes() -> list[str]:
    return [hashlib.sha256(p.read_bytes()).hexdigest() for p in OUTPUT_FILES]


def _ensure_governance_inputs() -> None:
    missing = [p for p in GOVERNANCE_INPUTS if not p.exists()]
    if not missing:
        return

    # Intentionally call the module writer directly instead of the CLI.
    # The CLI suppresses --write when CI=true, but these tests need canonical
    # governance artifacts available in-process and restore them afterward.
    check_route_inventory.write_inventory()

    still_missing = [str(p) for p in GOVERNANCE_INPUTS if not p.exists()]
    if still_missing:
        joined = "\n - ".join(still_missing)
        raise AssertionError(
            "Required governance inputs are missing for platform inventory tests "
            "after bootstrap:\n"
            f" - {joined}"
        )


def _run_platform_inventory() -> None:
    subprocess.run(
        [sys.executable, "scripts/generate_platform_inventory.py"],
        check=True,
    )


def test_platform_inventory_deterministic():
    with _preserve_files(FILES_TO_PRESERVE):
        _ensure_governance_inputs()

        _run_platform_inventory()
        h1 = _hashes()

        _run_platform_inventory()
        h2 = _hashes()

    assert h1 == h2


def test_platform_inventory_sections_present():
    with _preserve_files(FILES_TO_PRESERVE):
        _ensure_governance_inputs()

        _run_platform_inventory()
        inv = Path("artifacts/PLATFORM_INVENTORY.md").read_text(encoding="utf-8")
        gaps = Path("artifacts/PLATFORM_GAPS.md").read_text(encoding="utf-8")

    assert "## Planes" in inv
    assert "## Enterprise readiness checklist status" in inv
    assert "# Platform Gaps" in gaps
