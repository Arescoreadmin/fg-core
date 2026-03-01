#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import yaml


PROTECTED_PATH_PREFIXES = (
    "auth/",
    "db/",
    "migrations/",
    "security/",
    "planes/",
    "contracts/",
)


def _load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def validate_critical_coverage(invariants: list[dict[str, object]]) -> None:
    for inv in invariants:
        if inv.get("severity") == "critical" and not inv.get("enforced_by"):
            raise SystemExit(
                f"critical invariant missing enforcing tests: {inv.get('id')}"
            )


def validate_path_mapping(
    changed_paths: list[str], mapping: dict[str, list[str]]
) -> None:
    for path in changed_paths:
        if path.startswith(PROTECTED_PATH_PREFIXES) and not any(
            path.startswith(k) or path == k for k in mapping
        ):
            raise SystemExit(f"protected path lacks invariant mapping: {path}")


def validate_route_prefix_registrations(
    changed_paths: list[str], mapping: dict[str, list[str]]
) -> None:
    for path in changed_paths:
        if not path.startswith("api/") or not path.endswith(".py"):
            continue
        f = Path(path)
        if not f.exists():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        if "APIRouter(" in text and "prefix=" in text:
            if not any(path == k or path.startswith(k) for k in mapping):
                raise SystemExit(f"api route module lacks invariant mapping: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--invariants", default="tools/testing/policy/invariants.yaml")
    parser.add_argument(
        "--path-map", default="tools/testing/policy/path_to_invariants.yaml"
    )
    parser.add_argument("--changed", nargs="*", default=[])
    args = parser.parse_args()

    invariants = _load_yaml(Path(args.invariants)) or []
    path_map = _load_yaml(Path(args.path_map)) or {}
    validate_critical_coverage(invariants)
    validate_path_mapping(args.changed, path_map)
    validate_route_prefix_registrations(args.changed, path_map)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
