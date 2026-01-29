#!/usr/bin/env python3
from __future__ import annotations

import importlib.metadata as metadata
import sys
from pathlib import Path


TARGET_PACKAGES = {
    "fastapi",
    "starlette",
    "pydantic",
    "pydantic-core",
    "typing-extensions",
}


def _parse_pins(requirements_path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line or line.startswith("-"):
            continue
        name_part, version = line.split("==", 1)
        name = name_part.split("[", 1)[0]
        pins[name.lower()] = version
    return pins


def _version_for(package: str) -> str:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError as exc:
        raise SystemExit(f"Package {package} is not installed") from exc


def main() -> None:
    root_reqs = _parse_pins(Path("requirements.txt"))
    admin_reqs = _parse_pins(Path("admin_gateway/requirements.txt"))

    missing = sorted(TARGET_PACKAGES - admin_reqs.keys())
    if missing:
        raise SystemExit(
            "Missing pinned versions for admin contract toolchain: "
            + ", ".join(missing)
        )

    root_mismatch = {
        package: (root_reqs.get(package), admin_reqs[package])
        for package in ("fastapi", "pydantic")
        if root_reqs.get(package) and root_reqs.get(package) != admin_reqs[package]
    }
    if root_mismatch:
        formatted = ", ".join(
            f"{pkg} root={root} admin={admin}"
            for pkg, (root, admin) in root_mismatch.items()
        )
        raise SystemExit(f"Root/admin contract pins diverged: {formatted}")

    mismatched_installs = []
    for package in sorted(TARGET_PACKAGES):
        installed = _version_for(package)
        expected = admin_reqs[package]
        if installed != expected:
            mismatched_installs.append(
                f"{package} installed={installed} expected={expected}"
            )

    if mismatched_installs:
        raise SystemExit(
            "Contract toolchain mismatch: " + "; ".join(mismatched_installs)
        )

    print("Contract toolchain check: OK")


if __name__ == "__main__":
    main()
