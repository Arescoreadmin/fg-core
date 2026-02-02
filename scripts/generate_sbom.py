#!/usr/bin/env python3
"""
SBOM (Software Bill of Materials) Generator for FrostGate Core.

Generates CycloneDX-format SBOM from:
- Python dependencies (requirements.txt)
- Node.js dependencies (package.json) if present
- System packages (optional)

Output: artifacts/sbom.json (CycloneDX 1.5 format)

Usage:
    python scripts/generate_sbom.py [--output PATH]
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# CycloneDX spec version
CYCLONEDX_SPEC_VERSION = "1.5"

# Output directory
ARTIFACTS_DIR = Path(os.getenv("FG_ARTIFACTS_DIR", "artifacts"))


def sha256_file(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_requirements(filepath: Path) -> list[dict[str, Any]]:
    """
    Parse requirements.txt and extract dependencies.

    Returns list of component dicts in CycloneDX format.
    """
    if not filepath.exists():
        return []

    components = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse package==version or package>=version
            name = line
            version = "unknown"

            for sep in ["==", ">=", "<=", "~=", "!="]:
                if sep in line:
                    parts = line.split(sep)
                    name = parts[0].strip()
                    version = parts[1].strip().split(",")[0].split(";")[0]
                    break

            # Create CycloneDX component
            component = {
                "type": "library",
                "name": name.lower(),
                "version": version,
                "purl": f"pkg:pypi/{name.lower()}@{version}",
                "bom-ref": f"pypi:{name.lower()}:{version}",
            }
            components.append(component)

    return components


def parse_package_json(filepath: Path) -> list[dict[str, Any]]:
    """
    Parse package.json and extract dependencies.

    Returns list of component dicts in CycloneDX format.
    """
    if not filepath.exists():
        return []

    with open(filepath) as f:
        pkg = json.load(f)

    components = []
    for dep_type in ["dependencies", "devDependencies"]:
        deps = pkg.get(dep_type, {})
        for name, version in deps.items():
            # Clean version string
            version = version.lstrip("^~>=<")

            component = {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}",
                "bom-ref": f"npm:{name}:{version}",
            }
            components.append(component)

    return components


def get_git_info() -> dict[str, str]:
    """Get current git commit info."""
    info = {}
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            info["commit"] = result.stdout.strip()

        result = subprocess.run(
            ["git", "describe", "--tags", "--always"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["version"] = result.stdout.strip()

    except Exception:
        pass

    return info


def generate_sbom(
    project_dir: Path,
    output_path: Optional[Path] = None,
) -> dict[str, Any]:
    """
    Generate SBOM in CycloneDX format.

    Args:
        project_dir: Root directory of the project
        output_path: Optional path to write SBOM JSON

    Returns:
        CycloneDX SBOM dict
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    git_info = get_git_info()

    # Collect components from all sources
    components = []

    # Python dependencies
    for req_file in ["requirements.txt", "requirements-dev.txt"]:
        req_path = project_dir / req_file
        components.extend(parse_requirements(req_path))

    # Node.js dependencies (console)
    console_pkg = project_dir / "console" / "package.json"
    components.extend(parse_package_json(console_pkg))

    # Admin gateway dependencies
    admin_req = project_dir / "admin_gateway" / "requirements.txt"
    components.extend(parse_requirements(admin_req))

    # Deduplicate by bom-ref
    seen = set()
    unique_components = []
    for comp in components:
        ref = comp.get("bom-ref", comp["name"])
        if ref not in seen:
            seen.add(ref)
            unique_components.append(comp)

    # Build CycloneDX SBOM
    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{hashlib.sha256(timestamp.encode()).hexdigest()[:36]}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "FrostGate",
                    "name": "generate_sbom.py",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "frostgate-core",
                "version": git_info.get("version", "unknown"),
                "purl": f"pkg:github/frostgate/fg-core@{git_info.get('commit', 'unknown')[:7]}",
            },
        },
        "components": unique_components,
    }

    # Write to file if path provided
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(sbom, f, indent=2)
        print(f"SBOM written to {output_path}")
        print(f"  Components: {len(unique_components)}")

    return sbom


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate SBOM for FrostGate Core")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=ARTIFACTS_DIR / "sbom.json",
        help="Output path for SBOM JSON",
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=Path.cwd(),
        help="Project root directory",
    )
    args = parser.parse_args()

    try:
        sbom = generate_sbom(args.project_dir, args.output)
        print(f"SBOM generation complete: {len(sbom['components'])} components")
        return 0
    except Exception as e:
        print(f"Error generating SBOM: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
