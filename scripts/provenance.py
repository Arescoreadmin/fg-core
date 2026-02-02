#!/usr/bin/env python3
"""
SLSA-style Provenance Generator for FrostGate Core.

Generates provenance attestation documenting:
- Build environment
- Source materials (git info)
- Build process
- Output artifacts

Output: artifacts/provenance.json (SLSA Provenance v1.0 format)

This is a minimal SLSA provenance generator that runs locally and in CI
without requiring external signing services.

Usage:
    python scripts/provenance.py [--output PATH]
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# SLSA Provenance predicate type
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

# Output directory
ARTIFACTS_DIR = Path(os.getenv("FG_ARTIFACTS_DIR", "artifacts"))


def sha256_file(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    if filepath.exists():
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    return h.hexdigest()


def sha256_string(data: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def get_git_info() -> dict[str, Any]:
    """Get comprehensive git info for provenance."""
    info = {
        "commit": None,
        "branch": None,
        "tag": None,
        "remote": None,
        "dirty": False,
    }

    try:
        # Commit SHA
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            info["commit"] = result.stdout.strip()

        # Branch name
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["branch"] = result.stdout.strip()

        # Tag if on tag
        result = subprocess.run(
            ["git", "describe", "--tags", "--exact-match"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["tag"] = result.stdout.strip()

        # Remote URL
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["remote"] = result.stdout.strip()

        # Check if working tree is dirty
        result = subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            info["dirty"] = len(result.stdout.strip()) > 0

    except Exception:
        pass

    return info


def get_build_environment() -> dict[str, Any]:
    """Get build environment information."""
    env = {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
    }

    # CI environment detection
    if os.getenv("GITHUB_ACTIONS") == "true":
        env["ci"] = "github-actions"
        env["ci_run_id"] = os.getenv("GITHUB_RUN_ID")
        env["ci_workflow"] = os.getenv("GITHUB_WORKFLOW")
        env["ci_actor"] = os.getenv("GITHUB_ACTOR")
    elif os.getenv("GITLAB_CI") == "true":
        env["ci"] = "gitlab-ci"
        env["ci_job_id"] = os.getenv("CI_JOB_ID")
    elif os.getenv("CI") == "true":
        env["ci"] = "unknown"
    else:
        env["ci"] = None

    return env


def get_dockerfile_digest(project_dir: Path) -> Optional[str]:
    """Get digest of Dockerfile if it exists."""
    dockerfile = project_dir / "Dockerfile"
    if dockerfile.exists():
        return sha256_file(dockerfile)
    return None


def get_image_digest() -> Optional[str]:
    """Get Docker image digest if available."""
    # This would be populated by CI after image build
    return os.getenv("FG_IMAGE_DIGEST")


def generate_provenance(
    project_dir: Path,
    output_path: Optional[Path] = None,
    subject_name: str = "frostgate-core",
) -> dict[str, Any]:
    """
    Generate SLSA-style provenance attestation.

    Args:
        project_dir: Root directory of the project
        output_path: Optional path to write provenance JSON
        subject_name: Name of the build subject

    Returns:
        SLSA provenance dict
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    git_info = get_git_info()
    build_env = get_build_environment()

    # Build materials (source inputs)
    materials = []

    # Git repository as primary material
    if git_info.get("remote"):
        materials.append(
            {
                "uri": git_info["remote"],
                "digest": {
                    "sha1": git_info.get("commit", "unknown"),
                },
            }
        )

    # Dockerfile
    dockerfile_digest = get_dockerfile_digest(project_dir)
    if dockerfile_digest:
        materials.append(
            {
                "uri": "file://Dockerfile",
                "digest": {
                    "sha256": dockerfile_digest,
                },
            }
        )

    # Requirements files
    for req_file in ["requirements.txt", "requirements-dev.txt"]:
        req_path = project_dir / req_file
        if req_path.exists():
            materials.append(
                {
                    "uri": f"file://{req_file}",
                    "digest": {
                        "sha256": sha256_file(req_path),
                    },
                }
            )

    # Build subject (output)
    subjects = []

    # Add SBOM as subject if it exists
    sbom_path = ARTIFACTS_DIR / "sbom.json"
    if sbom_path.exists():
        subjects.append(
            {
                "name": "sbom.json",
                "digest": {
                    "sha256": sha256_file(sbom_path),
                },
            }
        )

    # Add image digest if available
    image_digest = get_image_digest()
    if image_digest:
        subjects.append(
            {
                "name": f"{subject_name}:latest",
                "digest": {
                    "sha256": image_digest,
                },
            }
        )

    # Build SLSA Provenance
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects
        or [
            {
                "name": subject_name,
                "digest": {
                    "sha256": sha256_string(timestamp + (git_info.get("commit") or "")),
                },
            }
        ],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://frostgate.io/build/v1",
                "externalParameters": {
                    "source": git_info.get("remote"),
                    "ref": git_info.get("branch"),
                    "commit": git_info.get("commit"),
                },
                "internalParameters": {
                    "dirty": git_info.get("dirty", False),
                },
                "resolvedDependencies": materials,
            },
            "runDetails": {
                "builder": {
                    "id": f"https://frostgate.io/builders/{build_env.get('ci', 'local')}",
                    "version": {
                        "python": build_env.get("python_version"),
                        "platform": build_env.get("platform"),
                    },
                },
                "metadata": {
                    "invocationId": build_env.get("ci_run_id")
                    or sha256_string(timestamp)[:16],
                    "startedOn": timestamp,
                    "finishedOn": datetime.now(timezone.utc).isoformat(),
                },
                "byproducts": [],
            },
        },
    }

    # Write to file if path provided
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(provenance, f, indent=2)
        print(f"Provenance written to {output_path}")

    return provenance


def verify_provenance(provenance_path: Path) -> tuple[bool, list[str]]:
    """
    Verify a provenance file's integrity.

    Returns (is_valid, list of errors).
    """
    errors = []

    if not provenance_path.exists():
        return False, ["Provenance file not found"]

    try:
        with open(provenance_path) as f:
            prov = json.load(f)
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"]

    # Check required fields
    if prov.get("_type") != "https://in-toto.io/Statement/v1":
        errors.append("Invalid statement type")

    if prov.get("predicateType") != SLSA_PREDICATE_TYPE:
        errors.append("Invalid predicate type")

    if not prov.get("subject"):
        errors.append("Missing subject")

    predicate = prov.get("predicate", {})
    if not predicate.get("buildDefinition"):
        errors.append("Missing buildDefinition")

    if not predicate.get("runDetails"):
        errors.append("Missing runDetails")

    return len(errors) == 0, errors


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate SLSA provenance for FrostGate Core"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=ARTIFACTS_DIR / "provenance.json",
        help="Output path for provenance JSON",
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=Path.cwd(),
        help="Project root directory",
    )
    parser.add_argument(
        "--verify",
        type=Path,
        help="Verify existing provenance file instead of generating",
    )
    args = parser.parse_args()

    try:
        if args.verify:
            is_valid, errors = verify_provenance(args.verify)
            if is_valid:
                print(f"Provenance valid: {args.verify}")
                return 0
            else:
                print(f"Provenance invalid: {errors}")
                return 1

        generate_provenance(args.project_dir, args.output)
        print("Provenance generation complete")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
