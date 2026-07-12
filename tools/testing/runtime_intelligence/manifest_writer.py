"""Write and load manifest artifacts under ``artifacts/ci/manifests/``.

These helpers are pure I/O — they never sign, verify, or mutate manifest
content. Their sole responsibility is deterministic on-disk layout.
"""

from __future__ import annotations

import json
from pathlib import Path

from .fingerprints import REPO_ROOT
from .manifest import (
    ValidationManifest,
    deserialize_manifest,
    serialize_manifest,
)
from .signing import VerificationResult

MANIFEST_DIR = REPO_ROOT / "artifacts" / "ci" / "manifests"


def _gate_slug(gate: str) -> str:
    return gate.replace("/", "-")


def write_manifest(
    manifest: ValidationManifest, manifest_dir: Path = MANIFEST_DIR
) -> Path:
    """Write ``{gate}.manifest.json``. Returns the written path."""
    manifest_dir.mkdir(parents=True, exist_ok=True)
    path = manifest_dir / f"{_gate_slug(manifest.gate)}.manifest.json"
    path.write_text(serialize_manifest(manifest) + "\n", encoding="utf-8")
    return path


def write_verification_report(
    manifest: ValidationManifest,
    checks: dict[str, VerificationResult],
    manifest_dir: Path = MANIFEST_DIR,
) -> Path:
    """Write ``verification.json`` summarising the verification outcome."""
    manifest_dir.mkdir(parents=True, exist_ok=True)
    all_valid = all(r.valid for r in checks.values())
    report = {
        "manifest_id": manifest.manifest_id,
        "manifest_hash": manifest.manifest_hash,
        "gate": manifest.gate,
        "overall": "verified" if all_valid else "failed",
        "checks": {
            name: {
                "valid": r.valid,
                "algorithm": r.algorithm,
                "reason": r.reason,
                "detail": r.detail,
                "signing_identity": r.signing_identity,
            }
            for name, r in checks.items()
        },
    }
    path = manifest_dir / "verification.json"
    path.write_text(
        json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return path


def write_chain_record(
    manifests: list[ValidationManifest], manifest_dir: Path = MANIFEST_DIR
) -> Path:
    """Write ``chain.json`` recording ordered manifest hashes."""
    manifest_dir.mkdir(parents=True, exist_ok=True)
    chain = [
        {
            "gate": m.gate,
            "manifest_id": m.manifest_id,
            "manifest_hash": m.manifest_hash,
            "previous_manifest_hash": m.previous_manifest_hash,
        }
        for m in manifests
    ]
    path = manifest_dir / "chain.json"
    path.write_text(
        json.dumps({"chain": chain}, sort_keys=True, indent=2, ensure_ascii=True)
        + "\n",
        encoding="utf-8",
    )
    return path


def load_manifest(path: Path) -> ValidationManifest | None:
    """Load a manifest from ``path``.

    Returns ``None`` if the file is missing or malformed. Callers that need
    to distinguish those cases should use :func:`manifest.deserialize_manifest`
    directly.
    """
    if not path.exists():
        return None
    try:
        return deserialize_manifest(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
