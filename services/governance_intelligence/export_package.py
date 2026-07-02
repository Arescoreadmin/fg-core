"""Signed Explainability Package (PR 18.5A).

Pure functions only.  No DB I/O.
Note: PDF requires external libs — only JSON, HTML, and MANIFEST are supported.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# ---------------------------------------------------------------------------
# Supported formats
# ---------------------------------------------------------------------------

EXPORT_FORMATS: frozenset[str] = frozenset({"JSON", "HTML", "MANIFEST"})


# ---------------------------------------------------------------------------
# Hash helper
# ---------------------------------------------------------------------------


def compute_package_hash(package_data: dict[str, Any]) -> str:
    """SHA-256 of the deterministically sorted JSON of package_data."""
    serialised = json.dumps(package_data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def build_export_manifest(
    package_id: str,
    tenant_id: str,
    contents: dict[str, Any],
) -> dict[str, Any]:
    """Build a manifest dict for an export package."""
    from services.canonical import utc_iso8601_z_now

    contents_hash = compute_package_hash(contents)
    return {
        "package_id": package_id,
        "tenant_id": tenant_id,
        "created_at": utc_iso8601_z_now(),
        "contents_hash": contents_hash,
        "schema_version": "1.0",
        "export_format": "MANIFEST",
        "offline_verification_supported": True,
    }


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


def _strip_tenant_id(obj: Any) -> Any:
    """Recursively strip tenant_id from dicts."""
    if isinstance(obj, dict):
        return {k: _strip_tenant_id(v) for k, v in obj.items() if k != "tenant_id"}
    if isinstance(obj, list):
        return [_strip_tenant_id(item) for item in obj]
    return obj


def build_json_export(
    package_id: str,
    tenant_id: str,
    evidence_graph: dict[str, Any],
    recommendation_matrix: dict[str, Any],
    trust_refs: list[str],
    transparency_refs: list[str],
    confidence: dict[str, Any],
    replay: dict[str, Any] | None,
    simulation_comparison: dict[str, Any] | None,
) -> dict[str, Any]:
    """Assemble a full JSON export bundle.

    Strips tenant_id from all nested data before including.
    """
    from services.canonical import utc_iso8601_z_now

    bundle: dict[str, Any] = {
        "package_id": package_id,
        "schema_version": "1.0",
        "export_format": "JSON",
        "created_at": utc_iso8601_z_now(),
        "evidence_graph": _strip_tenant_id(evidence_graph),
        "recommendation_matrix": _strip_tenant_id(recommendation_matrix),
        "trust_refs": sorted(trust_refs),
        "transparency_refs": sorted(transparency_refs),
        "confidence": _strip_tenant_id(confidence),
    }
    if replay is not None:
        bundle["replay"] = _strip_tenant_id(replay)
    if simulation_comparison is not None:
        bundle["simulation_comparison"] = _strip_tenant_id(simulation_comparison)

    bundle["package_hash"] = compute_package_hash(bundle)
    return bundle


# ---------------------------------------------------------------------------
# HTML export
# ---------------------------------------------------------------------------


def build_html_export(package_data: dict[str, Any]) -> str:
    """Build a simple HTML string summarising the package.

    No external dependencies — pure string formatting.
    """
    package_id = package_data.get("package_id", "unknown")
    created_at = package_data.get("created_at", "")
    pkg_hash = package_data.get("package_hash", compute_package_hash(package_data))
    schema_version = package_data.get("schema_version", "1.0")

    evidence_graph = package_data.get("evidence_graph", {})
    node_count = evidence_graph.get("node_count", len(evidence_graph.get("nodes", [])))

    rows = []
    for key, val in package_data.items():
        if key in ("package_id", "created_at", "package_hash", "schema_version"):
            continue
        if isinstance(val, (dict, list)):
            display = f"[{type(val).__name__}]"
        else:
            display = str(val)
        rows.append(f"    <tr><td><strong>{key}</strong></td><td>{display}</td></tr>")

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="UTF-8">\n'
        "  <title>FrostGate Governance Export Package</title>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>FrostGate Governance Export Package</h1>\n"
        f"  <p><strong>Package ID:</strong> {package_id}</p>\n"
        f"  <p><strong>Created:</strong> {created_at}</p>\n"
        f"  <p><strong>Schema version:</strong> {schema_version}</p>\n"
        f"  <p><strong>Package hash (SHA-256):</strong> {pkg_hash}</p>\n"
        f"  <p><strong>Evidence nodes:</strong> {node_count}</p>\n"
        "  <h2>Package Contents</h2>\n"
        '  <table border="1">\n'
        "    <tr><th>Field</th><th>Value</th></tr>\n" + "\n".join(rows) + "\n"
        "  </table>\n"
        "  <p><em>This package supports offline verification using the package hash above.</em></p>\n"
        "</body>\n"
        "</html>"
    )
