"""services/report_authority/export.py

Export bundle construction. Produces signed, verifiable export packages.
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

from services.report_authority.hashing import compute_sha256, compute_sha512
from services.report_authority.signature import sign_payload

BUNDLE_VERSION = "1.0"

VERIFICATION_INSTRUCTIONS = """
FrostGate Export Bundle — Offline Verification Instructions
===========================================================

1. Verify checksums.json:
   For each file listed, compute SHA-256 and compare to the value in checksums.json.
   Command: sha256sum <filename>

2. Verify bundle signature:
   The bundle_signature in manifest.json is HMAC-SHA256 of the canonical JSON content
   (sorted keys, no whitespace). Contact your FrostGate administrator for the
   verification key, or use the online verification endpoint:
   POST /reports/{report_id}/verify

3. Verify report hash:
   The report_hash_sha256 in manifest.json must match the SHA-256 of report.json.

4. Verify manifest integrity:
   The manifest_hash_sha256 field in manifest.json is computed from all other manifest
   fields (excluding itself). Recompute and compare.

5. Trust Manifest:
   trust_manifest.json contains the cryptographic trust chain.
   Verify provider signatures using the public keys in trust_manifest.json.

6. Transparency Proof:
   transparency_proof.json contains the Merkle membership proof.
   Verify using the transparency_root in manifest.json.
"""


def build_export_bundle(
    *,
    report_id: str,
    pdf_bytes: bytes,
    html_bytes: bytes,
    json_bytes: bytes,
    manifest: dict[str, Any],
    trust_manifest: dict[str, Any] | None = None,
    transparency_proof: dict[str, Any] | None = None,
    evidence_index: list[dict[str, Any]] | None = None,
) -> bytes:
    """Build a signed ZIP export bundle. Returns raw ZIP bytes.

    Files written to the archive:
      report.pdf, report.html, report.json — rendered report outputs
      manifest.json                         — cryptographic manifest
      trust_manifest.json                   — provider trust chain
      transparency_proof.json               — Merkle membership proof
      evidence_index.json                   — sorted evidence index
      VERIFICATION_INSTRUCTIONS.txt         — offline verification guide
      checksums.json                        — SHA-256 per file
      bundle_meta.json                      — bundle signature and metadata
    """
    buf = io.BytesIO()
    checksums: dict[str, str] = {}

    with zipfile.ZipFile(
        buf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as zf:
        # Report outputs
        zf.writestr("report.pdf", pdf_bytes)
        checksums["report.pdf"] = compute_sha256(pdf_bytes)

        zf.writestr("report.html", html_bytes)
        checksums["report.html"] = compute_sha256(html_bytes)

        zf.writestr("report.json", json_bytes)
        checksums["report.json"] = compute_sha256(json_bytes)

        # Manifest
        manifest_bytes = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        zf.writestr("manifest.json", manifest_bytes)
        checksums["manifest.json"] = compute_sha256(manifest_bytes)

        # Trust manifest
        tm_bytes = json.dumps(
            trust_manifest or {}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        zf.writestr("trust_manifest.json", tm_bytes)
        checksums["trust_manifest.json"] = compute_sha256(tm_bytes)

        # Transparency proof
        tp_bytes = json.dumps(
            transparency_proof or {}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        zf.writestr("transparency_proof.json", tp_bytes)
        checksums["transparency_proof.json"] = compute_sha256(tp_bytes)

        # Evidence index — sorted by evidence_id for determinism
        ei_bytes = json.dumps(
            sorted(evidence_index or [], key=lambda x: x.get("evidence_id", "")),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        zf.writestr("evidence_index.json", ei_bytes)
        checksums["evidence_index.json"] = compute_sha256(ei_bytes)

        # Verification instructions
        vi_bytes = VERIFICATION_INSTRUCTIONS.encode("utf-8")
        zf.writestr("VERIFICATION_INSTRUCTIONS.txt", vi_bytes)
        checksums["VERIFICATION_INSTRUCTIONS.txt"] = compute_sha256(vi_bytes)

        # Checksums file (must come after all content files are checksummed)
        checksums_bytes = json.dumps(
            checksums, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        zf.writestr("checksums.json", checksums_bytes)

        # Bundle metadata and signature (sign the checksums payload)
        bundle_sig = sign_payload(checksums_bytes)
        bundle_meta: dict[str, Any] = {
            "bundle_version": BUNDLE_VERSION,
            "report_id": report_id,
            "bundle_signature": bundle_sig,
            "bundle_hash_sha256": compute_sha256(checksums_bytes),
            "bundle_hash_sha512": compute_sha512(checksums_bytes),
            "file_count": len(checksums),
        }
        bundle_meta_bytes = json.dumps(
            bundle_meta, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        zf.writestr("bundle_meta.json", bundle_meta_bytes)

    return buf.getvalue()
