from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def verify_bundle(bundle_dir: Path, pubkey_path: Path, hmac_key: str | None) -> tuple[bool, list[str]]:
    errors: list[str] = []
    manifest_path = bundle_dir / "manifest.json"
    sig_path = bundle_dir / "attestation.sig"

    if not manifest_path.exists():
        return False, ["missing_manifest"]
    if not sig_path.exists():
        return False, ["missing_attestation_sig"]
    if not pubkey_path.exists():
        return False, ["missing_pubkey"]

    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    if manifest.get("billing_evidence_spec_version") != "v1":
        errors.append("billing_evidence_spec_version_mismatch")
    if manifest.get("verifier_version") != "fg-billing-verify/1":
        errors.append("verifier_version_mismatch")
    if manifest.get("expected_pubkey_kid") != "fg_billing_default":
        errors.append("pubkey_kid_mismatch")

    for entry in manifest.get("files", []):
        file_path = bundle_dir / str(entry.get("path"))
        if not file_path.exists():
            errors.append(f"missing_file:{entry.get('path')}")
            continue
        payload = file_path.read_bytes()
        got_hash = hashlib.sha256(payload).hexdigest()
        if got_hash != entry.get("sha256"):
            errors.append(f"hash_mismatch:{entry.get('path')}")
        if len(payload) != int(entry.get("size", -1)):
            errors.append(f"size_mismatch:{entry.get('path')}")

    pub = _read_text(pubkey_path)
    if not pub.startswith("hmac-sha256"):
        errors.append("unsupported_pubkey_format")
    else:
        key = (
            hmac_key
            or os.getenv("FG_BILLING_EVIDENCE_HMAC_KEY")
            or "billing-dev-key"
        ).encode("utf-8")
        expected_sig = hmac.new(key, manifest_raw, hashlib.sha256).hexdigest()
        got_sig = _read_text(sig_path)
        if not hmac.compare_digest(expected_sig, got_sig):
            errors.append("attestation_signature_mismatch")

    return len(errors) == 0, errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify FrostGate billing evidence bundle")
    parser.add_argument("bundle_dir", help="Path to extracted bundle directory")
    parser.add_argument("--pubkey", required=True, help="Path to attestation.pub")
    parser.add_argument("--hmac-key", default=None, help="Override HMAC key for verification")
    args = parser.parse_args()

    ok, errors = verify_bundle(Path(args.bundle_dir), Path(args.pubkey), args.hmac_key)
    if ok:
        print("PASS: billing evidence bundle verified")
        print("REASON_CODES: []")
        return 0
    print("FAIL: billing evidence bundle verification failed")
    for err in errors:
        print(f" - {err}")
    print(f"REASON_CODES: {errors}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
