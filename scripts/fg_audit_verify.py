#!/usr/bin/env python3
from __future__ import annotations

# ruff: noqa: E402

import argparse
import json
import os
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.audit_engine.engine import verify_export_manifest
from services.audit_engine.signing import verify_manifest_signature

_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _emit(ok: bool, code: str, *, as_json: bool) -> int:
    payload = {"status": "PASS" if ok else "FAIL", "code": code}
    if as_json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        print(f"{payload['status']} {payload['code']}")
    return 0 if ok else 1


def _load_pubkeys(path: str) -> None:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    os.environ["FG_AUDIT_ED25519_PUBLIC_KEYS_JSON"] = json.dumps(data, sort_keys=True, separators=(",", ":"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline FrostGate audit evidence verifier")
    parser.add_argument("--bundle", required=True, help="Path to exported evidence bundle zip")
    parser.add_argument("--pubkeys", required=False, help="Public keys JSON (kid -> base64 raw pubkey)")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    args = parser.parse_args(argv)

    if args.pubkeys:
        _load_pubkeys(args.pubkeys)

    zpath = Path(args.bundle)
    if not zpath.exists():
        return _emit(False, "MISSING_FILE", as_json=args.json)

    try:
        with zipfile.ZipFile(zpath, "r") as zf:
            names = set(zf.namelist())
            required = {"bundle.json", "manifest.json"}
            if not required.issubset(names):
                return _emit(False, "MISSING_FILE", as_json=args.json)
            bundle = json.loads(zf.read("bundle.json").decode("utf-8"))
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    except Exception:
        return _emit(False, "MALFORMED_BUNDLE", as_json=args.json)

    if not _TS.match(str(manifest.get("signed_at", ""))):
        return _emit(False, "BAD_TIMESTAMP", as_json=args.json)

    if not verify_export_manifest(manifest, bundle):
        return _emit(False, "HASH_MISMATCH", as_json=args.json)

    payload = {
        "root_hash": manifest.get("root_hash"),
        "bundle_hash": manifest.get("bundle_sha256"),
        "sections": manifest.get("sections", {}),
        "range_start_utc": manifest.get("range_start_utc"),
        "range_end_utc": manifest.get("range_end_utc"),
        "range_end_inclusive": manifest.get("range_end_inclusive", True),
    }
    if not verify_manifest_signature(
        payload,
        signature_algo=str(manifest.get("signature_algo", "")),
        kid=str(manifest.get("kid", "")),
        signature=str(manifest.get("signature", "")),
    ):
        return _emit(False, "SIG_INVALID", as_json=args.json)

    if "audit_sessions" in bundle and bundle["audit_sessions"]:
        head = bundle["audit_sessions"][-1].get("sha256_self_hash")
        if not head:
            return _emit(False, "CHAIN_HEAD_MISSING", as_json=args.json)

    return _emit(True, "VERIFIED", as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
