from __future__ import annotations

import hashlib
from pathlib import Path

from engine.policy_fingerprint import build_opa_bundle_bytes, get_active_policy_fingerprint


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def test_policy_hash_derived_from_opa_bundle_bytes(tmp_path) -> None:
    fingerprint = get_active_policy_fingerprint()
    bundle_bytes = build_opa_bundle_bytes()
    assert fingerprint.policy_hash == _sha256_hex(bundle_bytes)

    policy_root = Path("policy") / "opa"
    tmp_policy = tmp_path / "opa"
    tmp_policy.mkdir()
    for src in policy_root.glob("*.rego"):
        (tmp_policy / src.name).write_bytes(src.read_bytes())

    modified = tmp_policy / "defend.rego"
    modified.write_text(modified.read_text() + "\n# mutation for hash test\n")

    original_hash = _sha256_hex(build_opa_bundle_bytes(policy_root))
    mutated_hash = _sha256_hex(build_opa_bundle_bytes(tmp_policy))
    assert original_hash != mutated_hash
