from __future__ import annotations

from api.config_versioning import (
    canonicalize_config,
    hash_config,
    verify_config_hash_integrity,
)


def test_canonicalization_golden_vector() -> None:
    payload = {
        "z": [3, 2, 1],
        "a": {"y": 2, "x": 1},
        "u": "μ",
        "f": 1.5,
        "n": None,
        "zero": -0.0,
    }
    expected_canonical = '{"a":{"x":1,"y":2},"f":1.5,"n":null,"u":"μ","z":[3,2,1],"zero":0.0}'
    expected_hash = "d97df257eb557a6ad23b630f0a18d65cd61f8a5756b6ec920d3ce6b6e825a8ff"

    canonical = canonicalize_config(payload)
    assert canonical == expected_canonical
    assert hash_config(canonical) == expected_hash


def test_config_hash_integrity_uses_stored_payload_canonical_form() -> None:
    payload = {"b": 2, "a": 1}
    canonical = canonicalize_config(payload)
    digest = hash_config(canonical)

    assert verify_config_hash_integrity(config_payload=payload, config_hash=digest)
    assert not verify_config_hash_integrity(
        config_payload={"a": 1, "b": 3},
        config_hash=digest,
    )
