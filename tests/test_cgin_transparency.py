"""PR 17.7D — CGIN Transparency Authority tests.

225+ deterministic tests. No mocks, no DB, pure Python.
"""

from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.cgin.key_management import ACTIVE_PROVIDER_REGISTRY, MemoryKeyProvider
from services.cgin.transparency import (
    ACTIVE_TRANSPARENCY_LEDGER,
    TRANSPARENCY_SCHEMA_VERSION,
    TRANSPARENCY_VERSION,
    IntegrityStatistics,
    MembershipProof,
    MerkleTree,
    MemoryTransparencyStore,
    TransparencyEntry,
    TransparencyLedger,
    TransparencyRoot,
    TransparencyVerificationResult,
    _compute_entry_id,
)
from services.cgin.transparency.merkle import EMPTY_LEAF, _hash_leaf, _hash_pair
from services.cgin.transparency.statistics import compute_statistics
from services.cgin.trust import (
    canonicalize_snapshot,
    generate_digest,
    sign_payload,
    verify_payload,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_PRIV = Ed25519PrivateKey.generate()
_PROVIDER = MemoryKeyProvider(_PRIV)


def _make_entry(
    entry_type: str = "cgin_snapshot",
    artifact_digest: str = None,
    sequence_number: int = 0,
    parent_digest: str | None = None,
    tenant_fingerprint: str = "a" * 32,
) -> TransparencyEntry:
    if artifact_digest is None:
        artifact_digest = hashlib.sha256(
            f"artifact-{sequence_number}".encode()
        ).hexdigest()
    entry_id = _compute_entry_id(entry_type, artifact_digest, sequence_number)
    return TransparencyEntry(
        entry_id=entry_id,
        entry_type=entry_type,
        authority_name="test-authority",
        authority_version="1.0",
        artifact_digest=artifact_digest,
        parent_digest=parent_digest,
        sequence_number=sequence_number,
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        tenant_fingerprint=tenant_fingerprint,
        signature_algorithm="ed25519-v1",
        signature_provider="memory",
        schema_version=TRANSPARENCY_SCHEMA_VERSION,
        transparency_version=TRANSPARENCY_VERSION,
    )


def _make_ledger(provider=None) -> tuple[TransparencyLedger, MemoryTransparencyStore]:
    store = MemoryTransparencyStore()
    p = provider or _PROVIDER
    ledger = TransparencyLedger(store=store, key_provider=p)
    return ledger, store


def _append_n(ledger: TransparencyLedger, n: int) -> list[TransparencyEntry]:
    entries = []
    for i in range(n):
        digest = hashlib.sha256(f"leaf-{i}".encode()).hexdigest()
        entry = ledger.append(
            entry_type="cgin_snapshot",
            artifact_digest=digest,
            tenant_fingerprint="f" * 32,
        )
        entries.append(entry)
    return entries


# ===========================================================================
# 1. TestMerkleTree
# ===========================================================================


class TestMerkleTree:
    def test_empty_tree_root_is_empty_leaf(self):
        tree = MerkleTree([])
        assert tree.root() == EMPTY_LEAF

    def test_empty_leaf_is_32_zero_bytes(self):
        assert EMPTY_LEAF == b"\x00" * 32
        assert len(EMPTY_LEAF) == 32

    def test_single_leaf_root_is_hash_leaf(self):
        leaf = b"hello"
        tree = MerkleTree([leaf])
        assert tree.root() == _hash_leaf(leaf)

    def test_two_leaves_root_correct(self):
        a, b = b"alpha", b"beta"
        tree = MerkleTree([a, b])
        expected = _hash_pair(_hash_leaf(a), _hash_leaf(b))
        assert tree.root() == expected

    def test_three_leaves_odd_duplication(self):
        leaves = [b"a", b"b", b"c"]
        tree = MerkleTree(leaves)
        h0 = _hash_leaf(b"a")
        h1 = _hash_leaf(b"b")
        h2 = _hash_leaf(b"c")
        # level 1: [h01, h22] where h22 = hash_pair(h2, h2)
        h01 = _hash_pair(h0, h1)
        h22 = _hash_pair(h2, h2)
        root = _hash_pair(h01, h22)
        assert tree.root() == root

    def test_four_leaves_symmetric_tree(self):
        leaves = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(leaves)
        h0 = _hash_leaf(b"a")
        h1 = _hash_leaf(b"b")
        h2 = _hash_leaf(b"c")
        h3 = _hash_leaf(b"d")
        h01 = _hash_pair(h0, h1)
        h23 = _hash_pair(h2, h3)
        root = _hash_pair(h01, h23)
        assert tree.root() == root

    def test_deterministic_same_input_same_root(self):
        leaves = [b"x", b"y", b"z"]
        r1 = MerkleTree(leaves).root()
        r2 = MerkleTree(leaves).root()
        assert r1 == r2

    def test_different_inputs_different_roots(self):
        r1 = MerkleTree([b"a", b"b"]).root()
        r2 = MerkleTree([b"a", b"c"]).root()
        assert r1 != r2

    def test_height_empty_is_zero(self):
        assert MerkleTree([]).height() == 0

    def test_height_single_leaf_is_one(self):
        assert MerkleTree([b"x"]).height() == 1

    def test_height_two_leaves_is_two(self):
        assert MerkleTree([b"a", b"b"]).height() == 2

    def test_height_three_leaves(self):
        assert MerkleTree([b"a", b"b", b"c"]).height() == math.ceil(math.log2(3)) + 1

    def test_height_four_leaves_is_three(self):
        assert MerkleTree([b"a", b"b", b"c", b"d"]).height() == 3

    def test_height_seven_leaves(self):
        leaves = [b"x"] * 7
        assert MerkleTree(leaves).height() == math.ceil(math.log2(7)) + 1

    def test_height_eight_leaves_is_four(self):
        leaves = [b"x"] * 8
        assert MerkleTree(leaves).height() == 4

    def test_proof_leaf0_in_2_leaf_tree(self):
        leaves = [b"a", b"b"]
        tree = MerkleTree(leaves)
        proof = tree.proof(0)
        assert len(proof) == 1
        assert proof[0][0] == "right"
        assert proof[0][1] == _hash_leaf(b"b").hex()

    def test_proof_leaf1_in_2_leaf_tree(self):
        leaves = [b"a", b"b"]
        tree = MerkleTree(leaves)
        proof = tree.proof(1)
        assert len(proof) == 1
        assert proof[0][0] == "left"
        assert proof[0][1] == _hash_leaf(b"a").hex()

    def test_proof_for_leaf_in_4_leaf_tree(self):
        leaves = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(leaves)
        proof = tree.proof(0)
        assert len(proof) == 2

    def test_verify_proof_valid(self):
        leaves = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(leaves)
        root_hex = tree.root().hex()
        for i in range(4):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, root_hex)

    def test_verify_proof_corrupted_root_fails(self):
        leaves = [b"a", b"b"]
        tree = MerkleTree(leaves)
        proof = tree.proof(0)
        bad_root = "0" * 64
        assert not MerkleTree.verify_proof(leaves[0], proof, bad_root)

    def test_verify_proof_wrong_leaf_fails(self):
        leaves = [b"a", b"b"]
        tree = MerkleTree(leaves)
        proof = tree.proof(0)
        root_hex = tree.root().hex()
        assert not MerkleTree.verify_proof(b"z", proof, root_hex)

    def test_verify_proof_flipped_side_fails(self):
        leaves = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(leaves)
        proof = tree.proof(0)
        root_hex = tree.root().hex()
        flipped = [("left" if s == "right" else "right", h) for s, h in proof]
        assert not MerkleTree.verify_proof(leaves[0], flipped, root_hex)

    def test_verify_proof_never_raises(self):
        # Garbage inputs should return False, not raise
        assert MerkleTree.verify_proof(b"", [("bad", "notHex")], "notHex") is False

    def test_proof_serialization_roundtrip(self):
        leaves = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(leaves)
        proof = tree.proof(2)
        mp = MembershipProof(
            entry_id="test",
            entry_index=2,
            leaf_hash=tree._leaf_hashes[2].hex(),
            proof_path=proof,
            root_digest=tree.root().hex(),
            root_id="rootid",
            algorithm="sha256",
            transparency_version=TRANSPARENCY_VERSION,
        )
        d = mp.to_dict()
        mp2 = MembershipProof.from_dict(d)
        assert mp2.entry_id == mp.entry_id
        assert mp2.proof_path == mp.proof_path
        assert mp2.root_digest == mp.root_digest

    def test_proof_for_every_leaf_in_8_leaf_tree_verifies(self):
        leaves = [f"leaf-{i}".encode() for i in range(8)]
        tree = MerkleTree(leaves)
        root_hex = tree.root().hex()
        for i in range(8):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, root_hex)

    def test_domain_separation_hash_leaf_ne_hash_pair(self):
        x = b"testdata"
        h_leaf = _hash_leaf(x)
        h_pair = _hash_pair(x, x)
        assert h_leaf != h_pair

    def test_large_tree_100_leaves_deterministic(self):
        leaves = [f"leaf-{i}".encode() for i in range(100)]
        r1 = MerkleTree(leaves).root()
        r2 = MerkleTree(leaves).root()
        assert r1 == r2
        assert len(r1) == 32

    def test_single_leaf_proof_is_empty(self):
        tree = MerkleTree([b"only"])
        assert tree.proof(0) == []

    def test_proof_index_out_of_range_raises(self):
        tree = MerkleTree([b"a", b"b"])
        with pytest.raises(IndexError):
            tree.proof(5)

    def test_empty_tree_proof_raises(self):
        tree = MerkleTree([])
        with pytest.raises(IndexError):
            tree.proof(0)


# ===========================================================================
# 2. TestTransparencyEntry
# ===========================================================================


class TestTransparencyEntry:
    def test_frozen_dataclass_mutation_raises(self):
        e = _make_entry()
        with pytest.raises((TypeError, AttributeError)):
            e.entry_type = "mutated"  # type: ignore[misc]

    def test_entry_id_is_deterministic(self):
        digest = "a" * 64
        e1 = _compute_entry_id("cgin_snapshot", digest, 0)
        e2 = _compute_entry_id("cgin_snapshot", digest, 0)
        assert e1 == e2

    def test_same_inputs_same_entry_id(self):
        d = "b" * 64
        assert _compute_entry_id("type_a", d, 5) == _compute_entry_id("type_a", d, 5)

    def test_different_sequence_number_different_entry_id(self):
        d = "c" * 64
        assert _compute_entry_id("type_a", d, 0) != _compute_entry_id("type_a", d, 1)

    def test_entry_type_is_string(self):
        e = _make_entry(entry_type="governance_recommendation")
        assert isinstance(e.entry_type, str)

    def test_artifact_digest_is_64_char_hex(self):
        digest = hashlib.sha256(b"test").hexdigest()
        e = _make_entry(artifact_digest=digest)
        assert len(e.artifact_digest) == 64
        int(e.artifact_digest, 16)  # must be valid hex

    def test_parent_digest_can_be_none(self):
        e = _make_entry(parent_digest=None)
        assert e.parent_digest is None

    def test_parent_digest_can_be_hex_string(self):
        parent = "d" * 64
        e = _make_entry(parent_digest=parent)
        assert e.parent_digest == parent

    def test_generated_at_is_iso_format(self):
        e = _make_entry()
        # Should parse without error
        datetime.fromisoformat(e.generated_at.replace("Z", "+00:00"))

    def test_transparency_version_is_version(self):
        e = _make_entry()
        assert e.transparency_version == TRANSPARENCY_VERSION

    def test_schema_version_is_version(self):
        e = _make_entry()
        assert e.schema_version == TRANSPARENCY_SCHEMA_VERSION

    def test_all_required_fields_present(self):
        e = _make_entry()
        for field in [
            "entry_id",
            "entry_type",
            "authority_name",
            "authority_version",
            "artifact_digest",
            "sequence_number",
            "generated_at",
            "tenant_fingerprint",
            "signature_algorithm",
            "signature_provider",
            "schema_version",
            "transparency_version",
        ]:
            assert hasattr(e, field), f"Missing field: {field}"

    def test_tenant_fingerprint_not_raw_tenant_id(self):
        # fingerprint must differ from raw tenant id
        tenant_id = "tenant-12345"
        fingerprint = hashlib.sha256(f"cgin:v1:{tenant_id}".encode()).hexdigest()[:32]
        e = _make_entry(tenant_fingerprint=fingerprint)
        assert e.tenant_fingerprint != tenant_id

    def test_sequence_number_non_negative(self):
        e = _make_entry(sequence_number=0)
        assert e.sequence_number >= 0

    def test_entry_id_is_sha256_hex(self):
        e = _make_entry()
        assert len(e.entry_id) == 64
        int(e.entry_id, 16)

    def test_different_entry_type_different_id(self):
        d = "e" * 64
        id1 = _compute_entry_id("type_a", d, 0)
        id2 = _compute_entry_id("type_b", d, 0)
        assert id1 != id2


# ===========================================================================
# 3. TestTransparencyRoot
# ===========================================================================


class TestTransparencyRoot:
    def _make_root(self) -> TransparencyRoot:
        ledger, _ = _make_ledger()
        _append_n(ledger, 2)
        return ledger.build_root()

    def test_frozen_dataclass(self):
        root = self._make_root()
        with pytest.raises((TypeError, AttributeError)):
            root.root_digest = "mutated"  # type: ignore[misc]

    def test_root_id_is_deterministic_for_same_body(self):
        # Two different ledgers with same entries, same timestamp are not practical to test
        # but we can check that root_id is a 64-char hex
        root = self._make_root()
        assert len(root.root_id) == 64
        int(root.root_id, 16)

    def test_root_digest_is_64_char_hex(self):
        root = self._make_root()
        assert len(root.root_digest) == 64
        int(root.root_digest, 16)

    def test_entry_count_non_negative(self):
        root = self._make_root()
        assert root.entry_count >= 0

    def test_tree_height_non_negative(self):
        root = self._make_root()
        assert root.tree_height >= 0

    def test_algorithm_is_sha256(self):
        root = self._make_root()
        assert root.algorithm == "sha256"

    def test_signature_is_non_empty_string(self):
        root = self._make_root()
        assert isinstance(root.signature, str)
        assert len(root.signature) > 0

    def test_signing_algorithm_is_string(self):
        root = self._make_root()
        assert isinstance(root.signing_algorithm, str)

    def test_provider_name_is_string(self):
        root = self._make_root()
        assert isinstance(root.provider_name, str)

    def test_transparency_version(self):
        root = self._make_root()
        assert root.transparency_version == TRANSPARENCY_VERSION

    def test_schema_version(self):
        root = self._make_root()
        assert root.schema_version == TRANSPARENCY_SCHEMA_VERSION

    def test_generation_timestamp_is_iso(self):
        root = self._make_root()
        datetime.fromisoformat(root.generation_timestamp.replace("Z", "+00:00"))

    def test_entry_count_matches_entries(self):
        ledger, _ = _make_ledger()
        _append_n(ledger, 5)
        root = ledger.build_root()
        assert root.entry_count == 5

    def test_tree_height_matches_tree(self):
        ledger, _ = _make_ledger()
        _append_n(ledger, 4)
        root = ledger.build_root()
        assert root.tree_height == 3  # ceil(log2(4)) + 1 = 3

    def test_empty_ledger_root(self):
        ledger, _ = _make_ledger()
        root = ledger.build_root()
        assert root.entry_count == 0
        assert root.tree_height == 0


# ===========================================================================
# 4. TestMemoryTransparencyStore
# ===========================================================================


class TestMemoryTransparencyStore:
    def test_append_entry_stores_it(self):
        s = MemoryTransparencyStore()
        e = _make_entry()
        s.append_entry(e)
        assert s.get_entry(e.entry_id) is e

    def test_get_entry_retrieves_it(self):
        s = MemoryTransparencyStore()
        e = _make_entry()
        s.append_entry(e)
        assert s.get_entry(e.entry_id) == e

    def test_get_entry_returns_none_for_unknown(self):
        s = MemoryTransparencyStore()
        assert s.get_entry("nonexistent") is None

    def test_duplicate_entry_id_raises_value_error(self):
        s = MemoryTransparencyStore()
        e = _make_entry()
        s.append_entry(e)
        with pytest.raises(ValueError, match="Duplicate entry_id"):
            s.append_entry(e)

    def test_all_entries_in_insertion_order(self):
        s = MemoryTransparencyStore()
        entries = [
            _make_entry(
                sequence_number=i,
                artifact_digest=hashlib.sha256(f"a{i}".encode()).hexdigest(),
            )
            for i in range(5)
        ]
        for e in entries:
            s.append_entry(e)
        result = s.all_entries()
        assert [e.entry_id for e in result] == [e.entry_id for e in entries]

    def test_entry_count_matches(self):
        s = MemoryTransparencyStore()
        for i in range(7):
            s.append_entry(
                _make_entry(
                    sequence_number=i,
                    artifact_digest=hashlib.sha256(f"b{i}".encode()).hexdigest(),
                )
            )
        assert s.entry_count() == 7

    def test_append_root_stores_it(self):
        s = MemoryTransparencyStore()
        ledger = TransparencyLedger(store=s, key_provider=_PROVIDER)
        root = ledger.build_root()
        assert s.get_root(root.root_id) == root

    def test_get_root_retrieves_it(self):
        s = MemoryTransparencyStore()
        ledger = TransparencyLedger(store=s, key_provider=_PROVIDER)
        root = ledger.build_root()
        assert s.get_root(root.root_id) is not None

    def test_get_latest_root_returns_most_recent(self):
        s = MemoryTransparencyStore()
        ledger = TransparencyLedger(store=s, key_provider=_PROVIDER)
        ledger.append(
            entry_type="t", artifact_digest="a" * 64, tenant_fingerprint="f" * 32
        )
        ledger.build_root()
        ledger.append(
            entry_type="t", artifact_digest="b" * 64, tenant_fingerprint="f" * 32
        )
        r2 = ledger.build_root()
        assert s.get_latest_root().root_id == r2.root_id

    def test_get_latest_root_returns_none_if_no_roots(self):
        s = MemoryTransparencyStore()
        assert s.get_latest_root() is None

    def test_all_roots_in_insertion_order(self):
        s = MemoryTransparencyStore()
        ledger = TransparencyLedger(store=s, key_provider=_PROVIDER)
        ledger.append(
            entry_type="t", artifact_digest="a" * 64, tenant_fingerprint="f" * 32
        )
        r1 = ledger.build_root()
        ledger.append(
            entry_type="t", artifact_digest="b" * 64, tenant_fingerprint="f" * 32
        )
        r2 = ledger.build_root()
        roots = s.all_roots()
        assert roots[0].root_id == r1.root_id
        assert roots[1].root_id == r2.root_id

    def test_root_count_matches(self):
        s = MemoryTransparencyStore()
        ledger = TransparencyLedger(store=s, key_provider=_PROVIDER)
        ledger.build_root()
        ledger.build_root()
        assert s.root_count() == 2

    def test_entries_cannot_be_overwritten(self):
        s = MemoryTransparencyStore()
        e = _make_entry()
        s.append_entry(e)
        with pytest.raises(ValueError):
            s.append_entry(e)

    def test_store_with_multiple_entries_and_roots(self):
        s = MemoryTransparencyStore()
        ledger = TransparencyLedger(store=s, key_provider=_PROVIDER)
        for i in range(3):
            ledger.append(
                entry_type="t",
                artifact_digest=hashlib.sha256(f"x{i}".encode()).hexdigest(),
                tenant_fingerprint="f" * 32,
            )
        ledger.build_root()
        assert s.entry_count() == 3
        assert s.root_count() == 1


# ===========================================================================
# 5. TestTransparencyLedger
# ===========================================================================


class TestTransparencyLedger:
    def test_append_creates_entry_with_correct_sequence_numbers(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 3)
        assert [e.sequence_number for e in entries] == [0, 1, 2]

    def test_append_returns_transparency_entry(self):
        ledger, _ = _make_ledger()
        e = ledger.append(
            entry_type="t", artifact_digest="a" * 64, tenant_fingerprint="f" * 32
        )
        assert isinstance(e, TransparencyEntry)

    def test_entry_has_correct_entry_type(self):
        ledger, _ = _make_ledger()
        e = ledger.append(
            entry_type="trust_manifest",
            artifact_digest="a" * 64,
            tenant_fingerprint="f" * 32,
        )
        assert e.entry_type == "trust_manifest"

    def test_entry_has_correct_artifact_digest(self):
        ledger, _ = _make_ledger()
        d = "b" * 64
        e = ledger.append(
            entry_type="t", artifact_digest=d, tenant_fingerprint="f" * 32
        )
        assert e.artifact_digest == d

    def test_entry_has_correct_parent_digest(self):
        ledger, _ = _make_ledger()
        parent = "c" * 64
        e = ledger.append(
            entry_type="t",
            artifact_digest="a" * 64,
            tenant_fingerprint="f" * 32,
            parent_digest=parent,
        )
        assert e.parent_digest == parent

    def test_entry_id_is_deterministic(self):
        d = "d" * 64
        id1 = _compute_entry_id("t", d, 0)
        id2 = _compute_entry_id("t", d, 0)
        assert id1 == id2

    def test_build_root_returns_transparency_root(self):
        ledger, _ = _make_ledger()
        _append_n(ledger, 2)
        root = ledger.build_root()
        assert isinstance(root, TransparencyRoot)

    def test_root_root_digest_is_non_empty(self):
        ledger, _ = _make_ledger()
        _append_n(ledger, 2)
        root = ledger.build_root()
        assert len(root.root_digest) == 64

    def test_root_entry_count_matches(self):
        ledger, _ = _make_ledger()
        _append_n(ledger, 4)
        root = ledger.build_root()
        assert root.entry_count == 4

    def test_root_is_appended_to_store(self):
        ledger, store = _make_ledger()
        _append_n(ledger, 2)
        root = ledger.build_root()
        assert store.get_root(root.root_id) is not None

    def test_membership_proof_for_valid_entry(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 3)
        ledger.build_root()
        proof = ledger.membership_proof(entries[0].entry_id)
        assert isinstance(proof, MembershipProof)

    def test_membership_proof_for_unknown_raises_key_error(self):
        ledger, _ = _make_ledger()
        ledger.build_root()
        with pytest.raises(KeyError):
            ledger.membership_proof("nonexistent")

    def test_membership_proof_before_root_raises(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        with pytest.raises(RuntimeError):
            ledger.membership_proof(entries[0].entry_id)

    def test_verify_entry_valid_digest_true(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 3)
        ledger.build_root()
        result = ledger.verify_entry(entries[1].entry_id, entries[1].artifact_digest)
        assert result.valid is True

    def test_verify_entry_wrong_digest_digest_match_false(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        ledger.build_root()
        result = ledger.verify_entry(entries[0].entry_id, "wrong_digest")
        assert result.digest_match is False

    def test_verify_entry_unknown_entry_id_entry_found_false(self):
        ledger, _ = _make_ledger()
        ledger.build_root()
        result = ledger.verify_entry("unknown_id", "a" * 64)
        assert result.entry_found is False

    def test_verify_entry_returns_verification_result(self):
        ledger, _ = _make_ledger()
        result = ledger.verify_entry("x", "a" * 64)
        assert isinstance(result, TransparencyVerificationResult)

    def test_verify_entry_never_raises(self):
        ledger, _ = _make_ledger()
        # Should not raise even with garbage
        result = ledger.verify_entry("", "")
        assert isinstance(result, TransparencyVerificationResult)

    def test_statistics_returns_integrity_statistics(self):
        ledger, _ = _make_ledger()
        stats = ledger.statistics()
        assert isinstance(stats, IntegrityStatistics)

    def test_statistics_entry_count_matches(self):
        ledger, _ = _make_ledger()
        _append_n(ledger, 5)
        stats = ledger.statistics()
        assert stats.entry_count == 5

    def test_build_root_twice_produces_different_roots(self):
        # timestamps differ → different root_id (canonical body differs)
        ledger, store = _make_ledger()
        _append_n(ledger, 2)
        r1 = ledger.build_root()
        _append_n(ledger, 1)
        r2 = ledger.build_root()
        assert r1.root_id != r2.root_id

    def test_entry_order_is_fifo(self):
        ledger, store = _make_ledger()
        entries = _append_n(ledger, 4)
        stored = store.all_entries()
        assert [e.entry_id for e in stored] == [e.entry_id for e in entries]

    def test_multiple_appends_sequence_numbers_monotonic(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 10)
        nums = [e.sequence_number for e in entries]
        assert nums == list(range(10))

    def test_append_with_parent_digest_links_correctly(self):
        ledger, _ = _make_ledger()
        parent = "e" * 64
        e = ledger.append(
            entry_type="t",
            artifact_digest="a" * 64,
            tenant_fingerprint="f" * 32,
            parent_digest=parent,
        )
        assert e.parent_digest == parent

    def test_ledger_has_key_provider(self):
        ledger, _ = _make_ledger()
        assert ledger._key_provider is not None

    def test_build_root_increments_root_count(self):
        ledger, store = _make_ledger()
        assert store.root_count() == 0
        ledger.build_root()
        assert store.root_count() == 1
        ledger.build_root()
        assert store.root_count() == 2


# ===========================================================================
# 6. TestTransparencyVerification
# ===========================================================================


class TestTransparencyVerification:
    def test_valid_entry_verifies_as_valid(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 3)
        ledger.build_root()
        result = ledger.verify_entry(entries[2].entry_id, entries[2].artifact_digest)
        assert result.valid is True

    def test_corrupted_artifact_digest_digest_match_false(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        ledger.build_root()
        result = ledger.verify_entry(entries[0].entry_id, "corrupted")
        assert result.digest_match is False

    def test_unknown_entry_id_entry_found_false(self):
        ledger, _ = _make_ledger()
        ledger.build_root()
        result = ledger.verify_entry("no_such_id", "a" * 64)
        assert result.entry_found is False

    def test_no_root_built_proof_valid_false(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        result = ledger.verify_entry(entries[0].entry_id, entries[0].artifact_digest)
        assert result.proof_valid is False

    def test_wrong_root_id_errors_populated(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        ledger.build_root()
        result = ledger.verify_entry(
            entries[0].entry_id, entries[0].artifact_digest, root_id="wrong_root_id"
        )
        assert len(result.errors) > 0

    def test_result_is_transparency_verification_result(self):
        ledger, _ = _make_ledger()
        result = ledger.verify_entry("x", "a")
        assert isinstance(result, TransparencyVerificationResult)

    def test_valid_field_true_only_when_all_sub_checks_pass(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        ledger.build_root()
        # valid digest
        r_good = ledger.verify_entry(entries[0].entry_id, entries[0].artifact_digest)
        assert r_good.valid is True
        # wrong digest
        r_bad = ledger.verify_entry(entries[0].entry_id, "wrong")
        assert r_bad.valid is False

    def test_never_raises(self):
        ledger, _ = _make_ledger()
        # All kinds of bad inputs
        ledger.verify_entry("", "")
        ledger.verify_entry("abc", None)  # type: ignore[arg-type]
        ledger.verify_entry(None, "abc")  # type: ignore[arg-type]

    def test_errors_is_list(self):
        ledger, _ = _make_ledger()
        result = ledger.verify_entry("no_such", "a" * 64)
        assert isinstance(result.errors, list)

    def test_valid_with_specific_root_id(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 3)
        root = ledger.build_root()
        result = ledger.verify_entry(
            entries[1].entry_id, entries[1].artifact_digest, root_id=root.root_id
        )
        assert result.valid is True


# ===========================================================================
# 7. TestMerkleProof
# ===========================================================================


class TestMerkleProof:
    def test_proof_for_each_leaf_in_4_leaf_tree_is_valid(self):
        leaves = [f"leaf-{i}".encode() for i in range(4)]
        tree = MerkleTree(leaves)
        root_hex = tree.root().hex()
        for i in range(4):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, root_hex)

    def test_proof_for_each_leaf_in_8_leaf_tree_is_valid(self):
        leaves = [f"leaf-{i}".encode() for i in range(8)]
        tree = MerkleTree(leaves)
        root_hex = tree.root().hex()
        for i in range(8):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, root_hex)

    def test_proof_to_dict_serializes(self):
        leaves = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(leaves)
        proof_path = tree.proof(1)
        mp = MembershipProof(
            entry_id="eid",
            entry_index=1,
            leaf_hash=tree._leaf_hashes[1].hex(),
            proof_path=proof_path,
            root_digest=tree.root().hex(),
            root_id="rid",
            algorithm="sha256",
            transparency_version=TRANSPARENCY_VERSION,
        )
        d = mp.to_dict()
        assert "entry_id" in d
        assert "proof_path" in d
        assert isinstance(d["proof_path"], list)
        for item in d["proof_path"]:
            assert "side" in item
            assert "hash" in item

    def test_membership_proof_from_dict_deserializes(self):
        d = {
            "entry_id": "eid",
            "entry_index": 0,
            "leaf_hash": "a" * 64,
            "proof_path": [{"side": "right", "hash": "b" * 64}],
            "root_digest": "c" * 64,
            "root_id": "rid",
            "algorithm": "sha256",
            "transparency_version": TRANSPARENCY_VERSION,
        }
        mp = MembershipProof.from_dict(d)
        assert mp.entry_id == "eid"
        assert mp.proof_path == [("right", "b" * 64)]

    def test_roundtrip_to_from_dict(self):
        leaves = [b"a", b"b", b"c"]
        tree = MerkleTree(leaves)
        proof_path = tree.proof(2)
        mp = MembershipProof(
            entry_id="x",
            entry_index=2,
            leaf_hash=tree._leaf_hashes[2].hex(),
            proof_path=proof_path,
            root_digest=tree.root().hex(),
            root_id="r",
            algorithm="sha256",
            transparency_version=TRANSPARENCY_VERSION,
        )
        mp2 = MembershipProof.from_dict(mp.to_dict())
        assert mp2.entry_id == mp.entry_id
        assert mp2.entry_index == mp.entry_index
        assert mp2.proof_path == mp.proof_path
        assert mp2.root_digest == mp.root_digest

    def test_corrupted_proof_path_entry_invalidates_proof(self):
        leaves = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(leaves)
        root_hex = tree.root().hex()
        proof = tree.proof(0)
        # Corrupt the first sibling hash
        corrupted = [("right", "0" * 64)] + proof[1:]
        assert not MerkleTree.verify_proof(leaves[0], corrupted, root_hex)

    def test_wrong_root_in_verify_proof_fails(self):
        leaves = [b"a", b"b"]
        tree = MerkleTree(leaves)
        proof = tree.proof(0)
        wrong_root = "f" * 64
        assert not MerkleTree.verify_proof(leaves[0], proof, wrong_root)

    def test_proof_path_length_equals_height_minus_one(self):
        # For non-trivial trees, proof length = tree_height - 1
        for n in [2, 4, 8]:
            leaves = [f"x{i}".encode() for i in range(n)]
            tree = MerkleTree(leaves)
            for i in range(n):
                proof = tree.proof(i)
                assert len(proof) == tree.height() - 1

    def test_entry_index_matches_position_in_tree(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 5)
        ledger.build_root()
        for i, e in enumerate(entries):
            proof = ledger.membership_proof(e.entry_id)
            assert proof.entry_index == i

    def test_from_dict_missing_field_raises(self):
        d = {
            "entry_id": "eid",
            "entry_index": 0,
            # missing leaf_hash
            "proof_path": [],
            "root_digest": "c" * 64,
            "root_id": "rid",
            "algorithm": "sha256",
            "transparency_version": TRANSPARENCY_VERSION,
        }
        with pytest.raises((ValueError, KeyError)):
            MembershipProof.from_dict(d)

    def test_verify_proof_for_5_leaf_tree(self):
        leaves = [f"item-{i}".encode() for i in range(5)]
        tree = MerkleTree(leaves)
        root_hex = tree.root().hex()
        for i in range(5):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, root_hex)


# ===========================================================================
# 8. TestIntegrityStatistics
# ===========================================================================


class TestIntegrityStatistics:
    def test_entry_count_matches_actual_count(self):
        ledger, store = _make_ledger()
        _append_n(ledger, 6)
        stats = compute_statistics(store, ledger)
        assert stats.entry_count == 6

    def test_root_count_matches_actual_count(self):
        ledger, store = _make_ledger()
        _append_n(ledger, 3)
        ledger.build_root()
        ledger.build_root()
        stats = compute_statistics(store, ledger)
        assert stats.root_count == 2

    def test_tree_height_matches_tree(self):
        ledger, store = _make_ledger()
        _append_n(ledger, 4)
        stats = compute_statistics(store, ledger)
        assert stats.tree_height == 3  # ceil(log2(4)) + 1

    def test_average_proof_length_computed_correctly(self):
        ledger, store = _make_ledger()
        _append_n(ledger, 4)
        stats = compute_statistics(store, ledger)
        # For 4-leaf tree: height=3, avg_proof_length = 2
        assert stats.average_proof_length == 2.0

    def test_generated_at_is_iso_format(self):
        ledger, store = _make_ledger()
        stats = compute_statistics(store, ledger)
        datetime.fromisoformat(stats.generated_at.replace("Z", "+00:00"))

    def test_algorithm_is_sha256(self):
        ledger, store = _make_ledger()
        stats = compute_statistics(store, ledger)
        assert stats.algorithm == "sha256"

    def test_empty_store_statistics_defined(self):
        ledger, store = _make_ledger()
        stats = compute_statistics(store, ledger)
        assert stats.entry_count == 0
        assert stats.root_count == 0
        assert stats.tree_height == 0
        assert stats.average_proof_length == 0.0

    def test_single_entry_statistics(self):
        ledger, store = _make_ledger()
        _append_n(ledger, 1)
        stats = compute_statistics(store, ledger)
        assert stats.entry_count == 1
        assert stats.tree_height == 1
        assert stats.average_proof_length == 0.0

    def test_transparency_version_in_stats(self):
        ledger, store = _make_ledger()
        stats = compute_statistics(store, ledger)
        assert stats.transparency_version == TRANSPARENCY_VERSION

    def test_statistics_is_integrity_statistics(self):
        ledger, store = _make_ledger()
        stats = compute_statistics(store, ledger)
        assert isinstance(stats, IntegrityStatistics)


# ===========================================================================
# 9. TestActiveTransparencyLedger
# ===========================================================================


class TestActiveTransparencyLedger:
    def test_active_transparency_ledger_exists(self):
        assert ACTIVE_TRANSPARENCY_LEDGER is not None

    def test_active_ledger_is_transparency_ledger(self):
        assert isinstance(ACTIVE_TRANSPARENCY_LEDGER, TransparencyLedger)

    def test_can_append_entry(self):
        d = hashlib.sha256(b"active-test").hexdigest()
        e = ACTIVE_TRANSPARENCY_LEDGER.append(
            entry_type="test",
            artifact_digest=d,
            tenant_fingerprint="a" * 32,
        )
        assert isinstance(e, TransparencyEntry)

    def test_can_build_root(self):
        root = ACTIVE_TRANSPARENCY_LEDGER.build_root()
        assert isinstance(root, TransparencyRoot)

    def test_can_get_statistics(self):
        stats = ACTIVE_TRANSPARENCY_LEDGER.statistics()
        assert isinstance(stats, IntegrityStatistics)

    def test_ledger_has_key_provider(self):
        assert ACTIVE_TRANSPARENCY_LEDGER._key_provider is not None

    def test_key_provider_is_from_active_provider_registry(self):
        # The active ledger's provider should match the registry's active provider
        registry_provider = ACTIVE_PROVIDER_REGISTRY.active()
        ledger_provider = ACTIVE_TRANSPARENCY_LEDGER._key_provider
        assert ledger_provider.provider_name == registry_provider.provider_name

    def test_active_ledger_store_exists(self):
        assert ACTIVE_TRANSPARENCY_LEDGER._store is not None

    def test_active_ledger_has_authority_name(self):
        assert (
            ACTIVE_TRANSPARENCY_LEDGER._authority_name == "cgin-transparency-authority"
        )

    def test_active_ledger_statistics_entry_count_increases(self):
        before = ACTIVE_TRANSPARENCY_LEDGER._store.entry_count()
        d = hashlib.sha256(b"count-test").hexdigest()
        ACTIVE_TRANSPARENCY_LEDGER.append(
            entry_type="test",
            artifact_digest=d,
            tenant_fingerprint="b" * 32,
        )
        after = ACTIVE_TRANSPARENCY_LEDGER._store.entry_count()
        assert after == before + 1


# ===========================================================================
# 10. TestTransparencyTrustIntegration
# ===========================================================================


class TestTransparencyTrustIntegration:
    def test_root_is_signed_using_key_management_provider_name_is_memory(self):
        ledger, _ = _make_ledger()
        _append_n(ledger, 2)
        root = ledger.build_root()
        assert root.provider_name == "memory"

    def test_root_signature_verifies_via_verify_payload(self):
        ledger, _ = _make_ledger(_PROVIDER)
        _append_n(ledger, 2)
        root = ledger.build_root()

        from services.cgin.key_management.provider import ACTIVE_SIGNING_ALGORITHM

        root_body = {
            "root_digest": root.root_digest,
            "entry_count": root.entry_count,
            "generation_timestamp": root.generation_timestamp,
            "tree_height": root.tree_height,
            "algorithm": root.algorithm,
            "authority_version": root.authority_version,
            "schema_version": root.schema_version,
            "transparency_version": root.transparency_version,
        }
        canonical_bytes = canonicalize_snapshot(root_body)
        assert verify_payload(
            canonical_bytes, root.signature, _PROVIDER, ACTIVE_SIGNING_ALGORITHM
        )

    def test_canonicalize_snapshot_from_trust_is_reused(self):
        # Verify we can call it without error
        result = canonicalize_snapshot({"key": "value"})
        assert isinstance(result, bytes)

    def test_generate_digest_from_trust_is_reused(self):
        digest = generate_digest(b"test")
        assert len(digest) == 64

    def test_sign_payload_from_trust_is_reused(self):
        sig = sign_payload(b"test", _PROVIDER)
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_memory_key_provider_from_private_key_works_as_custom_provider(self):
        key = Ed25519PrivateKey.generate()
        provider = MemoryKeyProvider.from_private_key(key)
        ledger, _ = _make_ledger(provider)
        _append_n(ledger, 2)
        root = ledger.build_root()
        assert root.provider_name == "memory"

    def test_custom_ledger_with_custom_provider_signs_correctly(self):
        key = Ed25519PrivateKey.generate()
        provider = MemoryKeyProvider.from_private_key(key)
        ledger, _ = _make_ledger(provider)
        entries = _append_n(ledger, 3)
        ledger.build_root()

        result = ledger.verify_entry(entries[0].entry_id, entries[0].artifact_digest)
        assert result.valid is True

    def test_root_signature_fails_with_wrong_key(self):
        # Sign with one key; verify with another
        key1 = Ed25519PrivateKey.generate()
        key2 = Ed25519PrivateKey.generate()
        provider1 = MemoryKeyProvider.from_private_key(key1)
        provider2 = MemoryKeyProvider.from_private_key(key2)

        ledger, _ = _make_ledger(provider1)
        _append_n(ledger, 2)
        root = ledger.build_root()

        from services.cgin.key_management.provider import ACTIVE_SIGNING_ALGORITHM

        root_body = {
            "root_digest": root.root_digest,
            "entry_count": root.entry_count,
            "generation_timestamp": root.generation_timestamp,
            "tree_height": root.tree_height,
            "algorithm": root.algorithm,
            "authority_version": root.authority_version,
            "schema_version": root.schema_version,
            "transparency_version": root.transparency_version,
        }
        canonical_bytes = canonicalize_snapshot(root_body)
        # Verify with wrong provider should fail
        assert not verify_payload(
            canonical_bytes, root.signature, provider2, ACTIVE_SIGNING_ALGORITHM
        )

    def test_signing_algorithm_in_root_matches_active(self):
        from services.cgin.key_management.provider import ACTIVE_SIGNING_ALGORITHM

        ledger, _ = _make_ledger()
        ledger.build_root()
        root = ledger._store.get_latest_root()
        assert root.signing_algorithm == ACTIVE_SIGNING_ALGORITHM.value


# ===========================================================================
# 11. TestTransparencyDeterminism
# ===========================================================================


class TestTransparencyDeterminism:
    def test_same_entries_same_merkle_root(self):
        leaves1 = [b"alpha", b"beta", b"gamma"]
        leaves2 = [b"alpha", b"beta", b"gamma"]
        r1 = MerkleTree(leaves1).root()
        r2 = MerkleTree(leaves2).root()
        assert r1 == r2

    def test_same_root_body_same_root_id(self):
        root_body = {
            "root_digest": "a" * 64,
            "entry_count": 5,
            "generation_timestamp": "2026-01-01T00:00:00+00:00",
            "tree_height": 3,
            "algorithm": "sha256",
            "authority_version": "1.0",
            "schema_version": TRANSPARENCY_SCHEMA_VERSION,
            "transparency_version": TRANSPARENCY_VERSION,
        }
        c1 = canonicalize_snapshot(root_body)
        c2 = canonicalize_snapshot(root_body)
        assert generate_digest(c1) == generate_digest(c2)

    def test_same_entry_body_same_entry_id(self):
        id1 = _compute_entry_id("type_x", "e" * 64, 7)
        id2 = _compute_entry_id("type_x", "e" * 64, 7)
        assert id1 == id2

    def test_append_10_entries_twice_identical_order_identical_roots(self):
        # Two ledgers with identical entry sequences → identical Merkle root digests
        digests = [hashlib.sha256(f"d{i}".encode()).hexdigest() for i in range(10)]

        ledger1, _ = _make_ledger()
        for d in digests:
            ledger1.append(
                entry_type="t", artifact_digest=d, tenant_fingerprint="f" * 32
            )
        root1 = ledger1.build_root()

        ledger2, _ = _make_ledger()
        for d in digests:
            ledger2.append(
                entry_type="t", artifact_digest=d, tenant_fingerprint="f" * 32
            )
        root2 = ledger2.build_root()

        assert root1.root_digest == root2.root_digest

    def test_entry_ordering_is_fifo_not_sorted(self):
        digests = [hashlib.sha256(f"z{i}".encode()).hexdigest() for i in range(5)]
        ledger, store = _make_ledger()
        for d in digests:
            ledger.append(
                entry_type="t", artifact_digest=d, tenant_fingerprint="f" * 32
            )
        stored = store.all_entries()
        stored_digests = [e.artifact_digest for e in stored]
        assert stored_digests == digests  # FIFO, not sorted

    def test_different_ordering_different_root(self):
        d1 = hashlib.sha256(b"first").hexdigest()
        d2 = hashlib.sha256(b"second").hexdigest()

        ledger_ab, _ = _make_ledger()
        ledger_ab.append(
            entry_type="t", artifact_digest=d1, tenant_fingerprint="f" * 32
        )
        ledger_ab.append(
            entry_type="t", artifact_digest=d2, tenant_fingerprint="f" * 32
        )
        root_ab = ledger_ab.build_root()

        ledger_ba, _ = _make_ledger()
        ledger_ba.append(
            entry_type="t", artifact_digest=d2, tenant_fingerprint="f" * 32
        )
        ledger_ba.append(
            entry_type="t", artifact_digest=d1, tenant_fingerprint="f" * 32
        )
        root_ba = ledger_ba.build_root()

        assert root_ab.root_digest != root_ba.root_digest

    def test_proof_path_stable_for_same_tree(self):
        leaves = [b"a", b"b", b"c", b"d"]
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(leaves)
        assert tree1.proof(2) == tree2.proof(2)

    def test_merkle_root_is_32_bytes(self):
        tree = MerkleTree([b"test"])
        assert len(tree.root()) == 32

    def test_empty_tree_root_is_deterministic(self):
        assert MerkleTree([]).root() == MerkleTree([]).root()

    def test_100_leaves_produces_consistent_root(self):
        leaves = [f"leaf-{i}".encode() for i in range(100)]
        r1 = MerkleTree(leaves).root()
        r2 = MerkleTree(leaves).root()
        assert r1 == r2


# ===========================================================================
# 12. TestAppendOnlyInvariants
# ===========================================================================


class TestAppendOnlyInvariants:
    def test_duplicate_entry_id_raises_immediately(self):
        s = MemoryTransparencyStore()
        e = _make_entry()
        s.append_entry(e)
        with pytest.raises(ValueError):
            s.append_entry(e)

    def test_entries_once_appended_cannot_be_changed(self):
        s = MemoryTransparencyStore()
        e = _make_entry()
        s.append_entry(e)
        original_digest = e.artifact_digest
        # Frozen dataclass — mutation raises
        with pytest.raises((TypeError, AttributeError)):
            e.artifact_digest = "mutated"  # type: ignore[misc]
        # Value in store unchanged
        assert s.get_entry(e.entry_id).artifact_digest == original_digest

    def test_all_entries_returns_list(self):
        s = MemoryTransparencyStore()
        e = _make_entry()
        s.append_entry(e)
        result = s.all_entries()
        assert isinstance(result, list)

    def test_historical_entries_survive_root_rebuild(self):
        ledger, store = _make_ledger()
        entries = _append_n(ledger, 3)
        ledger.build_root()
        _append_n(ledger, 2)
        ledger.build_root()
        # All original entries still present
        for e in entries:
            assert store.get_entry(e.entry_id) is not None

    def test_root_count_can_only_increase(self):
        ledger, store = _make_ledger()
        c0 = store.root_count()
        ledger.build_root()
        c1 = store.root_count()
        ledger.build_root()
        c2 = store.root_count()
        assert c1 > c0
        assert c2 > c1

    def test_entry_count_can_only_increase(self):
        ledger, store = _make_ledger()
        c0 = store.entry_count()
        ledger.append(
            entry_type="t", artifact_digest="a" * 64, tenant_fingerprint="f" * 32
        )
        c1 = store.entry_count()
        ledger.append(
            entry_type="t", artifact_digest="b" * 64, tenant_fingerprint="f" * 32
        )
        c2 = store.entry_count()
        assert c1 > c0
        assert c2 > c1

    def test_all_entries_count_matches_entry_count(self):
        s = MemoryTransparencyStore()
        for i in range(5):
            s.append_entry(
                _make_entry(
                    sequence_number=i,
                    artifact_digest=hashlib.sha256(f"c{i}".encode()).hexdigest(),
                )
            )
        assert len(s.all_entries()) == s.entry_count()

    def test_root_cannot_be_appended_twice_with_same_id(self):
        # Can't easily test duplicate root_id without duplicating timestamps
        # But we can verify the store guard works
        s = MemoryTransparencyStore()
        ledger = TransparencyLedger(store=s, key_provider=_PROVIDER)
        _append_n(ledger, 2)
        root = ledger.build_root()
        with pytest.raises(ValueError):
            s.append_root(root)  # duplicate root_id

    def test_empty_store_counts_are_zero(self):
        s = MemoryTransparencyStore()
        assert s.entry_count() == 0
        assert s.root_count() == 0

    def test_all_roots_count_matches_root_count(self):
        ledger, store = _make_ledger()
        ledger.build_root()
        ledger.build_root()
        assert len(store.all_roots()) == store.root_count()


# ===========================================================================
# 13. TestMerkleDomainSeparation
# ===========================================================================


class TestMerkleDomainSeparation:
    """Verify domain separation prevents second-preimage attacks."""

    def test_hash_leaf_uses_0x00_prefix(self):
        data = b"test"
        expected = hashlib.sha256(b"\x00" + data).digest()
        assert _hash_leaf(data) == expected

    def test_hash_pair_uses_0x01_prefix(self):
        left = b"L" * 32
        right = b"R" * 32
        expected = hashlib.sha256(b"\x01" + left + right).digest()
        assert _hash_pair(left, right) == expected

    def test_hash_leaf_different_from_hash_pair_same_content(self):
        data = b"content"
        # hash_leaf and hash_pair of same byte string should differ
        h_leaf = _hash_leaf(data)
        # hash_pair needs 32-byte arguments; pad data to 32 bytes
        padded = data.ljust(32, b"\x00")
        h_pair = _hash_pair(padded, padded)
        assert h_leaf != h_pair

    def test_hash_leaf_returns_32_bytes(self):
        assert len(_hash_leaf(b"anything")) == 32

    def test_hash_pair_returns_32_bytes(self):
        assert len(_hash_pair(b"L" * 32, b"R" * 32)) == 32

    def test_leaf_order_matters_for_root(self):
        a, b = b"alpha", b"beta"
        r_ab = MerkleTree([a, b]).root()
        r_ba = MerkleTree([b, a]).root()
        assert r_ab != r_ba

    def test_prefix_prevents_length_extension(self):
        # A raw SHA256(leaf_data) should differ from _hash_leaf(leaf_data)
        data = b"raw"
        h_raw = hashlib.sha256(data).digest()
        h_domain = _hash_leaf(data)
        assert h_raw != h_domain

    def test_pair_order_matters(self):
        left = b"L" * 32
        right = b"R" * 32
        assert _hash_pair(left, right) != _hash_pair(right, left)

    def test_empty_leaf_is_not_hash_of_empty(self):
        # EMPTY_LEAF is 32 zero bytes, not sha256(b"")
        sha_empty = hashlib.sha256(b"").digest()
        assert EMPTY_LEAF != sha_empty

    def test_five_leaf_tree_verifies_all(self):
        leaves = [f"item{i}".encode() for i in range(5)]
        tree = MerkleTree(leaves)
        root_hex = tree.root().hex()
        for i in range(5):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, root_hex)

    def test_six_leaf_tree_root_deterministic(self):
        leaves = [f"x{i}".encode() for i in range(6)]
        assert MerkleTree(leaves).root() == MerkleTree(leaves).root()

    def test_nine_leaf_tree_verifies_all(self):
        leaves = [f"n{i}".encode() for i in range(9)]
        tree = MerkleTree(leaves)
        root_hex = tree.root().hex()
        for i in range(9):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, root_hex)

    def test_odd_last_node_duplication_effect(self):
        # For 3 leaves [a, b, c]: last node c is duplicated at level 1
        # This means proof[0] for leaf 2 is ('left', hash_pair(hash_leaf(c), hash_leaf(c)).hex())?
        # No — proof for leaf 2 is its sibling in the padded level
        leaves = [b"x", b"y", b"z"]
        tree = MerkleTree(leaves)
        proof_leaf2 = tree.proof(2)
        # The sibling of leaf 2 (at level 0) is its duplicate (index 3 = itself)
        assert proof_leaf2[0][0] == "right"
        assert proof_leaf2[0][1] == _hash_leaf(b"z").hex()

    def test_verify_proof_with_empty_proof_for_single_leaf(self):
        tree = MerkleTree([b"solo"])
        root_hex = tree.root().hex()
        assert MerkleTree.verify_proof(b"solo", [], root_hex)

    def test_verify_proof_with_extra_step_fails(self):
        leaves = [b"a"]
        tree = MerkleTree(leaves)
        root_hex = tree.root().hex()
        # Adding a bogus extra step should fail
        extra_step = [("right", "0" * 64)]
        assert not MerkleTree.verify_proof(b"a", extra_step, root_hex)


# ===========================================================================
# 14. TestTransparencyEntryEdgeCases
# ===========================================================================


class TestTransparencyEntryEdgeCases:
    """Additional edge case coverage for TransparencyEntry."""

    def test_entry_id_64_hex_chars(self):
        e = _make_entry()
        assert len(e.entry_id) == 64
        assert all(c in "0123456789abcdef" for c in e.entry_id)

    def test_two_entries_same_type_different_sequence_different_id(self):
        d = "f" * 64
        id0 = _compute_entry_id("snapshot", d, 0)
        id1 = _compute_entry_id("snapshot", d, 1)
        assert id0 != id1

    def test_two_entries_same_sequence_different_digest_different_id(self):
        id_a = _compute_entry_id("t", "a" * 64, 0)
        id_b = _compute_entry_id("t", "b" * 64, 0)
        assert id_a != id_b

    def test_entry_authority_name_is_string(self):
        e = _make_entry()
        assert isinstance(e.authority_name, str)

    def test_entry_signature_algorithm_is_ed25519_v1(self):
        e = _make_entry()
        assert e.signature_algorithm == "ed25519-v1"

    def test_entry_signature_provider_is_string(self):
        e = _make_entry()
        assert isinstance(e.signature_provider, str)

    def test_entry_hash_determinism_across_calls(self):
        d = "01" * 32
        id1 = _compute_entry_id("type_x", d, 3)
        id2 = _compute_entry_id("type_x", d, 3)
        id3 = _compute_entry_id("type_x", d, 3)
        assert id1 == id2 == id3

    def test_sequence_number_zero(self):
        e = _make_entry(sequence_number=0)
        assert e.sequence_number == 0

    def test_sequence_number_large(self):
        d = hashlib.sha256(b"large").hexdigest()
        e = _make_entry(sequence_number=999, artifact_digest=d)
        assert e.sequence_number == 999

    def test_entry_with_empty_parent_digest_none(self):
        e = _make_entry(parent_digest=None)
        assert e.parent_digest is None

    def test_entry_with_long_entry_type_string(self):
        e = _make_entry(entry_type="cgin_snapshot_v2_governance_recommendation_full")
        assert e.entry_type == "cgin_snapshot_v2_governance_recommendation_full"


# ===========================================================================
# 15. TestLedgerEdgeCases
# ===========================================================================


class TestLedgerEdgeCases:
    """Additional edge case tests for TransparencyLedger."""

    def test_empty_ledger_build_root_root_digest_is_empty_leaf_hex(self):
        ledger, _ = _make_ledger()
        root = ledger.build_root()
        # Empty tree → EMPTY_LEAF (32 zero bytes)
        assert root.root_digest == EMPTY_LEAF.hex()

    def test_single_entry_root_digest_is_hash_leaf(self):
        ledger, _ = _make_ledger()
        d = "aa" * 32
        ledger.append(entry_type="t", artifact_digest=d, tenant_fingerprint="f" * 32)
        root = ledger.build_root()
        expected_root = _hash_leaf(d.encode("utf-8")).hex()
        assert root.root_digest == expected_root

    def test_build_root_with_zero_entries_succeeds(self):
        ledger, store = _make_ledger()
        root = ledger.build_root()
        assert store.root_count() == 1
        assert root.entry_count == 0

    def test_append_does_not_change_existing_root(self):
        ledger, store = _make_ledger()
        _append_n(ledger, 2)
        root1 = ledger.build_root()
        _append_n(ledger, 3)
        # root1 is still in store unchanged
        retrieved = store.get_root(root1.root_id)
        assert retrieved is not None
        assert retrieved.root_digest == root1.root_digest
        assert retrieved.entry_count == 2

    def test_membership_proof_entry_index_0(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 3)
        ledger.build_root()
        proof = ledger.membership_proof(entries[0].entry_id)
        assert proof.entry_index == 0

    def test_membership_proof_root_id_matches_latest_root(self):
        ledger, store = _make_ledger()
        entries = _append_n(ledger, 2)
        root = ledger.build_root()
        proof = ledger.membership_proof(entries[0].entry_id)
        assert proof.root_id == root.root_id

    def test_verify_entry_entry_found_true_when_exists(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        ledger.build_root()
        result = ledger.verify_entry(entries[0].entry_id, entries[0].artifact_digest)
        assert result.entry_found is True

    def test_verify_entry_proof_valid_is_bool(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        ledger.build_root()
        result = ledger.verify_entry(entries[0].entry_id, entries[0].artifact_digest)
        assert isinstance(result.proof_valid, bool)

    def test_verify_entry_root_signature_valid_true(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        ledger.build_root()
        result = ledger.verify_entry(entries[1].entry_id, entries[1].artifact_digest)
        assert result.root_signature_valid is True

    def test_ledger_authority_name_in_entries(self):
        ledger, _ = _make_ledger()
        e = ledger.append(
            entry_type="t", artifact_digest="a" * 64, tenant_fingerprint="f" * 32
        )
        assert e.authority_name == "cgin-transparency-authority"

    def test_ledger_custom_authority_name(self):
        store = MemoryTransparencyStore()
        ledger = TransparencyLedger(
            store=store,
            key_provider=_PROVIDER,
            authority_name="custom-authority",
        )
        e = ledger.append(
            entry_type="t", artifact_digest="b" * 64, tenant_fingerprint="f" * 32
        )
        assert e.authority_name == "custom-authority"

    def test_statistics_root_count_after_two_builds(self):
        ledger, _ = _make_ledger()
        _append_n(ledger, 2)
        ledger.build_root()
        ledger.build_root()
        stats = ledger.statistics()
        assert stats.root_count == 2

    def test_membership_proof_algorithm_is_sha256(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        ledger.build_root()
        proof = ledger.membership_proof(entries[0].entry_id)
        assert proof.algorithm == "sha256"

    def test_membership_proof_transparency_version(self):
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, 2)
        ledger.build_root()
        proof = ledger.membership_proof(entries[0].entry_id)
        assert proof.transparency_version == TRANSPARENCY_VERSION


# ---------------------------------------------------------------------------
# Class 16: TestMerkleProofSerialization — MembershipProof round-trip
# ---------------------------------------------------------------------------


class TestMerkleProofSerialization:
    """Test MembershipProof to_dict / from_dict round-trip."""

    def _make_proof(self, n: int = 4, index: int = 0) -> MembershipProof:
        ledger, _ = _make_ledger()
        entries = _append_n(ledger, n)
        ledger.build_root()
        return ledger.membership_proof(entries[index].entry_id)

    def test_to_dict_returns_dict(self):
        proof = self._make_proof()
        d = proof.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_has_entry_id(self):
        proof = self._make_proof()
        d = proof.to_dict()
        assert d["entry_id"] == proof.entry_id

    def test_to_dict_has_entry_index(self):
        proof = self._make_proof()
        d = proof.to_dict()
        assert d["entry_index"] == proof.entry_index

    def test_to_dict_has_leaf_hash(self):
        proof = self._make_proof()
        d = proof.to_dict()
        assert d["leaf_hash"] == proof.leaf_hash

    def test_to_dict_has_root_digest(self):
        proof = self._make_proof()
        d = proof.to_dict()
        assert d["root_digest"] == proof.root_digest

    def test_to_dict_has_root_id(self):
        proof = self._make_proof()
        d = proof.to_dict()
        assert d["root_id"] == proof.root_id

    def test_to_dict_has_algorithm(self):
        proof = self._make_proof()
        d = proof.to_dict()
        assert d["algorithm"] == "sha256"

    def test_to_dict_has_transparency_version(self):
        proof = self._make_proof()
        d = proof.to_dict()
        assert d["transparency_version"] == TRANSPARENCY_VERSION

    def test_to_dict_proof_path_is_list(self):
        proof = self._make_proof()
        d = proof.to_dict()
        assert isinstance(d["proof_path"], list)

    def test_from_dict_round_trips_entry_id(self):
        proof = self._make_proof()
        reconstructed = MembershipProof.from_dict(proof.to_dict())
        assert reconstructed.entry_id == proof.entry_id

    def test_from_dict_round_trips_root_digest(self):
        proof = self._make_proof()
        reconstructed = MembershipProof.from_dict(proof.to_dict())
        assert reconstructed.root_digest == proof.root_digest

    def test_from_dict_round_trips_leaf_hash(self):
        proof = self._make_proof()
        reconstructed = MembershipProof.from_dict(proof.to_dict())
        assert reconstructed.leaf_hash == proof.leaf_hash

    def test_from_dict_round_trips_entry_index(self):
        proof = self._make_proof()
        reconstructed = MembershipProof.from_dict(proof.to_dict())
        assert reconstructed.entry_index == proof.entry_index

    def test_from_dict_round_trips_proof_path(self):
        proof = self._make_proof()
        reconstructed = MembershipProof.from_dict(proof.to_dict())
        assert list(reconstructed.proof_path) == list(proof.proof_path)

    def test_proof_path_tuples_have_side_and_hash(self):
        proof = self._make_proof(n=4, index=1)
        for side, h in proof.proof_path:
            assert side in ("left", "right")
            assert len(h) == 64  # sha256 hex digest

    def test_single_entry_proof_has_empty_path(self):
        ledger, _ = _make_ledger()
        e = ledger.append(
            entry_type="t",
            artifact_digest="a" * 64,
            tenant_fingerprint="f" * 32,
        )
        ledger.build_root()
        proof = ledger.membership_proof(e.entry_id)
        assert len(proof.proof_path) == 0
