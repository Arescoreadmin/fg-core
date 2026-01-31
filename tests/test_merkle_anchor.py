"""
Tests for the Merkle Anchor Job.

Tests verify:
- Merkle tree construction and verification
- Anchor record creation and integrity
- Chain verification
- Tamper detection (mutating entries causes verification failure)
"""

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from jobs.merkle_anchor.job import (
    MerkleTree,
    canonical_json,
    compute_leaf_hash,
    create_anchor_record,
    sha256_hex,
    verify_anchor_chain,
    verify_anchor_record,
    verify_entry_in_anchor,
)


class TestSha256Hex:
    """Tests for sha256_hex function."""

    def test_string_input(self):
        result = sha256_hex("hello")
        assert len(result) == 64
        assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_bytes_input(self):
        result = sha256_hex(b"hello")
        assert result == sha256_hex("hello")

    def test_empty_string(self):
        result = sha256_hex("")
        assert len(result) == 64
        # Known hash of empty string
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestCanonicalJson:
    """Tests for canonical_json function."""

    def test_sorted_keys(self):
        obj = {"z": 1, "a": 2, "m": 3}
        result = canonical_json(obj)
        assert result == '{"a":2,"m":3,"z":1}'

    def test_no_spaces(self):
        obj = {"key": "value"}
        result = canonical_json(obj)
        assert " " not in result
        assert result == '{"key":"value"}'

    def test_nested_objects(self):
        obj = {"outer": {"inner": "value"}}
        result = canonical_json(obj)
        assert result == '{"outer":{"inner":"value"}}'


class TestMerkleTree:
    """Tests for MerkleTree class."""

    def test_empty_tree(self):
        tree = MerkleTree([])
        assert tree.root == sha256_hex("")

    def test_single_leaf(self):
        leaf = sha256_hex("data")
        tree = MerkleTree([leaf])
        assert tree.root == leaf

    def test_two_leaves(self):
        leaf1 = sha256_hex("data1")
        leaf2 = sha256_hex("data2")
        tree = MerkleTree([leaf1, leaf2])
        expected_root = sha256_hex(leaf1 + leaf2)
        assert tree.root == expected_root

    def test_three_leaves(self):
        leaves = [sha256_hex(f"data{i}") for i in range(3)]
        tree = MerkleTree(leaves)
        # Three leaves: [L0, L1, L2]
        # Level 1: [H(L0+L1), H(L2+L2)]
        # Level 2: root
        level1_0 = sha256_hex(leaves[0] + leaves[1])
        level1_1 = sha256_hex(leaves[2] + leaves[2])
        expected_root = sha256_hex(level1_0 + level1_1)
        assert tree.root == expected_root

    def test_four_leaves(self):
        leaves = [sha256_hex(f"data{i}") for i in range(4)]
        tree = MerkleTree(leaves)
        # Four leaves form a balanced tree
        level1_0 = sha256_hex(leaves[0] + leaves[1])
        level1_1 = sha256_hex(leaves[2] + leaves[3])
        expected_root = sha256_hex(level1_0 + level1_1)
        assert tree.root == expected_root

    def test_proof_generation_and_verification(self):
        leaves = [sha256_hex(f"data{i}") for i in range(4)]
        tree = MerkleTree(leaves)

        # Verify each leaf's proof
        for i, leaf in enumerate(leaves):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(leaf, proof, tree.root)

    def test_proof_fails_for_wrong_leaf(self):
        leaves = [sha256_hex(f"data{i}") for i in range(4)]
        tree = MerkleTree(leaves)

        proof = tree.get_proof(0)
        wrong_leaf = sha256_hex("wrong_data")
        assert not MerkleTree.verify_proof(wrong_leaf, proof, tree.root)

    def test_deterministic_root(self):
        """Same leaves always produce same root."""
        leaves = [sha256_hex(f"data{i}") for i in range(5)]
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(leaves)
        assert tree1.root == tree2.root


class TestComputeLeafHash:
    """Tests for compute_leaf_hash function."""

    def test_deterministic(self):
        entry = {"id": 1, "event": "test", "timestamp": "2024-01-01T00:00:00Z"}
        hash1 = compute_leaf_hash(entry)
        hash2 = compute_leaf_hash(entry)
        assert hash1 == hash2

    def test_different_entries_different_hashes(self):
        entry1 = {"id": 1, "event": "test1"}
        entry2 = {"id": 2, "event": "test2"}
        assert compute_leaf_hash(entry1) != compute_leaf_hash(entry2)

    def test_key_order_independent(self):
        entry1 = {"a": 1, "b": 2}
        entry2 = {"b": 2, "a": 1}
        assert compute_leaf_hash(entry1) == compute_leaf_hash(entry2)


class TestCreateAnchorRecord:
    """Tests for create_anchor_record function."""

    def test_creates_valid_record(self):
        leaves = [sha256_hex(f"data{i}") for i in range(3)]
        tree = MerkleTree(leaves)
        window_start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        window_end = datetime(2024, 1, 1, 1, 0, 0, tzinfo=timezone.utc)

        record = create_anchor_record(
            merkle_root=tree.root,
            window_start=window_start,
            window_end=window_end,
            leaf_count=3,
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        assert record["anchor_version"] == "1.0"
        assert record["merkle_root"] == tree.root
        assert record["leaf_count"] == 3
        assert record["leaf_hashes"] == leaves
        assert record["prev_anchor_hash"] is None
        assert "anchor_hash" in record
        assert "anchor_time" in record

    def test_record_self_verifies(self):
        leaves = [sha256_hex(f"data{i}") for i in range(3)]
        tree = MerkleTree(leaves)
        window_start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        window_end = datetime(2024, 1, 1, 1, 0, 0, tzinfo=timezone.utc)

        record = create_anchor_record(
            merkle_root=tree.root,
            window_start=window_start,
            window_end=window_end,
            leaf_count=3,
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        is_valid, msg = verify_anchor_record(record)
        assert is_valid, f"Verification failed: {msg}"


class TestVerifyAnchorRecord:
    """Tests for verify_anchor_record function."""

    def test_valid_record(self):
        leaves = [sha256_hex("data")]
        tree = MerkleTree(leaves)
        record = create_anchor_record(
            merkle_root=tree.root,
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            leaf_count=1,
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        is_valid, msg = verify_anchor_record(record)
        assert is_valid

    def test_missing_anchor_hash(self):
        record = {"merkle_root": "abc", "leaf_hashes": []}
        is_valid, msg = verify_anchor_record(record)
        assert not is_valid
        assert "Missing anchor_hash" in msg

    def test_tampered_anchor_hash(self):
        leaves = [sha256_hex("data")]
        tree = MerkleTree(leaves)
        record = create_anchor_record(
            merkle_root=tree.root,
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            leaf_count=1,
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        # Tamper with anchor hash
        record["anchor_hash"] = "tampered_hash"
        is_valid, msg = verify_anchor_record(record)
        assert not is_valid
        assert "mismatch" in msg.lower()

    def test_tampered_merkle_root(self):
        leaves = [sha256_hex("data")]
        tree = MerkleTree(leaves)
        record = create_anchor_record(
            merkle_root=tree.root,
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            leaf_count=1,
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        # Tamper with merkle root (but not anchor_hash)
        original_hash = record["anchor_hash"]
        record["merkle_root"] = "tampered_root"
        # This should fail because anchor_hash no longer matches
        is_valid, msg = verify_anchor_record(record)
        assert not is_valid

    def test_tampered_leaf_hash_detected(self):
        """Critical test: mutating an audit entry must cause verification failure."""
        # Create entries
        entries = [
            {"id": 1, "event": "login", "user": "alice"},
            {"id": 2, "event": "logout", "user": "bob"},
            {"id": 3, "event": "access", "user": "charlie"},
        ]
        leaves = [compute_leaf_hash(e) for e in entries]
        tree = MerkleTree(leaves)

        record = create_anchor_record(
            merkle_root=tree.root,
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            leaf_count=len(entries),
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        # Verify original record is valid
        is_valid, msg = verify_anchor_record(record)
        assert is_valid, f"Original record should be valid: {msg}"

        # Tamper with one leaf hash (simulating modified audit entry)
        record_copy = json.loads(json.dumps(record))
        record_copy["leaf_hashes"][1] = sha256_hex("tampered")

        # Verification should now fail
        is_valid, msg = verify_anchor_record(record_copy)
        assert not is_valid, "Tampered record should fail verification"


class TestVerifyAnchorChain:
    """Tests for verify_anchor_chain function."""

    def test_empty_chain(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "anchor.jsonl"
            # File doesn't exist - empty chain
            is_valid, errors = verify_anchor_chain(log_path)
            assert is_valid
            assert len(errors) == 0

    def test_single_record_chain(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "anchor.jsonl"

            leaves = [sha256_hex("data")]
            record = create_anchor_record(
                merkle_root=MerkleTree(leaves).root,
                window_start=datetime.now(timezone.utc),
                window_end=datetime.now(timezone.utc),
                leaf_count=1,
                leaf_hashes=leaves,
                prev_anchor_hash=None,
            )

            with log_path.open("w") as f:
                f.write(json.dumps(record) + "\n")

            is_valid, errors = verify_anchor_chain(log_path)
            assert is_valid, f"Chain validation failed: {errors}"

    def test_multi_record_chain(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "anchor.jsonl"

            prev_hash = None
            with log_path.open("w") as f:
                for i in range(3):
                    leaves = [sha256_hex(f"data{i}")]
                    record = create_anchor_record(
                        merkle_root=MerkleTree(leaves).root,
                        window_start=datetime.now(timezone.utc) - timedelta(hours=3 - i),
                        window_end=datetime.now(timezone.utc) - timedelta(hours=2 - i),
                        leaf_count=1,
                        leaf_hashes=leaves,
                        prev_anchor_hash=prev_hash,
                    )
                    f.write(json.dumps(record) + "\n")
                    prev_hash = record["anchor_hash"]

            is_valid, errors = verify_anchor_chain(log_path)
            assert is_valid, f"Chain validation failed: {errors}"

    def test_broken_chain_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "anchor.jsonl"

            # Create first record
            leaves1 = [sha256_hex("data1")]
            record1 = create_anchor_record(
                merkle_root=MerkleTree(leaves1).root,
                window_start=datetime.now(timezone.utc),
                window_end=datetime.now(timezone.utc),
                leaf_count=1,
                leaf_hashes=leaves1,
                prev_anchor_hash=None,
            )

            # Create second record with WRONG prev_anchor_hash
            leaves2 = [sha256_hex("data2")]
            record2 = create_anchor_record(
                merkle_root=MerkleTree(leaves2).root,
                window_start=datetime.now(timezone.utc),
                window_end=datetime.now(timezone.utc),
                leaf_count=1,
                leaf_hashes=leaves2,
                prev_anchor_hash="wrong_prev_hash",  # Should be record1["anchor_hash"]
            )

            with log_path.open("w") as f:
                f.write(json.dumps(record1) + "\n")
                f.write(json.dumps(record2) + "\n")

            is_valid, errors = verify_anchor_chain(log_path)
            assert not is_valid, "Broken chain should be detected"
            assert len(errors) > 0
            assert any("chain broken" in e.lower() for e in errors)


class TestVerifyEntryInAnchor:
    """Tests for verify_entry_in_anchor function."""

    def test_valid_entry(self):
        entries = [
            {"id": 1, "event": "login"},
            {"id": 2, "event": "logout"},
        ]
        leaves = [compute_leaf_hash(e) for e in entries]
        record = create_anchor_record(
            merkle_root=MerkleTree(leaves).root,
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            leaf_count=len(entries),
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        for entry in entries:
            is_valid, msg = verify_entry_in_anchor(entry, record)
            assert is_valid, f"Entry verification failed: {msg}"

    def test_missing_entry(self):
        entries = [{"id": 1, "event": "login"}]
        leaves = [compute_leaf_hash(e) for e in entries]
        record = create_anchor_record(
            merkle_root=MerkleTree(leaves).root,
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            leaf_count=len(entries),
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        # Try to verify an entry that wasn't included
        missing_entry = {"id": 999, "event": "not_included"}
        is_valid, msg = verify_entry_in_anchor(missing_entry, record)
        assert not is_valid
        assert "not found" in msg.lower()

    def test_tampered_entry_fails_verification(self):
        """Critical: A mutated entry must fail verification."""
        original_entry = {"id": 1, "event": "login", "user": "alice"}
        leaves = [compute_leaf_hash(original_entry)]
        record = create_anchor_record(
            merkle_root=MerkleTree(leaves).root,
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            leaf_count=1,
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        # Original entry verifies
        is_valid, _ = verify_entry_in_anchor(original_entry, record)
        assert is_valid

        # Tampered entry fails
        tampered_entry = {"id": 1, "event": "login", "user": "mallory"}
        is_valid, msg = verify_entry_in_anchor(tampered_entry, record)
        assert not is_valid, "Tampered entry should fail verification"


class TestTamperDetection:
    """Integration tests for tamper detection - CRITICAL for audit integrity."""

    def test_mutating_single_audit_entry_fails_verification(self):
        """
        Critical test case: mutating ONE audit entry must cause
        the entire anchor verification to fail.
        """
        # Create audit entries
        entries = [
            {"id": 1, "created_at": "2024-01-01T00:00:00Z", "event_type": "auth_success", "user": "alice"},
            {"id": 2, "created_at": "2024-01-01T00:01:00Z", "event_type": "auth_failure", "user": "bob"},
            {"id": 3, "created_at": "2024-01-01T00:02:00Z", "event_type": "data_access", "user": "charlie"},
        ]

        # Compute leaf hashes for original entries
        original_leaves = [compute_leaf_hash(e) for e in entries]

        # Create anchor record
        record = create_anchor_record(
            merkle_root=MerkleTree(original_leaves).root,
            window_start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2024, 1, 1, 1, 0, 0, tzinfo=timezone.utc),
            leaf_count=len(entries),
            leaf_hashes=original_leaves,
            prev_anchor_hash=None,
        )

        # Verify anchor record is valid
        is_valid, msg = verify_anchor_record(record)
        assert is_valid, f"Original anchor should be valid: {msg}"

        # Verify each original entry
        for entry in entries:
            is_valid, _ = verify_entry_in_anchor(entry, record)
            assert is_valid, "Original entries should verify"

        # Now MUTATE the second entry (change auth_failure to auth_success)
        mutated_entry = entries[1].copy()
        mutated_entry["event_type"] = "auth_success"  # TAMPERED!

        # Verification of mutated entry MUST fail
        is_valid, msg = verify_entry_in_anchor(mutated_entry, record)
        assert not is_valid, "Mutated entry MUST fail verification - tamper detection failed!"

        # Attempting to create a new anchor with mutated entries would have different root
        mutated_entries = entries.copy()
        mutated_entries[1] = mutated_entry
        mutated_leaves = [compute_leaf_hash(e) for e in mutated_entries]

        assert mutated_leaves != original_leaves, "Mutated leaves should differ"
        assert MerkleTree(mutated_leaves).root != record["merkle_root"], (
            "Merkle root MUST change when entries are mutated"
        )

    def test_insertion_attack_detected(self):
        """Inserting a new entry without updating anchor must fail."""
        entries = [{"id": 1, "event": "original"}]
        leaves = [compute_leaf_hash(e) for e in entries]
        record = create_anchor_record(
            merkle_root=MerkleTree(leaves).root,
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            leaf_count=1,
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        # Try to insert a fake entry
        fake_entry = {"id": 2, "event": "inserted_by_attacker"}
        is_valid, _ = verify_entry_in_anchor(fake_entry, record)
        assert not is_valid, "Inserted entry must not verify"

    def test_deletion_attack_detected(self):
        """Deleting entries would change the leaf count and Merkle root."""
        entries = [
            {"id": 1, "event": "keep"},
            {"id": 2, "event": "to_be_deleted"},
        ]
        leaves = [compute_leaf_hash(e) for e in entries]
        record = create_anchor_record(
            merkle_root=MerkleTree(leaves).root,
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            leaf_count=2,
            leaf_hashes=leaves,
            prev_anchor_hash=None,
        )

        # If attacker tries to claim only entry 1 existed
        reduced_entries = [entries[0]]
        reduced_leaves = [compute_leaf_hash(e) for e in reduced_entries]

        # The root would be different
        assert MerkleTree(reduced_leaves).root != record["merkle_root"]

        # The original anchor record still shows 2 entries
        assert record["leaf_count"] == 2
        assert len(record["leaf_hashes"]) == 2
