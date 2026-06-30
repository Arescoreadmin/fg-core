"""CGIN Transparency Ledger — append-only Merkle-backed transparency log."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from services.cgin.key_management.provider import ACTIVE_SIGNING_ALGORITHM, KeyProvider
from services.cgin.transparency.entry import (
    TRANSPARENCY_SCHEMA_VERSION,
    TRANSPARENCY_VERSION,
    TransparencyEntry,
    _compute_entry_id,
)
from services.cgin.transparency.merkle import MembershipProof, MerkleTree
from services.cgin.transparency.root import TransparencyRoot
from services.cgin.transparency.store import TransparencyStore
from services.cgin.trust import canonicalize_snapshot, generate_digest, sign_payload
from services.cgin.transparency.verify import TransparencyVerificationResult

if TYPE_CHECKING:
    from services.cgin.transparency.statistics import IntegrityStatistics


class TransparencyLedger:
    """Append-only, Merkle-backed transparency authority ledger.

    Entries are assigned monotonically increasing sequence numbers (starting at 0).
    Roots are built on demand and signed by the key provider.
    """

    def __init__(
        self,
        store: TransparencyStore,
        key_provider: KeyProvider,
        authority_name: str = "cgin-transparency-authority",
        authority_version: str = "1.0",
    ) -> None:
        self._store = store
        self._key_provider = key_provider
        self._authority_name = authority_name
        self._authority_version = authority_version

    def append(
        self,
        *,
        entry_type: str,
        artifact_digest: str,
        tenant_fingerprint: str,
        parent_digest: str | None = None,
    ) -> TransparencyEntry:
        """Create and append a new entry. Returns the created entry."""
        sequence_number = self._store.entry_count()
        entry_id = _compute_entry_id(entry_type, artifact_digest, sequence_number)
        generated_at = datetime.now(tz=timezone.utc).isoformat()

        entry = TransparencyEntry(
            entry_id=entry_id,
            entry_type=entry_type,
            authority_name=self._authority_name,
            authority_version=self._authority_version,
            artifact_digest=artifact_digest,
            parent_digest=parent_digest,
            sequence_number=sequence_number,
            generated_at=generated_at,
            tenant_fingerprint=tenant_fingerprint,
            signature_algorithm=ACTIVE_SIGNING_ALGORITHM.value,
            signature_provider=self._key_provider.provider_name,
            schema_version=TRANSPARENCY_SCHEMA_VERSION,
            transparency_version=TRANSPARENCY_VERSION,
        )
        self._store.append_entry(entry)
        return entry

    def build_root(self) -> TransparencyRoot:
        """Build and sign a Merkle root over all current entries. Appends root to store."""
        entries = self._store.all_entries()
        leaves = [e.artifact_digest.encode("utf-8") for e in entries]
        tree = MerkleTree(leaves)
        root_bytes = tree.root()
        root_hex = root_bytes.hex()

        timestamp = datetime.now(tz=timezone.utc).isoformat()

        # Sign the canonical root body
        root_body = {
            "root_digest": root_hex,
            "entry_count": len(entries),
            "generation_timestamp": timestamp,
            "tree_height": tree.height(),
            "algorithm": "sha256",
            "authority_version": self._authority_version,
            "schema_version": TRANSPARENCY_SCHEMA_VERSION,
            "transparency_version": TRANSPARENCY_VERSION,
        }
        canonical_bytes = canonicalize_snapshot(root_body)
        root_id = generate_digest(canonical_bytes)
        signature = sign_payload(canonical_bytes, self._key_provider)

        root = TransparencyRoot(
            root_id=root_id,
            root_digest=root_hex,
            entry_count=len(entries),
            generation_timestamp=timestamp,
            tree_height=tree.height(),
            algorithm="sha256",
            authority_version=self._authority_version,
            schema_version=TRANSPARENCY_SCHEMA_VERSION,
            transparency_version=TRANSPARENCY_VERSION,
            signature=signature,
            signing_algorithm=ACTIVE_SIGNING_ALGORITHM.value,
            provider_name=self._key_provider.provider_name,
        )
        self._store.append_root(root)
        return root

    def membership_proof(self, entry_id: str) -> MembershipProof:
        """Return a membership proof for the given entry_id.

        Raises KeyError if entry not found.
        Raises RuntimeError if no root has been built yet.
        """
        entry = self._store.get_entry(entry_id)
        if entry is None:
            raise KeyError(f"entry_id not found: {entry_id}")

        root = self._store.get_latest_root()
        if root is None:
            raise RuntimeError("No root built yet; call build_root() first")

        entries = self._store.all_entries()[: root.entry_count]
        entry_index = next(
            (i for i, e in enumerate(entries) if e.entry_id == entry_id), None
        )
        if entry_index is None:
            raise RuntimeError(
                f"entry_id {entry_id!r} is not covered by the latest root "
                f"(root covers {root.entry_count} entries); call build_root() to include it"
            )

        leaves = [e.artifact_digest.encode("utf-8") for e in entries]
        tree = MerkleTree(leaves)

        proof_path = tree.proof(entry_index)
        leaf_hash = tree._leaf_hashes[entry_index].hex()

        return MembershipProof(
            entry_id=entry_id,
            entry_index=entry_index,
            leaf_hash=leaf_hash,
            proof_path=proof_path,
            root_digest=root.root_digest,
            root_id=root.root_id,
            algorithm="sha256",
            transparency_version=TRANSPARENCY_VERSION,
        )

    def verify_entry(
        self,
        entry_id: str,
        artifact_digest: str,
        root_id: str | None = None,
    ) -> TransparencyVerificationResult:
        """Verify an entry exists, its digest matches, and it is in the Merkle tree."""
        from services.cgin.transparency.verify import verify_entry_in_store

        return verify_entry_in_store(
            self._store,
            entry_id,
            artifact_digest,
            root_id=root_id,
            key_provider=self._key_provider,
        )

    def statistics(self) -> "IntegrityStatistics":
        """Return current integrity statistics."""
        from services.cgin.transparency.statistics import compute_statistics

        return compute_statistics(self._store, self)
