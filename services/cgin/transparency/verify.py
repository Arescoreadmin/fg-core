"""Transparency verification logic — never raises, always returns a result."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from services.cgin.transparency.store import TransparencyStore


@dataclass
class TransparencyVerificationResult:
    """Result of verifying an entry's existence and integrity."""

    valid: bool
    entry_found: bool
    digest_match: bool
    proof_valid: bool
    root_signature_valid: bool
    errors: list[str] = field(default_factory=list)


def verify_entry_in_store(
    store: "TransparencyStore",
    entry_id: str,
    artifact_digest: str,
    root_id: str | None = None,
    key_provider: Any = None,
) -> TransparencyVerificationResult:
    """Verify an entry exists, its digest matches, and it is in the Merkle tree.

    Never raises. Always returns TransparencyVerificationResult.
    """
    errors: list[str] = []
    entry_found = False
    digest_match = False
    proof_valid = False
    root_signature_valid = False

    # 1. Check entry exists
    entry = store.get_entry(entry_id)
    if entry is None:
        errors.append(f"entry_id not found: {entry_id}")
        return TransparencyVerificationResult(
            valid=False,
            entry_found=False,
            digest_match=False,
            proof_valid=False,
            root_signature_valid=False,
            errors=errors,
        )
    entry_found = True

    # 2. Check artifact_digest matches
    if entry.artifact_digest == artifact_digest:
        digest_match = True
    else:
        errors.append(
            f"artifact_digest mismatch: expected {artifact_digest!r}, "
            f"got {entry.artifact_digest!r}"
        )

    # 3. Resolve root to use
    try:
        if root_id is not None:
            root = store.get_root(root_id)
            if root is None:
                errors.append(f"root_id not found: {root_id}")
                return TransparencyVerificationResult(
                    valid=False,
                    entry_found=entry_found,
                    digest_match=digest_match,
                    proof_valid=False,
                    root_signature_valid=False,
                    errors=errors,
                )
        else:
            root = store.get_latest_root()
            if root is None:
                errors.append("no root available; call build_root() first")
                return TransparencyVerificationResult(
                    valid=False,
                    entry_found=entry_found,
                    digest_match=digest_match,
                    proof_valid=False,
                    root_signature_valid=False,
                    errors=errors,
                )
    except Exception as exc:
        errors.append(f"root resolution failed: {exc}")
        return TransparencyVerificationResult(
            valid=False,
            entry_found=entry_found,
            digest_match=digest_match,
            proof_valid=False,
            root_signature_valid=False,
            errors=errors,
        )

    # 4. Check membership proof
    try:
        from services.cgin.transparency.merkle import MerkleTree

        entries = store.all_entries()
        entry_index = next(
            (i for i, e in enumerate(entries) if e.entry_id == entry_id), None
        )
        if entry_index is None:
            errors.append(
                "entry found in store but not in ordered list (internal error)"
            )
        else:
            leaves = [e.artifact_digest.encode("utf-8") for e in entries]
            tree = MerkleTree(leaves)
            tree_root_hex = tree.root().hex()

            if tree_root_hex != root.root_digest:
                errors.append(
                    "computed Merkle root does not match stored root_digest; "
                    "store may have been modified after root was built"
                )
            else:
                proof_path = tree.proof(entry_index)
                leaf_bytes = entries[entry_index].artifact_digest.encode("utf-8")
                proof_valid = MerkleTree.verify_proof(
                    leaf_bytes, proof_path, tree_root_hex
                )
                if not proof_valid:
                    errors.append("membership proof verification failed")
    except Exception as exc:
        errors.append(f"proof verification failed: {exc}")

    # 5. Verify root signature
    try:
        from services.cgin.key_management import ACTIVE_PROVIDER_REGISTRY
        from services.cgin.trust import (
            ACTIVE_SIGNING_ALGORITHM,
            canonicalize_snapshot,
        )

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
        # Use the injected provider if available, otherwise fall back to active registry
        provider = key_provider if key_provider is not None else ACTIVE_PROVIDER_REGISTRY.active()
        root_signature_valid = provider.verify(
            canonical_bytes, root.signature, ACTIVE_SIGNING_ALGORITHM
        )
        if not root_signature_valid:
            errors.append("root signature verification failed")
    except Exception as exc:
        errors.append(f"root signature verification error: {exc}")

    valid = entry_found and digest_match and proof_valid and root_signature_valid
    return TransparencyVerificationResult(
        valid=valid,
        entry_found=entry_found,
        digest_match=digest_match,
        proof_valid=proof_valid,
        root_signature_valid=root_signature_valid,
        errors=errors,
    )
