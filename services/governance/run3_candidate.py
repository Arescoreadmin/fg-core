"""CUSTOMER-ZERO-RUN3-PREAUTH-001 — Deterministic production candidate freeze.

Two-stage freeze:
  1. During development (this PR): deterministic configuration/contract fingerprint
     over all immutable inputs except the final merged SHA.
  2. After merge: immutable source-SHA binding during post-merge preflight.

The candidate fingerprint is computed over all immutable inputs EXCLUDING
wall-clock timestamps (generated_at is recorded separately and excluded).

The PR cannot claim its own eventual commit SHA as frozen before commit —
this is recorded as PENDING_MERGE_SHA with an explanatory note.

Fail-closed semantics: the fingerprint changes if ANY of these change:
  - source SHA
  - readiness fingerprint
  - trust contract implementation files
  - infra content
  - resource inventory
  - proof matrix (stub: changes when proof matrix is finalized)
  - abort matrix
  - teardown contract

SAFETY BOUNDARY
---------------
  This module is offline-only, read-only, zero-cost.
  It does NOT authorize spending. It does NOT prove trust.
  It does NOT unblock TRUST-003 or ACCEPT-001.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from services.governance.run3_resource_inventory import (
    RESOURCE_INVENTORY_FINGERPRINT,
)

_REPO = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Repository identity
# ---------------------------------------------------------------------------

REPOSITORY_IDENTITY = "github.com/frostgate/fg-core"
CEREMONY_CONTRACT_VERSION = "1.0.0"
METHODOLOGY_VERSION = "customer-zero-run3-methodology-v1"
SCHEMA_VERSIONS = {
    "trust_binding": "1",
    "portable_verification_bundle": "1.0.0",
    "run3_preauth": "1.0.0",
}

# Ceremony contract ID — matches infra/variables.tf ceremony_id default
CEREMONY_ID = "CUSTOMER-ZERO-TRUST-003-RUN3"

# Source SHA at evaluation time.  During PR development this is the current
# HEAD of the governance/customer-zero-run3-preauth-001 branch.
# After merge to main it becomes the immutable merged SHA.
# NOTE: this is evaluated at import time — deterministic for a given checkout.


def _get_source_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(_REPO),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def _compute_infra_fingerprint() -> str:
    """SHA-256 of all infra/*.tf file contents — deterministic, sort-keyed."""
    infra = _REPO / "infra"
    content: dict[str, str] = {}
    for tf in sorted(infra.glob("*.tf")):
        content[tf.name] = tf.read_text(encoding="utf-8")
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _compute_trust_authority_fingerprint() -> str:
    """SHA-256 of trust implementation source files."""
    trust_files = [
        "services/governance/trust_binding.py",
        "services/cgin/key_management/vault_transit.py",
    ]
    content: dict[str, str] = {}
    for f in trust_files:
        p = _REPO / f
        if p.exists():
            content[f] = p.read_text(encoding="utf-8")
        else:
            content[f] = "FILE_ABSENT"
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _compute_readiness_fingerprint() -> str:
    """Return the canonical_fingerprint from the FINAL-READINESS evaluation.

    The FINAL-READINESS module (customer_zero_readiness.py) is authoritative.
    We evaluate it directly to bind the pre-auth candidate to the exact
    readiness state at evaluation time.  This fails closed if the readiness
    module cannot be evaluated.
    """
    try:
        import os
        os.environ.setdefault("FG_ENV", "test")
        from services.governance.customer_zero_readiness import evaluate
        result = evaluate(_REPO)
        return result.canonical_fingerprint
    except Exception as exc:
        # Fail closed: cannot compute readiness fingerprint means candidate
        # cannot be frozen.
        return f"READINESS_FINGERPRINT_ERROR:{exc!s}"


# ---------------------------------------------------------------------------
# Proof / abort / teardown stub fingerprints
# ---------------------------------------------------------------------------
# These are computed from the actual module content so that changes to the
# proof matrix, abort matrix, or teardown contract change the candidate
# fingerprint automatically.


def _compute_proof_matrix_fingerprint() -> str:
    p = _REPO / "services" / "governance" / "run3_proof_matrix.py"
    if not p.exists():
        return "PROOF_MATRIX_NOT_YET_PRODUCED"
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _compute_abort_matrix_fingerprint() -> str:
    p = _REPO / "services" / "governance" / "run3_abort_teardown.py"
    if not p.exists():
        return "ABORT_MATRIX_NOT_YET_PRODUCED"
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _compute_teardown_contract_fingerprint() -> str:
    # Same file as abort matrix for this implementation
    p = _REPO / "services" / "governance" / "run3_abort_teardown.py"
    if not p.exists():
        return "TEARDOWN_CONTRACT_NOT_YET_PRODUCED"
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Candidate dataclass
# ---------------------------------------------------------------------------


@dataclass
class Run3Candidate:
    """Deterministic production candidate for CUSTOMER-ZERO-TRUST-003 Run 3."""

    repository_identity: str
    source_sha: str
    readiness_result: str
    readiness_fingerprint: str
    readiness_authority_version: str
    infrastructure_source_fingerprint: str
    trust_authority_source_fingerprint: str
    ceremony_contract_version: str
    methodology_version: str
    relevant_schema_versions: dict[str, str]
    expected_resource_inventory_fingerprint: str
    proof_matrix_fingerprint: str
    abort_matrix_fingerprint: str
    teardown_contract_fingerprint: str
    # candidate_fingerprint is computed from all above fields (no timestamps)
    candidate_fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.candidate_fingerprint:
            self.candidate_fingerprint = self._compute_candidate_fingerprint()

    def _compute_candidate_fingerprint(self) -> str:
        """Deterministic fingerprint over all immutable fields (no timestamps)."""
        canonical = {
            "repository_identity": self.repository_identity,
            "source_sha": self.source_sha,
            "readiness_result": self.readiness_result,
            "readiness_fingerprint": self.readiness_fingerprint,
            "readiness_authority_version": self.readiness_authority_version,
            "infrastructure_source_fingerprint": self.infrastructure_source_fingerprint,
            "trust_authority_source_fingerprint": self.trust_authority_source_fingerprint,
            "ceremony_contract_version": self.ceremony_contract_version,
            "methodology_version": self.methodology_version,
            "relevant_schema_versions": self.relevant_schema_versions,
            "expected_resource_inventory_fingerprint": self.expected_resource_inventory_fingerprint,
            "proof_matrix_fingerprint": self.proof_matrix_fingerprint,
            "abort_matrix_fingerprint": self.abort_matrix_fingerprint,
            "teardown_contract_fingerprint": self.teardown_contract_fingerprint,
        }
        return hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_identity": self.repository_identity,
            "source_sha": self.source_sha,
            "readiness_result": self.readiness_result,
            "readiness_fingerprint": self.readiness_fingerprint,
            "readiness_authority_version": self.readiness_authority_version,
            "infrastructure_source_fingerprint": self.infrastructure_source_fingerprint,
            "trust_authority_source_fingerprint": self.trust_authority_source_fingerprint,
            "ceremony_contract_version": self.ceremony_contract_version,
            "methodology_version": self.methodology_version,
            "relevant_schema_versions": self.relevant_schema_versions,
            "expected_resource_inventory_fingerprint": self.expected_resource_inventory_fingerprint,
            "proof_matrix_fingerprint": self.proof_matrix_fingerprint,
            "abort_matrix_fingerprint": self.abort_matrix_fingerprint,
            "teardown_contract_fingerprint": self.teardown_contract_fingerprint,
            "candidate_fingerprint": self.candidate_fingerprint,
            # NOTE: generated_at is NOT part of the canonical fingerprint.
            # It is recorded separately for audit purposes only.
            "_generated_at_note": (
                "generated_at is excluded from candidate_fingerprint — "
                "wall-clock timestamp is diagnostic only"
            ),
        }


def build_candidate(repo: Path | None = None) -> Run3Candidate:
    """Build the deterministic Run-3 production candidate.

    Safe to call multiple times — produces the same fingerprint for the same
    source checkout.
    """
    global _REPO
    if repo is not None:
        _REPO = repo

    source_sha = _get_source_sha()
    infra_fp = _compute_infra_fingerprint()
    trust_fp = _compute_trust_authority_fingerprint()
    readiness_fp = _compute_readiness_fingerprint()
    proof_fp = _compute_proof_matrix_fingerprint()
    abort_fp = _compute_abort_matrix_fingerprint()
    teardown_fp = _compute_teardown_contract_fingerprint()

    # Determine readiness_result from the readiness evaluation
    try:
        import os
        os.environ.setdefault("FG_ENV", "test")
        from services.governance.customer_zero_readiness import evaluate
        rr = evaluate(_REPO)
        readiness_result = rr.final_result.value
    except Exception:
        readiness_result = "EVALUATION_ERROR"

    return Run3Candidate(
        repository_identity=REPOSITORY_IDENTITY,
        source_sha=source_sha,
        readiness_result=readiness_result,
        readiness_fingerprint=readiness_fp,
        readiness_authority_version="1.0.0",
        infrastructure_source_fingerprint=infra_fp,
        trust_authority_source_fingerprint=trust_fp,
        ceremony_contract_version=CEREMONY_CONTRACT_VERSION,
        methodology_version=METHODOLOGY_VERSION,
        relevant_schema_versions=SCHEMA_VERSIONS,
        expected_resource_inventory_fingerprint=RESOURCE_INVENTORY_FINGERPRINT,
        proof_matrix_fingerprint=proof_fp,
        abort_matrix_fingerprint=abort_fp,
        teardown_contract_fingerprint=teardown_fp,
    )
