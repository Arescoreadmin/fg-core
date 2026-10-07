"""CZ-REPAIR-CLOSEOUT-001 — State reconciliation: P0 repairs recorded as completed.

This module is NOT standalone. It is a component of the FrostGate governance platform
and Customer-Zero trust ceremony repair closeout.

These tests verify that PROVENANCE-INTEGRITY-001 (PR #750) and VAULT-VERIFY-CONTRACT-001
(PR #751) have been correctly moved from next_sequence to completed in
customer_one/roadmap_authority.yaml, and that CUSTOMER-ZERO-FINAL-READINESS-001 is now
authorized by the roadmap checker.

Truth invariants preserved:
- trust_proof_status: NOT_PROVEN (ceremony truth is unchanged)
- DEFECT-PROVENANCE-INTEGRITY and DEFECT-VERIFIER-CONTRACT remain in blocking_defects
  (defect records are historical facts; they persist even after repair)
- CUSTOMER-ZERO-TRUST-001 remains in blocked (ATTEMPTED_NOT_PROVEN)

Scope boundary: offline-only. No live infrastructure. No Vault server. No AWS API calls.
No Railway mutations. No HCP API calls. No paid infrastructure of any kind.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
ROADMAP_AUTHORITY = REPO / "customer_one" / "roadmap_authority.yaml"
CEREMONY_STATE = REPO / "customer_one" / "ceremony_state.yaml"


def _load_roadmap_authority() -> dict:
    with open(ROADMAP_AUTHORITY, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "roadmap_authority.yaml must be a YAML mapping"
    return data


def _load_ceremony_state() -> dict:
    with open(CEREMONY_STATE, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "ceremony_state.yaml must be a YAML mapping"
    return data


def _find_item(authority: dict, section: str, item_id: str) -> dict | None:
    return next((e for e in authority.get(section, []) if e.get("id") == item_id), None)


def _ids_in_section(authority: dict, section: str) -> list[str]:
    return [e.get("id") for e in authority.get(section, [])]


# ---------------------------------------------------------------------------
# A. Both repairs are in completed — exactly once
# ---------------------------------------------------------------------------


def test_a1_provenance_integrity_001_in_completed() -> None:
    """PROVENANCE-INTEGRITY-001 must appear in the completed section."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "PROVENANCE-INTEGRITY-001")
    assert item is not None, "PROVENANCE-INTEGRITY-001 must be in completed"


def test_a2_vault_verify_contract_001_in_completed() -> None:
    """VAULT-VERIFY-CONTRACT-001 must appear in the completed section."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "VAULT-VERIFY-CONTRACT-001")
    assert item is not None, "VAULT-VERIFY-CONTRACT-001 must be in completed"


def test_a3_provenance_integrity_001_not_in_next_sequence() -> None:
    """PROVENANCE-INTEGRITY-001 must not still appear as active work in next_sequence."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "PROVENANCE-INTEGRITY-001")
    assert item is None, (
        "PROVENANCE-INTEGRITY-001 must not remain in next_sequence after being completed"
    )


def test_a4_vault_verify_contract_001_not_in_next_sequence() -> None:
    """VAULT-VERIFY-CONTRACT-001 must not still appear as active work in next_sequence."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "VAULT-VERIFY-CONTRACT-001")
    assert item is None, (
        "VAULT-VERIFY-CONTRACT-001 must not remain in next_sequence after being completed"
    )


def test_a5_provenance_integrity_001_exactly_once_in_completed() -> None:
    """PROVENANCE-INTEGRITY-001 must appear exactly once in completed (no duplicates)."""
    authority = _load_roadmap_authority()
    ids = _ids_in_section(authority, "completed")
    count = ids.count("PROVENANCE-INTEGRITY-001")
    assert count == 1, (
        f"PROVENANCE-INTEGRITY-001 must appear exactly once in completed; got {count}"
    )


def test_a6_vault_verify_contract_001_exactly_once_in_completed() -> None:
    """VAULT-VERIFY-CONTRACT-001 must appear exactly once in completed (no duplicates)."""
    authority = _load_roadmap_authority()
    ids = _ids_in_section(authority, "completed")
    count = ids.count("VAULT-VERIFY-CONTRACT-001")
    assert count == 1, (
        f"VAULT-VERIFY-CONTRACT-001 must appear exactly once in completed; got {count}"
    )


# ---------------------------------------------------------------------------
# B. Completed entries carry the required PR and SHA fields
# ---------------------------------------------------------------------------


def test_b1_provenance_integrity_001_has_pr_number() -> None:
    """PROVENANCE-INTEGRITY-001 completed entry must name PR #750."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "PROVENANCE-INTEGRITY-001")
    assert item is not None
    assert "#750" in item.get("prs", []), (
        "PROVENANCE-INTEGRITY-001 must list '#750' in prs"
    )


def test_b2_vault_verify_contract_001_has_pr_number() -> None:
    """VAULT-VERIFY-CONTRACT-001 completed entry must name PR #751."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "VAULT-VERIFY-CONTRACT-001")
    assert item is not None
    assert "#751" in item.get("prs", []), (
        "VAULT-VERIFY-CONTRACT-001 must list '#751' in prs"
    )


def test_b3_provenance_integrity_001_has_merged_sha() -> None:
    """PROVENANCE-INTEGRITY-001 completed entry must carry a merged_sha."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "PROVENANCE-INTEGRITY-001")
    assert item is not None
    sha = item.get("merged_sha", "")
    assert sha and len(sha) >= 8, (
        f"PROVENANCE-INTEGRITY-001 must carry a non-empty merged_sha; got {sha!r}"
    )


def test_b4_vault_verify_contract_001_has_merged_sha() -> None:
    """VAULT-VERIFY-CONTRACT-001 completed entry must carry a merged_sha."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "VAULT-VERIFY-CONTRACT-001")
    assert item is not None
    sha = item.get("merged_sha", "")
    assert sha and len(sha) >= 8, (
        f"VAULT-VERIFY-CONTRACT-001 must carry a non-empty merged_sha; got {sha!r}"
    )


# ---------------------------------------------------------------------------
# C. CUSTOMER-ZERO-FINAL-READINESS-001 is now authorized by the checker
# ---------------------------------------------------------------------------


def test_c1_checker_authorizes_final_readiness() -> None:
    """check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-FINAL-READINESS-001 must exit 0."""
    result = subprocess.run(
        [
            "python",
            "tools/ci/check_customer_one_roadmap.py",
            "--work-item",
            "CUSTOMER-ZERO-FINAL-READINESS-001",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"Checker must authorize CUSTOMER-ZERO-FINAL-READINESS-001 now that its "
        f"blocked_by deps (PROVENANCE-INTEGRITY-001, VAULT-VERIFY-CONTRACT-001) are complete; "
        f"got rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}"
    )


def test_c2_final_readiness_still_in_next_sequence() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 must still be in next_sequence (it is not yet done)."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is not None, (
        "CUSTOMER-ZERO-FINAL-READINESS-001 must remain in next_sequence; "
        "it is authorized but not yet executed"
    )


# ---------------------------------------------------------------------------
# D. Ceremony truth is unchanged by this closeout
# ---------------------------------------------------------------------------


def test_d1_trust_proof_status_still_not_proven() -> None:
    """trust_proof_status must remain NOT_PROVEN — closeout does not alter ceremony truth."""
    state = _load_ceremony_state()
    status = state.get("trust_proof_status")
    assert status == "NOT_PROVEN", (
        f"trust_proof_status must remain NOT_PROVEN after closeout; got {status!r}"
    )


def test_d2_defect_provenance_integrity_still_in_blocking_defects() -> None:
    """DEFECT-PROVENANCE-INTEGRITY must remain in blocking_defects (historical fact)."""
    state = _load_ceremony_state()
    defect_ids = [d["id"] for d in state.get("blocking_defects", [])]
    assert "DEFECT-PROVENANCE-INTEGRITY" in defect_ids, (
        "DEFECT-PROVENANCE-INTEGRITY must remain in blocking_defects; "
        "defect records are historical facts even after repair ships"
    )


def test_d3_defect_verifier_contract_still_in_blocking_defects() -> None:
    """DEFECT-VERIFIER-CONTRACT must remain in blocking_defects (historical fact)."""
    state = _load_ceremony_state()
    defect_ids = [d["id"] for d in state.get("blocking_defects", [])]
    assert "DEFECT-VERIFIER-CONTRACT" in defect_ids, (
        "DEFECT-VERIFIER-CONTRACT must remain in blocking_defects; "
        "defect records are historical facts even after repair ships"
    )
