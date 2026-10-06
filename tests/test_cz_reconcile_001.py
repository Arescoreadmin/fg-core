"""CZ-RECONCILE-001 — ceremony state determinism and sequence enforcement tests.

This module is NOT standalone. It is a component of the FrostGate governance
platform and Customer-Zero trust ceremony reconciliation.

These tests verify:
  A. Current trust status cannot be interpreted as PASS.
  B. Cost containment COMPLETE does not imply trust PROVEN.
  C. Customer-Zero acceptance remains BLOCKED.
  D. Third paid ceremony remains unauthorized until offline prerequisites complete.
  E. Roadmap sequence requires PROVENANCE-INTEGRITY-001 before FINAL READINESS.
  F. Roadmap sequence requires VAULT-VERIFY-CONTRACT-001 before FINAL READINESS.
  G. CUSTOMER-ZERO-FINAL-READINESS-001 required before paid Run 3.
  H. Persistent AWS audit authority is PRESERVED, not teardown-targeted.
  I. No teardown completion state authorizes deletion of persistent AWS audit resources.
  J. Machine-readable ceremony status is deterministic.
  K. Existing teardown safety tests remain green (structural check).
  L. Existing Customer-One roadmap authority checker can locate CZ-RECONCILE-001.
  M. No new tests require live HCP Vault, AWS mutation, Railway mutation, or paid infra.

Scope boundary: offline-only. No live infrastructure. No Vault server. No AWS API calls.
No Railway mutations. No HCP API calls. No paid infrastructure of any kind.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

os.environ.setdefault("FG_ENV", "test")

REPO = Path(__file__).resolve().parents[1]
CEREMONY_STATE = REPO / "customer_one" / "ceremony_state.yaml"
ROADMAP_AUTHORITY = REPO / "customer_one" / "roadmap_authority.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_ceremony_state() -> dict:
    with open(CEREMONY_STATE, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "ceremony_state.yaml must be a YAML mapping"
    return data


def _load_roadmap_authority() -> dict:
    with open(ROADMAP_AUTHORITY, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "roadmap_authority.yaml must be a YAML mapping"
    return data


def _find_item(authority: dict, section: str, item_id: str) -> dict | None:
    return next(
        (e for e in authority.get(section, []) if e.get("id") == item_id), None
    )


# ---------------------------------------------------------------------------
# A. Trust status cannot be interpreted as PASS
# ---------------------------------------------------------------------------


def test_a1_trust_proof_status_is_not_proven() -> None:
    """trust_proof_status must be NOT_PROVEN — not PASS, COMPLETE, or any affirmative."""
    state = _load_ceremony_state()
    status = state["trust_proof_status"]
    assert status == "NOT_PROVEN", (
        f"trust_proof_status must be NOT_PROVEN; got {status!r}. "
        "Failed ceremonies must not be converted to success."
    )


def test_a2_trust_status_is_not_ambiguous() -> None:
    """trust_proof_status must not use any passing synonym."""
    state = _load_ceremony_state()
    status = state["trust_proof_status"].upper()
    passing_synonyms = {"PASS", "PROVEN", "COMPLETE", "COMPLETED", "SUCCESS", "OK", "GREEN"}
    assert status not in passing_synonyms, (
        f"trust_proof_status {status!r} is a passing synonym — use NOT_PROVEN"
    )


def test_a3_ceremony_status_encodes_attempted() -> None:
    """operational_ceremony_status must be ATTEMPTED (runs done, not PASS)."""
    state = _load_ceremony_state()
    assert state["operational_ceremony_status"] == "ATTEMPTED"


def test_a4_roadmap_trust_001_status_is_attempted_not_proven() -> None:
    """CUSTOMER-ZERO-TRUST-001 in roadmap_authority must be ATTEMPTED_NOT_PROVEN."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-TRUST-001")
    assert item is not None, "CUSTOMER-ZERO-TRUST-001 must be present in next_sequence"
    status = item.get("status")
    assert status == "ATTEMPTED_NOT_PROVEN", (
        f"CUSTOMER-ZERO-TRUST-001 status must be ATTEMPTED_NOT_PROVEN; got {status!r}"
    )


# ---------------------------------------------------------------------------
# B. Cost containment COMPLETE does not imply trust PROVEN
# ---------------------------------------------------------------------------


def test_b1_cost_containment_complete_and_trust_not_proven_coexist() -> None:
    """Both states must hold simultaneously — COMPLETE teardown and NOT_PROVEN trust."""
    state = _load_ceremony_state()
    assert state["cost_containment_status"] == "COMPLETE"
    assert state["trust_proof_status"] == "NOT_PROVEN"


def test_b2_cost_containment_outcome_field_is_explicit() -> None:
    """Cost containment record must state CUSTOMER_ZERO_COST_CONTAINMENT_COMPLETE."""
    state = _load_ceremony_state()
    outcome = state["cost_containment"]["outcome"]
    assert outcome == "CUSTOMER_ZERO_COST_CONTAINMENT_COMPLETE"


def test_b3_preservation_invariant_explicitly_decouples_teardown_from_trust() -> None:
    """The preservation_invariant field must exist and state the decoupling explicitly."""
    state = _load_ceremony_state()
    invariant = state["cost_containment"]["preservation_invariant"]
    assert invariant, "preservation_invariant must not be empty"
    # The invariant must explicitly state that cost containment does not change NOT_PROVEN
    invariant_lower = invariant.lower()
    assert "does not change" in invariant_lower or "not change" in invariant_lower, (
        "preservation_invariant must explicitly state cost containment does not change "
        "CUSTOMER_ZERO_TRUST_NOT_PROVEN"
    )


# ---------------------------------------------------------------------------
# C. Customer-Zero acceptance remains BLOCKED
# ---------------------------------------------------------------------------


def test_c1_acceptance_status_is_blocked() -> None:
    """acceptance_status must be BLOCKED in ceremony state."""
    state = _load_ceremony_state()
    assert state["acceptance_status"] == "BLOCKED"


def test_c2_roadmap_accept_001_is_in_blocked_section() -> None:
    """CUSTOMER-ZERO-ACCEPT-001 must be in the blocked section of roadmap_authority."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "blocked", "CUSTOMER-ZERO-ACCEPT-001")
    assert item is not None, "CUSTOMER-ZERO-ACCEPT-001 must be in blocked section"


def test_c3_roadmap_accept_001_reason_references_not_proven() -> None:
    """CUSTOMER-ZERO-ACCEPT-001 blocked reason must reference trust not proven."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "blocked", "CUSTOMER-ZERO-ACCEPT-001")
    assert item is not None
    reason = item.get("reason", "").lower()
    # Must reference the attempted/not-proven state
    assert any(term in reason for term in ("not_proven", "attempted_not_proven", "two ceremony", "defect")), (
        "CUSTOMER-ZERO-ACCEPT-001 blocked reason must reference the not-proven defect state"
    )


# ---------------------------------------------------------------------------
# D. Third paid ceremony remains unauthorized
# ---------------------------------------------------------------------------


def test_d1_third_ceremony_status_is_not_authorized() -> None:
    """third_paid_ceremony_status must be NOT_AUTHORIZED in ceremony state."""
    state = _load_ceremony_state()
    assert state["third_paid_ceremony_status"] == "NOT_AUTHORIZED"


def test_d2_customer_zero_trust_003_is_in_blocked_section() -> None:
    """CUSTOMER-ZERO-TRUST-003 must be in blocked section of roadmap_authority."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "blocked", "CUSTOMER-ZERO-TRUST-003")
    assert item is not None, (
        "CUSTOMER-ZERO-TRUST-003 (third paid ceremony) must be in blocked section"
    )


def test_d3_trust_003_blocked_reason_requires_final_readiness() -> None:
    """Third ceremony blocked reason must reference CUSTOMER-ZERO-FINAL-READINESS-001."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "blocked", "CUSTOMER-ZERO-TRUST-003")
    assert item is not None
    reason = item.get("reason", "")
    assert "CUSTOMER-ZERO-FINAL-READINESS-001" in reason, (
        "CUSTOMER-ZERO-TRUST-003 blocked reason must reference CUSTOMER-ZERO-FINAL-READINESS-001"
    )


def test_d4_trust_001_records_third_ceremony_prerequisite() -> None:
    """CUSTOMER-ZERO-TRUST-001 must name its next_authorized_ceremony and prerequisite."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-TRUST-001")
    assert item is not None
    assert item.get("next_authorized_ceremony") == "CUSTOMER-ZERO-TRUST-003"
    assert item.get("ceremony_prerequisite") == "CUSTOMER-ZERO-FINAL-READINESS-001"


# ---------------------------------------------------------------------------
# E. Roadmap sequence requires PROVENANCE-INTEGRITY-001 before final readiness
# ---------------------------------------------------------------------------


def test_e1_provenance_integrity_001_in_next_sequence() -> None:
    """PROVENANCE-INTEGRITY-001 must be in next_sequence."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "PROVENANCE-INTEGRITY-001")
    assert item is not None, "PROVENANCE-INTEGRITY-001 must be in next_sequence"


def test_e2_final_readiness_blocked_by_provenance_integrity() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 must declare it is blocked by PROVENANCE-INTEGRITY-001."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is not None
    blocked_by = item.get("blocked_by", [])
    if isinstance(blocked_by, str):
        blocked_by = [blocked_by]
    assert "PROVENANCE-INTEGRITY-001" in blocked_by, (
        "CUSTOMER-ZERO-FINAL-READINESS-001 must declare blocked_by PROVENANCE-INTEGRITY-001"
    )


def test_e3_ceremony_state_names_provenance_defect() -> None:
    """ceremony_state.yaml must name DEFECT-PROVENANCE-INTEGRITY in blocking_defects."""
    state = _load_ceremony_state()
    defect_ids = [d["id"] for d in state.get("blocking_defects", [])]
    assert "DEFECT-PROVENANCE-INTEGRITY" in defect_ids, (
        "blocking_defects must include DEFECT-PROVENANCE-INTEGRITY"
    )


def test_e4_provenance_defect_maps_to_repair_work_item() -> None:
    """DEFECT-PROVENANCE-INTEGRITY must map to repair work item PROVENANCE-INTEGRITY-001."""
    state = _load_ceremony_state()
    defect = next(
        (d for d in state.get("blocking_defects", []) if d["id"] == "DEFECT-PROVENANCE-INTEGRITY"),
        None,
    )
    assert defect is not None
    assert defect.get("repair_work_item") == "PROVENANCE-INTEGRITY-001"


# ---------------------------------------------------------------------------
# F. Roadmap sequence requires VAULT-VERIFY-CONTRACT-001 before final readiness
# ---------------------------------------------------------------------------


def test_f1_vault_verify_contract_001_in_next_sequence() -> None:
    """VAULT-VERIFY-CONTRACT-001 must be in next_sequence."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "VAULT-VERIFY-CONTRACT-001")
    assert item is not None, "VAULT-VERIFY-CONTRACT-001 must be in next_sequence"


def test_f2_final_readiness_blocked_by_verifier_contract() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 must declare it is blocked by VAULT-VERIFY-CONTRACT-001."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is not None
    blocked_by = item.get("blocked_by", [])
    if isinstance(blocked_by, str):
        blocked_by = [blocked_by]
    assert "VAULT-VERIFY-CONTRACT-001" in blocked_by, (
        "CUSTOMER-ZERO-FINAL-READINESS-001 must declare blocked_by VAULT-VERIFY-CONTRACT-001"
    )


def test_f3_ceremony_state_names_verifier_contract_defect() -> None:
    """ceremony_state.yaml must name DEFECT-VERIFIER-CONTRACT in blocking_defects."""
    state = _load_ceremony_state()
    defect_ids = [d["id"] for d in state.get("blocking_defects", [])]
    assert "DEFECT-VERIFIER-CONTRACT" in defect_ids, (
        "blocking_defects must include DEFECT-VERIFIER-CONTRACT"
    )


def test_f4_verifier_contract_defect_maps_to_repair_work_item() -> None:
    """DEFECT-VERIFIER-CONTRACT must map to repair work item VAULT-VERIFY-CONTRACT-001."""
    state = _load_ceremony_state()
    defect = next(
        (d for d in state.get("blocking_defects", []) if d["id"] == "DEFECT-VERIFIER-CONTRACT"),
        None,
    )
    assert defect is not None
    assert defect.get("repair_work_item") == "VAULT-VERIFY-CONTRACT-001"


# ---------------------------------------------------------------------------
# G. CUSTOMER-ZERO-FINAL-READINESS-001 required before paid Run 3
# ---------------------------------------------------------------------------


def test_g1_final_readiness_in_next_sequence() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 must be in next_sequence."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is not None, "CUSTOMER-ZERO-FINAL-READINESS-001 must be in next_sequence"


def test_g2_final_readiness_requires_no_paid_infrastructure() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 must not require paid infrastructure."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is not None
    assert item.get("requires_paid_infrastructure") is False, (
        "CUSTOMER-ZERO-FINAL-READINESS-001 must not require paid infrastructure"
    )


def test_g3_ceremony_state_names_final_readiness_prerequisite() -> None:
    """ceremony_state.yaml third_ceremony_prerequisites must include CUSTOMER-ZERO-FINAL-READINESS-001."""
    state = _load_ceremony_state()
    prereq_ids = [p["id"] for p in state.get("third_ceremony_prerequisites", [])]
    assert "CUSTOMER-ZERO-FINAL-READINESS-001" in prereq_ids


def test_g4_third_ceremony_prerequisites_are_ordered() -> None:
    """third_ceremony_prerequisites must declare an explicit order."""
    state = _load_ceremony_state()
    prereqs = state.get("third_ceremony_prerequisites", [])
    orders = [p.get("order") for p in prereqs]
    assert all(isinstance(o, int) for o in orders), "all prerequisites must have an integer order"
    assert sorted(orders) == list(range(1, len(orders) + 1)), (
        "prerequisite orders must be 1, 2, 3, ... without gaps"
    )


def test_g5_provenance_and_verifier_before_final_readiness() -> None:
    """PROVENANCE-INTEGRITY-001 and VAULT-VERIFY-CONTRACT-001 must have lower order than final readiness."""
    state = _load_ceremony_state()
    prereqs = {p["id"]: p["order"] for p in state.get("third_ceremony_prerequisites", [])}
    assert "PROVENANCE-INTEGRITY-001" in prereqs
    assert "VAULT-VERIFY-CONTRACT-001" in prereqs
    assert "CUSTOMER-ZERO-FINAL-READINESS-001" in prereqs
    final_order = prereqs["CUSTOMER-ZERO-FINAL-READINESS-001"]
    assert prereqs["PROVENANCE-INTEGRITY-001"] < final_order
    assert prereqs["VAULT-VERIFY-CONTRACT-001"] < final_order


# ---------------------------------------------------------------------------
# H. Persistent AWS audit authority represented as preserved
# ---------------------------------------------------------------------------


def test_h1_aws_audit_lifecycle_status_is_preserved() -> None:
    """aws_audit_lifecycle_status must be AWS_AUDIT_PRESERVED."""
    state = _load_ceremony_state()
    assert state["aws_audit_lifecycle_status"] == "AWS_AUDIT_PRESERVED"


def test_h2_exactly_four_aws_core_resources_preserved() -> None:
    """Exactly four AWS core audit resources must be listed as preserved."""
    state = _load_ceremony_state()
    preserved = state["cost_containment"]["preserved_aws_resources"]
    assert len(preserved) == 4, f"Expected 4 preserved AWS resources, got {len(preserved)}"


def test_h3_all_preserved_resources_are_active() -> None:
    """All four preserved AWS audit resources must have status ACTIVE."""
    state = _load_ceremony_state()
    for resource in state["cost_containment"]["preserved_aws_resources"]:
        assert resource["status"] == "ACTIVE", (
            f"{resource['address']} has status {resource['status']!r}, expected ACTIVE"
        )


def test_h4_all_preserved_resources_are_persistent_audit_authority() -> None:
    """All four preserved AWS audit resources must have lifecycle PERSISTENT_AUDIT_AUTHORITY."""
    state = _load_ceremony_state()
    for resource in state["cost_containment"]["preserved_aws_resources"]:
        assert resource["lifecycle"] == "PERSISTENT_AUDIT_AUTHORITY", (
            f"{resource['address']} lifecycle is {resource['lifecycle']!r}, "
            "expected PERSISTENT_AUDIT_AUTHORITY"
        )


def test_h5_expected_aws_resource_addresses_are_present() -> None:
    """The four canonical AWS audit resource addresses must be present."""
    state = _load_ceremony_state()
    addresses = {r["address"] for r in state["cost_containment"]["preserved_aws_resources"]}
    expected = {
        "aws_cloudwatch_log_group.vault_audit",
        "aws_iam_policy.vault_audit",
        "aws_iam_user.vault_audit",
        "aws_iam_user_policy_attachment.vault_audit",
    }
    assert expected == addresses, f"Preserved addresses mismatch: expected {expected}, got {addresses}"


# ---------------------------------------------------------------------------
# I. No teardown completion state authorizes deletion of AWS audit resources
# ---------------------------------------------------------------------------


def test_i1_teardown_script_excludes_aws_core_resources() -> None:
    """The teardown script AWS_CORE set must include the four preserved resources."""
    import importlib.util

    script = REPO / "infra/scripts/customer_zero_teardown.py"
    spec = importlib.util.spec_from_file_location("customer_zero_teardown", script)
    assert spec is not None and spec.loader is not None
    teardown = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(teardown)

    # The four preserved resources must be in AWS_CORE
    required = {
        "aws_cloudwatch_log_group.vault_audit",
        "aws_iam_policy.vault_audit",
        "aws_iam_user.vault_audit",
        "aws_iam_user_policy_attachment.vault_audit",
    }
    missing = required - teardown.AWS_CORE
    assert not missing, (
        f"These AWS audit resources are missing from teardown.AWS_CORE: {missing}. "
        "The teardown script must never target these resources."
    )


def test_i2_teardown_targets_do_not_overlap_aws_core() -> None:
    """No teardown stage target may include any AWS_CORE resource address."""
    import importlib.util

    script = REPO / "infra/scripts/customer_zero_teardown.py"
    spec = importlib.util.spec_from_file_location("customer_zero_teardown", script)
    assert spec is not None and spec.loader is not None
    teardown = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(teardown)

    for stage, targets in teardown.TARGETS.items():
        overlap = teardown.AWS_CORE & targets
        assert not overlap, (
            f"Stage {stage!r} targets {overlap} which are in AWS_CORE — "
            "teardown stages must never destroy the persistent AWS audit boundary."
        )


def test_i3_preservation_invariant_prohibits_audit_resource_deletion() -> None:
    """ceremony_state.yaml preservation_invariant must prohibit deleting audit resources."""
    state = _load_ceremony_state()
    invariant = state["cost_containment"]["preservation_invariant"]
    invariant_lower = invariant.lower()
    # Must say teardown does not authorize deletion
    assert any(
        phrase in invariant_lower
        for phrase in ("not authorize", "not change", "authorizes deletion", "no teardown")
    ), "preservation_invariant must explicitly prohibit audit resource deletion"


# ---------------------------------------------------------------------------
# J. Machine-readable ceremony status is deterministic
# ---------------------------------------------------------------------------


def test_j1_ceremony_state_has_all_required_status_dimensions() -> None:
    """All six required status dimensions must be present in ceremony_state.yaml."""
    state = _load_ceremony_state()
    required_dimensions = {
        "trust_proof_status",
        "operational_ceremony_status",
        "cost_containment_status",
        "infrastructure_lifecycle_status",
        "aws_audit_lifecycle_status",
        "acceptance_status",
    }
    missing = required_dimensions - set(state.keys())
    assert not missing, f"ceremony_state.yaml missing dimensions: {missing}"


def test_j2_ceremony_state_schema_version_is_present() -> None:
    """schema_version must be present and non-empty."""
    state = _load_ceremony_state()
    assert state.get("schema_version"), "schema_version must be present and non-empty"


def test_j3_ceremony_state_reconciliation_id_is_correct() -> None:
    """reconciliation_id must be CZ-RECONCILE-001."""
    state = _load_ceremony_state()
    assert state.get("reconciliation_id") == "CZ-RECONCILE-001"


def test_j4_ceremony_state_base_sha_is_present_and_hex() -> None:
    """base_sha must be a valid 40-character hex SHA."""
    import re

    state = _load_ceremony_state()
    sha = state.get("base_sha", "")
    assert re.fullmatch(r"[0-9a-f]{40}", sha), (
        f"base_sha must be a 40-character hex SHA; got {sha!r}"
    )


def test_j5_status_values_are_from_known_vocabulary() -> None:
    """All status fields must use known vocabulary constants."""
    state = _load_ceremony_state()
    known_trust = {"NOT_PROVEN", "PROVEN"}
    known_ceremony = {"ATTEMPTED", "NOT_STARTED", "PROVEN"}
    known_containment = {"COMPLETE", "IN_PROGRESS", "NOT_STARTED"}
    known_infra = {"HCP_ABSENT", "HCP_PRESENT"}
    known_aws = {"AWS_AUDIT_PRESERVED", "AWS_AUDIT_ABSENT"}
    known_acceptance = {"BLOCKED", "OPEN", "COMPLETE"}
    known_third = {"NOT_AUTHORIZED", "AUTHORIZED", "COMPLETE"}

    assert state["trust_proof_status"] in known_trust
    assert state["operational_ceremony_status"] in known_ceremony
    assert state["cost_containment_status"] in known_containment
    assert state["infrastructure_lifecycle_status"] in known_infra
    assert state["aws_audit_lifecycle_status"] in known_aws
    assert state["acceptance_status"] in known_acceptance
    assert state["third_paid_ceremony_status"] in known_third


# ---------------------------------------------------------------------------
# K. Existing teardown safety tests — structural check
# ---------------------------------------------------------------------------


def test_k1_teardown_safety_test_file_exists() -> None:
    """tests/test_customer_zero_narrow_cost_teardown.py must exist."""
    teardown_tests = REPO / "tests" / "test_customer_zero_narrow_cost_teardown.py"
    assert teardown_tests.exists(), (
        "tests/test_customer_zero_narrow_cost_teardown.py must exist and not be deleted"
    )


def test_k2_ceremony_readiness_test_file_exists() -> None:
    """tests/test_customer_zero_trust_ceremony_readiness.py must exist."""
    readiness_tests = REPO / "tests" / "test_customer_zero_trust_ceremony_readiness.py"
    assert readiness_tests.exists(), (
        "tests/test_customer_zero_trust_ceremony_readiness.py must exist and not be deleted"
    )


# ---------------------------------------------------------------------------
# L. Roadmap authority checker can locate CZ-RECONCILE-001
# ---------------------------------------------------------------------------


def test_l1_roadmap_checker_authorizes_cz_reconcile_001() -> None:
    """check_customer_one_roadmap.py --work-item CZ-RECONCILE-001 must exit 0."""
    result = subprocess.run(
        [
            "python",
            "tools/ci/check_customer_one_roadmap.py",
            "--work-item",
            "CZ-RECONCILE-001",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Roadmap checker rejected CZ-RECONCILE-001: {result.stderr}"
    )
    assert "AUTHORIZED" in result.stdout


def test_l2_roadmap_checker_authorizes_provenance_integrity_001() -> None:
    """check_customer_one_roadmap.py --work-item PROVENANCE-INTEGRITY-001 must exit 0."""
    result = subprocess.run(
        [
            "python",
            "tools/ci/check_customer_one_roadmap.py",
            "--work-item",
            "PROVENANCE-INTEGRITY-001",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Roadmap checker rejected PROVENANCE-INTEGRITY-001: {result.stderr}"
    )


def test_l3_roadmap_checker_authorizes_vault_verify_contract_001() -> None:
    """check_customer_one_roadmap.py --work-item VAULT-VERIFY-CONTRACT-001 must exit 0."""
    result = subprocess.run(
        [
            "python",
            "tools/ci/check_customer_one_roadmap.py",
            "--work-item",
            "VAULT-VERIFY-CONTRACT-001",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Roadmap checker rejected VAULT-VERIFY-CONTRACT-001: {result.stderr}"
    )


def test_l4_roadmap_checker_authorizes_final_readiness_001() -> None:
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
    )
    assert result.returncode == 0, (
        f"Roadmap checker rejected CUSTOMER-ZERO-FINAL-READINESS-001: {result.stderr}"
    )


def test_l5_roadmap_checker_blocks_trust_003() -> None:
    """check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-TRUST-003 must exit 1 (blocked)."""
    result = subprocess.run(
        [
            "python",
            "tools/ci/check_customer_one_roadmap.py",
            "--work-item",
            "CUSTOMER-ZERO-TRUST-003",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, (
        f"Roadmap checker must block CUSTOMER-ZERO-TRUST-003; "
        f"got rc={result.returncode}, stdout={result.stdout!r}"
    )


def test_l6_roadmap_checker_blocks_accept_001() -> None:
    """check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-ACCEPT-001 must exit 1 (blocked)."""
    result = subprocess.run(
        [
            "python",
            "tools/ci/check_customer_one_roadmap.py",
            "--work-item",
            "CUSTOMER-ZERO-ACCEPT-001",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, (
        f"Roadmap checker must block CUSTOMER-ZERO-ACCEPT-001; "
        f"got rc={result.returncode}, stdout={result.stdout!r}"
    )


# ---------------------------------------------------------------------------
# M. No live infrastructure requirements
# ---------------------------------------------------------------------------


def test_m1_ceremony_state_requires_no_live_infrastructure() -> None:
    """All third_ceremony_prerequisites must declare requires_paid_infrastructure: false."""
    state = _load_ceremony_state()
    for prereq in state.get("third_ceremony_prerequisites", []):
        assert prereq.get("requires_paid_infrastructure") is False, (
            f"Prerequisite {prereq['id']!r} must declare requires_paid_infrastructure: false"
        )


def test_m2_provenance_and_verifier_items_require_no_paid_infra() -> None:
    """PROVENANCE-INTEGRITY-001 and VAULT-VERIFY-CONTRACT-001 must not require paid infrastructure."""
    authority = _load_roadmap_authority()
    for item_id in ("PROVENANCE-INTEGRITY-001", "VAULT-VERIFY-CONTRACT-001"):
        item = _find_item(authority, "next_sequence", item_id)
        assert item is not None, f"{item_id} must be in next_sequence"
        assert item.get("requires_paid_infrastructure") is False, (
            f"{item_id} must declare requires_paid_infrastructure: false"
        )


def test_m3_final_readiness_requires_no_paid_infra() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 must not require paid infrastructure."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is not None
    assert item.get("requires_paid_infrastructure") is False


def test_m4_cz_reconcile_itself_requires_no_infrastructure() -> None:
    """This test module itself does not import or call any live infrastructure client."""
    import ast
    import sys

    test_module = sys.modules[__name__]
    source = Path(test_module.__file__).read_text()
    tree = ast.parse(source)

    # Collect all top-level import names
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_names.add(node.module.split(".")[0])

    forbidden_modules = {"boto3", "hvac", "railway"}
    overlap = imported_names & forbidden_modules
    assert not overlap, (
        f"test_cz_reconcile_001.py must not import live infrastructure modules; "
        f"found: {overlap}"
    )
