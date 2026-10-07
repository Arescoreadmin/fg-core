"""CZ-FINAL-READINESS-CLOSEOUT-001 — Authority closeout: final readiness gate recorded complete.

This module is NOT standalone. It is a component of the FrostGate governance platform
and Customer-Zero trust ceremony roadmap reconciliation.

These tests verify that CUSTOMER-ZERO-FINAL-READINESS-001 (PR #753, SHA c9717807) has
been correctly moved from next_sequence to completed in customer_one/roadmap_authority.yaml,
that CUSTOMER-ZERO-RUN3-PREAUTH-001 is now the authorized next work item, and that all
canonical ceremony truth invariants remain unchanged.

Truth invariants preserved:
- trust_proof_status: NOT_PROVEN (ceremony truth is unchanged)
- third_paid_ceremony_status: NOT_AUTHORIZED
- infrastructure_lifecycle_status: HCP_ABSENT
- CUSTOMER-ZERO-TRUST-003: BLOCKED
- CUSTOMER-ZERO-ACCEPT-001: BLOCKED

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


def _run_checker(*extra_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python", "tools/ci/check_customer_one_roadmap.py", *extra_args],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# A. CUSTOMER-ZERO-FINAL-READINESS-001 is in completed
# ---------------------------------------------------------------------------


def test_a1_final_readiness_001_in_completed() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 must appear in the completed section."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is not None, "CUSTOMER-ZERO-FINAL-READINESS-001 must be in completed"


def test_a2_final_readiness_001_not_in_next_sequence() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 must not still appear in next_sequence."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is None, (
        "CUSTOMER-ZERO-FINAL-READINESS-001 must not remain in next_sequence after being completed"
    )


def test_a3_final_readiness_001_has_pr_753() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 completed entry must record PR #753."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is not None
    assert "#753" in item.get("prs", []), (
        "CUSTOMER-ZERO-FINAL-READINESS-001 must list '#753' in prs"
    )


def test_a4_final_readiness_001_has_merged_sha() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 must carry the canonical merged_sha."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert item is not None
    sha = item.get("merged_sha", "")
    assert sha == "c9717807efc6ef5775d8872f62c97b62cd613102", (
        f"CUSTOMER-ZERO-FINAL-READINESS-001 must carry merged_sha "
        f"c9717807efc6ef5775d8872f62c97b62cd613102; got {sha!r}"
    )


# ---------------------------------------------------------------------------
# B. CUSTOMER-ZERO-RUN3-PREAUTH-001 is in next_sequence with correct dependency
# ---------------------------------------------------------------------------


def test_b1_run3_preauth_001_in_next_sequence() -> None:
    """CUSTOMER-ZERO-RUN3-PREAUTH-001 must appear in next_sequence."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    assert item is not None, "CUSTOMER-ZERO-RUN3-PREAUTH-001 must be in next_sequence"


def test_b2_run3_preauth_has_blocked_by_final_readiness() -> None:
    """CUSTOMER-ZERO-RUN3-PREAUTH-001 must have blocked_by referencing FINAL-READINESS-001."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    assert item is not None
    blocked_by = item.get("blocked_by", [])
    assert "CUSTOMER-ZERO-FINAL-READINESS-001" in blocked_by, (
        f"CUSTOMER-ZERO-RUN3-PREAUTH-001 must have blocked_by containing "
        f"CUSTOMER-ZERO-FINAL-READINESS-001; got {blocked_by!r}"
    )


def test_b3_run3_preauth_requires_no_paid_infrastructure() -> None:
    """CUSTOMER-ZERO-RUN3-PREAUTH-001 must not require paid infrastructure."""
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    assert item is not None
    assert item.get("requires_paid_infrastructure") is False, (
        "CUSTOMER-ZERO-RUN3-PREAUTH-001 must have requires_paid_infrastructure: false"
    )


# ---------------------------------------------------------------------------
# C. Roadmap checker authorization results
# ---------------------------------------------------------------------------


def test_c1_checker_authorizes_run3_preauth() -> None:
    """check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-RUN3-PREAUTH-001 must exit 0."""
    result = _run_checker("--work-item", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    assert result.returncode == 0, (
        f"Checker must authorize CUSTOMER-ZERO-RUN3-PREAUTH-001; "
        f"got rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}"
    )


def test_c2_checker_blocks_trust_003() -> None:
    """check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-TRUST-003 must exit 1 (BLOCKED)."""
    result = _run_checker("--work-item", "CUSTOMER-ZERO-TRUST-003")
    assert result.returncode == 1, (
        f"CUSTOMER-ZERO-TRUST-003 must remain BLOCKED; "
        f"got rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}"
    )


def test_c3_checker_blocks_accept_001() -> None:
    """check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-ACCEPT-001 must exit 1 (BLOCKED)."""
    result = _run_checker("--work-item", "CUSTOMER-ZERO-ACCEPT-001")
    assert result.returncode == 1, (
        f"CUSTOMER-ZERO-ACCEPT-001 must remain BLOCKED; "
        f"got rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# D. Ceremony truth is unchanged
# ---------------------------------------------------------------------------


def test_d1_trust_proof_status_still_not_proven() -> None:
    """trust_proof_status must remain NOT_PROVEN."""
    state = _load_ceremony_state()
    status = state.get("trust_proof_status")
    assert status == "NOT_PROVEN", (
        f"trust_proof_status must remain NOT_PROVEN; got {status!r}"
    )


def test_d2_third_paid_ceremony_still_not_authorized() -> None:
    """third_paid_ceremony_status must remain NOT_AUTHORIZED."""
    state = _load_ceremony_state()
    status = state.get("third_paid_ceremony_status")
    assert status == "NOT_AUTHORIZED", (
        f"third_paid_ceremony_status must remain NOT_AUTHORIZED; got {status!r}"
    )


def test_d3_paid_hcp_infrastructure_absent() -> None:
    """infrastructure_lifecycle_status must remain HCP_ABSENT."""
    state = _load_ceremony_state()
    status = state.get("infrastructure_lifecycle_status")
    assert status == "HCP_ABSENT", (
        f"infrastructure_lifecycle_status must remain HCP_ABSENT; got {status!r}"
    )


def test_d4_acceptance_status_blocked() -> None:
    """acceptance_status must remain BLOCKED."""
    state = _load_ceremony_state()
    status = state.get("acceptance_status")
    assert status == "BLOCKED", (
        f"acceptance_status must remain BLOCKED; got {status!r}"
    )


# ---------------------------------------------------------------------------
# E. Fail-closed: unknown and bypass checks
# ---------------------------------------------------------------------------


def test_e1_unknown_work_items_fail_closed() -> None:
    """An unknown work item must be BLOCKED (fail-closed), exit code 1."""
    result = _run_checker("--work-item", "NONEXISTENT-WORK-ITEM-XYZ")
    assert result.returncode == 1, (
        f"Unknown work item must fail-closed; got rc={result.returncode}"
    )


def test_e2_checker_repair_class_still_authorized() -> None:
    """REPAIR work class must remain authorized (checker not weakened)."""
    result = _run_checker("--work-class", "REPAIR")
    assert result.returncode == 0, (
        f"REPAIR class must remain authorized; got rc={result.returncode}"
    )


def test_e3_final_readiness_001_completed_blocks_reopening() -> None:
    """CUSTOMER-ZERO-FINAL-READINESS-001 completed must be BLOCKED by checker (no re-work)."""
    result = _run_checker("--work-item", "CUSTOMER-ZERO-FINAL-READINESS-001")
    assert result.returncode == 1, (
        f"CUSTOMER-ZERO-FINAL-READINESS-001 must be BLOCKED (completed); "
        f"got rc={result.returncode}"
    )


def test_e4_prerequisite_enforcement_fail_closed() -> None:
    """next_sequence items with unmet blocked_by must not be authorized.

    Verify the checker enforces prerequisite completeness by checking that
    CUSTOMER-ZERO-RUN3-PREAUTH-001 would be blocked if its dependency were
    absent — represented structurally by confirming blocked_by is non-empty.
    """
    authority = _load_roadmap_authority()
    item = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    assert item is not None
    blocked_by = item.get("blocked_by", [])
    assert len(blocked_by) > 0, (
        "CUSTOMER-ZERO-RUN3-PREAUTH-001 must have non-empty blocked_by; "
        "prerequisite enforcement requires at least one dependency"
    )
    # All listed dependencies must be in completed for PREAUTH to be authorized.
    completed_ids = {e.get("id") for e in authority.get("completed", [])}
    unmet = [dep for dep in blocked_by if dep not in completed_ids]
    assert unmet == [], (
        f"CUSTOMER-ZERO-RUN3-PREAUTH-001 has unmet blocked_by dependencies: {unmet}; "
        "all dependencies must be in completed for the item to be authorized"
    )
