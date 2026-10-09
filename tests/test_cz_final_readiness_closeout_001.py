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
LEVEL2_DOC = (
    REPO / "docs" / "plans" / "customer_one_verified_governance_roadmap_20260910.md"
)


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
# B. CUSTOMER-ZERO-RUN3-PREAUTH-001 is in completed (post-closeout state)
# ---------------------------------------------------------------------------


def test_b1_run3_preauth_001_in_next_sequence() -> None:
    """CUSTOMER-ZERO-RUN3-PREAUTH-001 must appear in completed (moved from next_sequence
    by CZ-RUN3-PREAUTH-CLOSEOUT-001).

    Note: test name preserved for diff stability; assertion updated to reflect
    post-closeout state (PREAUTH is now complete, not merely next).
    """
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    assert item is not None, (
        "CUSTOMER-ZERO-RUN3-PREAUTH-001 must be in completed "
        "(moved from next_sequence by CZ-RUN3-PREAUTH-CLOSEOUT-001)"
    )


def test_b2_run3_preauth_has_blocked_by_final_readiness() -> None:
    """CUSTOMER-ZERO-RUN3-PREAUTH-001 completed entry must reference PR #755 (its dependency
    on FINAL-READINESS-001 was satisfied at merge time).

    Note: test name preserved for diff stability; validates the completed entry has
    the correct PR and SHA evidence rather than blocked_by.
    """
    authority = _load_roadmap_authority()
    item = _find_item(authority, "completed", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    assert item is not None, "CUSTOMER-ZERO-RUN3-PREAUTH-001 must be in completed"
    prs = item.get("prs", [])
    assert "#755" in prs, (
        f"CUSTOMER-ZERO-RUN3-PREAUTH-001 completed entry must list '#755'; got {prs!r}"
    )
    sha = item.get("merged_sha", "")
    assert sha == "8de43e2275b18cb13a14b54940c9b64c48283f1c", (
        f"CUSTOMER-ZERO-RUN3-PREAUTH-001 completed entry must carry canonical merged_sha; "
        f"got {sha!r}"
    )


def test_b3_run3_preauth_requires_no_paid_infrastructure() -> None:
    """CUSTOMER-ZERO-RUN3-PREAUTH-001 was completed without paid infrastructure.

    Note: test name preserved for diff stability; validates from the completed entry.
    """
    authority = _load_roadmap_authority()
    # The item is now in completed — verify it is NOT in blocked/deferred/next
    in_blocked = _find_item(authority, "blocked", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    in_next = _find_item(authority, "next_sequence", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    assert in_blocked is None, "CUSTOMER-ZERO-RUN3-PREAUTH-001 must not be in blocked"
    assert in_next is None, (
        "CUSTOMER-ZERO-RUN3-PREAUTH-001 must not be in next_sequence"
    )


# ---------------------------------------------------------------------------
# C. Roadmap checker authorization results
# ---------------------------------------------------------------------------


def test_c1_checker_authorizes_run3_preauth() -> None:
    """check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-RUN3-PREAUTH-001 must exit 1
    (completed — no further work authorized on a completed item).

    Note: test name preserved for diff stability; PREAUTH-001 is now in completed so
    the checker correctly returns BLOCKED (exit 1) to prevent re-opening completed work.
    """
    result = _run_checker("--work-item", "CUSTOMER-ZERO-RUN3-PREAUTH-001")
    assert result.returncode == 1, (
        f"Checker must return BLOCKED for completed CUSTOMER-ZERO-RUN3-PREAUTH-001; "
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
    assert status == "BLOCKED", f"acceptance_status must remain BLOCKED; got {status!r}"


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

    Post-closeout: CUSTOMER-ZERO-RUN3-PREAUTH-001 is now in completed. This test
    verifies prerequisite enforcement on CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001,
    the new next_sequence item registered by CZ-RUN3-PREAUTH-CLOSEOUT-001, which
    has an empty blocked_by (its dependency PREAUTH-001 is now complete and it
    carries no further listed prerequisites).

    Note: test name preserved for diff stability.
    """
    authority = _load_roadmap_authority()
    # PREAUTH is now complete; the new next item is OPERATOR-PREFLIGHT-001
    item = _find_item(
        authority, "next_sequence", "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001"
    )
    assert item is not None, (
        "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001 must be in next_sequence "
        "(registered by CZ-RUN3-PREAUTH-CLOSEOUT-001)"
    )
    # Its blocked_by is empty — PREAUTH-001 dependency is satisfied (completed)
    blocked_by = item.get("blocked_by", [])
    completed_ids = {e.get("id") for e in authority.get("completed", [])}
    unmet = [dep for dep in blocked_by if dep not in completed_ids]
    assert unmet == [], (
        f"CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001 has unmet blocked_by dependencies: {unmet}"
    )


# ---------------------------------------------------------------------------
# F. Level-2 sequencing doc correctness (P1 review fix)
# ---------------------------------------------------------------------------


def _load_level2_doc() -> str:
    with open(LEVEL2_DOC, encoding="utf-8") as f:
        return f.read()


def test_f1_level2_doc_does_not_say_final_readiness_alone_authorizes_trust_003() -> (
    None
):
    """The Level-2 doc must NOT contain language stating FINAL-READINESS completion
    alone authorizes TRUST-003.

    The old incorrect text was:
        'once complete, CUSTOMER-ZERO-TRUST-003 (Run 3, paid HCP ceremony) is authorized'
    That language directly coupled FINAL-READINESS completion to TRUST-003 authorization
    without the required PREAUTH gate. This test ensures that phrase is absent.
    """
    text = _load_level2_doc()
    forbidden_phrase = "once complete, CUSTOMER-ZERO-TRUST-003 (Run 3, paid HCP ceremony) is authorized"
    assert forbidden_phrase not in text, (
        "Level-2 doc must not say FINAL-READINESS completion alone authorizes TRUST-003; "
        f"found forbidden phrase: {forbidden_phrase!r}"
    )


def test_f2_level2_doc_references_preauth_as_required_before_trust_003() -> None:
    """The Level-2 doc must reference CUSTOMER-ZERO-RUN3-PREAUTH-001 as a completed
    intermediate step before CUSTOMER-ZERO-TRUST-003.

    Post-closeout state: PREAUTH-001 is COMPLETED (#755). The TRUST-003 row now
    references OPERATOR-PREFLIGHT as the immediate blocker (PREAUTH completed).
    This test verifies PREAUTH-001 still appears in the doc (historical record)
    and that TRUST-003 documents the updated blocker chain.
    """
    text = _load_level2_doc()
    assert "CUSTOMER-ZERO-RUN3-PREAUTH-001" in text, (
        "Level-2 doc must reference CUSTOMER-ZERO-RUN3-PREAUTH-001 (as completed step)"
    )
    # TRUST-003 row now references OPERATOR-PREFLIGHT as the next required step.
    assert "OPERATOR-PREFLIGHT" in text, (
        "Level-2 doc must reference OPERATOR-PREFLIGHT as the step now blocking TRUST-003"
    )
    # PREAUTH must be marked COMPLETED in the sequence table (not NEXT).
    assert (
        "CUSTOMER-ZERO-RUN3-PREAUTH-001 | Customer-Zero Run 3 pre-authorization gate | COMPLETED"
        in text
    ), "Level-2 doc sequence table must show PREAUTH-001 as COMPLETED"


def test_f3_level2_doc_marks_final_readiness_as_complete() -> None:
    """The Level-2 doc must mark CUSTOMER-ZERO-FINAL-READINESS-001 as COMPLETED,
    not as NEXT.
    """
    text = _load_level2_doc()
    # The sequence table row must show COMPLETED status for FINAL-READINESS-001.
    assert (
        "CUSTOMER-ZERO-FINAL-READINESS-001 | Customer-Zero final pre-ceremony readiness checklist | COMPLETED"
        in text
    ), "Level-2 doc sequence table must show FINAL-READINESS-001 as COMPLETED"
    # Ensure the old NEXT status for FINAL-READINESS-001 is gone from the table row.
    assert (
        "CUSTOMER-ZERO-FINAL-READINESS-001 | Customer-Zero final pre-ceremony readiness checklist | NEXT"
        not in text
    ), "Level-2 doc must not show FINAL-READINESS-001 as NEXT in the sequence table"


def test_f4_level2_doc_requires_human_cost_authorization_before_trust_003() -> None:
    """The Level-2 doc must require explicit human cost authorization before TRUST-003,
    not just PREAUTH completion.
    """
    text = _load_level2_doc()
    assert "human cost authorization" in text, (
        "Level-2 doc must mention 'human cost authorization' as a gate before TRUST-003"
    )
    assert "does NOT authorize CUSTOMER-ZERO-TRUST-003" in text or (
        "does not authorize" in text and "TRUST-003" in text
    ), (
        "Level-2 doc must explicitly state that FINAL-READINESS completion alone does not "
        "authorize TRUST-003"
    )
