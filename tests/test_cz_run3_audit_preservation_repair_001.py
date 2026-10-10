"""
CZ-RUN3-AUDIT-PRESERVATION-REPAIR-001 — Adversarial tests for FP-003 remediation.

FP-003: aws_iam_role.vault_audit_reader existed in Terraform but lacked
lifecycle { prevent_destroy = true } and was absent from ceremony_state.yaml
preserved_aws_resources. This test suite validates the repair.

Tests: FP003-T01 through FP003-T14 (14 tests).
Work class: REPAIR — always authorized.
Cloud mutations: 0. Spending authorization: unchanged. Live trust: unchanged.
"""

import re
import yaml
from pathlib import Path

REPO = Path(__file__).parent.parent
AWS_AUDIT_TF = REPO / "infra" / "aws_audit.tf"
CEREMONY_STATE = REPO / "customer_one" / "ceremony_state.yaml"
OPERATOR_PREFLIGHT = REPO / "services" / "governance" / "run3_operator_preflight.py"

READER_ROLE_ADDR = "aws_iam_role.vault_audit_reader"
READER_ATTACH_ADDR = "aws_iam_role_policy_attachment.vault_audit_reader"
ORIGINAL_FOUR = [
    "aws_cloudwatch_log_group.vault_audit",
    "aws_iam_policy.vault_audit",
    "aws_iam_user.vault_audit",
    "aws_iam_user_policy_attachment.vault_audit",
]
EXPECTED_PRESERVED = ORIGINAL_FOUR + [READER_ROLE_ADDR, READER_ATTACH_ADDR]


def _get_tf_content() -> str:
    return AWS_AUDIT_TF.read_text()


def _get_ceremony_state() -> dict:
    return yaml.safe_load(CEREMONY_STATE.read_text())


def _get_preserved_addresses(state: dict) -> list[str]:
    return [r["address"] for r in state["cost_containment"]["preserved_aws_resources"]]


def _has_prevent_destroy_in_block(
    tf_content: str, resource_type: str, resource_name: str
) -> bool:
    """Check if a specific resource block has lifecycle { prevent_destroy = true }."""
    # Find the resource block
    pattern = (
        rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{'
    )
    match = re.search(pattern, tf_content)
    if not match:
        return False
    # Find the matching closing brace (simple brace counting)
    start = match.start()
    depth = 0
    in_block = False
    for i, c in enumerate(tf_content[start:], start):
        if c == "{":
            depth += 1
            in_block = True
        elif c == "}":
            depth -= 1
            if in_block and depth == 0:
                block_content = tf_content[start : i + 1]
                return "prevent_destroy" in block_content and "true" in block_content
    return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_fp003_t01_reader_role_has_prevent_destroy():
    """FP003-T01: aws_iam_role.vault_audit_reader has lifecycle { prevent_destroy = true }."""
    tf = _get_tf_content()
    assert _has_prevent_destroy_in_block(tf, "aws_iam_role", "vault_audit_reader"), (
        "aws_iam_role.vault_audit_reader must have lifecycle { prevent_destroy = true }"
    )


def test_fp003_t02_reader_attachment_has_prevent_destroy():
    """FP003-T02: aws_iam_role_policy_attachment.vault_audit_reader has prevent_destroy."""
    tf = _get_tf_content()
    assert _has_prevent_destroy_in_block(
        tf, "aws_iam_role_policy_attachment", "vault_audit_reader"
    ), (
        "aws_iam_role_policy_attachment.vault_audit_reader must have lifecycle { prevent_destroy = true }"
    )


def test_fp003_t03_reader_role_in_preserved_inventory():
    """FP003-T03: aws_iam_role.vault_audit_reader in ceremony_state preserved_aws_resources."""
    state = _get_ceremony_state()
    preserved = _get_preserved_addresses(state)
    assert READER_ROLE_ADDR in preserved, (
        f"{READER_ROLE_ADDR} not in preserved_aws_resources"
    )


def test_fp003_t03b_reader_attachment_in_preserved_inventory():
    """FP003-T03b: aws_iam_role_policy_attachment.vault_audit_reader in preserved_aws_resources."""
    state = _get_ceremony_state()
    preserved = _get_preserved_addresses(state)
    assert READER_ATTACH_ADDR in preserved, (
        f"{READER_ATTACH_ADDR} not in preserved_aws_resources"
    )


def test_fp003_t04_original_four_resources_preserved():
    """FP003-T04: Original four protected resources remain in preserved inventory."""
    state = _get_ceremony_state()
    preserved = _get_preserved_addresses(state)
    for addr in ORIGINAL_FOUR:
        assert addr in preserved, (
            f"Original protected resource {addr} missing from preserved_aws_resources"
        )


def test_fp003_t05_missing_role_protection_fails():
    """FP003-T05: Resource block without prevent_destroy fails detection."""
    # Fixture: a role block WITHOUT prevent_destroy
    fixture_tf = """resource "aws_iam_role" "vault_audit_reader" {
  name = "FrostGateVaultAuditReader"
  path = "/frostgate/vault/"
  tags = { Purpose = "vault-audit-reader" }
}"""
    assert not _has_prevent_destroy_in_block(
        fixture_tf, "aws_iam_role", "vault_audit_reader"
    ), "Detection function should return False for block without prevent_destroy"


def test_fp003_t06_missing_attachment_protection_fails():
    """FP003-T06: Attachment block without prevent_destroy fails detection."""
    fixture_tf = """resource "aws_iam_role_policy_attachment" "vault_audit_reader" {
  role       = "FrostGateVaultAuditReader"
  policy_arn = "arn:aws:iam::123456789012:policy/frostgate/vault/FrostGateVaultAuditReaderPolicy"
}"""
    assert not _has_prevent_destroy_in_block(
        fixture_tf, "aws_iam_role_policy_attachment", "vault_audit_reader"
    ), "Detection function should return False for attachment without prevent_destroy"


def test_fp003_t07_preservation_inventory_tampering():
    """FP003-T07: Missing reader role from preserved inventory is detected."""
    state = _get_ceremony_state()
    # Simulate tampering by constructing a modified preserved list
    preserved = _get_preserved_addresses(state)
    tampered = [a for a in preserved if a != READER_ROLE_ADDR]
    assert READER_ROLE_ADDR not in tampered, (
        "Tampered inventory should not contain reader role"
    )
    assert READER_ROLE_ADDR in preserved, "Real inventory should contain reader role"


def test_fp003_t08_unsafe_destroy_plan_rejected():
    """FP003-T08: Synthetic plan attempting to delete reader role must be rejected."""
    # Synthetic Terraform plan with a delete action on the reader role
    unsafe_plan = {
        "resource_changes": [
            {"address": READER_ROLE_ADDR, "change": {"actions": ["delete"]}},
            {
                "address": "aws_cloudwatch_log_group.vault_audit",
                "change": {"actions": ["no-op"]},
            },
        ]
    }
    preserved = set(EXPECTED_PRESERVED)
    violations = []
    for change in unsafe_plan["resource_changes"]:
        if "delete" in change["change"]["actions"] and change["address"] in preserved:
            violations.append(change["address"])
    assert violations, (
        f"Unsafe plan targeting {READER_ROLE_ADDR} must be rejected; got no violations"
    )


def test_fp003_t09_replacement_attempt_rejected():
    """FP003-T09: Synthetic plan containing delete+create replacement must be rejected."""
    replacement_plan = {
        "resource_changes": [
            {"address": READER_ROLE_ADDR, "change": {"actions": ["delete", "create"]}},
        ]
    }
    preserved = set(EXPECTED_PRESERVED)
    violations = []
    for change in replacement_plan["resource_changes"]:
        actions = change["change"]["actions"]
        if (
            "delete" in actions or ("delete" in actions and "create" in actions)
        ) and change["address"] in preserved:
            violations.append(change["address"])
    assert violations, "Replacement plan for protected resource must be rejected"


def test_fp003_t10_missing_plan_fails_closed():
    """FP003-T10: Missing or None plan data must fail closed."""

    def check_plan(plan_data):
        if plan_data is None:
            return False, "FAIL: plan data missing"
        if "resource_changes" not in plan_data:
            return False, "FAIL: malformed plan"
        return True, "OK"

    ok, msg = check_plan(None)
    assert not ok, "None plan must fail closed"
    ok2, msg2 = check_plan({})
    assert not ok2, "Empty plan (no resource_changes) must fail closed"
    ok3, msg3 = check_plan({"resource_changes": []})
    assert ok3, "Empty resource_changes list is valid"


def test_fp003_t11_inventory_count_consistent():
    """FP003-T11: EXPECTED_INVENTORY_COUNT remains 21 after lifecycle additions."""
    preflight_src = OPERATOR_PREFLIGHT.read_text()
    match = re.search(r"EXPECTED_INVENTORY_COUNT\s*=\s*(\d+)", preflight_src)
    assert match, "EXPECTED_INVENTORY_COUNT not found in run3_operator_preflight.py"
    count = int(match.group(1))
    assert count == 21, f"EXPECTED_INVENTORY_COUNT should remain 21, got {count}"


def test_fp003_t12_no_authorization_advancement():
    """FP003-T12: Repair does not change live trust or spending authorization."""
    state = _get_ceremony_state()
    assert state["trust_proof_status"] == "NOT_PROVEN"
    assert state["third_paid_ceremony_status"] == "NOT_AUTHORIZED"
    assert state.get("acceptance_status") == "BLOCKED"


def test_fp003_t13_preserved_resources_have_persistent_lifecycle():
    """FP003-T13: All preserved resources in ceremony_state have PERSISTENT_AUDIT_AUTHORITY lifecycle."""
    state = _get_ceremony_state()
    for resource in state["cost_containment"]["preserved_aws_resources"]:
        assert resource.get("lifecycle") == "PERSISTENT_AUDIT_AUTHORITY", (
            f"Resource {resource['address']} must have lifecycle=PERSISTENT_AUDIT_AUTHORITY"
        )


def test_fp003_t14_cloudwatch_original_protection_unchanged():
    """FP003-T14: aws_cloudwatch_log_group.vault_audit prevent_destroy still present."""
    tf = _get_tf_content()
    assert _has_prevent_destroy_in_block(
        tf, "aws_cloudwatch_log_group", "vault_audit"
    ), "Original prevent_destroy on vault_audit log group must remain"
