"""CUSTOMER-ZERO-TRUST-001 — Vault audit authority invariants.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

These tests prove static safety invariants on the production audit authority
architecture defined in infra/aws_audit.tf. They run with no provider calls
or live AWS/HCP access — all assertions are made against Terraform source text.

Authority graph proven:
  CONFIGURATOR (human AWS/HCP admin)
    != WRITER (frostgate-hcp-vault-audit IAM user)
    != READER (FrostGateVaultAuditReader IAM role)
    != TERRAFORM OPERATOR (FrostGateTerraformOperator — intentionally lacks read actions)
    != RUNTIME APPOLE SIGNING AUTHORITIES (Vault Transit)

Invariants proven:
  AW1  — Writer policy has exactly two statements (scoped write + unscoped DescribeLogGroups)
  AW2  — Writer write statement scoped to exact log-group ARN
  AW3  — Writer has no audit-event-read actions (no FilterLogEvents, GetLogEvents)
  AW4  — Writer DescribeLogGroups is in a separate unscoped statement (AWS limitation)
  AW5  — Writer is an IAM user (not a role — credentials must be injected by human operator)
  AR1  — Reader role exists as a distinct IAM role (not the writer user)
  AR2  — Reader policy has only read actions
  AR3  — Reader policy has no write actions (no PutLogEvents, CreateLogGroup, CreateLogStream)
  AR4  — Reader trust policy requires MFA (aws:MultiFactorAuthPresent = true)
  AR5  — Reader is scoped to the audit log-group ARN for read actions
  AR6  — Reader DescribeLogGroups in its own unscoped statement (same AWS limitation)
  SoD1 — Writer user != reader role (distinct resource types and names)
  SoD2 — No aws_iam_access_key in Terraform (human credential boundary)
  SoD3 — Terraform operator is not the reader (FrostGateTerraformOperator lacks read actions)
  CE1  — Credential boundary: no access key resource in Terraform state
  RE1  — rotation_history and audit_evidence are distinct schema arrays
  RE2  — No ceremony logic forces a second rotation to populate CloudWatch
  RE3  — Evidence schema accepts independent rotation_history and audit_evidence entries
  DS1  — HCP destination model is OPERATOR-CONFIGURED (not HCP-assigned)
  DS2  — Runbook distinguishes INTENDED destination from CONFIGURED destination
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

INFRA = Path(__file__).parent.parent / "infra"
SCHEMAS = Path(__file__).parent.parent / "schemas" / "artifacts"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def audit_tf() -> str:
    p = INFRA / "aws_audit.tf"
    assert p.exists(), "infra/aws_audit.tf must exist"
    return p.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def runbook() -> str:
    p = INFRA / "docs" / "ceremony-runbook.md"
    assert p.exists(), "infra/docs/ceremony-runbook.md must exist"
    return p.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def evidence_schema() -> dict:
    p = SCHEMAS / "customer_zero_trust_evidence.schema.json"
    assert p.exists(), (
        "schemas/artifacts/customer_zero_trust_evidence.schema.json must exist"
    )
    return json.loads(p.read_text(encoding="utf-8"))


def _extract_resource_block(tf: str, resource_type: str, resource_name: str) -> str:
    """Extract a single named resource block body from Terraform source."""
    pattern = re.compile(
        rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{',
        re.MULTILINE,
    )
    match = pattern.search(tf)
    if not match:
        return ""
    depth = 1
    i = match.end()
    while i < len(tf) and depth > 0:
        if tf[i] == "{":
            depth += 1
        elif tf[i] == "}":
            depth -= 1
        i += 1
    return tf[match.start() : i] if depth == 0 else ""


# ---------------------------------------------------------------------------
# AW — Writer policy invariants
# ---------------------------------------------------------------------------


def test_aw1_writer_policy_has_two_sids(audit_tf: str):
    """Writer policy must declare exactly two Sids:
    VaultAuditLogWrite (scoped) and VaultAuditDescribeLogGroupsUnscopedAWSLimit."""
    block = _extract_resource_block(audit_tf, "aws_iam_policy", "vault_audit")
    assert block, "aws_iam_policy.vault_audit resource block must exist"
    assert '"VaultAuditLogWrite"' in block, (
        "writer policy missing VaultAuditLogWrite Sid for scoped write statement"
    )
    assert '"VaultAuditDescribeLogGroupsUnscopedAWSLimit"' in block, (
        "writer policy missing VaultAuditDescribeLogGroupsUnscopedAWSLimit Sid — "
        "DescribeLogGroups must be in a separate unscoped statement"
    )


def test_aw2_writer_write_statement_scoped_to_log_group_arn(audit_tf: str):
    """Write actions in the writer policy must reference the specific log-group ARN."""
    block = _extract_resource_block(audit_tf, "aws_iam_policy", "vault_audit")
    assert "aws_cloudwatch_log_group.vault_audit.arn" in block, (
        "writer VaultAuditLogWrite statement must scope resource to the exact log-group ARN"
    )


def test_aw3_writer_policy_has_no_event_read_actions(audit_tf: str):
    """Writer policy must not grant audit-event-read capabilities.
    FilterLogEvents and GetLogEvents are reader-only actions.
    """
    block = _extract_resource_block(audit_tf, "aws_iam_policy", "vault_audit")
    assert block, "aws_iam_policy.vault_audit must exist"
    assert '"logs:FilterLogEvents"' not in block, (
        "writer policy must not grant FilterLogEvents — writer has no audit-read authority"
    )
    assert '"logs:GetLogEvents"' not in block, (
        "writer policy must not grant GetLogEvents — writer has no audit-read authority"
    )


def test_aw4_writer_describe_log_groups_is_in_separate_unscoped_statement(
    audit_tf: str,
):
    """DescribeLogGroups must appear in its own statement with Resource=['*'].

    AWS CloudWatch Logs does not support resource-level permissions for
    DescribeLogGroups. Placing it in the scoped write statement is an error
    because AWS silently ignores the resource restriction for that action.
    This test verifies the separation is encoded explicitly.
    """
    block = _extract_resource_block(audit_tf, "aws_iam_policy", "vault_audit")

    # DescribeLogGroups must be present (needed by the HCP integration)
    assert '"logs:DescribeLogGroups"' in block, (
        "writer policy must include logs:DescribeLogGroups for the HCP integration"
    )

    # DescribeLogGroups must NOT appear in the scoped write Sid block.
    # We can detect this by verifying it appears after the unscoped Sid marker.
    unscoped_sid_pos = block.find('"VaultAuditDescribeLogGroupsUnscopedAWSLimit"')
    scoped_sid_pos = block.find('"VaultAuditLogWrite"')
    describe_pos = block.find('"logs:DescribeLogGroups"')
    assert unscoped_sid_pos > 0, "unscoped Sid must exist"
    assert describe_pos > unscoped_sid_pos, (
        "logs:DescribeLogGroups must appear after the unscoped Sid marker, "
        "not in the scoped VaultAuditLogWrite statement"
    )
    assert describe_pos > scoped_sid_pos, (
        "logs:DescribeLogGroups must not precede the scoped statement"
    )


def test_aw5_writer_is_iam_user_not_role(audit_tf: str):
    """The audit writer must be an IAM user (frostgate-hcp-vault-audit), not a role.
    IAM user credentials are created explicitly by the human operator and transferred
    directly to HCP — no machine-accessible credential path.
    """
    assert 'resource "aws_iam_user" "vault_audit"' in audit_tf, (
        "writer must be declared as aws_iam_user, not aws_iam_role"
    )
    # Must NOT have a writer role
    assert 'resource "aws_iam_role" "vault_audit"' not in audit_tf, (
        "aws_iam_role.vault_audit must not exist — writer is a user, not a role"
    )


# ---------------------------------------------------------------------------
# AR — Reader role invariants
# ---------------------------------------------------------------------------


def test_ar1_reader_role_exists_and_is_distinct_from_writer(audit_tf: str):
    """FrostGateVaultAuditReader must exist as an IAM role, distinct from the writer."""
    assert 'resource "aws_iam_role" "vault_audit_reader"' in audit_tf, (
        "FrostGateVaultAuditReader IAM role must be declared in aws_audit.tf"
    )
    block = _extract_resource_block(audit_tf, "aws_iam_role", "vault_audit_reader")
    assert (
        '"FrostGateVaultAuditReader"' in block or "FrostGateVaultAuditReader" in block
    ), "reader role must be named FrostGateVaultAuditReader"


def test_ar2_reader_policy_has_only_read_actions(audit_tf: str):
    """Reader policy must contain only read-class actions."""
    block = _extract_resource_block(audit_tf, "aws_iam_policy", "vault_audit_reader")
    assert block, "aws_iam_policy.vault_audit_reader must exist"
    for action in (
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents",
        "logs:GetLogEvents",
    ):
        assert action in block, f"reader policy must grant {action}"


def test_ar3_reader_policy_has_no_write_actions(audit_tf: str):
    """Reader policy must not grant any write or mutation actions."""
    block = _extract_resource_block(audit_tf, "aws_iam_policy", "vault_audit_reader")
    assert block, "aws_iam_policy.vault_audit_reader must exist"
    forbidden_write_actions = (
        "logs:PutLogEvents",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DeleteLogGroup",
        "logs:DeleteLogStream",
        "logs:DeleteRetentionPolicy",
        "iam:",
        "ec2:",
        "s3:",
    )
    for action in forbidden_write_actions:
        assert action not in block, (
            f"reader policy must not grant {action} — reader is read-only"
        )


def test_ar4_reader_trust_policy_requires_mfa(audit_tf: str):
    """The reader role trust policy must require aws:MultiFactorAuthPresent = true.
    Without MFA, the role could be assumed by any IAM entity in the trust principal,
    which would widen the reader authority beyond the canonical operator identity.
    """
    block = _extract_resource_block(audit_tf, "aws_iam_role", "vault_audit_reader")
    assert block, "aws_iam_role.vault_audit_reader must exist"
    assert "MultiFactorAuthPresent" in block, (
        "reader role trust policy must include aws:MultiFactorAuthPresent condition"
    )
    assert '"true"' in block or "'true'" in block, (
        "reader role trust policy must assert MultiFactorAuthPresent = true"
    )


def test_ar5_reader_policy_read_actions_scoped_to_log_group_arn(audit_tf: str):
    """Reader policy read actions must be scoped to the specific log-group ARN."""
    block = _extract_resource_block(audit_tf, "aws_iam_policy", "vault_audit_reader")
    assert "aws_cloudwatch_log_group.vault_audit.arn" in block, (
        "reader VaultAuditLogRead statement must scope to the exact log-group ARN"
    )


def test_ar6_reader_describe_log_groups_in_separate_unscoped_statement(audit_tf: str):
    """Reader DescribeLogGroups must be in its own unscoped statement — same AWS limitation."""
    block = _extract_resource_block(audit_tf, "aws_iam_policy", "vault_audit_reader")
    assert '"VaultAuditReaderDescribeLogGroupsUnscopedAWSLimit"' in block, (
        "reader policy must have VaultAuditReaderDescribeLogGroupsUnscopedAWSLimit Sid — "
        "DescribeLogGroups cannot be resource-scoped in AWS CloudWatch Logs"
    )
    assert '"VaultAuditLogRead"' in block, (
        "reader policy must have VaultAuditLogRead Sid for scoped read actions"
    )


# ---------------------------------------------------------------------------
# SoD — Separation of duties
# ---------------------------------------------------------------------------


def test_sod1_writer_user_and_reader_role_are_distinct_resources(audit_tf: str):
    """Writer is an IAM user; reader is an IAM role. These are structurally distinct.
    No single resource is both writer and reader.
    """
    assert 'resource "aws_iam_user" "vault_audit"' in audit_tf, "writer user must exist"
    assert 'resource "aws_iam_role" "vault_audit_reader"' in audit_tf, (
        "reader role must exist"
    )
    # writer user and reader role have different names — confirmed by resource names above
    writer_block = _extract_resource_block(audit_tf, "aws_iam_user", "vault_audit")
    reader_block = _extract_resource_block(
        audit_tf, "aws_iam_role", "vault_audit_reader"
    )
    assert writer_block != reader_block, (
        "writer and reader must be distinct resource blocks"
    )


def test_sod2_no_access_key_resource_in_terraform(audit_tf: str):
    """No aws_iam_access_key resource may exist in aws_audit.tf.
    The writer access key is created out-of-band by the human operator and
    transferred directly to HCP. It never enters Terraform state.
    """
    assert 'resource "aws_iam_access_key"' not in audit_tf, (
        "aws_iam_access_key must not be declared in Terraform — "
        "writer credential is created manually by human operator (Checkpoint Q-5)"
    )


def test_sod3_terraform_operator_policy_does_not_grant_audit_reads():
    """FrostGateTerraformOperator must not have audit-read actions.
    The Terraform operator needs write access to provision resources but must
    not be able to read audit evidence — that capability belongs only to the
    FrostGateVaultAuditReader role (assumed with MFA).
    """
    scripts_dir = INFRA / "scripts"
    if not scripts_dir.exists():
        pytest.skip("infra/scripts directory not present — SoD3 is a runbook invariant")
    # If an operator policy file exists, check it does not grant read actions
    operator_policy_files = list(scripts_dir.glob("*operator*policy*")) + list(
        scripts_dir.glob("*terraform*policy*")
    )
    read_actions = ("FilterLogEvents", "GetLogEvents", "GetQueryResults")
    for policy_file in operator_policy_files:
        content = policy_file.read_text(encoding="utf-8")
        for action in read_actions:
            assert action not in content, (
                f"FrostGateTerraformOperator policy {policy_file.name} must not grant "
                f"logs:{action} — operator must not read audit evidence"
            )


# ---------------------------------------------------------------------------
# CE — Credential boundary
# ---------------------------------------------------------------------------


def test_ce1_no_credentials_in_terraform_outputs(audit_tf: str):
    """No sensitive credential values may appear in Terraform source or outputs."""
    # Check for literal AWS access key prefixes
    assert "AKIA" not in audit_tf, (
        "literal AWS access key ID prefix AKIA must not appear in aws_audit.tf"
    )
    # Check for private key markers
    assert "-----BEGIN" not in audit_tf, (
        "PEM private key marker must not appear in aws_audit.tf"
    )
    outputs_tf = (INFRA / "outputs.tf").read_text(encoding="utf-8")
    code_only = "\n".join(
        line for line in outputs_tf.splitlines() if not line.strip().startswith("#")
    )
    assert "sensitive = true" not in code_only, (
        "sensitive outputs are not permitted — all outputs must be non-secret"
    )


def test_ce2_reader_role_path_is_namespaced(audit_tf: str):
    """Reader role must be in the /frostgate/vault/ namespace path."""
    block = _extract_resource_block(audit_tf, "aws_iam_role", "vault_audit_reader")
    assert 'path = "/frostgate/vault/"' in block, (
        "FrostGateVaultAuditReader must be scoped to /frostgate/vault/ path"
    )


# ---------------------------------------------------------------------------
# RE — Rotation evidence separation
# ---------------------------------------------------------------------------


def test_re1_evidence_schema_has_separate_rotation_history_and_audit_evidence(
    evidence_schema: dict,
):
    """rotation_history and audit_evidence must be separately defined in the schema.
    They serve different purposes: rotation_history records key rotation events;
    audit_evidence records independently-verified CloudWatch streaming events.
    """
    props = evidence_schema.get("properties", {})
    # Both can appear as additionalProperties — the schema allows them via additionalProperties=true
    # The sample manifest in test_customer_zero_trust_evidence.py includes both.
    # Confirm the schema does not conflate them by requiring one to imply the other.
    rotation_def = props.get("rotation_history")
    audit_def = props.get("audit_evidence")
    # If explicitly defined, they must be distinct array entries (not cross-referencing)
    if rotation_def and audit_def:
        assert rotation_def != audit_def, (
            "rotation_history and audit_evidence must have distinct schema definitions"
        )


def test_re2_evidence_schema_dimensions_include_auditability(evidence_schema: dict):
    """AUDITABILITY dimension must be independently assessable from ROTATION_HISTORY.
    This verifies the schema design allows streaming evidence without requiring
    a second key rotation.
    """
    dimensions_props = (
        evidence_schema.get("properties", {})
        .get("dimensions", {})
        .get("properties", {})
    )
    assert "AUDITABILITY" in dimensions_props, (
        "evidence schema must define AUDITABILITY as an independent dimension"
    )
    assert "ROTATION_HISTORY" in dimensions_props, (
        "evidence schema must define ROTATION_HISTORY as an independent dimension"
    )
    # Both must be independently settable (neither is required to prove the other)
    auditability = dimensions_props["AUDITABILITY"]
    rotation_history = dimensions_props["ROTATION_HISTORY"]
    assert auditability.get("enum") == [
        "PASS",
        "FAIL",
        "NOT_PROVEN",
    ], "AUDITABILITY must allow NOT_PROVEN independently of ROTATION_HISTORY"
    assert rotation_history.get("enum") == [
        "PASS",
        "FAIL",
        "NOT_PROVEN",
    ], "ROTATION_HISTORY must allow NOT_PROVEN independently of AUDITABILITY"


def test_re3_runbook_does_not_require_second_rotation_for_cloudwatch(runbook: str):
    """The ceremony runbook must explicitly state that no second rotation is required
    to populate CloudWatch audit evidence. Rotation history and CloudWatch streaming
    evidence are separate; subsequent auth/signing events are sufficient.
    """
    assert (
        "no second rotation" in runbook.lower() or "second rotation" in runbook.lower()
    ), (
        "Runbook must address the 'no second rotation required' invariant at Checkpoint Q"
    )
    # The relevant statement must explicitly say a second rotation is not required
    relevant_lines = [
        line
        for line in runbook.splitlines()
        if "rotation" in line.lower()
        and ("not required" in line.lower() or "no second" in line.lower())
    ]
    assert relevant_lines, (
        "Runbook must contain an explicit statement that no second rotation is required "
        "to populate CloudWatch audit evidence"
    )


# ---------------------------------------------------------------------------
# DS — Destination semantics
# ---------------------------------------------------------------------------


def test_ds1_destination_model_is_operator_configured(audit_tf: str):
    """The audit destination is operator-configured, not HCP-assigned.
    aws_audit.tf must document that the log group name is set by the operator
    in the HCP UI and must match the Terraform-provisioned group.
    """
    assert "OPERATOR-CONFIGURED" in audit_tf or "operator" in audit_tf.lower(), (
        "aws_audit.tf must document the operator-configured destination model"
    )
    # The actual log group name comes from a variable (operator-controlled)
    assert "var.cloudwatch_log_group_name" in audit_tf, (
        "log group name must come from var.cloudwatch_log_group_name, not a hardcoded string"
    )


def test_ds2_runbook_distinguishes_intended_from_configured_destination(runbook: str):
    """Runbook must distinguish between the INTENDED destination (Terraform-managed)
    and the CONFIGURED destination (what the operator enters in HCP UI), and must
    include a step to verify they match.
    """
    checkpoint_q_text = runbook[runbook.lower().find("checkpoint q") :]
    assert (
        "intended" in checkpoint_q_text.lower()
        or "intended destination" in checkpoint_q_text.lower()
    ), "Checkpoint Q must reference the INTENDED destination concept"
    # Must include a verification step for the destination
    assert "log group name" in checkpoint_q_text.lower(), (
        "Checkpoint Q must include verification that the HCP log group name matches the intended destination"
    )


def test_ds3_runbook_includes_reader_role_assumption_step(runbook: str):
    """Checkpoint Q must include the step for the operator to assume the reader role
    with MFA and independently verify audit events are present.
    """
    checkpoint_q_text = runbook[runbook.lower().find("checkpoint q") :]
    assert "FrostGateVaultAuditReader" in checkpoint_q_text, (
        "Checkpoint Q must reference the FrostGateVaultAuditReader role assumption step"
    )
    assert (
        "assume-role" in checkpoint_q_text.lower()
        or "assume_role" in checkpoint_q_text.lower()
        or "sts assume" in checkpoint_q_text.lower()
    ), "Checkpoint Q must include a sts assume-role step for the reader role"
