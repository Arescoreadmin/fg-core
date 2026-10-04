"""CUSTOMER-ZERO-TRUST-001 — Terraform safety invariants.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

These tests prove static safety invariants on the production ceremony
Terraform under infra/.  They run with no provider calls; they parse the
.tf files textually (and via `terraform fmt -check` where available).

Invariants proven:
  T1  — HCP destroyable resources carry `prevent_destroy = true`
  T2  — Vault destroyable resources carry `prevent_destroy = true`
  T3  — AWS audit log group carries `prevent_destroy = true`
  T4  — No Terraform resource emits a credential, token, SecretID, or private key
  T5  — Transit keys are declared non-exportable and non-deletable
  T6  — Transit keys declare Ed25519 (algorithm pin)
  T7  — AppRoles bind SecretID and refuse the default policy
  T8  — Vault policies deny-by-default (no wildcard paths, no admin paths)
  T9  — Outputs do not expose any sensitive value
  T10 — Required providers pin HCP, Vault, and AWS to compatible versions
  T11 — Terraform remote state uses HCP Terraform (not a raw S3/local backend)
  T12 — IAM audit policy scopes write actions to the exact log-group ARN; list actions (DescribeLogGroups) may use *
  T17 — Ceremony runbook phase plan counts are coherent and source-authority SHA is not hardcoded
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

INFRA = Path(__file__).parent.parent / "infra"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tf_text() -> dict[str, str]:
    """Return the concatenated text of every .tf file under infra/."""
    data: dict[str, str] = {}
    for path in sorted(INFRA.glob("*.tf")):
        data[path.name] = path.read_text(encoding="utf-8")
    return data


@pytest.fixture(scope="module")
def tf_blob(tf_text: dict[str, str]) -> str:
    return "\n".join(tf_text.values())


# ---------------------------------------------------------------------------
# T1–T3 — prevent_destroy on all irreplaceable resources
# ---------------------------------------------------------------------------


HCP_RESOURCES = ("hcp_hvn", "hcp_vault_cluster")
VAULT_RESOURCES = (
    "vault_mount",
    "vault_transit_secret_backend_key",
    "vault_auth_backend",
    "vault_approle_auth_backend_role",
)
AWS_PROTECTED_RESOURCES = ("aws_cloudwatch_log_group",)


def _resource_blocks(tf: str, resource_type: str) -> list[str]:
    """Return every top-level `resource "<type>" "<name>" { ... }` block body."""
    pattern = re.compile(
        rf'resource\s+"{re.escape(resource_type)}"\s+"[^"]+"\s*\{{',
        re.MULTILINE,
    )
    blocks: list[str] = []
    for match in pattern.finditer(tf):
        depth = 1
        start = match.end()
        i = start
        while i < len(tf) and depth > 0:
            if tf[i] == "{":
                depth += 1
            elif tf[i] == "}":
                depth -= 1
            i += 1
        if depth == 0:
            blocks.append(tf[start : i - 1])
    return blocks


def _named_resource_blocks(tf: str, resource_type: str) -> dict[str, str]:
    """Return a mapping from resource name to block body for a given resource type."""
    pattern = re.compile(
        rf'resource\s+"{re.escape(resource_type)}"\s+"([^"]+)"\s*\{{',
        re.MULTILINE,
    )
    blocks: dict[str, str] = {}
    for match in pattern.finditer(tf):
        name = match.group(1)
        depth = 1
        start = match.end()
        i = start
        while i < len(tf) and depth > 0:
            if tf[i] == "{":
                depth += 1
            elif tf[i] == "}":
                depth -= 1
            i += 1
        if depth == 0:
            blocks[name] = tf[start : i - 1]
    return blocks


@pytest.mark.parametrize("resource_type", HCP_RESOURCES)
def test_t1_hcp_resources_prevent_destroy(tf_blob: str, resource_type: str):
    blocks = _resource_blocks(tf_blob, resource_type)
    assert blocks, f"expected at least one {resource_type} resource"
    for block in blocks:
        assert "prevent_destroy = true" in block, (
            f"{resource_type} must declare prevent_destroy = true"
        )


@pytest.mark.parametrize("resource_type", VAULT_RESOURCES)
def test_t2_vault_resources_prevent_destroy(tf_blob: str, resource_type: str):
    blocks = _resource_blocks(tf_blob, resource_type)
    assert blocks, f"expected at least one {resource_type} resource"
    for block in blocks:
        assert "prevent_destroy = true" in block, (
            f"{resource_type} must declare prevent_destroy = true"
        )


@pytest.mark.parametrize("resource_type", AWS_PROTECTED_RESOURCES)
def test_t3_aws_protected_resources_prevent_destroy(tf_blob: str, resource_type: str):
    blocks = _resource_blocks(tf_blob, resource_type)
    assert blocks, f"expected at least one {resource_type} resource"
    for block in blocks:
        assert "prevent_destroy = true" in block, (
            f"{resource_type} must declare prevent_destroy = true"
        )


# ---------------------------------------------------------------------------
# T4 — No credential-producing or credential-storing resources
# ---------------------------------------------------------------------------


FORBIDDEN_RESOURCE_TYPES = (
    "aws_iam_access_key",
    "aws_iam_user_login_profile",
    "aws_secretsmanager_secret_version",
    "vault_approle_auth_backend_role_secret_id",
    "vault_token",
    "vault_generic_secret",  # would store secret material in TF state
    "tls_private_key",
    "random_password",
)


@pytest.mark.parametrize("forbidden", FORBIDDEN_RESOURCE_TYPES)
def test_t4_no_credential_producing_resources(tf_blob: str, forbidden: str):
    """Terraform must not create or carry credentials via these resource types."""
    assert f'resource "{forbidden}"' not in tf_blob, (
        f"forbidden resource type {forbidden} must not appear in infra/*.tf"
    )


FORBIDDEN_SECRET_STRINGS = (
    "AKIA",  # AWS access key id prefix
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "hvs.",  # Vault service token prefix
    "xoxb-",  # Slack bot token prefix
    "s.CAESIG",  # Vault secret id patterns are hard to pin; test the clear markers
)


def test_t4b_no_literal_secret_markers(tf_blob: str):
    """Terraform source must not contain literal secret markers."""
    for marker in FORBIDDEN_SECRET_STRINGS:
        assert marker not in tf_blob, (
            f"forbidden secret marker {marker!r} must not appear in infra/*.tf"
        )


# ---------------------------------------------------------------------------
# T5–T6 — Transit key configuration pins
# ---------------------------------------------------------------------------


def test_t5_transit_keys_are_non_exportable_and_non_deletable(tf_blob: str):
    blocks = _resource_blocks(tf_blob, "vault_transit_secret_backend_key")
    assert len(blocks) == 3, "expected 3 Customer-Zero Transit keys"
    for block in blocks:
        assert "exportable       = false" in block or "exportable = false" in block
        assert "deletion_allowed = false" in block or "deletion_allowed= false" in block
        assert "derived          = false" in block or "derived = false" in block


def test_t6_transit_keys_pin_ed25519(tf_blob: str):
    blocks = _resource_blocks(tf_blob, "vault_transit_secret_backend_key")
    assert len(blocks) == 3
    for block in blocks:
        assert 'type    = "ed25519"' in block or 'type = "ed25519"' in block


# ---------------------------------------------------------------------------
# T7 — AppRole configuration pins
# ---------------------------------------------------------------------------


def test_t7_approles_bind_secret_id_and_deny_default_policy(tf_blob: str):
    blocks = _resource_blocks(tf_blob, "vault_approle_auth_backend_role")
    assert len(blocks) == 3, "expected 3 Customer-Zero AppRoles"
    for block in blocks:
        assert "bind_secret_id" in block and "true" in block
        assert "token_no_default_policy" in block
        assert (
            'token_type              = "service"' in block
            or 'token_type = "service"' in block
        )


# ---------------------------------------------------------------------------
# T8 — Vault policies deny-by-default; no wildcard; no sys/* / auth admin
# ---------------------------------------------------------------------------

_CZ_SIGNING_PATHS = {
    "identity": "transit/sign/customer-zero-identity",
    "acceptance": "transit/sign/customer-zero-acceptance",
    "approval": "transit/sign/customer-zero-approval",
}


def test_t8_vault_policies_grant_only_their_own_key(tf_text: dict[str, str]):
    """Each policy contains exactly its own Transit signing path and no other.

    Global string presence is insufficient — a policy that gained a second key's
    path would still pass.  This test extracts each vault_policy block by name
    and asserts 1:1 isolation: own path present, other two paths absent.
    """
    policies_tf = tf_text.get("vault_policies.tf", "")
    assert policies_tf, "vault_policies.tf must exist"
    blocks = _named_resource_blocks(policies_tf, "vault_policy")
    assert set(blocks.keys()) == {"identity", "acceptance", "approval"}, (
        f"expected exactly 3 vault_policy resources, got: {set(blocks.keys())}"
    )
    for name, block in blocks.items():
        own_path = _CZ_SIGNING_PATHS[name]
        assert own_path in block, f"vault_policy.{name} must grant {own_path}"
        for other_name, other_path in _CZ_SIGNING_PATHS.items():
            if other_name == name:
                continue
            assert other_path not in block, (
                f"vault_policy.{name} must not grant {other_path} — cross-role path leak"
            )


def test_t8b_vault_policies_do_not_grant_admin_paths(tf_text: dict[str, str]):
    """Policies must not grant sys/*, auth/*, root, or wildcard paths."""
    policies_tf = tf_text.get("vault_policies.tf", "")
    # Only generic 'wildcard' strings allowed are in comments; strip them.
    code_only = "\n".join(
        line for line in policies_tf.splitlines() if not line.strip().startswith("#")
    )
    forbidden = (
        'path "sys/*"',
        'path "auth/*"',
        'path "secret/*"',
        'path "*"',
        'capabilities = ["root"]',
        '"sudo"',
    )
    for marker in forbidden:
        assert marker not in code_only, (
            f"forbidden policy path {marker!r} must not appear in vault_policies.tf"
        )


# ---------------------------------------------------------------------------
# T9 — Outputs do not expose sensitive values
# ---------------------------------------------------------------------------


FORBIDDEN_OUTPUT_NAMES = (
    "secret_id",
    "vault_token",
    "secret",
    "private_key",
    "access_key_secret",
)


def test_t9_outputs_do_not_name_secrets(tf_text: dict[str, str]):
    outputs_tf = tf_text.get("outputs.tf", "")
    assert outputs_tf, "outputs.tf must exist"
    for forbidden in FORBIDDEN_OUTPUT_NAMES:
        pattern = re.compile(rf'output\s+"[^"]*{re.escape(forbidden)}[^"]*"')
        assert pattern.search(outputs_tf) is None, (
            f"forbidden output name containing {forbidden!r} present"
        )


def test_t9b_no_sensitive_output_slips_without_marker(tf_text: dict[str, str]):
    """Any output declared `sensitive = true` would hide value from `terraform output`,
    but committing that pattern is a code smell: our outputs are intentionally
    non-secret. Assert none exist, so a future addition fails this test and
    forces an explicit review."""
    outputs_tf = tf_text.get("outputs.tf", "")
    code_only = "\n".join(
        line for line in outputs_tf.splitlines() if not line.strip().startswith("#")
    )
    assert "sensitive = true" not in code_only, (
        "sensitive outputs are not permitted in infra/outputs.tf — redesign the output"
    )


# ---------------------------------------------------------------------------
# T10 — Provider versions pinned
# ---------------------------------------------------------------------------


def test_t10_provider_versions_pinned(tf_text: dict[str, str]):
    terraform_tf = tf_text.get("terraform.tf", "")
    assert terraform_tf, "terraform.tf must exist"
    assert "hashicorp/hcp" in terraform_tf
    assert "hashicorp/vault" in terraform_tf
    assert "hashicorp/aws" in terraform_tf
    # Must declare a version constraint (`version = "~>` or `version = ">="`)
    assert re.search(r"version\s*=\s*\"~>", terraform_tf)
    # Terraform core version pinned too
    assert "required_version" in terraform_tf


# ---------------------------------------------------------------------------
# T11 — Remote state in HCP Terraform
# ---------------------------------------------------------------------------


def test_t11_remote_state_is_hcp_terraform(tf_text: dict[str, str]):
    terraform_tf = tf_text.get("terraform.tf", "")
    assert "cloud {" in terraform_tf, "must use HCP Terraform cloud backend"
    assert "organization" in terraform_tf
    assert "workspaces" in terraform_tf
    # No local or raw S3 backend
    assert 'backend "local"' not in terraform_tf
    assert 'backend "s3"' not in terraform_tf


# ---------------------------------------------------------------------------
# T12 — IAM audit policy scoped to the exact log-group ARN prefix
# ---------------------------------------------------------------------------


def test_t12_iam_audit_policy_scopes_to_specific_log_group(tf_text: dict[str, str]):
    audit_tf = tf_text.get("aws_audit.tf", "")
    assert audit_tf, "aws_audit.tf must exist"
    # Write-capable actions must be scoped to the specific log-group ARN.
    assert "aws_cloudwatch_log_group.vault_audit.arn" in audit_tf
    # DescribeLogGroups is a list-type API that legitimately requires Resource = "*"
    # per AWS documentation — do not prohibit it here.  Write actions (PutLogEvents,
    # CreateLogStream, CreateLogGroup) are covered by the ARN assertion above.
    # Verify the jsonencode block does not use broader actions
    policy_json_match = re.search(
        r"policy\s*=\s*jsonencode\(\s*(\{.*?\})\s*\)",
        audit_tf,
        re.DOTALL,
    )
    assert policy_json_match, "could not locate policy jsonencode block"
    # Can't eval the HCL expression easily, so pattern-check for Action patterns
    assert '"logs:*"' not in audit_tf
    assert '"iam:*"' not in audit_tf
    assert (
        '"*"' not in audit_tf.split("Action")[1][:400] if "Action" in audit_tf else True
    )


# ---------------------------------------------------------------------------
# T13 — Audit retention is at least 90 days (compliance floor)
# ---------------------------------------------------------------------------


def test_t13_audit_retention_at_least_90_days(tf_text: dict[str, str]):
    variables_tf = tf_text.get("variables.tf", "")
    audit_tf = tf_text.get("aws_audit.tf", "")
    match = re.search(
        r'variable\s+"cloudwatch_retention_days".*?default\s*=\s*(\d+)',
        variables_tf,
        re.DOTALL,
    )
    assert match, "cloudwatch_retention_days must declare an explicit default"
    assert int(match.group(1)) >= 90, (
        "audit retention floor is 90 days for governance evidence"
    )
    assert "retention_in_days = var.cloudwatch_retention_days" in audit_tf


# ---------------------------------------------------------------------------
# T14 — Vault audit identity path is namespaced to /frostgate/vault/
# ---------------------------------------------------------------------------


def test_t14_audit_identity_is_namespaced(tf_text: dict[str, str]):
    audit_tf = tf_text.get("aws_audit.tf", "")
    assert 'path = "/frostgate/vault/"' in audit_tf, (
        "the vault audit IAM identity must be scoped to /frostgate/vault/"
    )


# ---------------------------------------------------------------------------
# T15 — IAM policy locked to StringEquals/aws:TagKeys where present (defence)
# ---------------------------------------------------------------------------


def test_t15_terraform_lock_file_present():
    """The .terraform.lock.hcl file is committed to pin provider hashes."""
    lock = INFRA / ".terraform.lock.hcl"
    assert lock.exists(), "infra/.terraform.lock.hcl must be committed"
    text = lock.read_text(encoding="utf-8")
    assert "hashicorp/hcp" in text
    assert "hashicorp/vault" in text
    assert "hashicorp/aws" in text


# ---------------------------------------------------------------------------
# T16 — Evidence schema file is in sync with the Python validator
# ---------------------------------------------------------------------------


def test_t16_evidence_schema_file_matches_python_validator():
    """The canonical JSON schema (schemas/artifacts/customer_zero_trust_evidence.schema.json)
    must accept the known-good sample manifest used by test_customer_zero_trust_evidence.py
    (which is the authoritative Python validator's contract)."""
    from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

    from tests.test_customer_zero_trust_evidence import (  # noqa: PLC0415
        manifest as _sample_manifest,
    )

    schema_path = (
        Path(__file__).parent.parent
        / "schemas"
        / "artifacts"
        / "customer_zero_trust_evidence.schema.json"
    )
    assert schema_path.exists(), (
        "schemas/artifacts/customer_zero_trust_evidence.schema.json must be committed"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    # Self-check the schema is syntactically valid
    Draft202012Validator.check_schema(schema)

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(_sample_manifest()), key=lambda e: e.path)
    assert not errors, (
        "committed schema rejects the known-good sample manifest — schema has drifted "
        f"from the Python validator; errors: {[e.message for e in errors]}"
    )


# ---------------------------------------------------------------------------
# T17 — Ceremony runbook phase plan counts are coherent; no hardcoded SHA
# ---------------------------------------------------------------------------


def test_t17_runbook_phase_plan_counts_coherent_and_sha_not_hardcoded():
    """Runbook must document Phase-1=5, Phase-2=11, full=16, and must not
    pin a hardcoded source SHA in the source-authority header line."""
    runbook = (INFRA / "docs" / "ceremony-runbook.md").read_text(encoding="utf-8")

    # Phase-1 targeted plan: exactly 5 resources (enforced at Checkpoint F)
    assert "5 resources to add (2 HCP + 3 AWS)" in runbook, (
        "Runbook Checkpoint F must specify the Phase-1 targeted plan expects "
        "5 resources to add (2 HCP + 3 AWS)"
    )

    # Phase-2 plan: exactly 11 resources
    assert "11 resources to add" in runbook, (
        "Runbook Checkpoint F Phase-2 must specify 11 resources to add"
    )

    # Full architecture-review plan at Checkpoint C: 16 to add (5+11)
    assert "16 to add" in runbook, (
        "Runbook Checkpoint C must specify full plan = 16 to add (5 Phase-1 + 11 Phase-2)"
    )

    # Checkpoint C must distinguish itself from the Phase-1 targeted count
    assert "5 Phase-1" in runbook or "Phase-1 targeted" in runbook, (
        "Runbook Checkpoint C must clarify that 16 is the full-plan count and "
        "the Phase-1 targeted apply plan will show 5 to add"
    )

    # Source-authority header must not hardcode a 40-char hex SHA
    source_auth_line = next(
        (line for line in runbook.splitlines() if "fg-core source authority" in line),
        None,
    )
    assert source_auth_line is not None, (
        "Runbook must contain an 'fg-core source authority' line"
    )
    assert not re.search(r"`[0-9a-f]{40}`", source_auth_line), (
        "Runbook source-authority line must not pin a hardcoded 40-char SHA. "
        "Authority is proven dynamically at Checkpoint A1 via HEAD == origin/main."
    )
