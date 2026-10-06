"""Regression tests for the fail-closed staged Customer-Zero cost teardown."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "infra/scripts/customer_zero_teardown.py"
SPEC = importlib.util.spec_from_file_location("customer_zero_teardown", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
teardown = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(teardown)

OBSERVED_WRITER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VaultAuditLogStreaming",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:PutLogEvents",
            ],
            "Resource": [
                "arn:aws:logs:us-east-1:398915901105:log-group:/frostgate/customer-zero/vault-audit",
                "arn:aws:logs:us-east-1:398915901105:log-group:/frostgate/customer-zero/vault-audit:*",
            ],
        }
    ],
}


def _state_json(*, min_encryption_version: int = 0) -> str:
    resources = [
        {
            "mode": "managed",
            "type": "aws_iam_policy",
            "name": "vault_audit",
            "instances": [
                {
                    "attributes": {
                        "description": "Minimum permissions for HCP Vault Dedicated to stream audit logs to CloudWatch",
                        "policy": json.dumps(OBSERVED_WRITER_POLICY),
                    }
                }
            ],
        }
    ]
    for name in ("identity", "acceptance", "approval"):
        resources.append(
            {
                "mode": "managed",
                "type": "vault_transit_secret_backend_key",
                "name": f"customer_zero_{name}",
                "instances": [
                    {"attributes": {"min_encryption_version": min_encryption_version}}
                ],
            }
        )
    return json.dumps({"resources": resources})


def _observed_values(
    stage: str, addresses: set[str], *, min_encryption_version: int = 0
) -> dict[str, dict[str, object]]:
    return teardown.extract_observed_values(
        _state_json(min_encryption_version=min_encryption_version), stage, addresses
    )


def _render(stage: str, addresses: set[str]) -> dict[str, str]:
    return teardown.render_configuration(
        REPO / "infra", stage, "a" * 40, addresses, _observed_values(stage, addresses)
    )


def _configured_writer_policy(files: dict[str, str]) -> dict[str, object]:
    block = teardown._resource_block(
        files["aws_audit.tf"], "aws_iam_policy.vault_audit"
    )
    match = re.search(r'(?m)^\s*policy\s*=\s*("(?:[^"\\]|\\.)*")$', block)
    assert match is not None
    return json.loads(json.loads(match.group(1)))


def _inventory(
    *, readers: bool = False, vault: bool = True, cluster: bool = True, hvn: bool = True
) -> set[str]:
    addresses = set(teardown.AWS_CORE)
    if readers:
        addresses |= teardown.AWS_READER
    if vault:
        addresses |= teardown.VAULT_CHILDREN
    if cluster:
        addresses.add(teardown.HCP_CLUSTER)
    if hvn:
        addresses.add(teardown.HCP_HVN)
    return addresses


def _plan(
    *changes: tuple[str, list[str]], outputs: dict[str, list[str]] | None = None
) -> dict[str, object]:
    return {
        "resource_changes": [
            {"address": address, "mode": "managed", "change": {"actions": actions}}
            for address, actions in changes
        ],
        "output_changes": {
            name: {"actions": actions} for name, actions in (outputs or {}).items()
        },
    }


def _key_enable_plan(
    state: set[str], *, updated: set[str] | None = None
) -> dict[str, object]:
    updated = updated or set()
    changes = []
    for address in sorted(state):
        if address in teardown.TRANSIT_KEYS:
            changes.append(
                {
                    "address": address,
                    "mode": "managed",
                    "change": {
                        "actions": ["update"] if address in updated else ["no-op"],
                        "before": {
                            "deletion_allowed": address not in updated,
                            "min_encryption_version": 0,
                        },
                        "after": {
                            "deletion_allowed": True,
                            "min_encryption_version": 0,
                        },
                    },
                }
            )
        else:
            changes.append(
                {
                    "address": address,
                    "mode": "managed",
                    "change": {"actions": ["no-op"]},
                }
            )
    return {"resource_changes": changes, "output_changes": {}}


def _child_delete_plan(
    addresses: set[str], *, outputs: dict[str, list[str]] | None = None
) -> dict[str, object]:
    changes = []
    for address in sorted(addresses):
        item = {
            "address": address,
            "mode": "managed",
            "change": {"actions": ["delete"]},
        }
        if address in teardown.TRANSIT_KEYS:
            item["change"]["before"] = {"deletion_allowed": True}
        changes.append(item)
    return {
        "resource_changes": changes,
        "output_changes": {
            name: {"actions": actions} for name, actions in (outputs or {}).items()
        },
    }


def test_exact_ephemeral_boundary_is_explicit_and_split_by_provider_lifetime() -> None:
    assert len(teardown.VAULT_CHILDREN) == 11
    assert teardown.TARGETS["enable-key-deletion"] == teardown.TRANSIT_KEYS
    assert teardown.TARGETS["vault-children"] == teardown.VAULT_CHILDREN
    assert teardown.TARGETS["hcp-cluster"] == {teardown.HCP_CLUSTER}
    assert teardown.TARGETS["hvn"] == {teardown.HCP_HVN}


def test_aws_audit_resources_are_preserved_in_every_stage() -> None:
    assert len(teardown.AWS_CORE) == 4
    teardown.validate_inventory("enable-key-deletion", _inventory())
    teardown.validate_inventory("vault-children", _inventory())
    teardown.validate_inventory("hcp-cluster", _inventory(vault=False))
    teardown.validate_inventory("hvn", _inventory(vault=False, cluster=False))
    assert (
        not (teardown.AWS_CORE | teardown.AWS_READER)
        & teardown.TARGETS["enable-key-deletion"]
    )
    assert (
        not (teardown.AWS_CORE | teardown.AWS_READER)
        & teardown.TARGETS["vault-children"]
    )
    assert (
        not (teardown.AWS_CORE | teardown.AWS_READER) & teardown.TARGETS["hcp-cluster"]
    )
    assert not (teardown.AWS_CORE | teardown.AWS_READER) & teardown.TARGETS["hvn"]


def test_reader_authority_is_optional_but_must_be_complete_and_preserved() -> None:
    teardown.validate_inventory("vault-children", _inventory(readers=True))
    teardown.validate_inventory("hcp-cluster", _inventory(readers=True, vault=False))
    teardown.validate_inventory(
        "hvn", _inventory(readers=True, vault=False, cluster=False)
    )
    with pytest.raises(teardown.UnsafePlan, match="complete trio"):
        teardown.validate_inventory(
            "vault-children",
            _inventory(readers=True) - {"aws_iam_role.vault_audit_reader"},
        )


def test_extra_state_resource_fails_closed() -> None:
    for stage, state in (
        ("enable-key-deletion", _inventory()),
        ("vault-children", _inventory()),
        ("hcp-cluster", _inventory(vault=False)),
        ("hvn", _inventory(vault=False, cluster=False)),
    ):
        with pytest.raises(teardown.UnsafePlan, match="unexpected managed state"):
            teardown.validate_inventory(stage, state | {"aws_iam_access_key.audit"})


def test_later_hcp_stages_require_vault_children_already_absent() -> None:
    with pytest.raises(teardown.UnsafePlan, match="Vault child resources"):
        teardown.validate_inventory("hcp-cluster", _inventory())
    with pytest.raises(teardown.UnsafePlan, match="Vault child resources"):
        teardown.validate_inventory("hvn", _inventory(vault=True, cluster=False))


def test_hvn_stage_requires_cluster_absent() -> None:
    with pytest.raises(teardown.UnsafePlan, match="cluster must be absent"):
        teardown.validate_inventory("hvn", _inventory(vault=False, cluster=True))


def test_vault_stage_allows_partial_state_for_safe_replan_after_failure() -> None:
    partial = _inventory()
    partial.remove("vault_mount.transit")
    partial.remove("vault_policy.identity")
    teardown.validate_inventory("vault-children", partial)
    plan = _child_delete_plan(partial & teardown.VAULT_CHILDREN)
    result = teardown.validate_plan("vault-children", plan, partial)
    assert result == partial & teardown.VAULT_CHILDREN


def test_vault_plan_must_destroy_every_remaining_child_and_only_children() -> None:
    state = _inventory()
    changes = teardown.VAULT_CHILDREN
    assert (
        teardown.validate_plan("vault-children", _child_delete_plan(changes), state)
        == teardown.VAULT_CHILDREN
    )
    with pytest.raises(teardown.UnsafePlan, match="destroy set differs"):
        teardown.validate_plan(
            "vault-children", _child_delete_plan(set(sorted(changes)[:-1])), state
        )
    with pytest.raises(teardown.UnsafePlan, match="unexpected action"):
        teardown.validate_plan(
            "vault-children",
            _child_delete_plan(changes | {"aws_cloudwatch_log_group.vault_audit"}),
            state,
        )


def test_child_key_destroy_requires_state_with_deletion_allowed_true() -> None:
    state = _inventory()
    plan = _child_delete_plan(teardown.VAULT_CHILDREN)
    for change in plan["resource_changes"]:
        if change["address"] in teardown.TRANSIT_KEYS:
            change["change"]["before"]["deletion_allowed"] = False
            break
    with pytest.raises(teardown.UnsafePlan, match="not enabled in state"):
        teardown.validate_plan("vault-children", plan, state)


def test_key_deletion_enablement_is_a_precise_update_only_stage() -> None:
    state = _inventory()
    plan = _key_enable_plan(state, updated=teardown.TRANSIT_KEYS)
    assert (
        teardown.validate_plan("enable-key-deletion", plan, state)
        == teardown.TRANSIT_KEYS
    )
    assert (
        teardown.validate_plan("enable-key-deletion", _key_enable_plan(state), state)
        == set()
    )


def test_key_deletion_enablement_rejects_wrong_value_and_unrelated_mutation() -> None:
    state = _inventory()
    wrong = _key_enable_plan(state)
    for change in wrong["resource_changes"]:
        if change["address"] in teardown.TRANSIT_KEYS:
            change["change"]["after"]["deletion_allowed"] = False
            break
    with pytest.raises(teardown.UnsafePlan, match="deletion_allowed=true"):
        teardown.validate_plan("enable-key-deletion", wrong, state)

    changes = _key_enable_plan(state)["resource_changes"]
    changes.append(
        {
            "address": "aws_iam_policy.vault_audit",
            "mode": "managed",
            "change": {"actions": ["update"]},
        }
    )
    with pytest.raises(teardown.UnsafePlan, match="unexpected action"):
        teardown.validate_plan(
            "enable-key-deletion",
            {"resource_changes": changes, "output_changes": {}},
            state,
        )


def test_key_deletion_enablement_rejects_changes_to_other_key_properties() -> None:
    state = _inventory()
    plan = _key_enable_plan(state, updated=teardown.TRANSIT_KEYS)
    for change in plan["resource_changes"]:
        if change["address"] in teardown.TRANSIT_KEYS:
            change["change"]["after"]["exportable"] = True
            break
    with pytest.raises(teardown.UnsafePlan, match="beyond deletion_allowed"):
        teardown.validate_plan("enable-key-deletion", plan, state)


@pytest.mark.parametrize(
    "actions", [["create"], ["update"], ["delete", "create"], ["create", "delete"]]
)
def test_create_update_and_replace_actions_are_rejected(actions: list[str]) -> None:
    state = _inventory()
    with pytest.raises(teardown.UnsafePlan, match="unexpected action"):
        teardown.validate_plan(
            "vault-children",
            _plan(("vault_policy.identity", actions)),
            state,
        )


def test_cluster_then_hvn_are_separate_explicitly_ordered_authorizations() -> None:
    after_vault = _inventory(vault=False)
    assert teardown.validate_plan(
        "hcp-cluster", _plan((teardown.HCP_CLUSTER, ["delete"])), after_vault
    ) == {teardown.HCP_CLUSTER}
    after_cluster = _inventory(vault=False, cluster=False)
    assert teardown.validate_plan(
        "hvn", _plan((teardown.HCP_HVN, ["delete"])), after_cluster
    ) == {teardown.HCP_HVN}


def test_cluster_stage_allows_only_canonical_cluster_output_removals() -> None:
    state = _inventory(vault=False)
    plan = _plan(
        (teardown.HCP_CLUSTER, ["delete"]),
        outputs={"vault_version": ["delete"]},
    )
    assert teardown.validate_plan("hcp-cluster", plan, state) == {teardown.HCP_CLUSTER}
    plan["output_changes"]["unexpected_output"] = {"actions": ["delete"]}
    with pytest.raises(teardown.UnsafePlan, match="unexpected output action"):
        teardown.validate_plan("hcp-cluster", plan, state)


def test_all_later_stages_reject_unrelated_preserved_aws_policy_updates() -> None:
    vault_state = _inventory()
    vault_plan = _child_delete_plan(teardown.VAULT_CHILDREN)
    cluster_state = _inventory(vault=False)
    cluster_plan = _plan(
        (teardown.HCP_CLUSTER, ["delete"]),
        outputs={"vault_version": ["delete"]},
    )
    hvn_state = _inventory(vault=False, cluster=False)
    hvn_plan = _plan((teardown.HCP_HVN, ["delete"]))

    for stage, plan, state in (
        ("vault-children", vault_plan, vault_state),
        ("hcp-cluster", cluster_plan, cluster_state),
        ("hvn", hvn_plan, hvn_state),
    ):
        plan["resource_changes"].append(
            {
                "address": "aws_iam_policy.vault_audit",
                "mode": "managed",
                "change": {"actions": ["update"]},
            }
        )
        with pytest.raises(teardown.UnsafePlan, match="unexpected action"):
            teardown.validate_plan(stage, plan, state)


def test_noop_replan_is_idempotent_when_stage_targets_are_already_absent() -> None:
    for stage, state in (
        ("enable-key-deletion", _inventory()),
        ("vault-children", _inventory(vault=False)),
        ("hcp-cluster", _inventory(vault=False, cluster=False)),
        ("hvn", _inventory(vault=False, cluster=False, hvn=False)),
    ):
        plan = (
            _key_enable_plan(state)
            if stage == "enable-key-deletion"
            else _plan(*[(address, ["no-op"]) for address in state])
        )
        assert teardown.validate_plan(stage, plan, state) == set()


def test_unexpected_output_changes_are_rejected() -> None:
    state = _inventory()
    plan = _child_delete_plan(
        teardown.VAULT_CHILDREN,
        outputs={"iam_audit_user_arn": ["delete"]},
    )
    with pytest.raises(teardown.UnsafePlan, match="unexpected output action"):
        teardown.validate_plan("vault-children", plan, state)


def test_stage_one_accepts_retained_approle_role_id_noop_output() -> None:
    state = _inventory()
    plan = _key_enable_plan(state, updated=teardown.TRANSIT_KEYS)
    plan["output_changes"] = {"approle_role_id_acceptance": {"actions": ["no-op"]}}

    assert (
        teardown.validate_plan("enable-key-deletion", plan, state)
        == teardown.TRANSIT_KEYS
    )


@pytest.mark.parametrize(
    "actions", [["create"], ["update"], ["delete"], ["delete", "create"]]
)
def test_stage_one_rejects_output_mutations(actions: list[str]) -> None:
    state = _inventory()
    plan = _key_enable_plan(state)
    plan["output_changes"] = {"approle_role_id_acceptance": {"actions": actions}}

    with pytest.raises(teardown.UnsafePlan, match="unexpected output action"):
        teardown.validate_plan("enable-key-deletion", plan, state)


def test_generated_stage_config_uses_removed_blocks_and_only_stateful_aws_resources(
    tmp_path: Path,
) -> None:
    infra = REPO / "infra"
    generated = _render("vault-children", _inventory())
    assert "terraform destroy" not in "\n".join(generated.values())
    assert generated["removed.tf"].count("removed {") == 11
    assert "vault_transit.tf" not in generated
    assert (
        'resource "aws_iam_role" "vault_audit_reader"' not in generated["aws_audit.tf"]
    )
    assert "prevent_destroy = true" in (infra / "aws_audit.tf").read_text()
    assert 'resource "hcp_vault_cluster" "customer_zero"' in generated["hcp_cluster.tf"]


def test_key_enablement_configuration_only_opens_the_vault_deletion_guard() -> None:
    generated = _render("enable-key-deletion", _inventory())
    transit = generated["vault_transit.tf"]
    assert len(re.findall(r"(?m)^\s*deletion_allowed\s*=\s*true$", transit)) == 3
    assert "removed {" not in generated["removed.tf"]
    assert "prevent_destroy = true" in transit


def test_stage_one_uses_observed_writer_policy_and_key_minimum_version() -> None:
    generated = _render("enable-key-deletion", _inventory())
    configured_policy = _configured_writer_policy(generated)
    assert configured_policy == OBSERVED_WRITER_POLICY
    writer_block = teardown._resource_block(
        generated["aws_audit.tf"], "aws_iam_policy.vault_audit"
    )
    assert (
        'description = "Minimum permissions for HCP Vault Dedicated to stream '
        'audit logs to CloudWatch"' in writer_block
    )
    assert "VaultAuditLogWrite" in (REPO / "infra/aws_audit.tf").read_text()
    assert "VaultAuditLogStreaming" in json.dumps(configured_policy)
    assert "VaultAuditDescribeLogGroupsUnscopedAWSLimit" not in json.dumps(
        configured_policy
    )

    transit = generated["vault_transit.tf"]
    for address in teardown.TRANSIT_KEYS:
        block = teardown._resource_block(transit, address)
        assert re.search(r"(?m)^\s*min_encryption_version\s*=\s*0$", block)
        assert re.search(r"(?m)^\s*deletion_allowed\s*=\s*true$", block)
    for address in teardown.TRANSIT_KEYS:
        canonical = teardown._resource_block(
            (REPO / "infra/vault_transit.tf").read_text(), address
        )
        assert re.search(r"(?m)^\s*min_encryption_version\s*=\s*1$", canonical)


def test_state_projection_extracts_only_required_observed_attributes() -> None:
    projected = _observed_values("enable-key-deletion", _inventory())
    assert set(projected["aws_iam_policy.vault_audit"]) == {"description", "policy"}
    assert set(teardown.TRANSIT_KEYS) <= set(projected)
    assert all(
        projected[address]["min_encryption_version"] == 0
        for address in teardown.TRANSIT_KEYS
    )


def test_stage_one_verifier_allows_only_deletion_flag_change() -> None:
    state = _inventory()
    plan = _key_enable_plan(state, updated=teardown.TRANSIT_KEYS)
    assert (
        teardown.validate_plan("enable-key-deletion", plan, state)
        == teardown.TRANSIT_KEYS
    )

    min_version_drift = _key_enable_plan(state, updated=teardown.TRANSIT_KEYS)
    for change in min_version_drift["resource_changes"]:
        if change["address"] in teardown.TRANSIT_KEYS:
            change["change"]["after"]["min_encryption_version"] = 1
            break
    with pytest.raises(teardown.UnsafePlan, match="beyond deletion_allowed"):
        teardown.validate_plan("enable-key-deletion", min_version_drift, state)


@pytest.mark.parametrize(
    "actions",
    [["create"], ["delete"], ["delete", "create"], ["create", "delete"]],
)
def test_stage_one_rejects_create_delete_and_replacement(actions: list[str]) -> None:
    state = _inventory()
    plan = _key_enable_plan(state)
    target = next(
        item
        for item in plan["resource_changes"]
        if item["address"] in teardown.TRANSIT_KEYS
    )
    target["change"]["actions"] = actions
    with pytest.raises(teardown.UnsafePlan, match="unexpected key deletion-enablement"):
        teardown.validate_plan("enable-key-deletion", plan, state)


def test_stage_one_rejects_any_output_change() -> None:
    state = _inventory()
    plan = _key_enable_plan(state)
    plan["output_changes"] = {"unexpected": {"actions": ["delete"]}}
    with pytest.raises(teardown.UnsafePlan, match="unexpected output action"):
        teardown.validate_plan("enable-key-deletion", plan, state)


def test_generated_hcp_stages_do_not_configure_or_authenticate_vault() -> None:
    hcp = _render("hcp-cluster", _inventory(vault=False))
    hvn = _render("hvn", _inventory(vault=False, cluster=False))
    for files in (hcp, hvn):
        assert 'provider "vault"' not in files["providers.tf"]
        assert "VAULT_TOKEN" not in "\n".join(files.values())
        assert (
            'resource "aws_cloudwatch_log_group" "vault_audit"' in files["aws_audit.tf"]
        )
        assert _configured_writer_policy(files) == OBSERVED_WRITER_POLICY
    assert "from = hcp_vault_cluster.customer_zero" in hcp["removed.tf"]
    assert "from = hcp_hvn.frostgate" in hvn["removed.tf"]
    assert 'resource "hcp_hvn" "frostgate"' in hcp["hcp_hvn.tf"]
    assert 'data "hcp_project" "frostgate_production"' in hcp["hcp_project.tf"]
    assert 'data "hcp_project" "frostgate_production"' in hvn["hcp_project.tf"]


@pytest.mark.parametrize(
    ("stage", "state"),
    [
        ("enable-key-deletion", _inventory()),
        ("vault-children", _inventory()),
        ("hcp-cluster", _inventory(vault=False)),
        ("hvn", _inventory(vault=False, cluster=False)),
    ],
)
def test_generated_stage_configuration_is_terraform_formatted(
    tmp_path: Path, stage: str, state: set[str]
) -> None:
    destination = tmp_path / stage
    teardown.prepare(
        REPO / "infra",
        stage,
        destination,
        "a" * 40,
        state,
        _observed_values(stage, state),
    )
    result = subprocess.run(
        ["terraform", "fmt", "-check", "-recursive"],
        cwd=destination,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_generated_configuration_contains_no_credential_or_railway_resource() -> None:
    generated = _render("vault-children", _inventory())
    text = "\n".join(generated.values()).lower()
    assert "aws_iam_access_key" not in text
    assert 'resource "vault_token"' not in text
    assert "secret_id" not in generated["removed.tf"].lower()
    assert "railway" not in text


def test_source_guards_remain_protected_and_no_credential_or_railway_mutation_is_added() -> (
    None
):
    hcp_source = (REPO / "infra/hcp_cluster.tf").read_text()
    vault_source = "\n".join(
        (REPO / "infra" / name).read_text()
        for name in ("vault_transit.tf", "vault_approle.tf", "vault_policies.tf")
    )
    assert hcp_source.count("prevent_destroy = true") == 2
    assert vault_source.count("prevent_destroy = true") == 11
    infra_blob = "\n".join(path.read_text() for path in (REPO / "infra").glob("*.tf"))
    assert 'resource "aws_iam_access_key"' not in infra_blob
    runbook = (REPO / "infra/docs/ceremony-runbook.md").read_text()
    assert "`CUSTOMER_ZERO_TRUST_NOT_PROVEN` remains unchanged" in runbook
    section = runbook.split(
        "## CHECKPOINT V — NARROW PAID-INFRASTRUCTURE COST CONTAINMENT", 1
    )[1]
    assert (
        "railway" in section.lower()
    )  # Explicitly named as outside the mutation boundary.


def test_runbook_requires_plan_hash_human_approval_saved_plan_and_no_broad_destroy() -> (
    None
):
    runbook = (REPO / "infra/docs/ceremony-runbook.md").read_text()
    section = runbook.split(
        "## CHECKPOINT V — NARROW PAID-INFRASTRUCTURE COST CONTAINMENT", 1
    )[1]
    assert re.search(r"terraform plan .*?-out=\"\$PLAN_FILE\"", section)
    assert "SHA-256" in section
    assert "explicit human authorization" in section.lower()
    assert 'terraform apply "$PLAN_FILE"' in section
    assert not re.search(r"(?m)^\s*terraform destroy\b", section.lower())
    assert (
        "repository remains unchanged during operational execution" in section.lower()
    )


def test_full_teardown_runbook_accounts_for_policy_destroy_guards() -> None:
    runbook = (REPO / "infra/docs/ceremony-runbook.md").read_text()
    full_teardown = runbook.split("## CHECKPOINT U", 1)[1].split("## CHECKPOINT V", 1)[
        0
    ]
    assert "infra/vault_policies.tf" in full_teardown
    assert "vault_policies.tf" in full_teardown


def test_generator_rejects_directory_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "existing"
    destination.mkdir()
    with pytest.raises(teardown.UnsafePlan, match="refusing to overwrite"):
        teardown.prepare(
            REPO / "infra",
            "vault-children",
            destination,
            "a" * 40,
            _inventory(),
            _observed_values("vault-children", _inventory()),
        )
