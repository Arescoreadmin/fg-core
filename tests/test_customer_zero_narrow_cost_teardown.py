"""Regression tests for the fail-closed staged Customer-Zero cost teardown."""

from __future__ import annotations

import importlib.util
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


def test_exact_ephemeral_boundary_is_explicit_and_split_by_provider_lifetime() -> None:
    assert len(teardown.VAULT_CHILDREN) == 11
    assert teardown.TARGETS["vault-children"] == teardown.VAULT_CHILDREN
    assert teardown.TARGETS["hcp-cluster"] == {teardown.HCP_CLUSTER}
    assert teardown.TARGETS["hvn"] == {teardown.HCP_HVN}


def test_aws_audit_resources_are_preserved_in_every_stage() -> None:
    assert len(teardown.AWS_CORE) == 4
    teardown.validate_inventory("vault-children", _inventory())
    teardown.validate_inventory("hcp-cluster", _inventory(vault=False))
    teardown.validate_inventory("hvn", _inventory(vault=False, cluster=False))
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
    with pytest.raises(teardown.UnsafePlan, match="unexpected managed state"):
        teardown.validate_inventory(
            "vault-children", _inventory() | {"aws_iam_access_key.audit"}
        )


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
    plan = _plan(
        *[(address, ["delete"]) for address in partial & teardown.VAULT_CHILDREN]
    )
    result = teardown.validate_plan("vault-children", plan, partial)
    assert result == partial & teardown.VAULT_CHILDREN


def test_vault_plan_must_destroy_every_remaining_child_and_only_children() -> None:
    state = _inventory()
    changes = [(address, ["delete"]) for address in teardown.VAULT_CHILDREN]
    assert (
        teardown.validate_plan("vault-children", _plan(*changes), state)
        == teardown.VAULT_CHILDREN
    )
    with pytest.raises(teardown.UnsafePlan, match="destroy set differs"):
        teardown.validate_plan("vault-children", _plan(*changes[:-1]), state)
    with pytest.raises(teardown.UnsafePlan, match="unexpected action"):
        teardown.validate_plan(
            "vault-children",
            _plan(*changes, ("aws_cloudwatch_log_group.vault_audit", ["delete"])),
            state,
        )


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


def test_noop_replan_is_idempotent_when_stage_targets_are_already_absent() -> None:
    for stage, state in (
        ("vault-children", _inventory(vault=False)),
        ("hcp-cluster", _inventory(vault=False, cluster=False)),
        ("hvn", _inventory(vault=False, cluster=False, hvn=False)),
    ):
        plan = _plan(*[(address, ["no-op"]) for address in state])
        assert teardown.validate_plan(stage, plan, state) == set()


def test_unexpected_output_changes_are_rejected() -> None:
    state = _inventory()
    plan = _plan(
        *((address, ["delete"]) for address in teardown.VAULT_CHILDREN),
        outputs={"iam_audit_user_arn": ["delete"]},
    )
    with pytest.raises(teardown.UnsafePlan, match="unexpected output action"):
        teardown.validate_plan("vault-children", plan, state)


def test_generated_stage_config_uses_removed_blocks_and_only_stateful_aws_resources(
    tmp_path: Path,
) -> None:
    infra = REPO / "infra"
    generated = teardown.render_configuration(
        infra, "vault-children", "a" * 40, _inventory()
    )
    assert "terraform destroy" not in "\n".join(generated.values())
    assert generated["removed.tf"].count("removed {") == 11
    assert (
        'resource "aws_iam_role" "vault_audit_reader"' not in generated["aws_audit.tf"]
    )
    assert "prevent_destroy = true" in (infra / "aws_audit.tf").read_text()
    assert 'resource "hcp_vault_cluster" "customer_zero"' in generated["hcp_cluster.tf"]


def test_generated_hcp_stages_do_not_configure_or_authenticate_vault() -> None:
    hcp = teardown.render_configuration(
        REPO / "infra", "hcp-cluster", "a" * 40, _inventory(vault=False)
    )
    hvn = teardown.render_configuration(
        REPO / "infra", "hvn", "a" * 40, _inventory(vault=False, cluster=False)
    )
    for files in (hcp, hvn):
        assert 'provider "vault"' not in files["providers.tf"]
        assert "VAULT_TOKEN" not in "\n".join(files.values())
        assert "aws_cloudwatch_log_group.vault_audit" in files["aws_audit.tf"]
    assert "from = hcp_vault_cluster.customer_zero" in hcp["removed.tf"]
    assert "from = hcp_hvn.frostgate" in hvn["removed.tf"]
    assert 'resource "hcp_hvn" "frostgate"' in hcp["hcp_hvn.tf"]
    assert 'data "hcp_project" "frostgate_production"' in hcp["hcp_project.tf"]
    assert 'data "hcp_project" "frostgate_production"' in hvn["hcp_project.tf"]


@pytest.mark.parametrize(
    ("stage", "state"),
    [
        ("vault-children", _inventory()),
        ("hcp-cluster", _inventory(vault=False)),
        ("hvn", _inventory(vault=False, cluster=False)),
    ],
)
def test_generated_stage_configuration_is_terraform_formatted(
    tmp_path: Path, stage: str, state: set[str]
) -> None:
    destination = tmp_path / stage
    teardown.prepare(REPO / "infra", stage, destination, "a" * 40, state)
    result = subprocess.run(
        ["terraform", "fmt", "-check", "-recursive"],
        cwd=destination,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_generated_configuration_contains_no_credential_or_railway_resource() -> None:
    generated = teardown.render_configuration(
        REPO / "infra", "vault-children", "a" * 40, _inventory()
    )
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
            REPO / "infra", "vault-children", destination, "a" * 40, _inventory()
        )
