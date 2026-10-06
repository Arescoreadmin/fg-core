#!/usr/bin/env python3
"""Prepare and validate a staged, state-preserving Customer-Zero teardown.

The tool never runs Terraform apply/destroy. ``prepare`` reads the existing
remote state and writes an isolated configuration under /tmp. ``verify``
checks a saved plan and its current state inventory before a human may apply it.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


STAGES = ("enable-key-deletion", "vault-children", "hcp-cluster", "hvn")
AWS_CORE = {
    "aws_cloudwatch_log_group.vault_audit",
    "aws_iam_user.vault_audit",
    "aws_iam_policy.vault_audit",
    "aws_iam_user_policy_attachment.vault_audit",
}
AWS_READER = {
    "aws_iam_role.vault_audit_reader",
    "aws_iam_policy.vault_audit_reader",
    "aws_iam_role_policy_attachment.vault_audit_reader",
}
HCP_CLUSTER = "hcp_vault_cluster.customer_zero"
HCP_HVN = "hcp_hvn.frostgate"
VAULT_CHILDREN = {
    "vault_mount.transit",
    "vault_auth_backend.approle",
    "vault_policy.identity",
    "vault_policy.acceptance",
    "vault_policy.approval",
    "vault_approle_auth_backend_role.identity",
    "vault_approle_auth_backend_role.acceptance",
    "vault_approle_auth_backend_role.approval",
    "vault_transit_secret_backend_key.customer_zero_identity",
    "vault_transit_secret_backend_key.customer_zero_acceptance",
    "vault_transit_secret_backend_key.customer_zero_approval",
}
TRANSIT_KEYS = {
    "vault_transit_secret_backend_key.customer_zero_identity",
    "vault_transit_secret_backend_key.customer_zero_acceptance",
    "vault_transit_secret_backend_key.customer_zero_approval",
}
DATA_ADDRESSES = {"data.hcp_project.frostgate_production"}
TARGETS = {
    "enable-key-deletion": TRANSIT_KEYS,
    "vault-children": VAULT_CHILDREN,
    "hcp-cluster": {HCP_CLUSTER},
    "hvn": {HCP_HVN},
}
OUTPUTS_REMOVED = {
    "enable-key-deletion": set(),
    "vault-children": {
        "transit_key_identity",
        "transit_key_acceptance",
        "transit_key_approval",
        "policy_name_identity",
        "policy_name_acceptance",
        "policy_name_approval",
        "approle_role_id_identity",
        "approle_role_id_acceptance",
        "approle_role_id_approval",
    },
    "hcp-cluster": {
        "vault_cluster_id",
        "vault_cluster_tier",
        "vault_address",
        "vault_version",
    },
    "hvn": {"hcp_hvn_id"},
}


class UnsafePlan(ValueError):
    """A state inventory or saved plan violates the narrow teardown contract."""


def validate_inventory(stage: str, state_addresses: set[str]) -> None:
    """Reject unexpected state and require the resources needed for this stage."""
    if stage not in STAGES:
        raise UnsafePlan(f"unknown teardown stage: {stage}")
    managed = {
        address for address in state_addresses if not address.startswith("data.")
    }
    unexpected_data = {
        address for address in state_addresses if address.startswith("data.")
    } - DATA_ADDRESSES
    if unexpected_data:
        raise UnsafePlan(
            f"unexpected data-source state addresses: {', '.join(sorted(unexpected_data))}"
        )
    readers = managed & AWS_READER
    if readers and readers != AWS_READER:
        raise UnsafePlan("audit-reader resources are only safe as a complete trio")
    allowed = AWS_CORE | AWS_READER
    if stage in ("enable-key-deletion", "vault-children"):
        allowed |= {HCP_CLUSTER, HCP_HVN} | VAULT_CHILDREN
        required = AWS_CORE | {HCP_CLUSTER, HCP_HVN}
        if stage == "enable-key-deletion":
            required |= VAULT_CHILDREN
    elif stage == "hcp-cluster":
        allowed |= {HCP_CLUSTER, HCP_HVN}
        required = AWS_CORE | {HCP_HVN}
    else:
        allowed |= {HCP_CLUSTER, HCP_HVN}
        required = AWS_CORE
    if not required <= managed:
        missing = sorted(required - managed)
        raise UnsafePlan(f"required state addresses absent: {', '.join(missing)}")
    if (
        stage not in ("enable-key-deletion", "vault-children")
        and managed & VAULT_CHILDREN
    ):
        raise UnsafePlan("Vault child resources must be absent before HCP teardown")
    if stage == "hvn" and HCP_CLUSTER in managed:
        raise UnsafePlan("HCP Vault cluster must be absent before HVN teardown")
    unexpected = managed - allowed
    if unexpected:
        raise UnsafePlan(
            f"unexpected managed state addresses: {', '.join(sorted(unexpected))}"
        )


def validate_plan(
    stage: str, plan: dict[str, Any], state_addresses: set[str]
) -> set[str]:
    """Return the exact planned mutation set or fail closed on any other action."""
    validate_inventory(stage, state_addresses)
    managed = {
        address for address in state_addresses if not address.startswith("data.")
    }
    expected = managed & TARGETS[stage]
    actual: set[str] = set()
    seen_keys: set[str] = set()
    for change in plan.get("resource_changes", []):
        address = change.get("address", "")
        mode = change.get("mode", "managed")
        actions = change.get("change", {}).get("actions", [])
        if mode == "data" and actions in ([], ["no-op"], ["read"]):
            if address not in DATA_ADDRESSES:
                raise UnsafePlan(f"unexpected data-source plan address {address}")
            continue
        if mode != "managed":
            raise UnsafePlan(f"unexpected resource mode at {address}")
        if stage == "enable-key-deletion" and address in TRANSIT_KEYS:
            details = change.get("change", {})
            before = details.get("before") or {}
            values = details.get("after") or {}
            if actions not in (["no-op"], ["update"]):
                raise UnsafePlan(
                    f"unexpected key deletion-enablement action {actions} for {address}"
                )
            if values.get("deletion_allowed") is not True:
                raise UnsafePlan(
                    f"Transit key is not planned with deletion_allowed=true: {address}"
                )
            if actions == ["update"] and any(
                before.get(name) != values.get(name)
                for name in before.keys() | values.keys()
                if name != "deletion_allowed"
            ):
                raise UnsafePlan(
                    f"key enablement changes fields beyond deletion_allowed: {address}"
                )
            seen_keys.add(address)
            if actions == ["update"]:
                actual.add(address)
            continue
        if actions == ["no-op"]:
            if address not in managed:
                raise UnsafePlan(f"plan references untracked resource {address}")
            continue
        if actions == ["delete"] and address in TARGETS[stage]:
            if stage == "vault-children" and address in TRANSIT_KEYS:
                before = change.get("change", {}).get("before") or {}
                if before.get("deletion_allowed") is not True:
                    raise UnsafePlan(
                        f"Transit key deletion is not enabled in state: {address}"
                    )
            actual.add(address)
            continue
        raise UnsafePlan(f"unexpected action {actions} for {address}")
    if stage == "enable-key-deletion" and seen_keys != (managed & TRANSIT_KEYS):
        raise UnsafePlan("plan does not contain all tracked Transit keys")
    if stage != "enable-key-deletion" and actual != expected:
        raise UnsafePlan(
            f"plan destroy set differs from remaining {stage} state: "
            f"expected={sorted(expected)}, actual={sorted(actual)}"
        )
    allowed_outputs = OUTPUTS_REMOVED[stage]
    for name, change in plan.get("output_changes", {}).items():
        if change.get("actions") != ["delete"] or name not in allowed_outputs:
            raise UnsafePlan(f"unexpected output action for {name}")
    return actual


def extract_observed_values(
    raw_state: str, stage: str, state_addresses: set[str]
) -> dict[str, dict[str, Any]]:
    """Project only explicitly whitelisted non-secret attributes from Terraform state."""
    validate_inventory(stage, state_addresses)
    try:
        state = json.loads(raw_state)
    except json.JSONDecodeError as exc:
        raise UnsafePlan("Terraform state pull was not valid JSON") from exc

    required: dict[str, set[str]] = {
        "aws_iam_policy.vault_audit": {"description", "policy"}
    }
    if stage == "enable-key-deletion":
        required.update(
            {address: {"min_encryption_version"} for address in TRANSIT_KEYS}
        )

    found: dict[str, dict[str, Any]] = {}
    for resource in state.get("resources", []):
        if resource.get("mode") != "managed":
            continue
        module = resource.get("module")
        address = ".".join(
            part
            for part in (module, resource.get("type"), resource.get("name"))
            if part
        )
        if address not in required:
            continue
        instances = resource.get("instances", [])
        if len(instances) != 1:
            raise UnsafePlan(f"expected one state instance for {address}")
        attributes = instances[0].get("attributes") or {}
        if not required[address] <= attributes.keys():
            raise UnsafePlan(f"required observed attributes are absent for {address}")
        found[address] = {name: attributes[name] for name in required[address]}

    if set(found) != set(required):
        raise UnsafePlan(
            f"required observed state resources are absent: {sorted(set(required) - set(found))}"
        )
    policy = found["aws_iam_policy.vault_audit"].get("policy")
    description = found["aws_iam_policy.vault_audit"].get("description")
    if not isinstance(description, str) or not isinstance(policy, str):
        raise UnsafePlan("observed audit writer policy fields have invalid types")
    try:
        policy_document = json.loads(policy)
    except json.JSONDecodeError as exc:
        raise UnsafePlan("observed audit writer policy is not valid JSON") from exc
    if not isinstance(policy_document, dict):
        raise UnsafePlan("observed audit writer policy must be a JSON object")
    for address in TRANSIT_KEYS & set(found):
        version = found[address].get("min_encryption_version")
        if type(version) is not int or version < 0:
            raise UnsafePlan(
                f"observed min_encryption_version is invalid for {address}"
            )
    return found


def _run(argv: list[str], *, cwd: Path) -> str:
    """Run a local read-only command without ever echoing captured output on error."""
    result = subprocess.run(argv, cwd=cwd, check=False, capture_output=True, text=True)
    if result.returncode:
        raise UnsafePlan(
            f"read-only command failed ({argv[0]}, rc={result.returncode})"
        )
    return result.stdout


def _source_authority(repo: Path) -> str:
    branch = _run(["git", "branch", "--show-current"], cwd=repo).strip()
    head = _run(["git", "rev-parse", "HEAD"], cwd=repo).strip()
    origin = _run(["git", "rev-parse", "origin/main"], cwd=repo).strip()
    status = _run(["git", "status", "--porcelain"], cwd=repo)
    if branch != "main" or head != origin or status.strip():
        raise UnsafePlan("source authority requires clean main equal to origin/main")
    auth = _run(
        [
            sys.executable,
            "tools/ci/check_customer_one_roadmap.py",
            "--work-item",
            "CUSTOMER-ZERO-TRUST-001",
        ],
        cwd=repo,
    )
    if "AUTHORIZED" not in auth:
        raise UnsafePlan("roadmap authority did not report authorization")
    return head


def _matching_block(text: str, header: re.Match[str]) -> str:
    """Extract one simple top-level HCL block while respecting comments/strings."""
    opening = text.find("{", header.start())
    depth = 0
    quote = False
    escaped = False
    line_comment = False
    block_comment = False
    i = opening
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
        elif char == '"':
            quote = True
        elif char == "#" or (char == "/" and nxt == "/"):
            line_comment = True
            if char == "/":
                i += 1
        elif char == "/" and nxt == "*":
            block_comment = True
            i += 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[header.start() : i + 1].strip() + "\n"
        i += 1
    raise UnsafePlan("malformed source block encountered")


def _resource_block(source: str, address: str) -> str:
    return _source_block(source, "resource", address)


def _enable_key_deletion(source: str, address: str) -> str:
    """Change only the named Transit key's temporary teardown opt-in."""
    block = _resource_block(source, address)
    updated, count = re.subn(
        r"(?m)^(\s*deletion_allowed\s*=\s*)false\s*$",
        r"\1true",
        block,
    )
    if count != 1:
        raise UnsafePlan(f"expected one deletion_allowed=false in {address}")
    return source.replace(block, updated, 1)


def _replace_line_assignment(block: str, name: str, expression: str) -> str:
    pattern = re.compile(rf"(?m)^(\s*{re.escape(name)}\s*=\s*).+$")
    updated, count = pattern.subn(lambda match: match.group(1) + expression, block)
    if count != 1:
        raise UnsafePlan(f"expected one simple {name} assignment in temporary config")
    return updated


def _observed_writer_policy_block(source: str, observed: dict[str, Any]) -> str:
    address = "aws_iam_policy.vault_audit"
    block = _resource_block(source, address)
    block = _replace_line_assignment(
        block, "description", json.dumps(observed["description"])
    )
    # The canonical source expresses this policy as jsonencode({...}); the temporary
    # teardown root uses the exact state string so it preserves, rather than repairs,
    # the live policy while AWS resources are outside the approved mutation boundary.
    policy_pattern = re.compile(r"(?ms)^(\s*policy\s*=\s*)jsonencode\(\{.*?^\s*\}\)")
    block, count = policy_pattern.subn(
        lambda match: match.group(1) + json.dumps(observed["policy"]), block
    )
    if count != 1:
        raise UnsafePlan("could not safely project the observed audit writer policy")
    return block


def _data_block(source: str, address: str) -> str:
    if not address.startswith("data."):
        raise UnsafePlan(f"invalid data-source address: {address}")
    return _source_block(source, "data", address.removeprefix("data."))


def _source_block(source: str, block_type: str, address: str) -> str:
    resource_type, name = address.split(".", 1)
    header = re.search(
        rf'{re.escape(block_type)}\s+"{re.escape(resource_type)}"\s+'
        rf'"{re.escape(name)}"\s*\{{',
        source,
    )
    if not header:
        raise UnsafePlan(f"canonical {block_type} block absent for {address}")
    return _matching_block(source, header)


def _outputs_for(configured: set[str], source: str) -> str:
    blocks: list[str] = []
    for header in re.finditer(r'output\s+"[^"]+"\s*\{', source):
        block = _matching_block(source, header)
        name_match = re.match(r'output\s+"([^"]+)"', block)
        assert name_match is not None
        references = set(
            re.findall(r"\b(?:aws|hcp|vault)_[a-z0-9_]+\.[a-z0-9_]+", block)
        )
        # Output references without an active resource would invalidate the generated root.
        if references <= configured:
            blocks.append(block)
    return "\n\n".join(blocks) + ("\n" if blocks else "")


def render_configuration(
    infra: Path,
    stage: str,
    source_sha: str,
    state_addresses: set[str],
    observed_values: dict[str, dict[str, Any]],
) -> dict[str, str]:
    """Render the self-contained configuration for one stage from canonical source."""
    validate_inventory(stage, state_addresses)
    files: dict[str, str] = {
        "terraform.tf": (infra / "terraform.tf").read_text(encoding="utf-8"),
        "variables.tf": (infra / "variables.tf").read_text(encoding="utf-8"),
    }
    sources = {
        "aws": (infra / "aws_audit.tf").read_text(encoding="utf-8"),
        "hcp": (infra / "hcp_cluster.tf").read_text(encoding="utf-8"),
        "outputs": (infra / "outputs.tf").read_text(encoding="utf-8"),
    }
    aws_addresses = (state_addresses & AWS_CORE) | (state_addresses & AWS_READER)
    configured = set(aws_addresses)
    aws_blocks = []
    for address in sorted(aws_addresses):
        block = _resource_block(sources["aws"], address)
        if address == "aws_iam_policy.vault_audit":
            try:
                block = _observed_writer_policy_block(
                    sources["aws"], observed_values[address]
                )
            except KeyError as exc:
                raise UnsafePlan(
                    "observed audit writer policy values are required"
                ) from exc
        aws_blocks.append(block)

    if stage in ("enable-key-deletion", "vault-children"):
        hcp_source = sources["hcp"]
        configured |= {HCP_CLUSTER, HCP_HVN}
        files["hcp_cluster.tf"] = hcp_source
        provider_source = (infra / "providers.tf").read_text(encoding="utf-8")
        files["providers.tf"] = provider_source
        if stage == "enable-key-deletion":
            files["vault_transit.tf"] = (infra / "vault_transit.tf").read_text(
                encoding="utf-8"
            )
            files["vault_approle.tf"] = (infra / "vault_approle.tf").read_text(
                encoding="utf-8"
            )
            files["vault_policies.tf"] = (infra / "vault_policies.tf").read_text(
                encoding="utf-8"
            )
            for address in sorted(TRANSIT_KEYS):
                try:
                    observed_version = observed_values[address][
                        "min_encryption_version"
                    ]
                except KeyError as exc:
                    raise UnsafePlan(
                        f"observed min_encryption_version is required for {address}"
                    ) from exc
                key_block = _resource_block(files["vault_transit.tf"], address)
                versioned = _replace_line_assignment(
                    key_block, "min_encryption_version", str(observed_version)
                )
                files["vault_transit.tf"] = files["vault_transit.tf"].replace(
                    key_block, versioned, 1
                )
                files["vault_transit.tf"] = _enable_key_deletion(
                    files["vault_transit.tf"], address
                )
            configured |= VAULT_CHILDREN
            removed = []
        else:
            removed = sorted(VAULT_CHILDREN)
    else:
        files["providers.tf"] = (
            'provider "hcp" {\n  project_id = var.hcp_project_id\n}\n\n'
            'provider "aws" {\n  region = var.aws_region\n}\n'
        )
        files["terraform.tf"] = _terraform_without_vault(infra / "terraform.tf")
        files["hcp_project.tf"] = _data_block(
            sources["hcp"], "data.hcp_project.frostgate_production"
        )
        if stage == "hcp-cluster":
            files["hcp_hvn.tf"] = _resource_block(sources["hcp"], HCP_HVN)
            configured.add(HCP_HVN)
            removed = [HCP_CLUSTER]
        else:
            removed = [HCP_HVN]

    files["aws_audit.tf"] = "\n\n".join(aws_blocks) + "\n"
    files["removed.tf"] = (
        "\n".join(
            f"removed {{\n  from = {address}\n  lifecycle {{ destroy = true }}\n}}"
            for address in removed
        )
        + "\n"
    )
    files["outputs.tf"] = _outputs_for(configured, sources["outputs"])
    files["CEREMONY_SOURCE_SHA.txt"] = source_sha + "\n"
    files["README.txt"] = (
        f"Generated stage: {stage}\nSource SHA: {source_sha}\n"
        "Temporary plan configuration. Do not commit this directory or its saved plans.\n"
    )
    return files


def _terraform_without_vault(source_path: Path) -> str:
    """Keep backend and exact HCP/AWS provider constraints, excluding Vault."""
    source = source_path.read_text(encoding="utf-8")
    cloud = re.search(r"  cloud\s*\{.*?^  \}\n", source, re.MULTILINE | re.DOTALL)
    hcp = re.search(r"    hcp\s*=\s*\{[^}]+\}", source)
    aws = re.search(r"    aws\s*=\s*\{[^}]+\}", source)
    if not cloud or not hcp or not aws:
        raise UnsafePlan("canonical Terraform Cloud/provider configuration not found")
    return (
        'terraform {\n  required_version = "~> 1.16"\n\n'
        f"{cloud.group(0)}\n  required_providers {{\n{hcp.group(0)}\n{aws.group(0)}\n  }}\n}}\n"
    )


def prepare(
    infra: Path,
    stage: str,
    output_dir: Path,
    source_sha: str,
    state_addresses: set[str],
    observed_values: dict[str, dict[str, Any]],
) -> None:
    temp_root = Path(tempfile.gettempdir()).resolve()
    resolved = output_dir.resolve()
    if temp_root not in resolved.parents:
        raise UnsafePlan(
            "generated configuration must be placed under the system temporary directory"
        )
    if output_dir.exists():
        raise UnsafePlan("output directory already exists; refusing to overwrite")
    files = render_configuration(
        infra, stage, source_sha, state_addresses, observed_values
    )
    output_dir.mkdir(mode=0o700, parents=True)
    for name, content in files.items():
        path = output_dir / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
    lock = infra / ".terraform.lock.hcl"
    if lock.exists():
        shutil.copyfile(lock, output_dir / ".terraform.lock.hcl")
        (output_dir / ".terraform.lock.hcl").chmod(0o600)
    fmt = subprocess.run(
        ["terraform", "fmt", "-recursive"],
        cwd=output_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    if fmt.returncode:
        raise UnsafePlan(
            "Terraform could not format the generated temporary configuration"
        )
    print(f"PREPARED stage={stage} source_sha={source_sha} directory={output_dir}")
    print(
        f"MANAGED_STATE_COUNT={len([a for a in state_addresses if not a.startswith('data.')])}"
    )


def _state_addresses(cwd: Path) -> set[str]:
    output = _run(["terraform", "state", "list"], cwd=cwd)
    return {line.strip() for line in output.splitlines() if line.strip()}


def verify(stage: str, plan_path: Path, cwd: Path) -> None:
    repo = Path(__file__).resolve().parents[2]
    source_sha = _source_authority(repo)
    recorded_sha_path = cwd / "CEREMONY_SOURCE_SHA.txt"
    try:
        recorded_sha = recorded_sha_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise UnsafePlan("generated source authority record is unavailable") from exc
    if recorded_sha != source_sha:
        raise UnsafePlan(
            "repository source changed since temporary configuration generation"
        )
    state = _state_addresses(cwd)
    raw = _run(["terraform", "show", "-json", str(plan_path)], cwd=cwd)
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UnsafePlan("Terraform did not return valid plan JSON") from exc
    mutations = validate_plan(stage, plan, state)
    action = (
        "UPDATE deletion_allowed=true" if stage == "enable-key-deletion" else "DESTROY"
    )
    print(f"PLAN_SAFE stage={stage} action_count={len(mutations)}")
    for address in sorted(mutations):
        print(f"{action} {address}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--stage", choices=STAGES, required=True)
    prep.add_argument("--output-dir", type=Path, required=True)
    check = sub.add_parser("verify")
    check.add_argument("--stage", choices=STAGES, required=True)
    check.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args()
    try:
        script = Path(__file__).resolve()
        repo = script.parents[2]
        if args.command == "prepare":
            sha = _source_authority(repo)
            infra = repo / "infra"
            state = _state_addresses(infra)
            state_json = _run(["terraform", "state", "pull"], cwd=infra)
            observed_values = extract_observed_values(state_json, args.stage, state)
            prepare(infra, args.stage, args.output_dir, sha, state, observed_values)
        else:
            verify(args.stage, args.plan, Path.cwd())
    except (OSError, UnsafePlan) as exc:
        print(f"UNSAFE: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
