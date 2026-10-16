"""
CUSTOMER-ZERO-RUN3-AWS-AUDIT-LIFECYCLE-001 — Adversarial tests for FP-005
remediation.

Protects the 3 WRITER IAM resources (aws_iam_user.vault_audit,
aws_iam_policy.vault_audit, aws_iam_user_policy_attachment.vault_audit)
with `lifecycle { prevent_destroy = true }`, matching the CloudWatch log
group (already protected) and the 2 READER resources (protected in PR #761).

Positive tests validate the current `infra/aws_audit.tf` and the static gate.
Negative tests use `tmp_path` fixtures — production Terraform is never
modified by this suite.

Work class: REPAIR (hardening) — always authorized.
Cloud mutations: 0. Spending authorization: unchanged. Live trust: unchanged.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).parent.parent
AWS_AUDIT_TF = REPO / "infra" / "aws_audit.tf"
CEREMONY_STATE = REPO / "customer_one" / "ceremony_state.yaml"
GATE_SCRIPT = REPO / "tools" / "ci" / "check_aws_audit_lifecycle.py"

# Import the gate module directly for in-process parsing checks.
sys.path.insert(0, str(REPO))
from tools.ci.check_aws_audit_lifecycle import (  # noqa: E402
    PROTECTED_ADDRESSES,
    READER_ADDRESSES,
    check_tf_file,
    find_lifecycle_blocks,
    parse_resource_blocks,
)

WRITER_IAM_ADDRESSES = [
    ("aws_iam_user", "vault_audit"),
    ("aws_iam_policy", "vault_audit"),
    ("aws_iam_user_policy_attachment", "vault_audit"),
]


# ---------------------------------------------------------------------------
# Helpers for building temp fixtures from the real file
# ---------------------------------------------------------------------------


def _read_real_tf() -> str:
    return AWS_AUDIT_TF.read_text()


def _write_tmp_tf(tmp_path: Path, content: str) -> Path:
    """Write a Terraform fixture to tmp_path/aws_audit.tf."""
    p = tmp_path / "aws_audit.tf"
    p.write_text(content)
    return p


def _blocks_by_address(tf_text: str) -> dict[str, tuple[int, int]]:
    """Return {address: (start, end)} for every top-level resource block."""
    return {b.address: (b.start, b.end) for b in parse_resource_blocks(tf_text)}


def _remove_lifecycle_from_block(tf_text: str, type_: str, name: str) -> str:
    """Delete the first `lifecycle { prevent_destroy = true }` block inside the
    named resource. Falls back to removing any lifecycle inside the block."""
    blocks = _blocks_by_address(tf_text)
    start, end = blocks[f"{type_}.{name}"]
    block = tf_text[start:end]
    # Remove the entire lifecycle block
    marker = "lifecycle {"
    idx = block.find(marker)
    if idx == -1:
        return tf_text
    # Find matching closing brace of the lifecycle block
    depth = 0
    i = idx + len(marker) - 1  # at the '{'
    while i < len(block):
        if block[i] == "{":
            depth += 1
        elif block[i] == "}":
            depth -= 1
            if depth == 0:
                # Strip trailing newline/whitespace prior to lifecycle too
                stripped_start = idx
                while stripped_start > 0 and block[stripped_start - 1] in " \t":
                    stripped_start -= 1
                if stripped_start > 0 and block[stripped_start - 1] == "\n":
                    stripped_start -= 1
                new_block = block[:stripped_start] + block[i + 1 :]
                return tf_text[:start] + new_block + tf_text[end:]
        i += 1
    return tf_text


def _flip_prevent_destroy_false(tf_text: str, type_: str, name: str) -> str:
    blocks = _blocks_by_address(tf_text)
    start, end = blocks[f"{type_}.{name}"]
    block = tf_text[start:end]
    new_block = block.replace("prevent_destroy = true", "prevent_destroy = false", 1)
    return tf_text[:start] + new_block + tf_text[end:]


def _delete_block(tf_text: str, type_: str, name: str) -> str:
    blocks = _blocks_by_address(tf_text)
    start, end = blocks[f"{type_}.{name}"]
    # Also eat the trailing newline so we don't leave an empty line
    stop = end
    if stop < len(tf_text) and tf_text[stop] == "\n":
        stop += 1
    return tf_text[:start] + tf_text[stop:]


def _rename_block(tf_text: str, type_: str, name: str, new_name: str) -> str:
    """Rename a top-level resource (only the name token)."""
    blocks = _blocks_by_address(tf_text)
    start, _end = blocks[f"{type_}.{name}"]
    header = tf_text[start:]
    target = f'resource "{type_}" "{name}"'
    replacement = f'resource "{type_}" "{new_name}"'
    assert header.startswith(target), header[:80]
    return tf_text[:start] + replacement + header[len(target) :]


def _duplicate_lifecycle(tf_text: str, type_: str, name: str) -> str:
    """Insert an extra top-level lifecycle block inside the named resource."""
    blocks = _blocks_by_address(tf_text)
    start, end = blocks[f"{type_}.{name}"]
    block = tf_text[start:end]
    # Insert an extra lifecycle block just before the final closing brace.
    assert block.endswith("}")
    insertion = "\n  lifecycle {\n    prevent_destroy = true\n  }\n"
    new_block = block[:-1] + insertion + "}"
    return tf_text[:start] + new_block + tf_text[end:]


def _run_gate_cli(tf_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE_SCRIPT), "--tf", str(tf_path)],
        capture_output=True,
        text=True,
    )


# ===========================================================================
# POSITIVE TESTS — must pass on the current repo state
# ===========================================================================


def test_p001_all_three_writer_iam_resources_present():
    """P-001: All 3 WRITER IAM resources are present in aws_audit.tf."""
    tf = _read_real_tf()
    addresses = _blocks_by_address(tf)
    for type_, name in WRITER_IAM_ADDRESSES:
        assert f"{type_}.{name}" in addresses, (
            f"missing required WRITER resource {type_}.{name}"
        )


def test_p002_writer_resources_have_prevent_destroy_true():
    """P-002: Each of the 3 WRITER IAM resources has prevent_destroy = true."""
    tf = _read_real_tf()
    blocks = parse_resource_blocks(tf)
    by_addr = {b.address: b for b in blocks}
    for type_, name in WRITER_IAM_ADDRESSES:
        block = by_addr[f"{type_}.{name}"]
        lifecycles = find_lifecycle_blocks(block.body)
        assert len(lifecycles) == 1, (
            f"{type_}.{name}: expected exactly 1 lifecycle block, got {len(lifecycles)}"
        )
        assert "prevent_destroy = true" in lifecycles[0], (
            f"{type_}.{name}: lifecycle block missing prevent_destroy = true"
        )


def test_p003_reader_resources_also_protected_regression():
    """P-003 regression: READER resources protected by PR #761 remain protected."""
    tf = _read_real_tf()
    blocks = parse_resource_blocks(tf)
    by_addr = {b.address: b for b in blocks}
    for type_, name in READER_ADDRESSES:
        block = by_addr[f"{type_}.{name}"]
        lifecycles = find_lifecycle_blocks(block.body)
        assert len(lifecycles) == 1, (
            f"READER regression: {type_}.{name} has {len(lifecycles)} lifecycle blocks"
        )
        assert "prevent_destroy = true" in lifecycles[0], (
            f"READER regression: {type_}.{name} lost prevent_destroy = true"
        )


def test_p004_no_duplicate_lifecycle_blocks_on_any_protected_resource():
    """P-004: No protected resource has duplicate lifecycle blocks."""
    tf = _read_real_tf()
    blocks = parse_resource_blocks(tf)
    by_addr = {b.address: b for b in blocks}
    for type_, name in PROTECTED_ADDRESSES:
        block = by_addr[f"{type_}.{name}"]
        lifecycles = find_lifecycle_blocks(block.body)
        assert len(lifecycles) == 1, (
            f"{type_}.{name}: expected 1 lifecycle block, got {len(lifecycles)}"
        )


def test_p005_terraform_file_parses_cleanly():
    """P-005: The real aws_audit.tf parses cleanly (balanced braces, strings)."""
    tf = _read_real_tf()
    blocks = parse_resource_blocks(tf)
    # Must find at least the 6 protected resources
    assert len(blocks) >= 6
    # Every block body is parseable for lifecycle discovery
    for b in blocks:
        find_lifecycle_blocks(b.body)


def test_p006_static_gate_passes_on_current_tree():
    """P-006: tools/ci/check_aws_audit_lifecycle.py exits 0 on current repo."""
    result = _run_gate_cli(AWS_AUDIT_TF)
    assert result.returncode == 0, (
        f"gate failed on current repo: stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "PASS" in result.stdout


def test_p007_gate_inventory_matches_ceremony_state():
    """P-007: Gate's PROTECTED_ADDRESSES matches ceremony_state preserved list."""
    import yaml

    state = yaml.safe_load(CEREMONY_STATE.read_text())
    preserved = {
        r["address"] for r in state["cost_containment"]["preserved_aws_resources"]
    }
    gate_addresses = {f"{t}.{n}" for t, n in PROTECTED_ADDRESSES}
    assert gate_addresses == preserved, (
        f"gate inventory mismatch: gate={gate_addresses}, ceremony={preserved}"
    )


# ===========================================================================
# NEGATIVE TESTS — gate MUST fail-closed on each tampering fixture
# ===========================================================================


def test_n001_removed_prevent_destroy_from_first_writer_detected(tmp_path):
    """N-001: Removing prevent_destroy from aws_iam_user.vault_audit → gate FAILs."""
    tampered = _remove_lifecycle_from_block(
        _read_real_tf(), "aws_iam_user", "vault_audit"
    )
    tf = _write_tmp_tf(tmp_path, tampered)
    ok, messages = check_tf_file(tf)
    assert ok is False
    assert any("aws_iam_user.vault_audit" in m and "FAIL" in m for m in messages)


def test_n002_prevent_destroy_false_on_second_writer_detected(tmp_path):
    """N-002: prevent_destroy = false on aws_iam_policy.vault_audit → gate FAILs."""
    tampered = _flip_prevent_destroy_false(
        _read_real_tf(), "aws_iam_policy", "vault_audit"
    )
    tf = _write_tmp_tf(tmp_path, tampered)
    ok, messages = check_tf_file(tf)
    assert ok is False
    assert any(
        "aws_iam_policy.vault_audit" in m and "false" in m.lower() for m in messages
    )


def test_n003_third_writer_resource_block_deleted_detected(tmp_path):
    """N-003: Deleting aws_iam_user_policy_attachment.vault_audit → gate FAILs."""
    tampered = _delete_block(
        _read_real_tf(), "aws_iam_user_policy_attachment", "vault_audit"
    )
    tf = _write_tmp_tf(tmp_path, tampered)
    ok, messages = check_tf_file(tf)
    assert ok is False
    assert any(
        "aws_iam_user_policy_attachment.vault_audit" in m and "not found" in m
        for m in messages
    )


def test_n004_protected_resource_renamed_detected(tmp_path):
    """N-004: Renaming a protected resource → gate FAILs (inventory mismatch)."""
    tampered = _rename_block(
        _read_real_tf(),
        "aws_iam_user",
        "vault_audit",
        "vault_audit_renamed",
    )
    tf = _write_tmp_tf(tmp_path, tampered)
    ok, messages = check_tf_file(tf)
    assert ok is False
    assert any("aws_iam_user.vault_audit" in m and "not found" in m for m in messages)


def test_n005_duplicate_lifecycle_block_detected(tmp_path):
    """N-005: Duplicate lifecycle blocks on a protected resource → gate FAILs."""
    tampered = _duplicate_lifecycle(_read_real_tf(), "aws_iam_user", "vault_audit")
    tf = _write_tmp_tf(tmp_path, tampered)
    ok, messages = check_tf_file(tf)
    assert ok is False
    assert any(
        "aws_iam_user.vault_audit" in m and "duplicate" in m.lower() for m in messages
    )


def test_n006_empty_file_fails_closed(tmp_path):
    """N-006a: Empty Terraform file → gate fails closed (exit 1, no exception)."""
    tf = _write_tmp_tf(tmp_path, "")
    ok, messages = check_tf_file(tf)
    assert ok is False
    # Every protected address should report as not found
    missing_count = sum(1 for m in messages if "not found" in m)
    assert missing_count == len(PROTECTED_ADDRESSES)


def test_n006b_malformed_hcl_fails_closed(tmp_path):
    """N-006b: Malformed HCL (unterminated block) → gate fails closed, not raise."""
    # Unterminated resource block
    tampered = 'resource "aws_iam_user" "vault_audit" {\n  name = "x"\n'
    tf = _write_tmp_tf(tmp_path, tampered)
    ok, messages = check_tf_file(tf)
    assert ok is False
    # Either the parse error OR the missing addresses path must trip
    assert any("FAIL" in m for m in messages)


def test_n007_cli_exits_1_on_tampered_fixture(tmp_path):
    """N-007: CLI script exits 1 (not 0) on tampered fixture."""
    tampered = _remove_lifecycle_from_block(
        _read_real_tf(), "aws_iam_user", "vault_audit"
    )
    tf = _write_tmp_tf(tmp_path, tampered)
    result = _run_gate_cli(tf)
    assert result.returncode == 1
    assert "FAIL" in result.stdout


def test_n008_cli_exits_1_on_missing_file(tmp_path):
    """N-008: CLI exits 1 (fail-closed), not crash, when target file is absent."""
    missing = tmp_path / "does_not_exist.tf"
    result = _run_gate_cli(missing)
    assert result.returncode == 1
    assert "FAIL" in result.stdout


def test_n009_block_commented_resource_fails_closed(tmp_path):
    """N-009: Protected resource wrapped in /* ... */ block comment → gate FAILs.

    A block comment is valid HCL that Terraform ignores entirely. The gate must
    not count a commented-out resource as present.
    """
    tf_real = _read_real_tf()
    blocks = _blocks_by_address(tf_real)
    start, end = blocks["aws_iam_user.vault_audit"]
    # Wrap the entire resource block in a /* ... */ comment
    tampered = tf_real[:start] + "/*\n" + tf_real[start:end] + "\n*/" + tf_real[end:]
    tf = _write_tmp_tf(tmp_path, tampered)
    ok, messages = check_tf_file(tf)
    assert ok is False, (
        "gate must FAIL when a protected resource is inside a block comment"
    )
    assert any("aws_iam_user.vault_audit" in m and "not found" in m for m in messages)


def test_n010_line_commented_prevent_destroy_fails_closed(tmp_path):
    """N-010: `# prevent_destroy = true` inside lifecycle block → gate FAILs.

    A line comment is valid HCL that Terraform ignores. The gate must not
    accept a commented-out prevent_destroy assignment as real protection.
    """
    tf_real = _read_real_tf()
    # Replace the real setting with a commented-out version inside the block
    tampered = tf_real.replace(
        "    prevent_destroy = true",
        "    # prevent_destroy = true",
        1,  # only the first occurrence (aws_cloudwatch_log_group.vault_audit)
    )
    tf = _write_tmp_tf(tmp_path, tampered)
    ok, messages = check_tf_file(tf)
    assert ok is False, "gate must FAIL when prevent_destroy is commented out with #"
    assert any(
        "lifecycle block missing prevent_destroy" in m or "prevent_destroy" in m
        for m in messages
    )
