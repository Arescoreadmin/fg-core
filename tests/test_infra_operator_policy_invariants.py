"""
Regression tests for FrostGateTerraformOperatorPolicy in bootstrap-operator-role.sh.

Live-proven defect: logs:TagResource scoped to a specific not-yet-existing log-group ARN
cannot satisfy CreateLogGroup-with-Tags IAM evaluation (CUSTOMER-ZERO-TRUST-001, 2026-10-02).
Fix: two-statement design —
  CloudWatchLogGroup:    exact ARN, all lifecycle actions including TagResource (post-creation)
  CloudWatchLogGroupTag: account/region log-group wildcard, TagResource only,
                         constrained by ForAllValues:StringEquals on aws:TagKeys and
                         StringEquals on aws:RequestTag/* for the 3 fixed ceremony values

These tests fail if:
- the creation-time tagging defect is reintroduced
- log-group tagging authority is silently broadened to Resource:"*"
- CloudWatchLogGroupTag wildcard conditions are removed or weakened
- any CloudWatch action is replaced with a wildcard action
- operator role trust or MFA requirement is weakened
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

BOOTSTRAP = (
    Path(__file__).parent.parent / "infra" / "scripts" / "bootstrap-operator-role.sh"
)

REGION = "us-east-1"
ACCOUNT_ID = "398915901105"

SPECIFIC_LOG_GROUP_ARN = (
    f"arn:aws:logs:{REGION}:{ACCOUNT_ID}:log-group:/frostgate/customer-zero/vault-audit"
)
LOG_GROUP_WILDCARD_ARN = f"arn:aws:logs:{REGION}:{ACCOUNT_ID}:log-group:*"


def _extract_heredoc(script: str, var_name: str) -> str:
    """Extract the content of a bash heredoc assigned to var_name."""
    pattern = rf"{var_name}=\$\(cat <<['\"]?(\w+)['\"]?\n(.*?)\n\1\n\)"
    m = re.search(pattern, script, re.DOTALL)
    if not m:
        raise ValueError(f"Heredoc for {var_name} not found in bootstrap script")
    return m.group(2)


def _bash_vars(script: str) -> dict[str, str]:
    """Extract simple scalar variable assignments from the bootstrap script."""
    base: dict[str, str] = {"REGION": REGION, "ACCOUNT_ID": ACCOUNT_ID}
    for m in re.finditer(r'^(\w+)="([^"]*)"', script, re.MULTILINE):
        base[m.group(1)] = m.group(2)
    # Resolve one level of ${VAR} references in the collected values.
    resolved: dict[str, str] = {}
    for k, v in base.items():
        for name, val in base.items():
            v = v.replace(f"${{{name}}}", val)
        resolved[k] = v
    return resolved


def _render(template: str, extra: dict[str, str] | None = None) -> str:
    """Substitute bash variable references with ceremony values."""
    result = template.replace("${REGION}", REGION).replace("${ACCOUNT_ID}", ACCOUNT_ID)
    if extra:
        for k, v in extra.items():
            result = result.replace(f"${{{k}}}", v)
    return result


@pytest.fixture(scope="module")
def permissions_policy() -> dict:
    script = BOOTSTRAP.read_text()
    raw = _extract_heredoc(script, "PERMISSIONS_POLICY")
    rendered = _render(raw)
    return json.loads(rendered)


@pytest.fixture(scope="module")
def statements_by_sid(permissions_policy: dict) -> dict[str, dict]:
    return {s["Sid"]: s for s in permissions_policy["Statement"]}


@pytest.fixture(scope="module")
def final_trust_policy() -> dict:
    script = BOOTSTRAP.read_text()
    raw = _extract_heredoc(script, "FINAL_TRUST")
    return json.loads(_render(raw, extra=_bash_vars(script)))


# ── A: CloudWatchLogGroupTag statement exists ─────────────────────────────────


def test_cloudwatch_log_group_tag_statement_exists(
    statements_by_sid: dict[str, dict],
) -> None:
    assert "CloudWatchLogGroupTag" in statements_by_sid, (
        "CloudWatchLogGroupTag statement is missing — "
        "creation-time tagging will fail with AccessDenied"
    )


# ── B: CloudWatchLogGroupTag action is exactly logs:TagResource ───────────────


def test_cloudwatch_log_group_tag_action(
    statements_by_sid: dict[str, dict],
) -> None:
    stmt = statements_by_sid["CloudWatchLogGroupTag"]
    action = stmt["Action"]
    # Accept both scalar and single-element list
    if isinstance(action, list):
        assert action == [
            "logs:TagResource"
        ], f"CloudWatchLogGroupTag Action must be exactly logs:TagResource, got {action}"
    else:
        assert (
            action == "logs:TagResource"
        ), f"CloudWatchLogGroupTag Action must be exactly logs:TagResource, got {action}"


# ── C: CloudWatchLogGroupTag resource is account/region log-group wildcard ────


def test_cloudwatch_log_group_tag_resource(
    statements_by_sid: dict[str, dict],
) -> None:
    stmt = statements_by_sid["CloudWatchLogGroupTag"]
    resource = stmt["Resource"]
    assert resource == LOG_GROUP_WILDCARD_ARN, (
        f"CloudWatchLogGroupTag Resource must be {LOG_GROUP_WILDCARD_ARN!r}, got {resource!r} — "
        "too narrow to satisfy CreateLogGroup-with-Tags IAM evaluation"
    )


# ── D: CloudWatchLogGroupTag wildcard is constrained by tag-key/value conditions ─


def test_cloudwatch_log_group_tag_conditions(
    statements_by_sid: dict[str, dict],
) -> None:
    stmt = statements_by_sid["CloudWatchLogGroupTag"]
    cond = stmt.get("Condition", {})
    allowed_keys = cond.get("ForAllValues:StringEquals", {}).get("aws:TagKeys", [])
    assert set(allowed_keys) == {
        "Purpose",
        "Ceremony",
        "ManagedBy",
        "WorkItem",
    }, (
        f"CloudWatchLogGroupTag must constrain aws:TagKeys to the 4 ceremony keys, "
        f"got {allowed_keys!r} — wildcard resource without conditions allows tagging "
        "any log group in the account"
    )
    fixed = cond.get("StringEquals", {})
    assert (
        fixed.get("aws:RequestTag/Purpose") == "vault-audit"
    ), "CloudWatchLogGroupTag must require aws:RequestTag/Purpose == vault-audit"
    assert (
        fixed.get("aws:RequestTag/ManagedBy") == "terraform"
    ), "CloudWatchLogGroupTag must require aws:RequestTag/ManagedBy == terraform"
    assert (
        fixed.get("aws:RequestTag/WorkItem") == "CUSTOMER-ZERO-TRUST-001"
    ), "CloudWatchLogGroupTag must require aws:RequestTag/WorkItem == CUSTOMER-ZERO-TRUST-001"


# ── E: CloudWatchLogGroup remains scoped to the exact audit log group ─────────


def test_cloudwatch_log_group_resource_is_specific(
    statements_by_sid: dict[str, dict],
) -> None:
    stmt = statements_by_sid["CloudWatchLogGroup"]
    resource = stmt["Resource"]
    assert (
        resource == SPECIFIC_LOG_GROUP_ARN
    ), f"CloudWatchLogGroup Resource must remain {SPECIFIC_LOG_GROUP_ARN!r}, got {resource!r}"


# ── F: no CloudWatch statement uses a wildcard action (logs:*) ────────────────


def test_no_wildcard_cloudwatch_action(statements_by_sid: dict[str, dict]) -> None:
    cw_sids = {k for k in statements_by_sid if k.startswith("CloudWatch")}
    for sid in cw_sids:
        actions = statements_by_sid[sid]["Action"]
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            assert (
                action != "logs:*"
            ), f"Statement {sid!r} grants logs:* — CloudWatch authority must be explicit"
            assert not action.endswith(
                ":*"
            ), f"Statement {sid!r} grants wildcard action {action!r}"


# ── G: no CloudWatch tagging statement uses Resource:"*" ─────────────────────


def test_no_tagging_resource_star(statements_by_sid: dict[str, dict]) -> None:
    for sid, stmt in statements_by_sid.items():
        actions = stmt["Action"]
        if isinstance(actions, str):
            actions = [actions]
        if "logs:TagResource" in actions:
            assert stmt["Resource"] != "*", (
                f'Statement {sid!r} grants logs:TagResource on Resource:"*" — '
                "scope must be limited to account/region log-group ARN"
            )


# ── H: operator role trust still requires MFA from exact human user ──────────


def test_operator_role_trust_requires_mfa(final_trust_policy: dict) -> None:
    statements = final_trust_policy["Statement"]
    assert len(statements) == 1, "FINAL_TRUST must have exactly one statement"
    stmt = statements[0]
    condition = stmt.get("Condition", {})
    mfa = condition.get("Bool", {}).get("aws:MultiFactorAuthPresent") or condition.get(
        "Bool", {}
    ).get("aws:MultiFactorAuthPresent".lower())
    assert mfa in (
        "true",
        True,
    ), "FrostGateTerraformOperator trust policy must require aws:MultiFactorAuthPresent"


def test_operator_role_trust_principal_is_human_user(
    final_trust_policy: dict,
) -> None:
    stmt = final_trust_policy["Statement"][0]
    principal = stmt["Principal"]["AWS"]
    expected = f"arn:aws:iam::{ACCOUNT_ID}:user/frostgate/frostgate-terraform-human"
    assert (
        principal == expected
    ), f"FINAL_TRUST principal must be {expected!r}, got {principal!r}"
