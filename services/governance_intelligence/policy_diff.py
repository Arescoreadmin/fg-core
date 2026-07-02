"""Policy diff utilities for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from typing import Any


def diff_policy_data(
    old_data: dict[str, Any], new_data: dict[str, Any]
) -> dict[str, Any]:
    """Return dict with added_rules, removed_rules, threshold_changes, approval_changes, key_changes."""
    old_rules = set(str(r) for r in old_data.get("rules", []))
    new_rules = set(str(r) for r in new_data.get("rules", []))

    added_rules = [r for r in new_data.get("rules", []) if str(r) not in old_rules]
    removed_rules = [r for r in old_data.get("rules", []) if str(r) not in new_rules]

    # Threshold changes: compare numeric threshold keys
    threshold_changes: list[dict[str, Any]] = []
    old_thresholds = old_data.get("thresholds", {})
    new_thresholds = new_data.get("thresholds", {})
    all_threshold_keys = set(old_thresholds.keys()) | set(new_thresholds.keys())
    for key in sorted(all_threshold_keys):
        old_val = old_thresholds.get(key)
        new_val = new_thresholds.get(key)
        if old_val != new_val:
            threshold_changes.append({"key": key, "from": old_val, "to": new_val})

    # Approval changes
    approval_changes: list[dict[str, Any]] = []
    old_approvals = old_data.get("approvals", {})
    new_approvals = new_data.get("approvals", {})
    all_approval_keys = set(old_approvals.keys()) | set(new_approvals.keys())
    for key in sorted(all_approval_keys):
        old_val = old_approvals.get(key)
        new_val = new_approvals.get(key)
        if old_val != new_val:
            approval_changes.append({"key": key, "from": old_val, "to": new_val})

    # General key changes (top-level keys excluding rules/thresholds/approvals)
    skip_keys = {"rules", "thresholds", "approvals"}
    all_keys = (set(old_data.keys()) | set(new_data.keys())) - skip_keys
    key_changes: list[dict[str, Any]] = []
    for key in sorted(all_keys):
        old_val = old_data.get(key)
        new_val = new_data.get(key)
        if old_val != new_val:
            key_changes.append({"key": key, "from": old_val, "to": new_val})

    return {
        "added_rules": added_rules,
        "removed_rules": removed_rules,
        "threshold_changes": threshold_changes,
        "approval_changes": approval_changes,
        "key_changes": key_changes,
    }


def compute_governance_impact(diff: dict[str, Any]) -> dict[str, Any]:
    """Estimate governance impact based on what changed."""
    added = len(diff.get("added_rules", []))
    removed = len(diff.get("removed_rules", []))
    threshold_changes = len(diff.get("threshold_changes", []))
    approval_changes = len(diff.get("approval_changes", []))
    key_changes = len(diff.get("key_changes", []))

    total_changes = added + removed + threshold_changes + approval_changes + key_changes

    if total_changes == 0:
        impact_level = "NONE"
    elif removed > 0 or approval_changes > 0:
        impact_level = "HIGH"
    elif threshold_changes > 0:
        impact_level = "MEDIUM"
    elif added > 0:
        impact_level = "LOW"
    else:
        impact_level = "LOW"

    return {
        "impact_level": impact_level,
        "total_changes": total_changes,
        "rules_added": added,
        "rules_removed": removed,
        "threshold_changes": threshold_changes,
        "approval_changes": approval_changes,
        "key_changes": key_changes,
        "requires_reassessment": impact_level in {"HIGH", "MEDIUM"},
    }


def format_diff_summary(diff: dict[str, Any]) -> str:
    """Human-readable summary of a policy diff."""
    parts: list[str] = []

    added = diff.get("added_rules", [])
    removed = diff.get("removed_rules", [])
    threshold_changes = diff.get("threshold_changes", [])
    approval_changes = diff.get("approval_changes", [])
    key_changes = diff.get("key_changes", [])

    if added:
        parts.append(f"{len(added)} rule(s) added")
    if removed:
        parts.append(f"{len(removed)} rule(s) removed")
    if threshold_changes:
        parts.append(f"{len(threshold_changes)} threshold change(s)")
    if approval_changes:
        parts.append(f"{len(approval_changes)} approval change(s)")
    if key_changes:
        parts.append(f"{len(key_changes)} key change(s)")

    if not parts:
        return "No changes detected."
    return "Policy changes: " + ", ".join(parts) + "."
