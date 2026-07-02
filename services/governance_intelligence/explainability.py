"""Explainability utilities for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from typing import Any


def build_explanation(
    trigger: str,
    policy_version: str,
    evaluation: dict[str, Any],
    decision: str,
    authorities_invoked: list[str],
    expected_impact: dict[str, Any],
    observed_impact: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a human-readable explanation structure for a governance decision."""
    return {
        "trigger": trigger,
        "policy_version": policy_version,
        "evaluation": evaluation,
        "decision": decision,
        "authorities_invoked": authorities_invoked,
        "expected_impact": expected_impact,
        "observed_impact": observed_impact,
        "impact_delta": diff_impacts(expected_impact, observed_impact or {}),
        "summary": (
            f"Decision '{decision}' triggered by '{trigger}' "
            f"under policy v{policy_version}. "
            f"{len(authorities_invoked)} authorit{'y' if len(authorities_invoked) == 1 else 'ies'} invoked."
        ),
    }


def format_explanation_text(explanation: dict[str, Any]) -> str:
    """Produce a formatted text version of an explanation."""
    lines = [
        "Governance Decision Explanation",
        "================================",
        f"Trigger:         {explanation.get('trigger', 'unknown')}",
        f"Policy Version:  {explanation.get('policy_version', 'unknown')}",
        f"Decision:        {explanation.get('decision', 'unknown')}",
        "",
        "Authorities Invoked:",
    ]
    for auth in explanation.get("authorities_invoked", []):
        lines.append(f"  - {auth}")

    lines += [
        "",
        "Expected Impact:",
    ]
    for k, v in explanation.get("expected_impact", {}).items():
        lines.append(f"  {k}: {v}")

    observed = explanation.get("observed_impact")
    if observed:
        lines += ["", "Observed Impact:"]
        for k, v in observed.items():
            lines.append(f"  {k}: {v}")

    delta = explanation.get("impact_delta", {})
    if delta:
        lines += ["", "Impact Delta:"]
        for k, v in delta.items():
            lines.append(f"  {k}: {v}")

    return "\n".join(lines)


def diff_impacts(expected: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    """Compute delta between expected and observed impact dictionaries."""
    delta: dict[str, Any] = {}
    all_keys = set(expected.keys()) | set(observed.keys())
    for key in all_keys:
        exp_val = expected.get(key)
        obs_val = observed.get(key)
        if exp_val is None and obs_val is None:
            continue
        if isinstance(exp_val, (int, float)) and isinstance(obs_val, (int, float)):
            delta[key] = {
                "expected": exp_val,
                "observed": obs_val,
                "absolute_delta": obs_val - exp_val,
                "pct_delta": (
                    round((obs_val - exp_val) / abs(exp_val) * 100, 2)
                    if exp_val != 0
                    else None
                ),
            }
        else:
            delta[key] = {
                "expected": exp_val,
                "observed": obs_val,
                "changed": exp_val != obs_val,
            }
    return delta
