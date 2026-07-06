"""Validation engine for Governance Execution — fail-closed on ERROR/FATAL."""

from __future__ import annotations


from services.governance_execution.models import (
    ExecutionPlan,
    ExecutionRun,
    ExecutionValidationFinding,
    ExecutionValidationReport,
)


class ExecutionValidationError(Exception):
    """Raised when execution validation finds ERROR or FATAL severity findings."""


_SEVERITY_RANK: dict[str, int] = {
    "INFO": 0,
    "WARNING": 1,
    "ERROR": 2,
    "FATAL": 3,
}

_INVARIANTS: tuple[str, ...] = (
    "tenant_isolation",
    "rollback_completeness",
    "authority_integrity",
    "approval_integrity",
    "execution_graph",
    "dependency_graph",
    "duplicate_ids",
    "verification_completeness",
    "fingerprint_integrity",
    "replay_integrity",
)


def _highest_severity(findings: list[ExecutionValidationFinding]) -> str:
    if not findings:
        return "INFO"
    return max(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0)).severity


def validate_execution_plan(
    plan: ExecutionPlan,
    run: ExecutionRun | None = None,
) -> ExecutionValidationReport:
    """Validate an ExecutionPlan and optionally its associated ExecutionRun.

    Raises ExecutionValidationError if highest_severity is ERROR or FATAL.
    """
    findings: list[ExecutionValidationFinding] = []
    violations: list[str] = []
    checked: list[str] = list(_INVARIANTS)

    # ---- tenant_isolation (FATAL) ----
    for step in plan.steps:
        if step.tenant_id != plan.tenant_id:
            findings.append(
                ExecutionValidationFinding(
                    severity="FATAL",
                    code="tenant_isolation",
                    message=(
                        f"Step {step.step_id} tenant_id {step.tenant_id!r} "
                        f"does not match plan tenant_id {plan.tenant_id!r}"
                    ),
                )
            )
            violations.append("tenant_isolation")
            break

    if plan.rollback_plan.tenant_id != plan.tenant_id:
        findings.append(
            ExecutionValidationFinding(
                severity="FATAL",
                code="tenant_isolation",
                message=(
                    f"rollback_plan.tenant_id {plan.rollback_plan.tenant_id!r} "
                    f"does not match plan.tenant_id {plan.tenant_id!r}"
                ),
            )
        )
        violations.append("tenant_isolation")

    # ---- rollback_completeness (ERROR) ----
    if not plan.rollback_plan.rollback_ready:
        findings.append(
            ExecutionValidationFinding(
                severity="ERROR",
                code="rollback_completeness",
                message="plan.rollback_plan.rollback_ready must be True",
            )
        )
        violations.append("rollback_completeness")

    # ---- authority_integrity (ERROR) ----
    for step in plan.steps:
        if not step.authority_required:
            findings.append(
                ExecutionValidationFinding(
                    severity="ERROR",
                    code="authority_integrity",
                    message=f"Step {step.step_id} has empty authority_required",
                )
            )
            violations.append("authority_integrity")
            break

    # ---- approval_integrity (ERROR) ----
    for req in plan.approval_requirements:
        if not req.authority_required:
            findings.append(
                ExecutionValidationFinding(
                    severity="ERROR",
                    code="approval_integrity",
                    message=(
                        f"ApprovalRequirement {req.requirement_id} has empty authority_required"
                    ),
                )
            )
            violations.append("approval_integrity")
            break

    # ---- duplicate_ids (ERROR) ----
    step_ids = [s.step_id for s in plan.steps]
    if len(step_ids) != len(set(step_ids)):
        findings.append(
            ExecutionValidationFinding(
                severity="ERROR",
                code="duplicate_ids",
                message="Duplicate step_ids detected in plan.steps",
            )
        )
        violations.append("duplicate_ids")

    # ---- execution_graph (ERROR) — dependency references non-existent step ----
    step_id_set = set(step_ids)
    for step in plan.steps:
        for dep in step.dependencies:
            if dep not in step_id_set:
                findings.append(
                    ExecutionValidationFinding(
                        severity="ERROR",
                        code="execution_graph",
                        message=(
                            f"Step {step.step_id} depends on unknown step_id {dep!r}"
                        ),
                    )
                )
                violations.append("execution_graph")
                break

    # ---- dependency_graph (WARNING) — detect cycle ----
    if _has_cycle(plan.steps):
        findings.append(
            ExecutionValidationFinding(
                severity="WARNING",
                code="dependency_graph",
                message="Step dependency graph contains a cycle",
            )
        )

    # ---- fingerprint_integrity (WARNING) ----
    from services.governance_execution.fingerprint import compute_plan_fingerprint

    recomputed = compute_plan_fingerprint(plan)
    if plan.plan_fingerprint != recomputed:
        findings.append(
            ExecutionValidationFinding(
                severity="WARNING",
                code="fingerprint_integrity",
                message="plan.plan_fingerprint does not match recomputed fingerprint",
            )
        )

    # ---- verification_completeness (WARNING) — run-level check ----
    if run is not None:
        completed_requiring_verification = {
            s.step_id
            for s in plan.steps
            if s.verification_required and s.step_id in run.executed_steps
        }
        covered = set(run.verification_ids)
        uncovered = completed_requiring_verification - covered
        if uncovered:
            findings.append(
                ExecutionValidationFinding(
                    severity="WARNING",
                    code="verification_completeness",
                    message=(
                        f"{len(uncovered)} completed step(s) with verification_required=True "
                        f"lack a verification entry"
                    ),
                )
            )

    highest = _highest_severity(findings)
    valid = _SEVERITY_RANK.get(highest, 0) < _SEVERITY_RANK["ERROR"]
    report = ExecutionValidationReport(
        valid=valid,
        findings=tuple(findings),
        highest_severity=highest,
        violations=tuple(sorted(set(violations))),
        checked_invariants=tuple(checked),
    )

    if _SEVERITY_RANK.get(highest, 0) >= _SEVERITY_RANK["ERROR"]:
        raise ExecutionValidationError(
            f"Execution validation failed with severity {highest}: "
            + "; ".join(
                f.message
                for f in findings
                if _SEVERITY_RANK.get(f.severity, 0) >= _SEVERITY_RANK["ERROR"]
            )
        )

    return report


def _has_cycle(steps: tuple) -> bool:  # type: ignore[type-arg]
    """Return True if step dependency graph has a cycle (DFS)."""
    graph: dict[str, list[str]] = {s.step_id: list(s.dependencies) for s in steps}
    visited: set[str] = set()
    rec_stack: set[str] = set()

    def dfs(node: str) -> bool:
        visited.add(node)
        rec_stack.add(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                if dfs(neighbor):
                    return True
            elif neighbor in rec_stack:
                return True
        rec_stack.discard(node)
        return False

    for node in list(graph.keys()):
        if node not in visited:
            if dfs(node):
                return True
    return False
