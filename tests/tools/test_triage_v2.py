from __future__ import annotations

from tools.testing.harness.triage_report import _classify


CASES = {
    "CONTRACT_DRIFT": ["error: openapi contract mismatch"],
    "DUPLICATE_ROUTES": ["fatal duplicate route detected in route conflict"],
    "PLANE_REGISTRY_DRIFT": ["plane registry ownership_map mismatch"],
    "AUTH_SCOPE_MISMATCH": ["forbidden: missing scope control-plane:read"],
    "TENANT_ISOLATION_BREACH": ["cross-tenant isolation regression"],
    "RLS_MISSING_OR_WEAK": ["RLS policy missing for testing_runs"],
    "SSRF_GUARD_FAILURE": ["ssrf metadata endpoint 169.254.169.254 reachable"],
    "MIGRATION_RISK": ["migration rollback failed due to ddl lock"],
    "TIME_BUDGET_EXCEEDED": ["time budget exceeded for fg-fast"],
    "FLAKE_SUSPECTED": ["flaky rerun oscillating pass/fail"],
}


def test_triage_known_categories_confidence_and_excerpt_bounds() -> None:
    for category, log_lines in CASES.items():
        out = _classify(log_lines, lane="fg-fast")
        assert out["triage_schema_version"] == "2.0"
        assert out["category"] == category
        assert out["confidence"] >= 0.8
        assert len(out["evidence"]["log_excerpt"]) <= 30


def test_triage_unknown_only_when_no_pattern_matches() -> None:
    out = _classify(["totally novel failure signature"], lane="fg-fast")
    assert out["category"] == "UNKNOWN"


def test_triage_is_deterministic() -> None:
    lines = ["error: openapi contract mismatch", "File tests/a.py::test"]
    left = _classify(lines, lane="fg-contract")
    right = _classify(lines, lane="fg-contract")
    assert left == right
