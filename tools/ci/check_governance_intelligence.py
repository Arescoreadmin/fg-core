#!/usr/bin/env python3
"""tools/ci/check_governance_intelligence.py

Gate: verify the Governance Intelligence Authority (PR 18.5) is correctly
wired and internally consistent.

Checks (12):
  1. Explainability module exists and has required functions
  2. Simulation module exists and has required functions
  3. Policy lifecycle module exists and valid transitions defined
  4. Policy diff module exists and has required functions
  5. Benchmarking module exists and anonymize_benchmark strips tenant_id
  6. Confidence module exists and has required functions
  7. External event adapter abstraction (ExternalEventProviderBase exists)
  8. Federation abstraction exists and build_governance_summary never exposes tenant_id
  9. Authority registered in authority_manifest.yaml
  10. No duplicated business logic (governance_intelligence doesn't import from governance_orchestration engine)
  11. DB models file exists with expected tables
  12. Router file exists with /intelligence/health route

Exits 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent.parent

SERVICE_DIR = ROOT / "services" / "governance_intelligence"
API_ROUTER = ROOT / "api" / "governance_intelligence.py"
DB_MODELS = ROOT / "api" / "db_models_governance_intelligence.py"
MIGRATION = ROOT / "migrations" / "postgres" / "0146_governance_intelligence.sql"
AUTHORITY_MANIFEST = ROOT / "authority_manifest.yaml"

REQUIRED_ORM_CLASSES = [
    "GovIntelSimulation",
    "GovIntelSimulationHistory",
    "GovIntelPolicy",
    "GovIntelPolicyVersion",
    "GovIntelBenchmark",
    "GovIntelExternalEvent",
    "GovIntelFederation",
    "GovIntelExplainability",
    "GovIntelConfidenceHistory",
    "GovIntelTimeline",
]

REQUIRED_ROUTE_PREFIX = "/intelligence"
HEALTH_ROUTE = "/intelligence/health"
MINIMUM_ROUTE_COUNT = 30

_CLASS_RE = re.compile(r"^\s*class\s+(\w+)", re.MULTILINE)
_FUNC_OR_CLASS_RE = re.compile(r"^\s*(?:class|def|async\s+def)\s+(\w+)", re.MULTILINE)
_ROUTE_STR_RE = re.compile(r'@router\.\w+\(\s*["\']([^"\']+)["\']', re.MULTILINE)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _declared_classes(text: str) -> set[str]:
    return set(_CLASS_RE.findall(text))


def _declared_names(text: str) -> set[str]:
    return set(_FUNC_OR_CLASS_RE.findall(text))


def _extract_routes(text: str) -> list[str]:
    return _ROUTE_STR_RE.findall(text)


def main() -> int:
    parser = argparse.ArgumentParser(description="Governance Intelligence Gate")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []

    def fail(msg: str) -> None:
        failures.append(msg)

    def vprint(msg: str) -> None:
        if args.verbose:
            print(msg)

    # 1. Explainability module exists and has required functions
    vprint("Check 1: explainability module")
    expl_path = SERVICE_DIR / "explainability.py"
    if not expl_path.exists():
        fail("Missing: services/governance_intelligence/explainability.py")
    else:
        text = _read(expl_path) or ""
        names = _declared_names(text)
        for fn in ("build_explanation", "format_explanation_text", "diff_impacts"):
            if fn not in names:
                fail(f"explainability.py: missing function '{fn}'")

    # 2. Simulation module exists and has required functions
    vprint("Check 2: simulation module")
    sim_path = SERVICE_DIR / "simulation.py"
    if not sim_path.exists():
        fail("Missing: services/governance_intelligence/simulation.py")
    else:
        text = _read(sim_path) or ""
        names = _declared_names(text)
        for fn in (
            "validate_simulation_parameters",
            "run_simulation",
            "compute_simulation_diff",
        ):
            if fn not in names:
                fail(f"simulation.py: missing function '{fn}'")
        # All outputs must be labeled PROJECTED
        if "PROJECTED" not in text:
            fail("simulation.py: outputs must be labeled 'PROJECTED'")
        if "is_production" not in text:
            fail("simulation.py: outputs must include 'is_production' flag")

    # 3. Policy lifecycle module exists and valid transitions defined
    vprint("Check 3: policy lifecycle module")
    lifecycle_path = SERVICE_DIR / "policy_lifecycle.py"
    if not lifecycle_path.exists():
        fail("Missing: services/governance_intelligence/policy_lifecycle.py")
    else:
        text = _read(lifecycle_path) or ""
        names = _declared_names(text)
        if "VALID_TRANSITIONS" not in text:
            fail("policy_lifecycle.py: missing VALID_TRANSITIONS dict")
        for fn in ("validate_transition", "is_mutable"):
            if fn not in names:
                fail(f"policy_lifecycle.py: missing function '{fn}'")

    # 4. Policy diff module exists and has required functions
    vprint("Check 4: policy diff module")
    diff_path = SERVICE_DIR / "policy_diff.py"
    if not diff_path.exists():
        fail("Missing: services/governance_intelligence/policy_diff.py")
    else:
        text = _read(diff_path) or ""
        names = _declared_names(text)
        for fn in (
            "diff_policy_data",
            "compute_governance_impact",
            "format_diff_summary",
        ):
            if fn not in names:
                fail(f"policy_diff.py: missing function '{fn}'")

    # 5. Benchmarking module exists and anonymize_benchmark strips tenant_id
    vprint("Check 5: benchmarking module")
    bench_path = SERVICE_DIR / "benchmarking.py"
    if not bench_path.exists():
        fail("Missing: services/governance_intelligence/benchmarking.py")
    else:
        text = _read(bench_path) or ""
        names = _declared_names(text)
        for fn in (
            "compute_percentile",
            "assign_tier",
            "anonymize_benchmark",
            "compute_benchmark_summary",
        ):
            if fn not in names:
                fail(f"benchmarking.py: missing function '{fn}'")
        # anonymize_benchmark must NOT return tenant_id
        # Simple check: tenant_id must not be in the return dict keys
        if '"tenant_id"' in text and "anonymize_benchmark" in text:
            # Find the function body and ensure tenant_id is not returned
            # We look for the return statement — it should not contain "tenant_id"
            fn_match = re.search(
                r"def anonymize_benchmark.*?(?=\ndef |\Z)", text, re.DOTALL
            )
            if fn_match:
                fn_body = fn_match.group(0)
                if '"tenant_id"' in fn_body:
                    fail(
                        "benchmarking.py: anonymize_benchmark must not include "
                        "tenant_id in output"
                    )

    # 6. Confidence module exists and has required functions
    vprint("Check 6: confidence module")
    conf_path = SERVICE_DIR / "confidence.py"
    if not conf_path.exists():
        fail("Missing: services/governance_intelligence/confidence.py")
    else:
        text = _read(conf_path) or ""
        names = _declared_names(text)
        for fn in (
            "compute_data_freshness_score",
            "compute_coverage_score",
            "compute_sample_confidence",
            "compute_overall_confidence",
            "build_confidence_response",
        ):
            if fn not in names:
                fail(f"confidence.py: missing function '{fn}'")

    # 7. External event adapter abstraction (ExternalEventProviderBase exists)
    vprint("Check 7: external event abstraction")
    ext_path = SERVICE_DIR / "external_events.py"
    if not ext_path.exists():
        fail("Missing: services/governance_intelligence/external_events.py")
    else:
        text = _read(ext_path) or ""
        classes = _declared_classes(text)
        if "ExternalEventProviderBase" not in classes:
            fail("external_events.py: missing class ExternalEventProviderBase")
        names = _declared_names(text)
        if "validate_external_event" not in names:
            fail("external_events.py: missing function validate_external_event")
        if "normalize_event" not in names:
            fail("external_events.py: missing function normalize_event")

    # 8. Federation abstraction exists and build_governance_summary never exposes tenant_id
    vprint("Check 8: federation abstraction")
    fed_path = SERVICE_DIR / "federation.py"
    if not fed_path.exists():
        fail("Missing: services/governance_intelligence/federation.py")
    else:
        text = _read(fed_path) or ""
        names = _declared_names(text)
        if "build_governance_summary" not in names:
            fail("federation.py: missing function build_governance_summary")
        if "VALID_ROLES" not in text:
            fail("federation.py: missing VALID_ROLES")
        # build_governance_summary must NOT include tenant_id in output
        fn_match = re.search(
            r"def build_governance_summary.*?(?=\ndef |\Z)", text, re.DOTALL
        )
        if fn_match:
            fn_body = fn_match.group(0)
            # The output dict should not contain "tenant_id" as a key
            if '"tenant_id"' in fn_body:
                # Only fail if it appears in the return dict (not just a comment)
                # Check for "tenant_id" as a literal key in the returned dict
                return_section = re.search(r"return\s*\{.*?\}", fn_body, re.DOTALL)
                if return_section and '"tenant_id"' in return_section.group(0):
                    fail(
                        "federation.py: build_governance_summary must not include "
                        "tenant_id in output"
                    )

    # 9. Authority registered in authority_manifest.yaml
    vprint("Check 9: authority_manifest")
    if not AUTHORITY_MANIFEST.exists():
        fail(f"Missing: {AUTHORITY_MANIFEST.relative_to(ROOT)}")
    else:
        text = _read(AUTHORITY_MANIFEST) or ""
        if "governance_intelligence:" not in text:
            fail(
                f"{AUTHORITY_MANIFEST.relative_to(ROOT)}: "
                "'governance_intelligence:' entry not found"
            )

    # 10. No duplicated business logic — governance_intelligence must not import from governance_orchestration engine
    vprint("Check 10: no cross-authority engine imports")
    forbidden_import = "from services.governance_orchestration.engine"
    for py_file in (SERVICE_DIR).glob("*.py"):
        text = _read(py_file) or ""
        if forbidden_import in text:
            fail(
                f"{py_file.relative_to(ROOT)}: forbidden import "
                f"'{forbidden_import}' — intelligence must not import from orchestration engine"
            )

    # 11. DB models file exists with expected tables
    vprint("Check 11: ORM models")
    if not DB_MODELS.exists():
        fail(f"Missing: {DB_MODELS.relative_to(ROOT)}")
    else:
        text = _read(DB_MODELS) or ""
        classes = _declared_classes(text)
        for name in REQUIRED_ORM_CLASSES:
            if name not in classes:
                fail(f"{DB_MODELS.relative_to(ROOT)}: missing ORM class '{name}'")
        # Verify append-only guards
        if "before_update" not in text or "before_delete" not in text:
            fail(
                f"{DB_MODELS.relative_to(ROOT)}: expected ORM before_update/"
                "before_delete guards on append-only tables"
            )

    # 12. Router file exists with /intelligence/health route
    vprint("Check 12: router file")
    if not API_ROUTER.exists():
        fail(f"Missing: {API_ROUTER.relative_to(ROOT)}")
    else:
        text = _read(API_ROUTER) or ""
        routes = _extract_routes(text)
        if HEALTH_ROUTE not in routes:
            fail(f"{API_ROUTER.relative_to(ROOT)}: missing route '{HEALTH_ROUTE}'")
        matching = [
            r
            for r in routes
            if r == REQUIRED_ROUTE_PREFIX or r.startswith(REQUIRED_ROUTE_PREFIX)
        ]
        if len(matching) < MINIMUM_ROUTE_COUNT:
            fail(
                f"{API_ROUTER.relative_to(ROOT)}: expected at least "
                f"{MINIMUM_ROUTE_COUNT} routes under {REQUIRED_ROUTE_PREFIX!r}, "
                f"found {len(matching)}"
            )

    if failures:
        print(f"\nGovernance Intelligence Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  x  {f}")
        return 1

    print("Governance Intelligence Gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
