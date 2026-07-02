#!/usr/bin/env python3
"""tools/ci/check_governance_provenance.py

Gate: verify the Governance Intelligence Evidence Graph & Decision Provenance
(PR 18.5A) is correctly wired and internally consistent.

Checks (12):
  1. provenance.py exists with ProvenanceGraph class and required methods
  2. ProvenanceGraph.detect_cycles() returns empty list for acyclic graph (runtime check)
  3. counterfactual.py — all outputs labeled PROJECTED and is_production=false
  4. replay.py — all outputs labeled REPLAY and is_production=false
  5. evidence_matrix.py — raises error when evidence_ids is empty
  6. quality_score.py — grades are exactly ["A+", "A", "B", "C", "INSUFFICIENT_EVIDENCE"]
  7. benchmark_confidence.py — MINIMUM_SAMPLE_SIZE and MINIMUM_COHORT_SIZE defined
  8. timeline_diff.py — SUPPORTED_WINDOWS defined and non-empty
  9. simulation_compare.py — comparison_label is "DETERMINISTIC_COMPARISON"
  10. evidence_impact.py — IMPACT_CHAIN is defined and has correct length (10 entries)
  11. export_package.py — compute_package_hash uses sha256
  12. Migration file 0147 exists

Exits 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent.parent
SERVICE_DIR = ROOT / "services" / "governance_intelligence"
MIGRATION_0147 = (
    ROOT / "migrations" / "postgres" / "0147_governance_intelligence_provenance.sql"
)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Governance Provenance Gate")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []

    def fail(msg: str) -> None:
        failures.append(msg)

    def vprint(msg: str) -> None:
        if args.verbose:
            print(msg)

    # -----------------------------------------------------------------------
    # Check 1: provenance.py exists with ProvenanceGraph class and required methods
    # -----------------------------------------------------------------------
    vprint("Check 1: provenance.py exists with ProvenanceGraph and required methods")
    prov_path = SERVICE_DIR / "provenance.py"
    if not prov_path.exists():
        fail("Missing: services/governance_intelligence/provenance.py")
    else:
        text = _read(prov_path) or ""
        if "class ProvenanceGraph" not in text:
            fail("provenance.py: missing class ProvenanceGraph")
        for method in (
            "add_node",
            "get_node",
            "get_ancestors",
            "get_descendants",
            "detect_cycles",
            "export_graph",
            "to_sorted_list",
        ):
            if method not in text:
                fail(f"provenance.py: missing method '{method}'")
        if "build_node" not in text:
            fail("provenance.py: missing function 'build_node'")
        if "compute_node_digest" not in text:
            fail("provenance.py: missing function 'compute_node_digest'")

    # -----------------------------------------------------------------------
    # Check 2: ProvenanceGraph.detect_cycles() returns [] for acyclic graph
    # -----------------------------------------------------------------------
    vprint("Check 2: detect_cycles() returns empty list for acyclic graph")
    try:
        import sys as _sys

        _sys.path.insert(0, str(ROOT))
        from services.governance_intelligence.provenance import (  # type: ignore
            ProvenanceGraph,
            ProvenanceNode,
        )

        g = ProvenanceGraph()
        n1 = ProvenanceNode(
            id="node1",
            node_type="EVIDENCE",
            authority="test",
            authority_version="1.0",
            source_object_id="obj1",
            sha256_digest="aaa",
            timestamp="2026-01-01T00:00:00Z",
            parent_ids=[],
            child_ids=["node2"],
        )
        n2 = ProvenanceNode(
            id="node2",
            node_type="FINDING",
            authority="test",
            authority_version="1.0",
            source_object_id="obj2",
            sha256_digest="bbb",
            timestamp="2026-01-01T00:00:00Z",
            parent_ids=["node1"],
            child_ids=[],
        )
        g.add_node(n1)
        g.add_node(n2)
        cycles = g.detect_cycles()
        if cycles:
            fail(
                f"provenance.ProvenanceGraph.detect_cycles(): expected [] for acyclic graph, got {cycles}"
            )
    except Exception as exc:
        fail(f"provenance.py runtime check failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 3: counterfactual.py — PROJECTED + is_production=false
    # -----------------------------------------------------------------------
    vprint(
        "Check 3: counterfactual.py outputs labeled PROJECTED and is_production=false"
    )
    cf_path = SERVICE_DIR / "counterfactual.py"
    if not cf_path.exists():
        fail("Missing: services/governance_intelligence/counterfactual.py")
    else:
        text = _read(cf_path) or ""
        if '"PROJECTED"' not in text and "'PROJECTED'" not in text:
            fail("counterfactual.py: result_label 'PROJECTED' not found")
        if "is_production" not in text:
            fail("counterfactual.py: is_production flag not found")
        if "False" not in text and "false" not in text:
            fail("counterfactual.py: is_production must be False")
        # Runtime check
        try:
            from services.governance_intelligence.counterfactual import (
                run_counterfactual,
            )  # type: ignore

            result = run_counterfactual(
                "POLICY_ROLLBACK", {"governance_score": 0.7}, {"rollback_severity": 0.2}
            )
            if result.get("result_label") != "PROJECTED":
                fail(
                    f"counterfactual: result_label expected 'PROJECTED', got {result.get('result_label')!r}"
                )
            if result.get("is_production") is not False:
                fail(
                    f"counterfactual: is_production expected False, got {result.get('is_production')!r}"
                )
        except Exception as exc:
            fail(f"counterfactual.py runtime check failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 4: replay.py — REPLAY + is_production=false
    # -----------------------------------------------------------------------
    vprint("Check 4: replay.py outputs labeled REPLAY and is_production=false")
    replay_path = SERVICE_DIR / "replay.py"
    if not replay_path.exists():
        fail("Missing: services/governance_intelligence/replay.py")
    else:
        text = _read(replay_path) or ""
        if '"REPLAY"' not in text and "'REPLAY'" not in text:
            fail("replay.py: replay_label 'REPLAY' not found")
        if "is_production" not in text:
            fail("replay.py: is_production flag not found")
        # Runtime check
        try:
            from services.governance_intelligence.replay import (
                build_replay_snapshot,
                replay_governance,
            )  # type: ignore

            snap = build_replay_snapshot(
                policy_version="1.0",
                evidence_snapshot={"e1": "val"},
                trust_version="1.0",
                transparency_snapshot={},
                time_window={"start": "2026-01-01", "end": "2026-06-01"},
            )
            result = replay_governance(snap)
            if result.get("replay_label") != "REPLAY":
                fail(
                    f"replay: replay_label expected 'REPLAY', got {result.get('replay_label')!r}"
                )
            if result.get("is_production") is not False:
                fail(
                    f"replay: is_production expected False, got {result.get('is_production')!r}"
                )
        except Exception as exc:
            fail(f"replay.py runtime check failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 5: evidence_matrix.py — raises error when evidence_ids is empty
    # -----------------------------------------------------------------------
    vprint("Check 5: evidence_matrix.py raises error when evidence_ids is empty")
    em_path = SERVICE_DIR / "evidence_matrix.py"
    if not em_path.exists():
        fail("Missing: services/governance_intelligence/evidence_matrix.py")
    else:
        try:
            from services.governance_intelligence.evidence_matrix import (
                build_evidence_matrix,
            )  # type: ignore
            from services.governance_intelligence.schemas import (
                GovernanceIntelligenceValidationError,
            )  # type: ignore

            raised = False
            try:
                build_evidence_matrix(
                    recommendation_id="rec1",
                    evidence_ids=[],
                    control_ids=[],
                    framework_ids=[],
                    verification_ids=[],
                    trust_refs=[],
                    transparency_refs=[],
                    risk_factors=[],
                    confidence=0.8,
                    expected_improvement=0.1,
                    simulation_ids=[],
                )
            except GovernanceIntelligenceValidationError:
                raised = True
            except Exception:
                raised = True
            if not raised:
                fail(
                    "evidence_matrix.build_evidence_matrix(): must raise when evidence_ids is empty"
                )
        except Exception as exc:
            fail(f"evidence_matrix.py runtime check failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 6: quality_score.py — grades exactly ["A+", "A", "B", "C", "INSUFFICIENT_EVIDENCE"]
    # -----------------------------------------------------------------------
    vprint("Check 6: quality_score.py QUALITY_GRADES are exactly correct")
    qs_path = SERVICE_DIR / "quality_score.py"
    if not qs_path.exists():
        fail("Missing: services/governance_intelligence/quality_score.py")
    else:
        try:
            from services.governance_intelligence.quality_score import QUALITY_GRADES  # type: ignore

            expected_grades = ["A+", "A", "B", "C", "INSUFFICIENT_EVIDENCE"]
            if QUALITY_GRADES != expected_grades:
                fail(
                    f"quality_score.QUALITY_GRADES expected {expected_grades}, got {QUALITY_GRADES}"
                )
        except Exception as exc:
            fail(f"quality_score.py runtime check failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 7: benchmark_confidence.py — MINIMUM_SAMPLE_SIZE and MINIMUM_COHORT_SIZE defined
    # -----------------------------------------------------------------------
    vprint("Check 7: benchmark_confidence.py constants defined")
    bc_path = SERVICE_DIR / "benchmark_confidence.py"
    if not bc_path.exists():
        fail("Missing: services/governance_intelligence/benchmark_confidence.py")
    else:
        text = _read(bc_path) or ""
        if "MINIMUM_SAMPLE_SIZE" not in text:
            fail("benchmark_confidence.py: missing MINIMUM_SAMPLE_SIZE")
        if "MINIMUM_COHORT_SIZE" not in text:
            fail("benchmark_confidence.py: missing MINIMUM_COHORT_SIZE")
        try:
            from services.governance_intelligence.benchmark_confidence import (  # type: ignore
                MINIMUM_SAMPLE_SIZE,
                MINIMUM_COHORT_SIZE,
            )

            if not isinstance(MINIMUM_SAMPLE_SIZE, int) or MINIMUM_SAMPLE_SIZE <= 0:
                fail(
                    f"benchmark_confidence.MINIMUM_SAMPLE_SIZE must be a positive int, got {MINIMUM_SAMPLE_SIZE!r}"
                )
            if not isinstance(MINIMUM_COHORT_SIZE, int) or MINIMUM_COHORT_SIZE <= 0:
                fail(
                    f"benchmark_confidence.MINIMUM_COHORT_SIZE must be a positive int, got {MINIMUM_COHORT_SIZE!r}"
                )
        except ImportError as exc:
            fail(f"benchmark_confidence.py import failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 8: timeline_diff.py — SUPPORTED_WINDOWS defined and non-empty
    # -----------------------------------------------------------------------
    vprint("Check 8: timeline_diff.py SUPPORTED_WINDOWS defined and non-empty")
    td_path = SERVICE_DIR / "timeline_diff.py"
    if not td_path.exists():
        fail("Missing: services/governance_intelligence/timeline_diff.py")
    else:
        try:
            from services.governance_intelligence.timeline_diff import SUPPORTED_WINDOWS  # type: ignore

            if not SUPPORTED_WINDOWS:
                fail("timeline_diff.SUPPORTED_WINDOWS must not be empty")
        except Exception as exc:
            fail(f"timeline_diff.py runtime check failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 9: simulation_compare.py — comparison_label is "DETERMINISTIC_COMPARISON"
    # -----------------------------------------------------------------------
    vprint(
        "Check 9: simulation_compare.py comparison_label is 'DETERMINISTIC_COMPARISON'"
    )
    sc_path = SERVICE_DIR / "simulation_compare.py"
    if not sc_path.exists():
        fail("Missing: services/governance_intelligence/simulation_compare.py")
    else:
        text = _read(sc_path) or ""
        if "DETERMINISTIC_COMPARISON" not in text:
            fail(
                "simulation_compare.py: comparison_label 'DETERMINISTIC_COMPARISON' not found"
            )
        try:
            from services.governance_intelligence.simulation_compare import (
                compare_simulations,
            )  # type: ignore

            result = compare_simulations(
                {"id": "a", "governance_score": 0.6},
                {"id": "b", "governance_score": 0.8},
            )
            if result.get("comparison_label") != "DETERMINISTIC_COMPARISON":
                fail(
                    f"simulation_compare: comparison_label expected 'DETERMINISTIC_COMPARISON', got {result.get('comparison_label')!r}"
                )
            if result.get("is_production") is not False:
                fail(
                    f"simulation_compare: is_production expected False, got {result.get('is_production')!r}"
                )
        except Exception as exc:
            fail(f"simulation_compare.py runtime check failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 10: evidence_impact.py — IMPACT_CHAIN defined and has 10 entries
    # -----------------------------------------------------------------------
    vprint("Check 10: evidence_impact.py IMPACT_CHAIN defined with 10 entries")
    ei_path = SERVICE_DIR / "evidence_impact.py"
    if not ei_path.exists():
        fail("Missing: services/governance_intelligence/evidence_impact.py")
    else:
        try:
            from services.governance_intelligence.evidence_impact import IMPACT_CHAIN  # type: ignore

            if len(IMPACT_CHAIN) != 10:
                fail(
                    f"evidence_impact.IMPACT_CHAIN must have 10 entries, got {len(IMPACT_CHAIN)}"
                )
        except Exception as exc:
            fail(f"evidence_impact.py runtime check failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 11: export_package.py — compute_package_hash uses sha256
    # -----------------------------------------------------------------------
    vprint("Check 11: export_package.py compute_package_hash uses sha256")
    ep_path = SERVICE_DIR / "export_package.py"
    if not ep_path.exists():
        fail("Missing: services/governance_intelligence/export_package.py")
    else:
        text = _read(ep_path) or ""
        if "sha256" not in text:
            fail("export_package.py: compute_package_hash must use sha256")
        try:
            from services.governance_intelligence.export_package import (
                compute_package_hash,
            )  # type: ignore

            h1 = compute_package_hash({"key": "value"})
            h2 = compute_package_hash({"key": "value"})
            if h1 != h2:
                fail("export_package.compute_package_hash must be deterministic")
            if len(h1) != 64:
                fail(
                    f"export_package.compute_package_hash: expected 64-char SHA-256 hex, got {len(h1)}"
                )
        except Exception as exc:
            fail(f"export_package.py runtime check failed: {exc}")

    # -----------------------------------------------------------------------
    # Check 12: Migration file 0147 exists
    # -----------------------------------------------------------------------
    vprint("Check 12: migration 0147 exists")
    if not MIGRATION_0147.exists():
        fail(f"Missing migration: {MIGRATION_0147.relative_to(ROOT)}")
    else:
        text = _read(MIGRATION_0147) or ""
        if "fa_gov_intel_provenance_node" not in text:
            fail("migration 0147: missing table fa_gov_intel_provenance_node")
        if "fa_gov_intel_export_history" not in text:
            fail("migration 0147: missing table fa_gov_intel_export_history")

    # -----------------------------------------------------------------------
    # Result
    # -----------------------------------------------------------------------
    if failures:
        print(f"\nGovernance Provenance Gate: FAILED ({len(failures)} violation(s))")
        for f in failures:
            print(f"  x  {f}")
        return 1

    print("Governance Provenance Gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
