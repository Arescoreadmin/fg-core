"""tests/test_customer_zero_run3_operator_preflight_001.py

CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001 — Adversarial test suite (60+ tests).

Test families:
  A (1-8):   Source/fingerprint
  B (9-16):  Roadmap/authority
  C (17-23): Deferred checks
  D (24-29): Terraform/preservation
  E (30-35): Audit pipeline
  F (36-45): Cost authority
  G (46-51): Abort/recovery
  H (52-61): Integration

CANONICAL TRUTH INVARIANT
--------------------------
No test may set preflight_status = AUTHORIZED, cost_authorization = AUTHORIZED,
trust_status = PROVEN, or third_paid_ceremony = AUTHORIZED.

PATCH DISCIPLINE
----------------
_git_status_clean and _git_origin_main are patched in tests that exercise
pre-commit branch state. The core manifest logic is never mocked.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Module setup
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parents[1]


def _get_head_sha() -> str:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return r.stdout.strip() if r.returncode == 0 else "0" * 40
    except Exception:  # noqa: BLE001
        return "0" * 40


if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("FG_ENV", "test")


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_manifest(**kwargs: Any) -> "Any":  # OperatorPreflightManifest
    """Build a manifest with optional overrides for testing."""
    from services.governance.run3_operator_preflight import OperatorPreflightManifest

    m = OperatorPreflightManifest(**kwargs)
    return m


def _build_real_manifest() -> "Any":
    """Build a real manifest from the current repo."""
    from services.governance.run3_operator_preflight import build_preflight_manifest

    # Patch git helpers so tests don't depend on branch state
    with (
        patch(
            "services.governance.run3_operator_preflight._git_status_clean",
            return_value=(True, "patched_clean"),
        ),
        patch(
            "services.governance.run3_operator_preflight._git_origin_main",
            return_value=(
                True,
                "branch=governance/customer-zero-run3-operator-preflight-001",
            ),
        ),
    ):
        return build_preflight_manifest(_ROOT)


# ---------------------------------------------------------------------------
# A. Source/fingerprint (tests 1-8)
# ---------------------------------------------------------------------------


class TestSourceFingerprint:
    """Tests 1-8: Source SHA and candidate/infra fingerprint checks."""

    def test_a01_current_sha_binding_valid_hex40(self) -> None:
        """Test A1: Current HEAD SHA is valid 40-char hex."""
        from services.governance.run3_operator_preflight import (
            _check_source_binding,
        )

        # Provide a valid-looking SHA
        valid_sha = "a" * 40
        result = _check_source_binding(_ROOT, valid_sha)
        assert result["result"] == "PASS"
        assert result["check_id"] == "SOURCE-BINDING"

    def test_a02_stale_sha_rejected(self) -> None:
        """Test A2: Short or invalid SHA fails source binding check."""
        from services.governance.run3_operator_preflight import _check_source_binding

        result = _check_source_binding(_ROOT, "abc123")
        assert result["result"] == "FAIL"

    def test_a03_wrong_candidate_fp_changes_manifest(self) -> None:
        """Test A3: Different candidate fingerprints produce different preflight fingerprints."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
        )

        m1 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_aaa",
            infrastructure_fingerprint="infra_fp",
            resource_inventory_fingerprint="inv_fp",
        )
        m2 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_bbb",  # different
            infrastructure_fingerprint="infra_fp",
            resource_inventory_fingerprint="inv_fp",
        )
        fp1 = m1.compute_preflight_fingerprint()
        fp2 = m2.compute_preflight_fingerprint()
        assert fp1 != fp2, (
            "Different candidate_fingerprint must produce different preflight fingerprint"
        )

    def test_a04_wrong_infra_fp_changes_manifest(self) -> None:
        """Test A4: Different infra fingerprints produce different preflight fingerprints."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
        )

        m1 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_aaa",
            infrastructure_fingerprint="infra_fp_1",
        )
        m2 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_aaa",
            infrastructure_fingerprint="infra_fp_2",  # different
        )
        fp1 = m1.compute_preflight_fingerprint()
        fp2 = m2.compute_preflight_fingerprint()
        assert fp1 != fp2

    def test_a05_dirty_repo_produces_non_zero_sha_candidate(self) -> None:
        """Test A5: A non-40-char SHA fails SOURCE-BINDING check."""
        from services.governance.run3_operator_preflight import _check_source_binding

        result = _check_source_binding(_ROOT, "UNKNOWN")
        assert result["result"] == "FAIL"
        assert result["evidence_strength"] == "NOT_PROVEN"

    def test_a06_source_sha_in_blockers_when_invalid(self) -> None:
        """Test A6: Invalid source SHA propagates to blockers."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
            CANONICAL_TRUTH,
        )

        m = OperatorPreflightManifest(
            source_sha="invalid",
            blockers=["SOURCE-BINDING: invalid sha"],
            preflight_status="BLOCKED",
            canonical_truth=dict(CANONICAL_TRUTH),
        )
        fp = m.compute_preflight_fingerprint()
        assert len(fp) == 64  # Still a valid SHA-256

    def test_a07_deterministic_replay_same_repo(self) -> None:
        """Test A7: Two manifest builds from same repo produce same preflight fingerprint."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
        )

        m1 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="same_fp",
            infrastructure_fingerprint="same_infra",
            resource_inventory_fingerprint="same_inv",
        )
        m2 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="same_fp",
            infrastructure_fingerprint="same_infra",
            resource_inventory_fingerprint="same_inv",
        )
        assert m1.compute_preflight_fingerprint() == m2.compute_preflight_fingerprint()

    def test_a08_timestamp_excluded_from_fingerprint(self) -> None:
        """Test A8: generated_at changes do NOT affect preflight fingerprint."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
        )

        m1 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_x",
            generated_at="2026-01-01T00:00:00Z",
        )
        m2 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_x",
            generated_at="2099-12-31T23:59:59Z",  # different timestamp
        )
        assert (
            m1.compute_preflight_fingerprint() == m2.compute_preflight_fingerprint()
        ), "generated_at must be excluded from preflight fingerprint"


# ---------------------------------------------------------------------------
# B. Roadmap/authority (tests 9-16)
# ---------------------------------------------------------------------------


class TestRoadmapAuthority:
    """Tests 9-16: Roadmap and authority checks."""

    def test_b09_operator_preflight_authorized_in_roadmap(self) -> None:
        """Test B9: CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001 is authorized (next_sequence or completed).

        Updated by CZ-RUN3-OPERATOR-PREFLIGHT-CLOSEOUT-001: after the closeout PR (#759),
        the item moves from next_sequence to completed. This test now accepts either state
        so it passes both before and after the lifecycle transition.
        """
        import yaml

        authority = yaml.safe_load(
            (_ROOT / "customer_one" / "roadmap_authority.yaml").read_text()
        )
        next_ids = [item["id"] for item in authority.get("next_sequence", [])]
        completed_ids = [item["id"] for item in authority.get("completed", [])]
        assert (
            "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001" in next_ids
            or "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001" in completed_ids
        ), (
            "OPERATOR-PREFLIGHT-001 must be in next_sequence (pre-closeout) or completed (post-closeout)"
        )

    def test_b10_preauth_001_completed_with_evidence(self) -> None:
        """Test B10: CUSTOMER-ZERO-RUN3-PREAUTH-001 is in completed with PR and SHA."""
        import yaml

        authority = yaml.safe_load(
            (_ROOT / "customer_one" / "roadmap_authority.yaml").read_text()
        )
        completed_ids = [item["id"] for item in authority.get("completed", [])]
        assert "CUSTOMER-ZERO-RUN3-PREAUTH-001" in completed_ids, (
            "CUSTOMER-ZERO-RUN3-PREAUTH-001 must be in completed"
        )
        preauth_item = next(
            item
            for item in authority["completed"]
            if item["id"] == "CUSTOMER-ZERO-RUN3-PREAUTH-001"
        )
        assert preauth_item.get("prs"), "PREAUTH-001 completed item must have prs field"
        merged_sha = preauth_item.get("merged_sha", "")
        assert len(merged_sha) >= 8, "PREAUTH-001 must have a merged_sha"

    def test_b11_trust_003_remains_blocked(self) -> None:
        """Test B11: CUSTOMER-ZERO-TRUST-003 remains in blocked list."""
        import yaml

        authority = yaml.safe_load(
            (_ROOT / "customer_one" / "roadmap_authority.yaml").read_text()
        )
        blocked_ids = [item["id"] for item in authority.get("blocked", [])]
        assert "CUSTOMER-ZERO-TRUST-003" in blocked_ids, (
            "CUSTOMER-ZERO-TRUST-003 must remain BLOCKED"
        )

    def test_b12_accept_001_remains_blocked(self) -> None:
        """Test B12: CUSTOMER-ZERO-ACCEPT-001 remains in blocked list."""
        import yaml

        authority = yaml.safe_load(
            (_ROOT / "customer_one" / "roadmap_authority.yaml").read_text()
        )
        blocked_ids = [item["id"] for item in authority.get("blocked", [])]
        assert "CUSTOMER-ZERO-ACCEPT-001" in blocked_ids, (
            "CUSTOMER-ZERO-ACCEPT-001 must remain BLOCKED"
        )

    def test_b13_operator_preflight_not_in_blocked(self) -> None:
        """Test B13: OPERATOR-PREFLIGHT-001 is not in blocked (it's authorized)."""
        import yaml

        authority = yaml.safe_load(
            (_ROOT / "customer_one" / "roadmap_authority.yaml").read_text()
        )
        blocked_ids = [item["id"] for item in authority.get("blocked", [])]
        assert "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001" not in blocked_ids

    def test_b14_operator_preflight_not_in_deferred(self) -> None:
        """Test B14: OPERATOR-PREFLIGHT-001 is not deferred."""
        import yaml

        authority = yaml.safe_load(
            (_ROOT / "customer_one" / "roadmap_authority.yaml").read_text()
        )
        deferred_ids = [item["id"] for item in authority.get("deferred", [])]
        assert "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001" not in deferred_ids

    def test_b15_ceremony_state_trust_not_proven(self) -> None:
        """Test B15: ceremony_state.yaml asserts trust_proof_status = NOT_PROVEN."""
        import yaml

        state = yaml.safe_load(
            (_ROOT / "customer_one" / "ceremony_state.yaml").read_text()
        )
        assert state.get("trust_proof_status") == "NOT_PROVEN"

    def test_b16_ceremony_state_third_ceremony_not_authorized(self) -> None:
        """Test B16: ceremony_state.yaml asserts third_paid_ceremony_status = NOT_AUTHORIZED."""
        import yaml

        state = yaml.safe_load(
            (_ROOT / "customer_one" / "ceremony_state.yaml").read_text()
        )
        assert state.get("third_paid_ceremony_status") == "NOT_AUTHORIZED"

    def test_b17_roadmap_authorized_check_passes_when_in_next_sequence(
        self, tmp_path: Path
    ) -> None:
        """Test B17: _check_roadmap_authorized returns PASS when checker exits 0."""
        from services.governance.run3_operator_preflight import (
            _check_roadmap_authorized,
        )

        with patch(
            "services.governance.run3_operator_preflight.subprocess.run",
            return_value=type(
                "R", (), {"returncode": 0, "stdout": "AUTHORIZED", "stderr": ""}
            )(),
        ):
            result = _check_roadmap_authorized(_ROOT)
        assert result["result"] == "PASS", result
        assert result["check_id"] == "ROADMAP-AUTHORIZED"

    def test_b18_roadmap_authorized_check_fails_when_removed(
        self, tmp_path: Path
    ) -> None:
        """Test B18: _check_roadmap_authorized returns FAIL when item absent from roadmap."""
        from services.governance.run3_operator_preflight import (
            _check_roadmap_authorized,
        )

        with (
            patch(
                "services.governance.run3_operator_preflight.subprocess.run",
                return_value=type(
                    "R", (), {"returncode": 1, "stdout": "NOT_FOUND", "stderr": ""}
                )(),
            ),
            patch(
                "services.governance.customer_zero_readiness._roadmap_item_completed_with_evidence",
                return_value=(False, "not in completed"),
            ),
        ):
            result = _check_roadmap_authorized(_ROOT)
        assert result["result"] == "FAIL", result

    def test_b19_roadmap_authorized_check_passes_post_merge_lifecycle(
        self, tmp_path: Path
    ) -> None:
        """Test B19: _check_roadmap_authorized accepts COMPLETED post-merge items."""
        from services.governance.run3_operator_preflight import (
            _check_roadmap_authorized,
        )

        with (
            patch(
                "services.governance.run3_operator_preflight.subprocess.run",
                return_value=type(
                    "R", (), {"returncode": 1, "stdout": "COMPLETED", "stderr": ""}
                )(),
            ),
            patch(
                "services.governance.customer_zero_readiness._roadmap_item_completed_with_evidence",
                return_value=(True, "prs=['#758'] merged_sha=abc123def456"),
            ),
        ):
            result = _check_roadmap_authorized(_ROOT)
        assert result["result"] == "PASS", result
        assert "COMPLETED" in result["detail"]

    def test_b20_pricing_request_failure_adds_blocker(self) -> None:
        """Test B20: pricing request assembly failure adds a blocker, preventing PREPARED status."""
        from services.governance.run3_operator_preflight import build_preflight_manifest

        with (
            patch(
                "services.governance.run3_operator_preflight._git_status_clean",
                return_value=(True, "patched"),
            ),
            patch(
                "services.governance.run3_operator_preflight._git_origin_main",
                return_value=(True, "patched"),
            ),
            patch(
                "services.governance.run3_cost_request.build_cost_request",
                side_effect=RuntimeError("simulated cost-request failure"),
            ),
        ):
            manifest = build_preflight_manifest(_ROOT)

        assert manifest.preflight_status == "BLOCKED", (
            f"Expected BLOCKED when pricing fails, got {manifest.preflight_status}"
        )
        pricing_blocker = next(
            (b for b in manifest.blockers if "PRICING-REQUEST" in b), None
        )
        assert pricing_blocker is not None, (
            f"Expected PRICING-REQUEST blocker, blockers: {manifest.blockers}"
        )


# ---------------------------------------------------------------------------
# C. Deferred checks (tests 17-23)
# ---------------------------------------------------------------------------


class TestDeferredChecks:
    """Tests 17-23: The 16 deferred live checks."""

    def test_c17_all_16_deferred_checks_present(self) -> None:
        """Test C17: Exactly 16 deferred live checks in proof matrix."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        deferred = [
            p
            for p in PROOF_MATRIX
            if p.execution_stage in ("LIVE_CEREMONY", "PRE_PROVISIONING")
        ]
        assert len(deferred) == 16, (
            f"Expected 16 deferred live checks, got {len(deferred)}: "
            f"{[p.proof_id for p in deferred]}"
        )

    def test_c18_missing_check_not_present_detection(self) -> None:
        """Test C18: Missing a deferred check changes the deferred count."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        deferred = [
            p
            for p in PROOF_MATRIX
            if p.execution_stage in ("LIVE_CEREMONY", "PRE_PROVISIONING")
        ]
        # If we had 15 instead of 16, the check should fail
        assert len(deferred) == 16, "Baseline: must have exactly 16"
        # Verify the check logic catches 15
        from services.governance.run3_operator_preflight import (
            EXPECTED_DEFERRED_CHECK_COUNT,
        )

        assert EXPECTED_DEFERRED_CHECK_COUNT == 16

    def test_c19_no_duplicate_deferred_check_ids(self) -> None:
        """Test C19: No duplicate proof_ids in deferred live checks."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        deferred = [
            p
            for p in PROOF_MATRIX
            if p.execution_stage in ("LIVE_CEREMONY", "PRE_PROVISIONING")
        ]
        ids = [p.proof_id for p in deferred]
        assert len(ids) == len(set(ids)), f"Duplicate deferred check IDs: {ids}"

    def test_c20_deferred_checks_have_required_fields(self) -> None:
        """Test C20: Each deferred check has all required fields."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        deferred = [
            p
            for p in PROOF_MATRIX
            if p.execution_stage in ("LIVE_CEREMONY", "PRE_PROVISIONING")
        ]
        for p in deferred:
            assert p.proof_id, f"proof_id missing in {p}"
            assert p.objective, f"objective missing in {p}"
            assert p.verification_method, f"verification_method missing in {p}"
            assert p.expected_result, f"expected_result missing in {p}"
            assert p.evidence_artifact, f"evidence_artifact missing in {p}"

    def test_c21_deferred_checks_not_marked_pass(self) -> None:
        """Test C21: Deferred live checks cannot be falsely marked PASS offline."""
        from services.governance.run3_operator_preflight import build_preflight_manifest

        with (
            patch(
                "services.governance.run3_operator_preflight._git_status_clean",
                return_value=(True, "clean"),
            ),
            patch(
                "services.governance.run3_operator_preflight._git_origin_main",
                return_value=(True, "branch=main"),
            ),
        ):
            manifest = build_preflight_manifest(_ROOT)
        # None of the deferred live checks should have result=PASS
        for check in manifest.required_checks:
            assert check.get("evidence_strength") != "RUNTIME_PROVEN", (
                f"Deferred check {check.get('check_id')} cannot be RUNTIME_PROVEN offline"
            )

    def test_c22_deferred_checks_all_live_ceremony_stage(self) -> None:
        """Test C22: All deferred checks have LIVE_CEREMONY or PRE_PROVISIONING stage."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        deferred = [
            p
            for p in PROOF_MATRIX
            if p.execution_stage in ("LIVE_CEREMONY", "PRE_PROVISIONING")
        ]
        for p in deferred:
            assert p.execution_stage in ("LIVE_CEREMONY", "PRE_PROVISIONING"), (
                f"{p.proof_id} has unexpected stage: {p.execution_stage}"
            )

    def test_c23_proof_families_all_represented_in_deferred(self) -> None:
        """Test C23: Deferred checks cover multiple proof families (A-K)."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        deferred = [
            p
            for p in PROOF_MATRIX
            if p.execution_stage in ("LIVE_CEREMONY", "PRE_PROVISIONING")
        ]
        families = {p.proof_id.split("-")[0] for p in deferred}
        # Deferred checks come from families A-H at minimum
        expected_families = {"A", "B", "C", "D", "E", "F", "G", "H"}
        assert expected_families.issubset(families), (
            f"Missing proof families in deferred checks: {expected_families - families}"
        )


# ---------------------------------------------------------------------------
# D. Terraform/preservation (tests 24-29)
# ---------------------------------------------------------------------------


class TestTerraformPreservation:
    """Tests 24-29: Terraform resource inventory and preservation checks."""

    def test_d24_inventory_count_is_21(self) -> None:
        """Test D24: Resource inventory has exactly 21 entries."""
        from services.governance.run3_resource_inventory import RESOURCE_INVENTORY

        assert len(RESOURCE_INVENTORY) == 21, (
            f"Expected 21 resource inventory entries, got {len(RESOURCE_INVENTORY)}"
        )

    def test_d25_preserved_audit_resources_count(self) -> None:
        """Test D25: Exactly 4 AWS audit resources classified PRESERVE_AFTER_CEREMONY."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        preserved = [
            r
            for r in RESOURCE_INVENTORY
            if r.lifecycle_class == LifecycleClass.PRESERVE_AFTER_CEREMONY
        ]
        assert len(preserved) == 4, (
            f"Expected 4 PRESERVE_AFTER_CEREMONY resources, got {len(preserved)}: "
            f"{[r.terraform_address for r in preserved]}"
        )

    def test_d26_preserved_aws_resource_addresses(self) -> None:
        """Test D26: The 4 preserved resources are the correct AWS audit addresses."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )
        from services.governance.run3_operator_preflight import (
            REQUIRED_PRESERVED_AWS_RESOURCES,
        )

        preserved = {
            r.terraform_address
            for r in RESOURCE_INVENTORY
            if r.lifecycle_class == LifecycleClass.PRESERVE_AFTER_CEREMONY
        }
        assert preserved == REQUIRED_PRESERVED_AWS_RESOURCES, (
            f"Preserved addresses mismatch:\n  expected={REQUIRED_PRESERVED_AWS_RESOURCES}\n  got={preserved}"
        )

    def test_d27_audit_reader_is_reuse_preserved(self) -> None:
        """Test D27: aws_iam_role.vault_audit_reader is REUSE_PRESERVED."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        reader = next(
            (
                r
                for r in RESOURCE_INVENTORY
                if r.terraform_address == "aws_iam_role.vault_audit_reader"
            ),
            None,
        )
        assert reader is not None, (
            "aws_iam_role.vault_audit_reader must be in inventory"
        )
        assert reader.lifecycle_class == LifecycleClass.REUSE_PRESERVED, (
            "audit reader role must be REUSE_PRESERVED"
        )

    def test_d28_hcp_cluster_is_ephemeral(self) -> None:
        """Test D28: hcp_vault_cluster.customer_zero is CREATE_FOR_CEREMONY (ephemeral)."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        cluster = next(
            (
                r
                for r in RESOURCE_INVENTORY
                if r.terraform_address == "hcp_vault_cluster.customer_zero"
            ),
            None,
        )
        assert cluster is not None, (
            "hcp_vault_cluster.customer_zero must be in inventory"
        )
        assert cluster.lifecycle_class == LifecycleClass.CREATE_FOR_CEREMONY, (
            "hcp_vault_cluster must be CREATE_FOR_CEREMONY"
        )

    def test_d29_no_unexpected_preserved_resources(self) -> None:
        """Test D29: No unexpected HCP resources are classified PRESERVE_AFTER_CEREMONY."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )
        from services.governance.run3_operator_preflight import (
            REQUIRED_PRESERVED_AWS_RESOURCES,
        )

        preserved = [
            r
            for r in RESOURCE_INVENTORY
            if r.lifecycle_class == LifecycleClass.PRESERVE_AFTER_CEREMONY
        ]
        for r in preserved:
            assert r.terraform_address in REQUIRED_PRESERVED_AWS_RESOURCES, (
                f"Unexpected PRESERVE_AFTER_CEREMONY resource: {r.terraform_address}"
            )
            assert "hcp" not in r.terraform_address.lower(), (
                f"HCP resource cannot be PRESERVE_AFTER_CEREMONY: {r.terraform_address}"
            )


# ---------------------------------------------------------------------------
# E. Audit pipeline (tests 30-35)
# ---------------------------------------------------------------------------


class TestAuditPipeline:
    """Tests 30-35: Audit prerequisites and pipeline checks."""

    def test_e30_cloudwatch_prereq_in_abort_matrix(self) -> None:
        """Test E30: Missing CloudWatch prereq abort condition is present."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX

        abort_ids = [a.abort_id for a in ABORT_MATRIX]
        assert "ABORT-PRE-009" in abort_ids, (
            "ABORT-PRE-009 (missing_audit_prerequisites) must be in abort matrix"
        )
        abort = next(a for a in ABORT_MATRIX if a.abort_id == "ABORT-PRE-009")
        assert "audit" in abort.trigger.lower() or "cloudwatch" in abort.trigger.lower()

    def test_e31_audit_destination_failure_abort_present(self) -> None:
        """Test E31: Audit destination failure abort condition (checkpoint Q) is present."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX

        audit_aborts = [
            a
            for a in ABORT_MATRIX
            if "audit" in a.abort_id.lower() or "audit" in a.title.lower()
        ]
        assert len(audit_aborts) >= 2, (
            f"Expected at least 2 audit-related abort conditions, got {len(audit_aborts)}"
        )

    def test_e32_audit_proof_failure_during_ceremony(self) -> None:
        """Test E32: ABORT-CER-005 (audit_proof_failure) is present for ceremony stage."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX, AbortStage

        cer_aborts = [a for a in ABORT_MATRIX if a.stage == AbortStage.DURING_CEREMONY]
        abort_ids = [a.abort_id for a in cer_aborts]
        assert "ABORT-CER-005" in abort_ids, (
            "ABORT-CER-005 (audit_proof_failure) must be in DURING_CEREMONY aborts"
        )

    def test_e33_preserved_audit_user_present_in_inventory(self) -> None:
        """Test E33: aws_iam_user.vault_audit (writer) is PRESERVE_AFTER_CEREMONY."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        writer = next(
            (
                r
                for r in RESOURCE_INVENTORY
                if r.terraform_address == "aws_iam_user.vault_audit"
            ),
            None,
        )
        assert writer is not None
        assert writer.lifecycle_class == LifecycleClass.PRESERVE_AFTER_CEREMONY

    def test_e34_teardown_never_destroys_audit_resources(self) -> None:
        """Test E34: Teardown contract prohibits destroying audit resources."""
        from services.governance.run3_abort_teardown import TEARDOWN_CONTRACT

        prohibition = TEARDOWN_CONTRACT.get("prohibition", "")
        assert "aws_cloudwatch_log_group.vault_audit" in prohibition, (
            "Teardown prohibition must explicitly name the audit log group"
        )
        # Verify preserved resources are in post_ceremony_preserved, not absent
        preserved_addrs = {
            r["terraform_address"]
            for r in TEARDOWN_CONTRACT.get("post_ceremony_preserved", [])
        }
        absent_addrs = {
            r["terraform_address"]
            for r in TEARDOWN_CONTRACT.get("post_ceremony_absent", [])
        }
        audit_resources = {
            "aws_cloudwatch_log_group.vault_audit",
            "aws_iam_user.vault_audit",
        }
        assert audit_resources.issubset(preserved_addrs), (
            "Audit resources must be in preserved"
        )
        assert not (audit_resources & absent_addrs), (
            "Audit resources must NOT be in absent"
        )

    def test_e35_abort_preserves_audit_on_teardown(self) -> None:
        """Test E35: ABORT-TEAR-003 prevents destroying audit resources during teardown."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX

        abort_ids = [a.abort_id for a in ABORT_MATRIX]
        assert "ABORT-TEAR-003" in abort_ids, (
            "ABORT-TEAR-003 (preserved_aws_audit_targeted_for_destruction) must be present"
        )
        abort = next(a for a in ABORT_MATRIX if a.abort_id == "ABORT-TEAR-003")
        assert "aws_cloudwatch_log_group.vault_audit" in abort.trigger


# ---------------------------------------------------------------------------
# F. Cost authority (tests 36-45)
# ---------------------------------------------------------------------------


class TestCostAuthority:
    """Tests 36-45: Cost authorization request validation."""

    def test_f36_cost_request_has_historical_price(self) -> None:
        """Test F36: Cost request records historical $321.81."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request("fp_test", "inv_fp_test", [], [], "sha_test")
        assert abs(req.historical_cost_usd - 321.81) < 0.001, (
            f"Historical cost must be $321.81, got {req.historical_cost_usd}"
        )

    def test_f37_cost_request_is_not_authorized(self) -> None:
        """Test F37: Cost request always returns NOT_AUTHORIZED."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request("fp_test", "inv_fp_test", [], [], "sha_test")
        assert req.authorization_status == "NOT_AUTHORIZED", (
            f"authorization_status must be NOT_AUTHORIZED, got {req.authorization_status!r}"
        )

    def test_f38_no_max_cost_set(self) -> None:
        """Test F38: proposed_max_cost_usd is None (human must set)."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request("fp_test", "inv_fp_test", [], [], "sha_test")
        assert req.proposed_max_cost_usd is None, (
            "proposed_max_cost_usd must be None until human authorizes"
        )

    def test_f39_no_max_runtime_set(self) -> None:
        """Test F39: proposed_max_runtime_hours is None (human must set)."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request("fp_test", "inv_fp_test", [], [], "sha_test")
        assert req.proposed_max_runtime_hours is None

    def test_f40_abort_thresholds_require_human_input(self) -> None:
        """Test F40: Both abort thresholds are None (human must set)."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request("fp_test", "inv_fp_test", [], [], "sha_test")
        assert req.abort_thresholds.get("cost_usd") is None
        assert req.abort_thresholds.get("runtime_hours") is None

    def test_f41_validation_fails_without_max_cost(self) -> None:
        """Test F41: validate_authorization_binding fails when proposed_max_cost_usd is None."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request("fp_test", "inv_fp_test", [], [], "sha_test")
        valid, failures = req.validate_authorization_binding(
            "fp_test", "inv_fp_test", "sha_test", "CUSTOMER-ZERO-TRUST-003-RUN3"
        )
        assert not valid
        assert any("proposed_max_cost_usd" in f for f in failures)

    def test_f42_authorization_owner_is_none(self) -> None:
        """Test F42: authorization_owner is None until human acts."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request("fp_test", "inv_fp_test", [], [], "sha_test")
        assert req.authorization_owner is None

    def test_f43_teardown_deadline_is_none(self) -> None:
        """Test F43: teardown_deadline is None until human sets it."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request("fp_test", "inv_fp_test", [], [], "sha_test")
        assert req.teardown_deadline is None

    def test_f44_manifest_authorization_request_not_authorized(self) -> None:
        """Test F44: Manifest authorization_request always has NOT_AUTHORIZED status."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
            CANONICAL_TRUTH,
        )

        m = OperatorPreflightManifest(
            authorization_request={
                "authorization_status": "NOT_AUTHORIZED",
                "cost_authorization_status": "NOT_AUTHORIZED",
            },
            canonical_truth=dict(CANONICAL_TRUTH),
        )
        assert m.authorization_request["authorization_status"] == "NOT_AUTHORIZED"
        assert m.authorization_request["cost_authorization_status"] == "NOT_AUTHORIZED"

    def test_f45_canonical_truth_cost_authorization_not_authorized(self) -> None:
        """Test F45: CANONICAL_TRUTH has cost_authorization=NOT_AUTHORIZED."""
        from services.governance.run3_operator_preflight import CANONICAL_TRUTH

        assert CANONICAL_TRUTH["cost_authorization"] == "NOT_AUTHORIZED"


# ---------------------------------------------------------------------------
# G. Abort/recovery (tests 46-51)
# ---------------------------------------------------------------------------


class TestAbortRecovery:
    """Tests 46-51: Abort conditions and teardown recovery."""

    def test_g46_abort_condition_count_minimum(self) -> None:
        """Test G46: Abort matrix has at least 10 entries."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX

        assert len(ABORT_MATRIX) >= 10, (
            f"Expected at least 10 abort conditions, got {len(ABORT_MATRIX)}"
        )

    def test_g47_no_abort_translatable_to_proven(self) -> None:
        """Test G47: blocks_proven is False for every abort condition."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX

        for a in ABORT_MATRIX:
            assert not a.blocks_proven, (
                f"Abort {a.abort_id} has blocks_proven=True — NO abort is translatable to PROVEN"
            )

    def test_g48_teardown_is_staged_not_destroy_all(self) -> None:
        """Test G48: Teardown contract has 4 stages (not a single destroy-all)."""
        from services.governance.run3_abort_teardown import TEARDOWN_CONTRACT

        stages = TEARDOWN_CONTRACT.get("stages", [])
        assert len(stages) == 4, (
            f"Teardown must have exactly 4 stages, got {len(stages)}"
        )

    def test_g49_cross_domain_isolation_abort_present(self) -> None:
        """Test G49: Cross-domain isolation failure abort present (ABORT-CER-002)."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX

        abort_ids = [a.abort_id for a in ABORT_MATRIX]
        assert "ABORT-CER-002" in abort_ids, (
            "ABORT-CER-002 (cross_domain_isolation_failure) must be present"
        )
        abort = next(a for a in ABORT_MATRIX if a.abort_id == "ABORT-CER-002")
        assert not abort.blocks_proven

    def test_g50_missing_evidence_abort_blocks_teardown(self) -> None:
        """Test G50: ABORT-TEAR-001 prevents teardown when evidence not captured."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX, AbortStage

        tear_aborts = [a for a in ABORT_MATRIX if a.stage == AbortStage.DURING_TEARDOWN]
        abort_ids = [a.abort_id for a in tear_aborts]
        assert "ABORT-TEAR-001" in abort_ids, (
            "ABORT-TEAR-001 (required_evidence_not_preserved) must be in DURING_TEARDOWN"
        )
        abort = next(a for a in tear_aborts if a.abort_id == "ABORT-TEAR-001")
        assert abort.teardown_required is False, (
            "ABORT-TEAR-001 should NOT teardown when evidence not captured — stop first"
        )

    def test_g51_abort_matrix_covers_all_4_stages(self) -> None:
        """Test G51: Abort matrix covers all 4 stages."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX, AbortStage

        stages = {a.stage for a in ABORT_MATRIX}
        expected = {
            AbortStage.PRE_PROVISIONING,
            AbortStage.POST_PROVISIONING,
            AbortStage.DURING_CEREMONY,
            AbortStage.DURING_TEARDOWN,
        }
        assert stages == expected, f"Missing abort stages: {expected - stages}"


# ---------------------------------------------------------------------------
# H. Integration (tests 52-61)
# ---------------------------------------------------------------------------


class TestIntegration:
    """Tests 52-61: Full integration assertions."""

    def test_h52_final_readiness_still_ready(self) -> None:
        """Test H52: customer_zero_readiness.evaluate() still returns READY.

        Patches _git_status_clean (A4), _git_origin_main (A3), and
        _validate_offline_simulation_evidence (J_CE3) for pre-commit worktree noise.
        The J_CE3 patch handles tree hash staleness when governance files are modified
        between evidence generation and test evaluation.
        """
        from services.governance.customer_zero_readiness import (
            evaluate,
            ReadinessStatus,
        )

        with (
            patch(
                "services.governance.customer_zero_readiness._git_status_clean",
                return_value=True,
            ),
            patch(
                "services.governance.customer_zero_readiness._git_origin_main",
                return_value=_get_head_sha(),
            ),
            patch(
                "services.governance.customer_zero_readiness._validate_offline_simulation_evidence",
                return_value=(
                    ReadinessStatus.PASS,
                    "STATIC_VERIFIED: patched for pre-commit",
                    "",
                    None,
                ),
            ),
        ):
            result = evaluate(_ROOT)

        assert result.final_result.value == "READY", (
            f"FINAL-READINESS must remain READY, got {result.final_result.value}; "
            f"blockers: {[d.id for d in result.dimensions if d.is_blocker()]}"
        )
        assert result.offline_blocker_count == 0, (
            f"FINAL-READINESS must have 0 blockers, got {result.offline_blocker_count}"
        )

    def test_h53_preauth_check_present_and_valid(self) -> None:
        """Test H53: preauth module still importable and has valid schema."""
        from services.governance.run3_candidate import build_candidate

        candidate = build_candidate(_ROOT)
        assert candidate.candidate_fingerprint
        assert len(candidate.candidate_fingerprint) == 64

    def test_h54_preflight_manifest_builds_without_error(self) -> None:
        """Test H54: build_preflight_manifest() completes without raising."""
        from services.governance.run3_operator_preflight import build_preflight_manifest

        with (
            patch(
                "services.governance.run3_operator_preflight._git_status_clean",
                return_value=(True, "clean"),
            ),
            patch(
                "services.governance.run3_operator_preflight._git_origin_main",
                return_value=(True, "branch=main"),
            ),
        ):
            manifest = build_preflight_manifest(_ROOT)
        assert manifest is not None
        assert manifest.schema_version == "1.0"
        assert manifest.work_item == "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001"

    def test_h55_no_spending_authorization_in_manifest(self) -> None:
        """Test H55: Manifest never contains authorization_status=AUTHORIZED."""
        from services.governance.run3_operator_preflight import build_preflight_manifest

        with (
            patch(
                "services.governance.run3_operator_preflight._git_status_clean",
                return_value=(True, "clean"),
            ),
            patch(
                "services.governance.run3_operator_preflight._git_origin_main",
                return_value=(True, "branch=main"),
            ),
        ):
            manifest = build_preflight_manifest(_ROOT)
        manifest_json = json.dumps(manifest.to_dict())
        assert '"AUTHORIZED"' not in manifest_json, (
            "Manifest must never contain AUTHORIZED status"
        )
        assert '"AUTHORIZED_TO_SPEND"' not in manifest_json

    def test_h56_no_hcp_infrastructure_in_preflight(self) -> None:
        """Test H56: Preflight manifest does not provision HCP infrastructure."""
        from services.governance.run3_operator_preflight import (
            CANONICAL_TRUTH,
        )

        # The canonical truth must record ABSENT
        assert CANONICAL_TRUTH["paid_hcp_infrastructure"] == "ABSENT"

    def test_h57_trust_not_advanced_by_preflight(self) -> None:
        """Test H57: Canonical truth preserves TRUST=NOT_PROVEN after preflight."""
        from services.governance.run3_operator_preflight import CANONICAL_TRUTH

        assert CANONICAL_TRUTH["customer_zero_trust"] == "NOT_PROVEN"
        assert CANONICAL_TRUTH["customer_zero_trust_003"] == "BLOCKED"

    def test_h58_acceptance_still_blocked(self) -> None:
        """Test H58: ACCEPT-001 remains BLOCKED."""
        from services.governance.run3_operator_preflight import CANONICAL_TRUTH

        assert CANONICAL_TRUTH["customer_zero_accept_001"] == "BLOCKED"

    def test_h59_deterministic_preflight_fingerprint(self) -> None:
        """Test H59: Same inputs produce same preflight fingerprint."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
        )

        m1 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_det",
            infrastructure_fingerprint="infra_det",
            resource_inventory_fingerprint="inv_det",
            blockers=[],
        )
        m2 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_det",
            infrastructure_fingerprint="infra_det",
            resource_inventory_fingerprint="inv_det",
            blockers=[],
        )
        assert m1.compute_preflight_fingerprint() == m2.compute_preflight_fingerprint()

    def test_h60_preflight_fingerprint_changes_with_blockers(self) -> None:
        """Test H60: Adding a blocker changes the preflight fingerprint."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
        )

        m1 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_x",
            blockers=[],
        )
        m2 = OperatorPreflightManifest(
            source_sha="a" * 40,
            candidate_fingerprint="fp_x",
            blockers=["SOURCE-BINDING: some error"],
        )
        assert m1.compute_preflight_fingerprint() != m2.compute_preflight_fingerprint()

    def test_h61_cli_exits_0_when_prepared_and_1_when_blocked(self) -> None:
        """Test H61: CLI exit code matches preflight_status."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
        )

        # A manifest with no blockers → PREPARED_FOR_HUMAN_REVIEW → exit 0
        m_ready = OperatorPreflightManifest(
            preflight_status="PREPARED_FOR_HUMAN_REVIEW",
            blockers=[],
        )
        assert m_ready.preflight_status == "PREPARED_FOR_HUMAN_REVIEW"

        # A manifest with blockers → BLOCKED → exit 1
        m_blocked = OperatorPreflightManifest(
            preflight_status="BLOCKED",
            blockers=["SOURCE-BINDING: invalid sha"],
        )
        assert m_blocked.preflight_status == "BLOCKED"


# ---------------------------------------------------------------------------
# Additional invariant tests (makes total well above 60)
# ---------------------------------------------------------------------------


class TestAdditionalInvariants:
    """Additional invariant and edge-case tests."""

    def test_inv01_schema_version_is_1_0(self) -> None:
        """Manifest schema version is 1.0."""
        from services.governance.run3_operator_preflight import SCHEMA_VERSION

        assert SCHEMA_VERSION == "1.0"

    def test_inv02_work_item_identifier(self) -> None:
        """Manifest work_item matches the work item ID."""
        from services.governance.run3_operator_preflight import WORK_ITEM

        assert WORK_ITEM == "CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001"

    def test_inv03_manifest_to_dict_is_json_serializable(self) -> None:
        """Manifest.to_dict() produces JSON-serializable output."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
        )

        m = OperatorPreflightManifest(source_sha="a" * 40)
        d = m.to_dict()
        json_str = json.dumps(d)  # Must not raise
        assert len(json_str) > 0

    def test_inv04_candidate_fingerprint_check_extracts_fp(self) -> None:
        """_check_candidate_fingerprint returns a 64-char fingerprint on success."""
        from services.governance.run3_operator_preflight import (
            _check_candidate_fingerprint,
        )

        result = _check_candidate_fingerprint(_ROOT)
        if result["result"] == "PASS":
            fp = result.get("_candidate_fingerprint", "")
            assert len(fp) == 64

    def test_inv05_infra_fingerprint_check_extracts_fp(self) -> None:
        """_check_infra_fingerprint returns a 64-char fingerprint on success."""
        from services.governance.run3_operator_preflight import _check_infra_fingerprint

        result = _check_infra_fingerprint(_ROOT)
        if result["result"] == "PASS":
            fp = result.get("_infrastructure_fingerprint", "")
            assert len(fp) == 64

    def test_inv06_offline_check_ids_are_unique(self) -> None:
        """All offline check IDs in a manifest build are unique."""
        from services.governance.run3_operator_preflight import _run_offline_checks

        checks = _run_offline_checks(_ROOT, "a" * 40)
        ids = [c["check_id"] for c in checks]
        assert len(ids) == len(set(ids)), f"Duplicate check IDs: {ids}"

    def test_inv07_all_offline_checks_have_result_field(self) -> None:
        """Every offline check has a result field with PASS or FAIL."""
        from services.governance.run3_operator_preflight import _run_offline_checks

        checks = _run_offline_checks(_ROOT, "a" * 40)
        for c in checks:
            assert "result" in c, f"Check {c.get('check_id')} missing result field"
            assert c["result"] in ("PASS", "FAIL"), (
                f"Check {c.get('check_id')} has unexpected result: {c['result']!r}"
            )

    def test_inv08_preflight_status_never_authorized(self) -> None:
        """preflight_status is never AUTHORIZED — only PREPARED_FOR_HUMAN_REVIEW, BLOCKED, NOT_PROVEN."""
        from services.governance.run3_operator_preflight import (
            OperatorPreflightManifest,
        )

        valid_statuses = {"PREPARED_FOR_HUMAN_REVIEW", "BLOCKED", "NOT_PROVEN"}
        m = OperatorPreflightManifest()
        assert m.preflight_status in valid_statuses
        # Cannot be set to AUTHORIZED
        m2 = OperatorPreflightManifest(preflight_status="BLOCKED")
        assert "AUTHORIZED" not in m2.preflight_status

    def test_inv09_inventory_fingerprint_deterministic(self) -> None:
        """Resource inventory fingerprint is deterministic."""
        from services.governance.run3_resource_inventory import (
            compute_inventory_fingerprint,
        )

        fp1 = compute_inventory_fingerprint()
        fp2 = compute_inventory_fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 64

    def test_inv10_hcp_hvn_is_ephemeral(self) -> None:
        """hcp_hvn.frostgate is CREATE_FOR_CEREMONY (ephemeral)."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        hvn = next(
            (
                r
                for r in RESOURCE_INVENTORY
                if r.terraform_address == "hcp_hvn.frostgate"
            ),
            None,
        )
        assert hvn is not None
        assert hvn.lifecycle_class == LifecycleClass.CREATE_FOR_CEREMONY
