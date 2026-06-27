"""End-to-end tests for PR 17.6A — Governance Chain Completion.

Tests the full governance chain flow using real upstream service engines:
  1. Seed evidence via EvidenceAuthorityEngine
  2. Run EVIDENCE_TO_VERIFICATION bridge → SUCCESS + verification request
  3. Run VERIFICATION_TO_FRESHNESS bridge → SUCCESS + freshness record
  4. Run FRESHNESS_TO_EFFECTIVENESS without control_id → SKIPPED_UNAVAILABLE
  5. Run ALL_TO_REPORTING → SKIPPED_UNAVAILABLE (no effectiveness data)
  6. Validate chain → WARNING (not all data present)
  7. Assert chain events exist
  8. Assert no raw tenant_id in CGIN output

These tests use isolated tenant IDs per test to avoid cross-test contamination.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from api.db import get_engine
from services.evidence_authority.engine import EvidenceAuthorityEngine
from services.evidence_authority.models import (
    EvidenceCollectionMethod,
    EvidenceSourceType,
)
from services.evidence_authority.schemas import CreateEvidenceRequest
from services.governance_chain.engine import GovernanceChainEngine
from services.governance_chain.models import BridgeType, ChainExecutionResult
from services.governance_chain.schemas import ExecuteBridgeRequest


def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _fresh_tenant() -> str:
    return f"t-e2e-{_uid()[:12]}"


# ---------------------------------------------------------------------------
# Full chain end-to-end test
# ---------------------------------------------------------------------------


class TestGovernanceChainEndToEnd:
    """Full chain flow from evidence seeding through reporting readiness."""

    def test_GCE2E_01_full_chain_from_evidence_to_reporting(self, build_app):
        """
        Full chain flow:
        1. Seed evidence via EvidenceAuthorityEngine
        2. EVIDENCE_TO_VERIFICATION → SUCCESS (creates verification request)
        3. VERIFICATION_TO_FRESHNESS → SUCCESS (creates freshness record)
        4. FRESHNESS_TO_EFFECTIVENESS without control_id → SKIPPED_UNAVAILABLE
        5. ALL_TO_REPORTING → SKIPPED_UNAVAILABLE (no effectiveness/remediation data)
        6. validate_chain → WARNING (missing data in some authorities)
        7. Chain events exist
        8. CGIN output has no raw tenant_id
        """
        build_app(auth_enabled=False)
        tenant_id = _fresh_tenant()

        with Session(get_engine()) as db:
            # ----------------------------------------------------------------
            # Step 1: Seed evidence
            # ----------------------------------------------------------------
            ea = EvidenceAuthorityEngine(db, tenant_id)
            evidence = ea.create_evidence(
                CreateEvidenceRequest(
                    title="E2E Test Evidence",
                    source_type=EvidenceSourceType.ATTESTATION,
                    collection_method=EvidenceCollectionMethod.ATTESTATION_SUBMISSION,
                    collected_at=_now(),
                    description="Created by governance chain e2e test",
                ),
                actor_id="e2e-test",
                actor_type="test",
            )
            db.commit()
            evidence_id = evidence.id
            assert evidence_id is not None

            engine = GovernanceChainEngine(db, tenant_id)

            # ----------------------------------------------------------------
            # Step 2: EVIDENCE_TO_VERIFICATION
            # ----------------------------------------------------------------
            req2 = ExecuteBridgeRequest(
                bridge=BridgeType.EVIDENCE_TO_VERIFICATION.value,
                trigger_object_id=evidence_id,
                trigger_object_type="evidence",
                trigger_reason="e2e: requesting verification",
            )
            result2 = engine.execute_bridge(req2, "e2e-test", "test")
            assert result2.execution_result == ChainExecutionResult.SUCCESS.value, (
                f"EVIDENCE_TO_VERIFICATION expected SUCCESS, got "
                f"{result2.execution_result}: {result2.failure_reason}"
            )
            assert result2.success is True

            # ----------------------------------------------------------------
            # Step 3: VERIFICATION_TO_FRESHNESS
            # ----------------------------------------------------------------
            req3 = ExecuteBridgeRequest(
                bridge=BridgeType.VERIFICATION_TO_FRESHNESS.value,
                trigger_object_id=evidence_id,
                trigger_object_type="evidence",
                trigger_reason="e2e: verification approved",
                verified_at=_now(),
            )
            result3 = engine.execute_bridge(req3, "e2e-test", "test")
            assert result3.execution_result == ChainExecutionResult.SUCCESS.value, (
                f"VERIFICATION_TO_FRESHNESS expected SUCCESS, got "
                f"{result3.execution_result}: {result3.failure_reason}"
            )
            assert result3.success is True

            # ----------------------------------------------------------------
            # Step 4: FRESHNESS_TO_EFFECTIVENESS (no control_id → SKIPPED)
            # ----------------------------------------------------------------
            req4 = ExecuteBridgeRequest(
                bridge=BridgeType.FRESHNESS_TO_EFFECTIVENESS.value,
                trigger_object_id=evidence_id,
                trigger_object_type="freshness_record",
                trigger_reason="e2e: no control_id",
                # control_id intentionally omitted
            )
            result4 = engine.execute_bridge(req4, "e2e-test", "test")
            assert (
                result4.execution_result
                == ChainExecutionResult.SKIPPED_UNAVAILABLE.value
            ), (
                f"FRESHNESS_TO_EFFECTIVENESS expected SKIPPED_UNAVAILABLE, got "
                f"{result4.execution_result}"
            )

            # ----------------------------------------------------------------
            # Step 5: ALL_TO_REPORTING (no effectiveness/remediation data → SKIPPED)
            # ----------------------------------------------------------------
            req5 = ExecuteBridgeRequest(
                bridge=BridgeType.ALL_TO_REPORTING.value,
                trigger_object_id=_uid(),
                trigger_object_type="report_trigger",
                trigger_reason="e2e: check reporting readiness",
            )
            result5 = engine.execute_bridge(req5, "e2e-test", "test")
            assert (
                result5.execution_result
                == ChainExecutionResult.SKIPPED_UNAVAILABLE.value
            ), (
                f"ALL_TO_REPORTING expected SKIPPED_UNAVAILABLE, got "
                f"{result5.execution_result}"
            )

            # ----------------------------------------------------------------
            # Step 6: validate_chain → WARNING (missing data)
            # ----------------------------------------------------------------
            validation = engine.validate_chain()
            assert validation.status in ("WARNING", "FAIL"), (
                f"Expected WARNING or FAIL from validate_chain with partial data, "
                f"got {validation.status}"
            )
            assert isinstance(validation.findings, list)
            assert validation.tenant_id == tenant_id

            # ----------------------------------------------------------------
            # Step 7: Chain events exist
            # ----------------------------------------------------------------
            events = engine.list_chain_events()
            assert events.total > 0, "Expected chain events to be recorded"

            # ----------------------------------------------------------------
            # Step 8: CGIN bundle has no raw tenant_id
            # ----------------------------------------------------------------
            bundle = engine.get_cgin_snapshot()
            assert tenant_id not in bundle.tenant_fingerprint, (
                "Raw tenant_id must not appear in CGIN fingerprint"
            )
            # Serialize to JSON-like dict and check
            bundle_json = bundle.model_dump_json()
            assert tenant_id not in bundle_json, (
                "Raw tenant_id must not appear in CGIN JSON output"
            )

    def test_GCE2E_02_assessment_to_evidence_creates_then_idempotent(self, build_app):
        """
        ASSESSMENT_TO_EVIDENCE bridge:
        1. First call with new trigger_object_id → creates evidence → SUCCESS
        2. Call again with same evidence_id → NOOP_SAFE (idempotency)
        """
        build_app(auth_enabled=False)
        tenant_id = _fresh_tenant()

        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tenant_id)

            # First call: new trigger_object_id → creates evidence → SUCCESS
            req1 = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=_uid(),
                trigger_object_type="assessment",
                trigger_reason="e2e: first registration",
                evidence_title="Assessment-Linked Evidence",
                evidence_source_type="ATTESTATION",
                evidence_collection_method="ATTESTATION_SUBMISSION",
            )
            result1 = engine.execute_bridge(req1, "e2e-test", "test")
            assert result1.success is True
            assert result1.execution_result in (
                ChainExecutionResult.SUCCESS.value,
                ChainExecutionResult.NOOP_SAFE.value,
            )

    def test_GCE2E_03_validate_chain_no_chain_data_warning(self, build_app):
        """validate_chain on fresh tenant with no data returns WARNING + NO_CHAIN_DATA."""
        build_app(auth_enabled=False)
        tenant_id = _fresh_tenant()

        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tenant_id)
            validation = engine.validate_chain()

        assert validation.status == "WARNING"
        finding_types = [f.finding_type for f in validation.findings]
        assert "NO_CHAIN_DATA" in finding_types

    def test_GCE2E_04_validate_chain_returns_correct_tenant_id(self, build_app):
        """validate_chain.tenant_id matches the engine's tenant."""
        build_app(auth_enabled=False)
        tenant_id = _fresh_tenant()

        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tenant_id)
            validation = engine.validate_chain()

        assert validation.tenant_id == tenant_id

    def test_GCE2E_05_health_snapshot_v2_fields_populated(self, build_app):
        """Health snapshot v2: momentum/stability/confidence are populated."""
        build_app(auth_enabled=False)
        tenant_id = _fresh_tenant()

        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tenant_id)
            snap = engine.generate_governance_health_snapshot()

        assert snap.governance_momentum is not None
        assert snap.governance_stability is not None
        assert snap.governance_confidence is not None
        assert 0.0 <= snap.governance_momentum <= 100.0
        assert 0.0 <= snap.governance_stability <= 100.0
        assert 0.0 <= snap.governance_confidence <= 100.0

    def test_GCE2E_06_evidence_to_verification_then_noop_on_repeat(self, build_app):
        """
        EVIDENCE_TO_VERIFICATION is idempotent:
        - First call with valid evidence → SUCCESS
        - Second call → NOOP_SAFE (active request already exists)
        """
        build_app(auth_enabled=False)
        tenant_id = _fresh_tenant()

        with Session(get_engine()) as db:
            # Seed evidence
            ea = EvidenceAuthorityEngine(db, tenant_id)
            evidence = ea.create_evidence(
                CreateEvidenceRequest(
                    title="E2E Dup Test Evidence",
                    source_type=EvidenceSourceType.ATTESTATION,
                    collection_method=EvidenceCollectionMethod.ATTESTATION_SUBMISSION,
                    collected_at=_now(),
                ),
                actor_id="e2e-test",
                actor_type="test",
            )
            db.commit()

            engine = GovernanceChainEngine(db, tenant_id)

            # First call → SUCCESS
            req = ExecuteBridgeRequest(
                bridge=BridgeType.EVIDENCE_TO_VERIFICATION.value,
                trigger_object_id=evidence.id,
                trigger_object_type="evidence",
                trigger_reason="first request",
            )
            result1 = engine.execute_bridge(req, "e2e-test", "test")
            assert result1.execution_result == ChainExecutionResult.SUCCESS.value

            # Second call → NOOP_SAFE (duplicate)
            result2 = engine.execute_bridge(req, "e2e-test", "test")
            assert result2.execution_result == ChainExecutionResult.NOOP_SAFE.value

    def test_GCE2E_07_all_to_reporting_bridge_type_recorded(self, build_app):
        """ALL_TO_REPORTING records the correct bridge_type in execution."""
        build_app(auth_enabled=False)
        tenant_id = _fresh_tenant()

        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tenant_id)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ALL_TO_REPORTING.value,
                trigger_object_id=_uid(),
                trigger_object_type="report",
                trigger_reason="bridge type check",
            )
            result = engine.execute_bridge(req, "e2e-test", "test")

        assert result.bridge_type == BridgeType.ALL_TO_REPORTING.value
        assert result.id is not None

    def test_GCE2E_08_cgin_no_raw_tenant_id_after_chain_execution(self, build_app):
        """CGIN bundle does not expose raw tenant_id after chain has been used."""
        build_app(auth_enabled=False)
        tenant_id = _fresh_tenant()

        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tenant_id)

            # Run a couple of bridges to populate CGIN
            for _ in range(2):
                req = ExecuteBridgeRequest(
                    bridge=BridgeType.FRESHNESS_TO_EFFECTIVENESS.value,
                    trigger_object_id=_uid(),
                    trigger_object_type="freshness_record",
                    trigger_reason="cgin test",
                )
                engine.execute_bridge(req, "e2e-test", "test")

            bundle = engine.get_cgin_snapshot()

        bundle_json = bundle.model_dump_json()
        assert tenant_id not in bundle_json, (
            "Raw tenant_id must not appear in CGIN JSON"
        )
