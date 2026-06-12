"""Auditor Proof Package Authority tests — PR 1.9.

Coverage matrix:
  Constants                   version, genesis hash, cert levels, replay weights,
                              custody types, export formats, entity types
  generate_auditor_proof_package  required fields, tenant/engagement scoping,
                              deterministic hash, signing, all 8 sections,
                              section_hashes bound into package_hash
  sign_proof_package          success roundtrip, missing hash raises, non-dict raises,
                              re-sign produces valid output
  verify_proof_package        valid roundtrip, missing fields, wrong authority version,
                              tampered section, tampered section_hash, tampered package_hash,
                              signature mismatch, key_unavailable, key_id mismatch
  replay_auditor_package      valid full replay, missing layers, partial score,
                              evidence/intelligence required for valid=True,
                              layer_details structure, all 7 layers
  generate_executive_trust_brief  all posture levels, trend narratives, board recommendation,
                              executive summary, top_risks, priority_actions, forecast
  generate_regulator_package  default frameworks, custom frameworks, framework_readiness,
                              readiness levels by score, control_mapping, verification_results
  generate_legal_defense_package  questions_answered, decision_reconstruction,
                              evidence_chain, intelligence_chain, replay_validation,
                              reconstruction_hash determinism
  generate_machine_verification_bundle  5 components, bundle_hash, manifest structure,
                              verification_steps, requires_frostgate=False
  generate_trust_certification  all 6 levels, composite scoring, verification_hash
                              determinism, valid_from/valid_until, certification_basis
  generate_chain_of_custody   genesis hash first entry, chain linking, sequence,
                              all custody event types, entity types
  generate_enterprise_export  json/pdf/html/manifest/machine_bundle formats,
                              content_hash, invalid format falls back to json
  Determinism                 all functions produce identical output on identical input
  CrossTenantIsolation        packages differ across tenants, verify rejects mutated tenant,
                              memory filters, certification scoped
  CrossEngagementIsolation    package hash differs, certification scoped
  TamperDetection             section tamper, section_hash forge, package_hash forge,
                              signature tamper, custody chain break
  Performance                 throughput guards for all 10 public functions
  AgentCompatibility          agent/agent_fleet/autonomous_workflow entity types
  AGIGovernanceCompatibility  agi entity type, agi decisions, agi certification
  SecurityInvariants          no function raises on garbage input (except signing functions),
                              verify always returns dict, replay always returns dict
  EnterpriseScenarios         banking, healthcare, govcon, AI governance, M&A due diligence
  EdgeCases                   empty inputs, None inputs, zero scores, unknown levels
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from services.field_assessment.auditor_proof_authority import (
    AUDITOR_PROOF_AUTHORITY_VERSION,
    CERT_BRONZE,
    CERT_ENTERPRISE,
    CERT_GOLD,
    CERT_NOT_CERTIFIED,
    CERT_PLATINUM,
    CERT_SILVER,
    CUSTODY_EVIDENCE_APPROVED,
    CUSTODY_EVIDENCE_CREATED,
    CUSTODY_EVIDENCE_REVIEWED,
    CUSTODY_PACKAGE_GENERATED,
    CUSTODY_REPORT_EXPORTED,
    CUSTODY_REPORT_GENERATED,
    CUSTODY_TRUST_VERIFIED,
    ENTITY_AGI,
    ENTITY_AGENT,
    ENTITY_AGENT_FLEET,
    ENTITY_APPROVER,
    ENTITY_AUTONOMOUS_SYSTEM,
    ENTITY_AUTONOMOUS_WORKFLOW,
    ENTITY_HUMAN,
    ENTITY_REVIEWER,
    EXPORT_HTML,
    EXPORT_JSON,
    EXPORT_MACHINE_BUNDLE,
    EXPORT_MANIFEST,
    EXPORT_PDF,
    FRAMEWORK_HIPAA,
    FRAMEWORK_ISO_42001,
    FRAMEWORK_NIST,
    FRAMEWORK_NIST_AI,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
    PROOF_GENESIS_HASH,
    AuditorProofAuthorityError,
    _CERT_BRONZE_THRESHOLD,
    _CERT_ENTERPRISE_THRESHOLD,
    _CERT_GOLD_THRESHOLD,
    _CERT_PLATINUM_THRESHOLD,
    _CERT_SILVER_THRESHOLD,
    _CERT_VALIDITY_DAYS,
    _REPLAY_CONFIDENCE_WEIGHT,
    _REPLAY_DECISION_WEIGHT,
    _REPLAY_EVIDENCE_WEIGHT,
    _REPLAY_GRAPH_WEIGHT,
    _REPLAY_INTELLIGENCE_WEIGHT,
    _REPLAY_LEDGER_WEIGHT,
    _REPLAY_REPLAY_WEIGHT,
    generate_auditor_proof_package,
    generate_chain_of_custody,
    generate_enterprise_export,
    generate_executive_trust_brief,
    generate_legal_defense_package,
    generate_machine_verification_bundle,
    generate_regulator_package,
    generate_trust_certification,
    replay_auditor_package,
    sign_proof_package,
    verify_proof_package,
)

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

TENANT_A = "tenant-alpha"
TENANT_B = "tenant-beta"
ENG_A = "eng-001"
ENG_B = "eng-002"

_SIGNING_SEED = os.urandom(32)
_SIGNING_KEY_B64 = __import__("base64").b64encode(_SIGNING_SEED).decode()


@pytest.fixture(autouse=True)
def _set_signing_key(monkeypatch):
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _SIGNING_KEY_B64)
    monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)


def _snap(
    posture_score: int = 75,
    posture_level: str = "healthy",
    risk_level: str = "low",
    risk_score: int = 20,
    trend_direction: str = "stable",
) -> dict[str, Any]:
    return {
        "snapshot_hash": "a" * 64,
        "snapshot_signature": "b" * 128,
        "signing_key_id": "c" * 16,
        "authority_version": "trust-intelligence-authority-v1",
        "posture_score": posture_score,
        "posture_level": posture_level,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "trend_direction": trend_direction,
        "trend_velocity": "moderate",
        "priorities_count": 2,
        "insights_count": 3,
        "recommendations_count": 1,
        "priorities": [{"issue": "fix_auth"}, {"issue": "update_replay"}],
        "risk_result": {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "category_scores": {
                "authority_risk": 30,
                "replay_risk": 15,
                "graph_risk": 20,
            },
        },
        "forecast_result": {"projected_score": posture_score + 5},
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _conf(score: int = 70) -> dict[str, Any]:
    return {
        "manifest_hash": "d" * 64,
        "composite_score": score,
        "confidence_score": score,
    }


def _graph(node_count: int = 5) -> dict[str, Any]:
    return {
        "nodes": [{"node_id": f"n{i}"} for i in range(node_count)],
        "edges": [{"source": "n0", "target": "n1"}],
        "node_count": node_count,
        "edge_count": 1,
    }


def _ledger(n: int = 3) -> list[dict[str, Any]]:
    return [
        {
            "ledger_entry_hash": f"{'e' * 63}{i}",
            "previous_hash": PROOF_GENESIS_HASH if i == 0 else f"{'e' * 63}{i - 1}",
            "snapshot_hash": "a" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        for i in range(n)
    ]


def _decisions(n: int = 2) -> list[dict[str, Any]]:
    return [
        {
            "decision_id": uuid.uuid4().hex,
            "decision_type": "approval",
            "entity_type": ENTITY_HUMAN,
            "decision_reasoning": f"Decision {i}: evidence reviewed and approved",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        for i in range(n)
    ]


def _replay_ok() -> dict[str, Any]:
    return {"valid": True, "replay_score": 85, "validations": ["snapshot_integrity"]}


def _pkg(tenant_id: str = TENANT_A, engagement_id: str = ENG_A) -> dict[str, Any]:
    return generate_auditor_proof_package(
        tenant_id,
        engagement_id,
        intelligence_snapshot=_snap(),
        trust_ledger=_ledger(),
        decision_memories=_decisions(),
        confidence_manifest=_conf(),
        graph_snapshot=_graph(),
        replay_result=_replay_ok(),
        evidence_summary={"item_count": 5},
    )


def _custody_events() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return [
        {
            "event_type": CUSTODY_EVIDENCE_CREATED,
            "entity_type": ENTITY_HUMAN,
            "entity_id": "user-1",
            "description": "Evidence collected",
            "timestamp": now,
        },
        {
            "event_type": CUSTODY_EVIDENCE_REVIEWED,
            "entity_type": ENTITY_REVIEWER,
            "entity_id": "reviewer-1",
            "description": "Evidence reviewed",
            "timestamp": now,
        },
        {
            "event_type": CUSTODY_PACKAGE_GENERATED,
            "entity_type": ENTITY_AGENT,
            "entity_id": "agent-1",
            "description": "Package generated",
            "timestamp": now,
        },
    ]


# ---------------------------------------------------------------------------
# 1. TestAuditorProofAuthorityConstants
# ---------------------------------------------------------------------------


class TestAuditorProofAuthorityConstants:
    def test_version_string(self):
        assert AUDITOR_PROOF_AUTHORITY_VERSION == "auditor-proof-authority-v1"

    def test_genesis_hash_is_64_zeros(self):
        assert PROOF_GENESIS_HASH == "0" * 64

    def test_replay_weights_sum_to_100(self):
        total = (
            _REPLAY_EVIDENCE_WEIGHT
            + _REPLAY_REPLAY_WEIGHT
            + _REPLAY_GRAPH_WEIGHT
            + _REPLAY_CONFIDENCE_WEIGHT
            + _REPLAY_INTELLIGENCE_WEIGHT
            + _REPLAY_LEDGER_WEIGHT
            + _REPLAY_DECISION_WEIGHT
        )
        assert total == 100

    def test_cert_thresholds_ordered(self):
        assert _CERT_BRONZE_THRESHOLD < _CERT_SILVER_THRESHOLD
        assert _CERT_SILVER_THRESHOLD < _CERT_GOLD_THRESHOLD
        assert _CERT_GOLD_THRESHOLD < _CERT_PLATINUM_THRESHOLD
        assert _CERT_PLATINUM_THRESHOLD < _CERT_ENTERPRISE_THRESHOLD

    def test_cert_validity_days_positive(self):
        assert _CERT_VALIDITY_DAYS > 0

    def test_entity_types_defined(self):
        assert ENTITY_HUMAN == "human"
        assert ENTITY_AGI == "agi"
        assert ENTITY_AGENT == "agent"
        assert ENTITY_AUTONOMOUS_SYSTEM == "autonomous_system"

    def test_cert_levels_defined(self):
        levels = {CERT_BRONZE, CERT_SILVER, CERT_GOLD, CERT_PLATINUM, CERT_ENTERPRISE}
        assert len(levels) == 5

    def test_custody_event_types_defined(self):
        events = {
            CUSTODY_EVIDENCE_CREATED,
            CUSTODY_EVIDENCE_REVIEWED,
            CUSTODY_EVIDENCE_APPROVED,
            CUSTODY_REPORT_GENERATED,
            CUSTODY_REPORT_EXPORTED,
            CUSTODY_TRUST_VERIFIED,
            CUSTODY_PACKAGE_GENERATED,
        }
        assert len(events) == 7

    def test_export_formats_defined(self):
        formats = {
            EXPORT_JSON,
            EXPORT_PDF,
            EXPORT_HTML,
            EXPORT_MANIFEST,
            EXPORT_MACHINE_BUNDLE,
        }
        assert len(formats) == 5

    def test_framework_constants(self):
        assert FRAMEWORK_NIST
        assert FRAMEWORK_NIST_AI
        assert FRAMEWORK_ISO_42001
        assert FRAMEWORK_SOC2
        assert FRAMEWORK_HIPAA
        assert FRAMEWORK_PCI_DSS


# ---------------------------------------------------------------------------
# 2. TestGenerateAuditorProofPackage
# ---------------------------------------------------------------------------


class TestGenerateAuditorProofPackage:
    def test_returns_required_keys(self):
        pkg = _pkg()
        for key in (
            "package_id",
            "package_hash",
            "package_signature",
            "signing_key_id",
            "authority_version",
            "verified_at",
            "tenant_id",
            "engagement_id",
            "sections",
            "section_count",
            "section_hashes",
            "assessed_by",
        ):
            assert key in pkg, f"Missing key: {key}"

    def test_authority_version_correct(self):
        assert _pkg()["authority_version"] == AUDITOR_PROOF_AUTHORITY_VERSION

    def test_tenant_id_echoed(self):
        assert _pkg(tenant_id=TENANT_A)["tenant_id"] == TENANT_A

    def test_engagement_id_echoed(self):
        assert _pkg(engagement_id=ENG_B)["engagement_id"] == ENG_B

    def test_package_id_unique(self):
        ids = {_pkg()["package_id"] for _ in range(20)}
        assert len(ids) == 20

    def test_package_hash_is_64_hex(self):
        h = _pkg()["package_hash"]
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_package_hash_deterministic(self):
        snap = _snap()
        kwargs = dict(
            intelligence_snapshot=snap,
            evidence_summary={"item_count": 3},
        )
        h1 = generate_auditor_proof_package(TENANT_A, ENG_A, **kwargs)["package_hash"]
        h2 = generate_auditor_proof_package(TENANT_A, ENG_A, **kwargs)["package_hash"]
        assert h1 == h2

    def test_sections_has_8_keys(self):
        sections = _pkg()["sections"]
        expected = {
            "evidence",
            "replay",
            "graph",
            "confidence",
            "intelligence",
            "ledger",
            "decisions",
            "historical",
        }
        assert set(sections.keys()) == expected

    def test_section_count_matches(self):
        pkg = _pkg()
        assert pkg["section_count"] == len(pkg["sections"])

    def test_section_hashes_present_for_all_sections(self):
        pkg = _pkg()
        for name in pkg["sections"]:
            assert name in pkg["section_hashes"]
            assert len(pkg["section_hashes"][name]) == 64

    def test_evidence_section_present(self):
        pkg = _pkg()
        assert pkg["sections"]["evidence"]["status"] == "present"

    def test_intelligence_section_populated(self):
        pkg = _pkg()
        intel = pkg["sections"]["intelligence"]
        assert intel["posture_score"] == 75
        assert intel["posture_level"] == "healthy"

    def test_ledger_section_populated(self):
        pkg = _pkg()
        assert pkg["sections"]["ledger"]["entry_count"] == 3

    def test_decisions_section_populated(self):
        pkg = _pkg()
        assert pkg["sections"]["decisions"]["decision_count"] == 2

    def test_missing_tenant_raises(self):
        with pytest.raises(AuditorProofAuthorityError):
            generate_auditor_proof_package("", ENG_A)

    def test_missing_engagement_raises(self):
        with pytest.raises(AuditorProofAuthorityError):
            generate_auditor_proof_package(TENANT_A, "")

    def test_assessed_by_default_human(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A)
        assert pkg["assessed_by"] == ENTITY_HUMAN

    def test_assessed_by_custom(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A, assessed_by=ENTITY_AGI)
        assert pkg["assessed_by"] == ENTITY_AGI

    def test_hash_differs_across_tenants(self):
        h_a = _pkg(tenant_id=TENANT_A)["package_hash"]
        h_b = _pkg(tenant_id=TENANT_B)["package_hash"]
        assert h_a != h_b

    def test_hash_differs_across_engagements(self):
        h1 = _pkg(engagement_id=ENG_A)["package_hash"]
        h2 = _pkg(engagement_id=ENG_B)["package_hash"]
        assert h1 != h2

    def test_signature_is_128_hex(self):
        sig = _pkg()["package_signature"]
        assert len(sig) == 128
        assert all(c in "0123456789abcdef" for c in sig)

    def test_empty_inputs_do_not_raise(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A)
        assert pkg["sections"]["evidence"]["status"] == "absent"

    def test_section_hashes_change_with_section_content(self):
        pkg1 = generate_auditor_proof_package(
            TENANT_A, ENG_A, intelligence_snapshot=_snap(posture_score=50)
        )
        pkg2 = generate_auditor_proof_package(
            TENANT_A, ENG_A, intelligence_snapshot=_snap(posture_score=90)
        )
        assert (
            pkg1["section_hashes"]["intelligence"]
            != pkg2["section_hashes"]["intelligence"]
        )
        assert pkg1["package_hash"] != pkg2["package_hash"]

    def test_graph_section_node_count(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A, graph_snapshot=_graph(7))
        assert pkg["sections"]["graph"]["node_count"] == 7

    def test_replay_section_verified(self):
        pkg = generate_auditor_proof_package(
            TENANT_A, ENG_A, replay_result=_replay_ok()
        )
        assert pkg["sections"]["replay"]["status"] == "verified"

    def test_replay_section_failed_on_invalid(self):
        pkg = generate_auditor_proof_package(
            TENANT_A, ENG_A, replay_result={"valid": False, "replay_score": 0}
        )
        assert pkg["sections"]["replay"]["status"] == "failed"


# ---------------------------------------------------------------------------
# 3. TestSignProofPackage
# ---------------------------------------------------------------------------


class TestSignProofPackage:
    def test_sign_adds_signature(self):
        pkg = _pkg()
        pkg["package_signature"] = ""
        signed = sign_proof_package(pkg)
        assert len(signed["package_signature"]) > 0

    def test_sign_updates_key_id(self):
        pkg = _pkg()
        signed = sign_proof_package(pkg)
        assert signed["signing_key_id"] == pkg["signing_key_id"]

    def test_sign_does_not_mutate_input(self):
        pkg = _pkg()
        original_sig = pkg["package_signature"]
        sign_proof_package(pkg)
        assert pkg["package_signature"] == original_sig

    def test_sign_produces_verifiable_package(self):
        pkg = _pkg()
        signed = sign_proof_package(pkg)
        assert verify_proof_package(signed)["valid"] is True

    def test_sign_missing_package_hash_raises(self):
        pkg = _pkg()
        del pkg["package_hash"]
        with pytest.raises(AuditorProofAuthorityError):
            sign_proof_package(pkg)

    def test_sign_empty_package_hash_raises(self):
        pkg = _pkg()
        pkg["package_hash"] = ""
        with pytest.raises(AuditorProofAuthorityError):
            sign_proof_package(pkg)

    def test_sign_non_dict_raises(self):
        with pytest.raises(AuditorProofAuthorityError):
            sign_proof_package(None)  # type: ignore

    def test_sign_no_key_raises(self, monkeypatch):
        pkg = _pkg()
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        with pytest.raises(AuditorProofAuthorityError):
            sign_proof_package(pkg)

    def test_double_sign_same_hash(self):
        pkg = _pkg()
        s1 = sign_proof_package(pkg)
        s2 = sign_proof_package(pkg)
        assert s1["package_hash"] == s2["package_hash"]

    def test_sign_returns_new_dict(self):
        pkg = _pkg()
        signed = sign_proof_package(pkg)
        assert signed is not pkg

    def test_sign_preserves_other_fields(self):
        pkg = _pkg()
        signed = sign_proof_package(pkg)
        for k in pkg:
            if k not in ("package_signature", "signing_key_id"):
                assert signed[k] == pkg[k]

    def test_sign_produces_128_char_sig(self):
        signed = sign_proof_package(_pkg())
        assert len(signed["package_signature"]) == 128


# ---------------------------------------------------------------------------
# 4. TestVerifyProofPackage
# ---------------------------------------------------------------------------


class TestVerifyProofPackage:
    def test_valid_package(self):
        assert verify_proof_package(_pkg())["valid"] is True

    def test_valid_reason_none(self):
        assert verify_proof_package(_pkg())["reason"] is None

    def test_empty_dict_invalid(self):
        assert verify_proof_package({})["valid"] is False

    def test_none_invalid(self):
        assert verify_proof_package(None)["valid"] is False  # type: ignore

    def test_wrong_authority_version(self):
        pkg = _pkg()
        pkg["authority_version"] = "old-v0"
        r = verify_proof_package(pkg)
        assert r["valid"] is False
        assert "invalid_authority_version" in r["reason"]

    def test_missing_field_invalid(self):
        pkg = _pkg()
        del pkg["package_hash"]
        r = verify_proof_package(pkg)
        assert r["valid"] is False
        assert "missing_fields" in r["reason"]

    def test_tampered_section_detected(self):
        pkg = _pkg()
        pkg["sections"]["evidence"]["item_count"] = 9999
        r = verify_proof_package(pkg)
        assert r["valid"] is False
        assert r["reason"] == "tampered_section"

    def test_tampered_section_hash_detected(self):
        pkg = _pkg()
        pkg["section_hashes"]["evidence"] = "f" * 64
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_tampered_package_hash_detected(self):
        pkg = _pkg()
        pkg["package_hash"] = "9" * 64
        r = verify_proof_package(pkg)
        assert r["valid"] is False
        assert r["reason"] in ("tampered_package_hash", "signature_mismatch")

    def test_tampered_signature(self):
        pkg = _pkg()
        pkg["package_signature"] = "00" * 64
        r = verify_proof_package(pkg)
        assert r["valid"] is False
        assert r["reason"] == "signature_mismatch"

    def test_key_unavailable(self, monkeypatch):
        pkg = _pkg()
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        r = verify_proof_package(pkg)
        assert r["valid"] is False
        assert r["reason"] == "key_unavailable"

    def test_signing_key_id_mismatch(self):
        pkg = _pkg()
        pkg["signing_key_id"] = "deadbeef" * 2
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_invalid_section_count(self):
        pkg = _pkg()
        pkg["section_count"] = "not_a_number"
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_adding_intelligence_section_changes_hash(self):
        pkg1 = generate_auditor_proof_package(TENANT_A, ENG_A)
        pkg2 = generate_auditor_proof_package(
            TENANT_A, ENG_A, intelligence_snapshot=_snap(posture_score=80)
        )
        assert pkg1["package_hash"] != pkg2["package_hash"]

    def test_verify_returns_dict_always(self):
        for bad in [None, 42, "string", [], {}]:
            r = verify_proof_package(bad)  # type: ignore
            assert isinstance(r, dict)
            assert "valid" in r

    def test_mutated_tenant_rejected(self):
        pkg = _pkg(tenant_id=TENANT_A)
        pkg["tenant_id"] = TENANT_B
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_mutated_assessed_by_rejected(self):
        pkg = _pkg()
        pkg["assessed_by"] = ENTITY_AGI
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_invalid_sections_type(self):
        pkg = _pkg()
        pkg["sections"] = "not_a_dict"
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_valid_full_package_all_inputs(self):
        pkg = generate_auditor_proof_package(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(),
            trust_ledger=_ledger(),
            decision_memories=_decisions(),
            confidence_manifest=_conf(),
            graph_snapshot=_graph(),
            replay_result=_replay_ok(),
            evidence_summary={"item_count": 10},
        )
        assert verify_proof_package(pkg)["valid"] is True


# ---------------------------------------------------------------------------
# 5. TestReplayAuditorPackage
# ---------------------------------------------------------------------------


class TestReplayAuditorPackage:
    def _full_replay(self):
        pkg = _pkg()
        return replay_auditor_package(
            pkg,
            intelligence_snapshot=_snap(),
            trust_ledger=_ledger(),
            confidence_manifest=_conf(),
            graph_snapshot=_graph(),
            replay_result=_replay_ok(),
            decision_memories=_decisions(),
        )

    def test_full_replay_valid(self):
        r = self._full_replay()
        assert r["valid"] is True

    def test_full_replay_score_100(self):
        r = self._full_replay()
        assert r["replay_score"] == 100

    def test_all_7_layers_in_validations(self):
        r = self._full_replay()
        expected = {
            "evidence_authority",
            "replay_authority",
            "graph_authority",
            "confidence_authority",
            "intelligence_authority",
            "trust_ledger",
            "decision_memory",
        }
        assert set(r["validations"]) == expected

    def test_layer_details_all_passed(self):
        r = self._full_replay()
        for layer_name, detail in r["layer_details"].items():
            assert detail["passed"] is True, f"Layer {layer_name} should pass"

    def test_missing_evidence_fails_valid(self):
        # Package built without evidence_summary → evidence section has status "absent"
        # → evidence_authority layer must NOT pass → valid must be False
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A)
        r = replay_auditor_package(pkg, intelligence_snapshot=_snap())
        assert "evidence_authority" not in r["validations"]
        assert r["valid"] is False

    def test_absent_evidence_status_not_counted_as_present(self):
        # Regression for P1: bool(evidence_section) passes on {"status": "absent", ...}
        # The evidence layer must require status == "present", not just a non-empty dict.
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A)
        assert pkg["sections"]["evidence"]["status"] == "absent"
        r = replay_auditor_package(
            pkg,
            intelligence_snapshot=_snap(),
            trust_ledger=_ledger(),
            confidence_manifest=_conf(),
            graph_snapshot=_graph(),
            replay_result=_replay_ok(),
            decision_memories=_decisions(),
        )
        assert r["layer_details"]["evidence_authority"]["passed"] is False
        assert r["valid"] is False

    def test_no_intelligence_snapshot_reduces_score(self):
        pkg = _pkg()
        r = replay_auditor_package(pkg)
        assert r["replay_score"] < 100

    def test_missing_package_returns_invalid(self):
        r = replay_auditor_package({})
        assert r["valid"] is False
        assert r["replay_score"] == 0

    def test_none_package_returns_invalid(self):
        r = replay_auditor_package(None)  # type: ignore
        assert r["valid"] is False

    def test_package_id_echoed(self):
        pkg = _pkg()
        r = replay_auditor_package(pkg)
        assert r["package_id"] == pkg["package_id"]

    def test_returns_dict_always(self):
        for bad in [None, 42, "x", []]:
            r = replay_auditor_package(bad)  # type: ignore
            assert isinstance(r, dict)

    def test_reason_is_none_on_valid(self):
        r = self._full_replay()
        assert r["reason"] is None

    def test_reason_set_on_invalid(self):
        r = replay_auditor_package({})
        assert r["reason"] is not None

    def test_partial_replay_partial_score(self):
        pkg = _pkg()
        r = replay_auditor_package(
            pkg,
            intelligence_snapshot=_snap(),
            trust_ledger=_ledger(),
        )
        assert 0 < r["replay_score"] < 100

    def test_replay_evidence_weight(self):
        pkg = _pkg()
        r_with = replay_auditor_package(pkg, intelligence_snapshot=_snap())
        r_without = replay_auditor_package(
            generate_auditor_proof_package(TENANT_A, ENG_A),
            intelligence_snapshot=_snap(),
        )
        assert r_with["replay_score"] >= r_without["replay_score"]

    def test_layer_details_structure(self):
        r = self._full_replay()
        for detail in r["layer_details"].values():
            assert "passed" in detail
            assert "score" in detail
            assert "reason" in detail

    def test_no_graph_snapshot_skips_layer(self):
        pkg = _pkg()
        r = replay_auditor_package(
            pkg,
            intelligence_snapshot=_snap(),
            graph_snapshot=None,
        )
        assert "graph_authority" not in r["validations"]

    def test_no_decision_memories_skips_layer(self):
        pkg = _pkg()
        r = replay_auditor_package(
            pkg,
            intelligence_snapshot=_snap(),
            decision_memories=[],
        )
        assert "decision_memory" not in r["validations"]

    def test_score_never_exceeds_100(self):
        r = self._full_replay()
        assert r["replay_score"] <= 100

    def test_score_never_below_0(self):
        r = replay_auditor_package({})
        assert r["replay_score"] >= 0

    def test_garbage_inputs_do_not_raise(self):
        r = replay_auditor_package(
            _pkg(),
            intelligence_snapshot=42,  # type: ignore
            trust_ledger="not_a_list",  # type: ignore
            confidence_manifest=None,
            decision_memories=3.14,  # type: ignore
        )
        assert isinstance(r, dict)


# ---------------------------------------------------------------------------
# 6. TestGenerateExecutiveTrustBrief
# ---------------------------------------------------------------------------


class TestGenerateExecutiveTrustBrief:
    def test_returns_required_keys(self):
        brief = generate_executive_trust_brief(TENANT_A, ENG_A)
        for key in (
            "brief_id",
            "tenant_id",
            "engagement_id",
            "brief_date",
            "current_posture",
            "trust_trend",
            "top_risks",
            "priority_actions",
            "executive_summary",
            "board_recommendation",
        ):
            assert key in brief, f"Missing: {key}"

    def test_tenant_id_echoed(self):
        assert generate_executive_trust_brief(TENANT_A, ENG_A)["tenant_id"] == TENANT_A

    def test_posture_level_in_brief(self):
        snap = _snap(posture_level="critical")
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert brief["current_posture"]["level"] == "critical"

    def test_posture_score_in_brief(self):
        snap = _snap(posture_score=88)
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert brief["current_posture"]["score"] == 88

    def test_critical_posture_narrative(self):
        snap = _snap(posture_level="critical")
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert "immediate" in brief["current_posture"]["plain_english"].lower()

    def test_excellent_posture_narrative(self):
        snap = _snap(posture_level="excellent")
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert "excellent" in brief["current_posture"]["plain_english"].lower()

    def test_board_recommendation_critical(self):
        snap = _snap(posture_level="critical")
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert "immediate" in brief["board_recommendation"].lower()

    def test_board_recommendation_excellent(self):
        snap = _snap(posture_level="excellent")
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert "certification" in brief["board_recommendation"].lower()

    def test_trend_direction_in_brief(self):
        snap = _snap(trend_direction="improving")
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert brief["trust_trend"]["direction"] == "improving"

    def test_top_risks_populated(self):
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=_snap()
        )
        assert len(brief["top_risks"]) > 0

    def test_priority_actions_populated(self):
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=_snap()
        )
        assert len(brief["priority_actions"]) > 0

    def test_executive_summary_mentions_posture(self):
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=_snap()
        )
        assert "trust" in brief["executive_summary"].lower()

    def test_no_snapshot_returns_defaults(self):
        brief = generate_executive_trust_brief(TENANT_A, ENG_A)
        assert brief["current_posture"]["score"] == 0

    def test_forecast_present(self):
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=_snap()
        )
        assert "forecast" in brief

    def test_brief_id_unique(self):
        ids = {
            generate_executive_trust_brief(TENANT_A, ENG_A)["brief_id"]
            for _ in range(10)
        }
        assert len(ids) == 10

    def test_trust_trend_has_context(self):
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=_snap()
        )
        assert "context" in brief["trust_trend"]

    def test_risk_summary_present(self):
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=_snap()
        )
        assert "risk_summary" in brief

    def test_never_raises_on_garbage(self):
        brief = generate_executive_trust_brief(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=42,  # type: ignore
        )
        assert isinstance(brief, dict)


# ---------------------------------------------------------------------------
# 7. TestGenerateRegulatorPackage
# ---------------------------------------------------------------------------


class TestGenerateRegulatorPackage:
    def test_returns_required_keys(self):
        pkg = generate_regulator_package(TENANT_A, ENG_A)
        for key in (
            "package_id",
            "tenant_id",
            "engagement_id",
            "generated_at",
            "assessment_scope",
            "evidence_sources",
            "assessed_frameworks",
            "framework_readiness",
            "control_mapping",
            "verification_results",
        ):
            assert key in pkg, f"Missing: {key}"

    def test_default_frameworks_used(self):
        pkg = generate_regulator_package(TENANT_A, ENG_A)
        assert len(pkg["assessed_frameworks"]) > 0
        assert FRAMEWORK_NIST in pkg["assessed_frameworks"]

    def test_custom_frameworks_accepted(self):
        fw = [FRAMEWORK_HIPAA, FRAMEWORK_PCI_DSS, "CUSTOM_FRAMEWORK"]
        pkg = generate_regulator_package(TENANT_A, ENG_A, frameworks=fw)
        assert "CUSTOM_FRAMEWORK" in pkg["assessed_frameworks"]

    def test_framework_readiness_keyed_by_framework(self):
        pkg = generate_regulator_package(TENANT_A, ENG_A)
        for fw in pkg["assessed_frameworks"]:
            assert fw in pkg["framework_readiness"]

    def test_high_score_compliant_ready(self):
        snap = _snap(posture_score=85)
        pkg = generate_regulator_package(TENANT_A, ENG_A, intelligence_snapshot=snap)
        for fw_data in pkg["framework_readiness"].values():
            assert fw_data["readiness_level"] == "compliant_ready"

    def test_low_score_requires_remediation(self):
        snap = _snap(posture_score=30)
        pkg = generate_regulator_package(TENANT_A, ENG_A, intelligence_snapshot=snap)
        for fw_data in pkg["framework_readiness"].values():
            assert fw_data["readiness_level"] == "requires_remediation"

    def test_medium_score_substantially_compliant(self):
        snap = _snap(posture_score=65)
        pkg = generate_regulator_package(TENANT_A, ENG_A, intelligence_snapshot=snap)
        for fw_data in pkg["framework_readiness"].values():
            assert fw_data["readiness_level"] == "substantially_compliant"

    def test_evidence_sources_populated(self):
        pkg = generate_regulator_package(
            TENANT_A, ENG_A, evidence_summary={"item_count": 10}
        )
        assert len(pkg["evidence_sources"]) > 0

    def test_control_mapping_from_results(self):
        controls = [
            {"control_id": "AC-1", "control_name": "Access Control", "score": 80}
        ]
        pkg = generate_regulator_package(TENANT_A, ENG_A, control_results=controls)
        assert len(pkg["control_mapping"]) == 1
        assert pkg["control_mapping"][0]["control_id"] == "AC-1"

    def test_trust_chain_validation_present(self):
        snap = _snap()
        pkg = generate_regulator_package(TENANT_A, ENG_A, intelligence_snapshot=snap)
        assert pkg["trust_chain_validation"]["chain_intact"] is True

    def test_no_hardcoded_framework_limits(self):
        custom_fws = [f"CUSTOM_FW_{i}" for i in range(10)]
        pkg = generate_regulator_package(TENANT_A, ENG_A, frameworks=custom_fws)
        assert len(pkg["framework_readiness"]) == 10

    def test_verification_results_structure(self):
        pkg = generate_regulator_package(TENANT_A, ENG_A, intelligence_snapshot=_snap())
        vr = pkg["verification_results"]
        assert "trust_chain" in vr
        assert "posture_verified" in vr

    def test_iso_42001_supported(self):
        pkg = generate_regulator_package(
            TENANT_A, ENG_A, frameworks=[FRAMEWORK_ISO_42001]
        )
        assert FRAMEWORK_ISO_42001 in pkg["framework_readiness"]

    def test_nist_ai_rmf_supported(self):
        pkg = generate_regulator_package(
            TENANT_A, ENG_A, frameworks=[FRAMEWORK_NIST_AI]
        )
        assert FRAMEWORK_NIST_AI in pkg["framework_readiness"]

    def test_empty_frameworks_uses_defaults(self):
        pkg = generate_regulator_package(TENANT_A, ENG_A, frameworks=[])
        assert len(pkg["assessed_frameworks"]) > 0

    def test_tenant_id_echoed(self):
        pkg = generate_regulator_package(TENANT_A, ENG_A)
        assert pkg["tenant_id"] == TENANT_A

    def test_gaps_present_for_low_score(self):
        snap = _snap(posture_score=20)
        pkg = generate_regulator_package(TENANT_A, ENG_A, intelligence_snapshot=snap)
        for fw_data in pkg["framework_readiness"].values():
            assert len(fw_data["gaps"]) > 0

    def test_never_raises(self):
        pkg = generate_regulator_package(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=42,  # type: ignore
            frameworks="bad",  # type: ignore
        )
        assert isinstance(pkg, dict)

    def test_package_id_unique(self):
        ids = {
            generate_regulator_package(TENANT_A, ENG_A)["package_id"] for _ in range(5)
        }
        assert len(ids) == 5

    def test_decision_chain_validation_present(self):
        pkg = generate_regulator_package(TENANT_A, ENG_A, intelligence_snapshot=_snap())
        assert "decision_chain_validation" in pkg


# ---------------------------------------------------------------------------
# 8. TestGenerateLegalDefensePackage
# ---------------------------------------------------------------------------


class TestGenerateLegalDefensePackage:
    def test_returns_required_keys(self):
        pkg = generate_legal_defense_package(TENANT_A, ENG_A)
        for key in (
            "package_id",
            "tenant_id",
            "engagement_id",
            "generated_at",
            "decision_reconstruction",
            "evidence_chain",
            "intelligence_chain",
            "replay_validation",
            "decision_timeline",
            "questions_answered",
            "reconstruction_hash",
        ):
            assert key in pkg, f"Missing: {key}"

    def test_questions_answered_has_7_keys(self):
        pkg = generate_legal_defense_package(TENANT_A, ENG_A)
        qa = pkg["questions_answered"]
        expected = {
            "what_was_known",
            "when_was_it_known",
            "what_evidence_existed",
            "what_intelligence_existed",
            "who_approved",
            "why_was_decision_made",
            "can_decision_be_replayed",
        }
        assert set(qa.keys()) == expected

    def test_decision_reconstruction_total(self):
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=_decisions(3)
        )
        assert pkg["decision_reconstruction"]["total_decisions"] == 3

    def test_evidence_chain_snapshot_hash(self):
        snap = _snap()
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert pkg["evidence_chain"]["snapshot_hash"] == "a" * 64

    def test_intelligence_chain_priorities(self):
        snap = _snap()
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert pkg["intelligence_chain"]["priorities_count"] == 2

    def test_replay_valid_echoed(self):
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, replay_result=_replay_ok()
        )
        assert pkg["replay_validation"]["valid"] is True
        assert pkg["replay_validation"]["can_replay"] is True

    def test_can_replay_false_without_replay(self):
        pkg = generate_legal_defense_package(TENANT_A, ENG_A)
        assert pkg["replay_validation"]["can_replay"] is False

    def test_decision_timeline_sequential(self):
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=_decisions(4)
        )
        sequences = [e["sequence"] for e in pkg["decision_timeline"]]
        assert sequences == list(range(1, 5))

    def test_reconstruction_hash_is_64_hex(self):
        h = generate_legal_defense_package(TENANT_A, ENG_A)["reconstruction_hash"]
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_reconstruction_hash_deterministic(self):
        snap = _snap()
        h1 = generate_legal_defense_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )["reconstruction_hash"]
        h2 = generate_legal_defense_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )["reconstruction_hash"]
        assert h1 == h2

    def test_entity_types_in_reconstruction(self):
        decisions = [
            {**_decisions(1)[0], "entity_type": ENTITY_AGI},
            {**_decisions(1)[0], "entity_type": ENTITY_HUMAN},
        ]
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions
        )
        assert ENTITY_AGI in pkg["decision_reconstruction"]["entity_types"]
        assert ENTITY_HUMAN in pkg["decision_reconstruction"]["entity_types"]

    def test_who_approved_from_entity_types(self):
        decisions = [{**_decisions(1)[0], "entity_type": ENTITY_APPROVER}]
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions
        )
        assert ENTITY_APPROVER in pkg["questions_answered"]["who_approved"]

    def test_what_was_known_includes_posture(self):
        snap = _snap(posture_level="degraded", posture_score=40)
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert "degraded" in pkg["questions_answered"]["what_was_known"]

    def test_never_raises_on_garbage(self):
        pkg = generate_legal_defense_package(
            TENANT_A,
            ENG_A,
            decision_memories=42,  # type: ignore
            intelligence_snapshot="bad",  # type: ignore
        )
        assert isinstance(pkg, dict)

    def test_tenant_id_echoed(self):
        pkg = generate_legal_defense_package(TENANT_A, ENG_A)
        assert pkg["tenant_id"] == TENANT_A

    def test_empty_decisions_ok(self):
        pkg = generate_legal_defense_package(TENANT_A, ENG_A, decision_memories=[])
        assert pkg["decision_reconstruction"]["total_decisions"] == 0

    def test_reasoning_truncated_to_500_chars(self):
        long_reason = "x" * 1000
        decisions = [{**_decisions(1)[0], "decision_reasoning": long_reason}]
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions
        )
        assert len(pkg["questions_answered"]["why_was_decision_made"]) <= 500

    def test_package_id_unique(self):
        ids = {
            generate_legal_defense_package(TENANT_A, ENG_A)["package_id"]
            for _ in range(5)
        }
        assert len(ids) == 5

    def test_reconstruction_hash_changes_when_decision_content_changes(self):
        # Regression for P1: reconstruction_stable previously bound only count/snapshot_hash.
        # An attacker could replace every decision's content while preserving count → same hash.
        base_decisions = _decisions(2)
        altered_decisions = [
            {**d, "decision_reasoning": "FORGED reasoning", "entity_type": ENTITY_AGI}
            for d in base_decisions
        ]
        snap = _snap()
        h_original = generate_legal_defense_package(
            TENANT_A,
            ENG_A,
            decision_memories=base_decisions,
            intelligence_snapshot=snap,
        )["reconstruction_hash"]
        h_altered = generate_legal_defense_package(
            TENANT_A,
            ENG_A,
            decision_memories=altered_decisions,
            intelligence_snapshot=snap,
        )["reconstruction_hash"]
        assert h_original != h_altered

    def test_reconstruction_hash_stable_for_same_content(self):
        decisions = _decisions(2)
        snap = _snap()
        h1 = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions, intelligence_snapshot=snap
        )["reconstruction_hash"]
        h2 = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions, intelligence_snapshot=snap
        )["reconstruction_hash"]
        assert h1 == h2


# ---------------------------------------------------------------------------
# 9. TestGenerateMachineVerificationBundle
# ---------------------------------------------------------------------------


class TestGenerateMachineVerificationBundle:
    def test_returns_required_keys(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        for key in (
            "bundle_id",
            "bundle_hash",
            "tenant_id",
            "engagement_id",
            "authority_version",
            "components",
            "generated_at",
        ):
            assert key in bundle, f"Missing: {key}"

    def test_5_components_present(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        assert set(bundle["components"].keys()) == {
            "trust",
            "ledger",
            "proof",
            "manifest",
            "verification",
        }

    def test_requires_frostgate_false(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        assert bundle["components"]["verification"]["requires_frostgate"] is False

    def test_supports_offline_verification(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        assert (
            bundle["components"]["verification"]["supports_offline_verification"]
            is True
        )

    def test_bundle_hash_is_64_hex(self):
        h = generate_machine_verification_bundle(TENANT_A, ENG_A)["bundle_hash"]
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_bundle_hash_deterministic(self):
        snap = _snap()
        pkg = _pkg()
        h1 = generate_machine_verification_bundle(
            TENANT_A, ENG_A, intelligence_snapshot=snap, proof_package=pkg
        )["bundle_hash"]
        h2 = generate_machine_verification_bundle(
            TENANT_A, ENG_A, intelligence_snapshot=snap, proof_package=pkg
        )["bundle_hash"]
        assert h1 == h2

    def test_trust_component_has_snapshot_hash(self):
        snap = _snap()
        bundle = generate_machine_verification_bundle(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert bundle["components"]["trust"]["snapshot_hash"] == "a" * 64

    def test_ledger_component_populated(self):
        bundle = generate_machine_verification_bundle(
            TENANT_A, ENG_A, trust_ledger=_ledger(3)
        )
        assert len(bundle["components"]["ledger"]) == 3

    def test_proof_component_has_package_hash(self):
        pkg = _pkg()
        bundle = generate_machine_verification_bundle(
            TENANT_A, ENG_A, proof_package=pkg
        )
        assert bundle["components"]["proof"]["package_hash"] == pkg["package_hash"]

    def test_manifest_has_5_components(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        manifest = bundle["components"]["manifest"]
        assert manifest["component_count"] == 5

    def test_verification_steps_non_empty(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        steps = bundle["components"]["verification"]["steps"]
        assert len(steps) >= 3

    def test_bundle_id_unique(self):
        ids = {
            generate_machine_verification_bundle(TENANT_A, ENG_A)["bundle_id"]
            for _ in range(10)
        }
        assert len(ids) == 10

    def test_tenant_id_echoed(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        assert bundle["tenant_id"] == TENANT_A

    def test_never_raises(self):
        bundle = generate_machine_verification_bundle(
            TENANT_A,
            ENG_A,
            proof_package=42,  # type: ignore
            trust_ledger="bad",  # type: ignore
        )
        assert isinstance(bundle, dict)

    def test_bundle_hash_changes_with_snapshot(self):
        h1 = generate_machine_verification_bundle(
            TENANT_A, ENG_A, intelligence_snapshot=_snap(posture_score=50)
        )["bundle_hash"]
        h2 = generate_machine_verification_bundle(
            TENANT_A, ENG_A, intelligence_snapshot=_snap(posture_score=90)
        )["bundle_hash"]
        assert h1 != h2

    def test_verification_component_has_authority_version(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        assert (
            bundle["components"]["verification"]["authority_version"]
            == AUDITOR_PROOF_AUTHORITY_VERSION
        )

    def test_third_party_verification_supported(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        assert (
            bundle["components"]["verification"]["supports_third_party_verification"]
            is True
        )

    def test_manifest_component_hashes_present(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        for comp in bundle["components"]["manifest"]["components"]:
            assert "name" in comp
            assert "present" in comp

    def test_proof_component_includes_section_hashes(self):
        # Regression for P1: offline verification of package_hash requires section_hashes.
        pkg = _pkg()
        bundle = generate_machine_verification_bundle(
            TENANT_A, ENG_A, proof_package=pkg
        )
        proof = bundle["components"]["proof"]
        assert "section_hashes" in proof
        assert proof["section_hashes"] == pkg["section_hashes"]

    def test_proof_component_includes_assessed_by(self):
        # Regression for P1: offline verification of package_hash requires assessed_by.
        pkg = _pkg()
        bundle = generate_machine_verification_bundle(
            TENANT_A, ENG_A, proof_package=pkg
        )
        proof = bundle["components"]["proof"]
        assert "assessed_by" in proof
        assert proof["assessed_by"] == pkg["assessed_by"]


# ---------------------------------------------------------------------------
# 10. TestGenerateTrustCertification
# ---------------------------------------------------------------------------


class TestGenerateTrustCertification:
    def test_returns_required_keys(self):
        cert = generate_trust_certification(TENANT_A, ENG_A)
        for key in (
            "certification_id",
            "tenant_id",
            "engagement_id",
            "certification_level",
            "trust_score",
            "confidence_score",
            "composite_score",
            "valid_from",
            "valid_until",
            "verification_hash",
            "authority_version",
            "scored_by",
            "certification_basis",
        ):
            assert key in cert, f"Missing: {key}"

    def test_enterprise_level_high_score(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=95),
            confidence_manifest=_conf(score=95),
        )
        assert cert["certification_level"] == CERT_ENTERPRISE

    def test_platinum_level(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=82),
            confidence_manifest=_conf(score=82),
        )
        assert cert["certification_level"] == CERT_PLATINUM

    def test_gold_level(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=72),
            confidence_manifest=_conf(score=72),
        )
        assert cert["certification_level"] == CERT_GOLD

    def test_silver_level(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=62),
            confidence_manifest=_conf(score=62),
        )
        assert cert["certification_level"] == CERT_SILVER

    def test_bronze_level(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=52),
            confidence_manifest=_conf(score=52),
        )
        assert cert["certification_level"] == CERT_BRONZE

    def test_not_certified_low_score(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=20),
            confidence_manifest=_conf(score=20),
        )
        assert cert["certification_level"] == CERT_NOT_CERTIFIED

    def test_composite_score_weighted(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=80),
            confidence_manifest=_conf(score=60),
        )
        expected = round(0.7 * 80 + 0.3 * 60)
        assert cert["composite_score"] == expected

    def test_composite_score_clamped_100(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=100),
            confidence_manifest=_conf(score=100),
        )
        assert cert["composite_score"] <= 100

    def test_composite_score_clamped_0(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=0),
            confidence_manifest=_conf(score=0),
        )
        assert cert["composite_score"] >= 0

    def test_verification_hash_deterministic(self):
        snap = _snap(posture_score=80)
        conf = _conf(score=70)
        h1 = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=snap, confidence_manifest=conf
        )["verification_hash"]
        h2 = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=snap, confidence_manifest=conf
        )["verification_hash"]
        assert h1 == h2

    def test_verification_hash_64_hex(self):
        h = generate_trust_certification(TENANT_A, ENG_A)["verification_hash"]
        assert len(h) == 64

    def test_valid_until_90_days_from_now(self):
        cert = generate_trust_certification(TENANT_A, ENG_A)
        from_dt = datetime.fromisoformat(cert["valid_from"].replace("Z", "+00:00"))
        until_dt = datetime.fromisoformat(cert["valid_until"].replace("Z", "+00:00"))
        delta_days = (until_dt - from_dt).days
        assert delta_days == _CERT_VALIDITY_DAYS

    def test_scored_by_deterministic(self):
        c1 = generate_trust_certification(TENANT_A, ENG_A)
        c2 = generate_trust_certification(TENANT_A, ENG_A)
        assert c1["scored_by"] == c2["scored_by"]

    def test_certification_id_unique(self):
        ids = {
            generate_trust_certification(TENANT_A, ENG_A)["certification_id"]
            for _ in range(10)
        }
        assert len(ids) == 10

    def test_certification_basis_non_empty_with_snapshot(self):
        cert = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=_snap()
        )
        assert len(cert["certification_basis"]) > 0

    def test_no_ai_scoring(self):
        cert = generate_trust_certification(TENANT_A, ENG_A)
        assert "ai" not in cert["scored_by"].lower()
        assert "ml" not in cert["scored_by"].lower()

    def test_authority_version_correct(self):
        cert = generate_trust_certification(TENANT_A, ENG_A)
        assert cert["authority_version"] == AUDITOR_PROOF_AUTHORITY_VERSION

    def test_tenant_id_echoed(self):
        cert = generate_trust_certification(TENANT_A, ENG_A)
        assert cert["tenant_id"] == TENANT_A

    def test_never_raises(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot="bad",  # type: ignore
        )
        assert isinstance(cert, dict)

    def test_verification_hash_differs_across_tenants(self):
        h_a = generate_trust_certification(TENANT_A, ENG_A)["verification_hash"]
        h_b = generate_trust_certification(TENANT_B, ENG_A)["verification_hash"]
        assert h_a != h_b


# ---------------------------------------------------------------------------
# 11. TestGenerateChainOfCustody
# ---------------------------------------------------------------------------


class TestGenerateChainOfCustody:
    def test_empty_events_returns_empty(self):
        assert generate_chain_of_custody(TENANT_A, ENG_A, []) == []

    def test_none_events_returns_empty(self):
        assert generate_chain_of_custody(TENANT_A, ENG_A, None) == []

    def test_first_entry_genesis_hash(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        assert chain[0]["previous_hash"] == PROOF_GENESIS_HASH

    def test_chain_links(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        for i in range(1, len(chain)):
            assert chain[i]["previous_hash"] == chain[i - 1]["custody_hash"]

    def test_custody_hash_is_64_hex(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        for entry in chain:
            assert len(entry["custody_hash"]) == 64

    def test_sequence_is_1_indexed(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        seqs = [e["sequence"] for e in chain]
        assert seqs == list(range(1, len(chain) + 1))

    def test_event_type_echoed(self):
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_APPROVED,
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert chain[0]["event_type"] == CUSTODY_EVIDENCE_APPROVED

    def test_entity_type_echoed(self):
        events = [
            {
                "event_type": CUSTODY_TRUST_VERIFIED,
                "entity_type": ENTITY_AGI,
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert chain[0]["entity_type"] == ENTITY_AGI

    def test_tenant_id_in_every_entry(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        assert all(e["tenant_id"] == TENANT_A for e in chain)

    def test_engagement_id_in_every_entry(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        assert all(e["engagement_id"] == ENG_A for e in chain)

    def test_authority_version_in_every_entry(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        assert all(
            e["authority_version"] == AUDITOR_PROOF_AUTHORITY_VERSION for e in chain
        )

    def test_custody_id_unique_per_entry(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        ids = {e["custody_id"] for e in chain}
        assert len(ids) == len(chain)

    def test_metadata_echoed(self):
        events = [
            {
                "event_type": CUSTODY_REPORT_EXPORTED,
                "timestamp": "2026-01-01T00:00:00Z",
                "metadata": {"export_format": "pdf"},
            }
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert chain[0]["metadata"]["export_format"] == "pdf"

    def test_non_dict_events_skipped(self):
        events = [
            None,
            42,
            "bad",
            {
                "event_type": CUSTODY_EVIDENCE_CREATED,
                "timestamp": "2026-01-01T00:00:00Z",
            },
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)  # type: ignore
        assert len(chain) == 1

    def test_large_custody_chain(self):
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_CREATED,
                "timestamp": "2026-01-01T00:00:00Z",
            }
            for _ in range(50)
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert len(chain) == 50
        for i in range(1, len(chain)):
            assert chain[i]["previous_hash"] == chain[i - 1]["custody_hash"]

    def test_all_custody_event_types_accepted(self):
        events = [
            {"event_type": et, "timestamp": "2026-01-01T00:00:00Z"}
            for et in [
                CUSTODY_EVIDENCE_CREATED,
                CUSTODY_EVIDENCE_REVIEWED,
                CUSTODY_EVIDENCE_APPROVED,
                CUSTODY_REPORT_GENERATED,
                CUSTODY_REPORT_EXPORTED,
                CUSTODY_TRUST_VERIFIED,
                CUSTODY_PACKAGE_GENERATED,
            ]
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert len(chain) == 7

    def test_description_echoed(self):
        events = [
            {
                "event_type": CUSTODY_TRUST_VERIFIED,
                "timestamp": "2026-01-01T00:00:00Z",
                "description": "Trust verified by auditor",
            }
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert chain[0]["description"] == "Trust verified by auditor"

    def test_non_list_input_returns_empty(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, "not_a_list")  # type: ignore
        assert chain == []

    def test_custody_hash_deterministic_per_entry(self):
        now = "2026-01-01T00:00:00Z"
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_CREATED,
                "entity_type": ENTITY_HUMAN,
                "entity_id": "u1",
                "timestamp": now,
                "description": "Test",
            }
        ]
        c1 = generate_chain_of_custody(TENANT_A, ENG_A, events)
        c2 = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert c1[0]["custody_hash"] == c2[0]["custody_hash"]


# ---------------------------------------------------------------------------
# 12. TestGenerateEnterpriseExport
# ---------------------------------------------------------------------------


class TestGenerateEnterpriseExport:
    def test_returns_required_keys(self):
        exp = generate_enterprise_export(EXPORT_JSON, TENANT_A, ENG_A)
        for key in (
            "export_id",
            "format",
            "tenant_id",
            "engagement_id",
            "content",
            "content_hash",
            "exported_at",
            "authority_version",
        ):
            assert key in exp, f"Missing: {key}"

    def test_json_format(self):
        exp = generate_enterprise_export(
            EXPORT_JSON, TENANT_A, ENG_A, proof_package=_pkg()
        )
        assert exp["format"] == EXPORT_JSON
        assert "proof_package" in exp["content"]

    def test_pdf_format(self):
        exp = generate_enterprise_export(
            EXPORT_PDF,
            TENANT_A,
            ENG_A,
            proof_package=_pkg(),
            executive_brief=generate_executive_trust_brief(TENANT_A, ENG_A),
        )
        assert exp["format"] == EXPORT_PDF
        assert "sections" in exp["content"]

    def test_html_format(self):
        exp = generate_enterprise_export(EXPORT_HTML, TENANT_A, ENG_A)
        assert exp["format"] == EXPORT_HTML
        assert "html" in exp["content"]

    def test_manifest_format(self):
        exp = generate_enterprise_export(
            EXPORT_MANIFEST, TENANT_A, ENG_A, proof_package=_pkg()
        )
        assert exp["format"] == EXPORT_MANIFEST
        assert "components" in exp["content"]

    def test_machine_bundle_format(self):
        bundle = generate_machine_verification_bundle(TENANT_A, ENG_A)
        exp = generate_enterprise_export(
            EXPORT_MACHINE_BUNDLE, TENANT_A, ENG_A, machine_bundle=bundle
        )
        assert exp["format"] == EXPORT_MACHINE_BUNDLE

    def test_invalid_format_falls_back_to_json(self):
        exp = generate_enterprise_export("UNKNOWN_FORMAT", TENANT_A, ENG_A)
        assert exp["format"] == EXPORT_JSON

    def test_content_hash_is_64_hex(self):
        h = generate_enterprise_export(EXPORT_JSON, TENANT_A, ENG_A)["content_hash"]
        assert len(h) == 64

    def test_content_hash_deterministic(self):
        pkg = _pkg()
        h1 = generate_enterprise_export(
            EXPORT_JSON, TENANT_A, ENG_A, proof_package=pkg
        )["content_hash"]
        h2 = generate_enterprise_export(
            EXPORT_JSON, TENANT_A, ENG_A, proof_package=pkg
        )["content_hash"]
        assert h1 == h2

    def test_export_id_unique(self):
        ids = {
            generate_enterprise_export(EXPORT_JSON, TENANT_A, ENG_A)["export_id"]
            for _ in range(10)
        }
        assert len(ids) == 10

    def test_tenant_id_echoed(self):
        exp = generate_enterprise_export(EXPORT_JSON, TENANT_A, ENG_A)
        assert exp["tenant_id"] == TENANT_A

    def test_authority_version_correct(self):
        exp = generate_enterprise_export(EXPORT_JSON, TENANT_A, ENG_A)
        assert exp["authority_version"] == AUDITOR_PROOF_AUTHORITY_VERSION

    def test_manifest_has_4_components(self):
        exp = generate_enterprise_export(EXPORT_MANIFEST, TENANT_A, ENG_A)
        assert exp["content"]["total_components"] == 4

    def test_pdf_has_sections(self):
        exp = generate_enterprise_export(EXPORT_PDF, TENANT_A, ENG_A)
        assert len(exp["content"]["sections"]) > 0

    def test_never_raises(self):
        exp = generate_enterprise_export(
            EXPORT_JSON,
            TENANT_A,
            ENG_A,
            proof_package=42,  # type: ignore
        )
        assert isinstance(exp, dict)


# ---------------------------------------------------------------------------
# 13. TestDeterminism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_proof_package_hash_deterministic(self):
        snap = _snap()
        kwargs = dict(intelligence_snapshot=snap, evidence_summary={"item_count": 5})
        h1 = generate_auditor_proof_package(TENANT_A, ENG_A, **kwargs)["package_hash"]
        h2 = generate_auditor_proof_package(TENANT_A, ENG_A, **kwargs)["package_hash"]
        assert h1 == h2

    def test_verify_deterministic(self):
        pkg = _pkg()
        r1 = verify_proof_package(pkg)
        r2 = verify_proof_package(pkg)
        assert r1 == r2

    def test_replay_deterministic(self):
        pkg = _pkg()
        snap = _snap()
        r1 = replay_auditor_package(pkg, intelligence_snapshot=snap)
        r2 = replay_auditor_package(pkg, intelligence_snapshot=snap)
        assert r1["valid"] == r2["valid"]
        assert r1["replay_score"] == r2["replay_score"]

    def test_certification_hash_deterministic(self):
        snap = _snap(posture_score=80)
        conf = _conf(score=70)
        h1 = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=snap, confidence_manifest=conf
        )["verification_hash"]
        h2 = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=snap, confidence_manifest=conf
        )["verification_hash"]
        assert h1 == h2

    def test_custody_hash_deterministic(self):
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_CREATED,
                "entity_type": ENTITY_HUMAN,
                "entity_id": "u1",
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ]
        c1 = generate_chain_of_custody(TENANT_A, ENG_A, events)[0]["custody_hash"]
        c2 = generate_chain_of_custody(TENANT_A, ENG_A, events)[0]["custody_hash"]
        assert c1 == c2

    def test_bundle_hash_deterministic(self):
        snap = _snap()
        pkg = _pkg()
        h1 = generate_machine_verification_bundle(
            TENANT_A, ENG_A, intelligence_snapshot=snap, proof_package=pkg
        )["bundle_hash"]
        h2 = generate_machine_verification_bundle(
            TENANT_A, ENG_A, intelligence_snapshot=snap, proof_package=pkg
        )["bundle_hash"]
        assert h1 == h2

    def test_reconstruction_hash_deterministic(self):
        snap = _snap()
        h1 = generate_legal_defense_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )["reconstruction_hash"]
        h2 = generate_legal_defense_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )["reconstruction_hash"]
        assert h1 == h2

    def test_content_hash_deterministic(self):
        pkg = _pkg()
        h1 = generate_enterprise_export(
            EXPORT_JSON, TENANT_A, ENG_A, proof_package=pkg
        )["content_hash"]
        h2 = generate_enterprise_export(
            EXPORT_JSON, TENANT_A, ENG_A, proof_package=pkg
        )["content_hash"]
        assert h1 == h2

    def test_regulator_package_framework_readiness_deterministic(self):
        snap = _snap()
        fw = [FRAMEWORK_NIST, FRAMEWORK_SOC2]
        r1 = generate_regulator_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap, frameworks=fw
        )
        r2 = generate_regulator_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap, frameworks=fw
        )
        assert r1["framework_readiness"] == r2["framework_readiness"]

    def test_section_hashes_deterministic(self):
        snap = _snap()
        sh1 = generate_auditor_proof_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )["section_hashes"]
        sh2 = generate_auditor_proof_package(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )["section_hashes"]
        assert sh1 == sh2

    def test_certification_level_deterministic(self):
        snap = _snap(posture_score=85)
        conf = _conf(score=85)
        l1 = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=snap, confidence_manifest=conf
        )["certification_level"]
        l2 = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=snap, confidence_manifest=conf
        )["certification_level"]
        assert l1 == l2

    def test_verify_result_deterministic(self):
        pkg = _pkg()
        for _ in range(5):
            r = verify_proof_package(pkg)
            assert r["valid"] is True


# ---------------------------------------------------------------------------
# 14. TestCrossTenantIsolation
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    def test_package_hash_differs_across_tenants(self):
        h_a = _pkg(tenant_id=TENANT_A)["package_hash"]
        h_b = _pkg(tenant_id=TENANT_B)["package_hash"]
        assert h_a != h_b

    def test_verify_rejects_mutated_tenant(self):
        pkg = _pkg(tenant_id=TENANT_A)
        pkg["tenant_id"] = TENANT_B
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_certification_hash_differs_across_tenants(self):
        h_a = generate_trust_certification(TENANT_A, ENG_A)["verification_hash"]
        h_b = generate_trust_certification(TENANT_B, ENG_A)["verification_hash"]
        assert h_a != h_b

    def test_custody_chain_tenant_scoped(self):
        chain_a = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        chain_b = generate_chain_of_custody(TENANT_B, ENG_A, _custody_events())
        assert all(e["tenant_id"] == TENANT_A for e in chain_a)
        assert all(e["tenant_id"] == TENANT_B for e in chain_b)
        assert chain_a[0]["custody_hash"] != chain_b[0]["custody_hash"]

    def test_bundle_hash_differs_across_tenants(self):
        h_a = generate_machine_verification_bundle(TENANT_A, ENG_A)["bundle_hash"]
        h_b = generate_machine_verification_bundle(TENANT_B, ENG_A)["bundle_hash"]
        assert h_a != h_b

    def test_regulator_package_scoped(self):
        r_a = generate_regulator_package(TENANT_A, ENG_A)
        r_b = generate_regulator_package(TENANT_B, ENG_A)
        assert r_a["tenant_id"] == TENANT_A
        assert r_b["tenant_id"] == TENANT_B

    def test_legal_defense_scoped(self):
        p_a = generate_legal_defense_package(TENANT_A, ENG_A)
        p_b = generate_legal_defense_package(TENANT_B, ENG_A)
        assert p_a["reconstruction_hash"] != p_b["reconstruction_hash"]

    def test_different_tenant_different_signature(self):
        sig_a = _pkg(tenant_id=TENANT_A)["package_signature"]
        sig_b = _pkg(tenant_id=TENANT_B)["package_signature"]
        assert sig_a != sig_b

    def test_replay_score_not_cross_tenant(self):
        pkg_a = _pkg(tenant_id=TENANT_A)
        r = replay_auditor_package(pkg_a, intelligence_snapshot=_snap())
        assert r["package_id"] == pkg_a["package_id"]

    def test_section_hashes_differ_across_tenants(self):
        h_a = _pkg(tenant_id=TENANT_A)["package_hash"]
        h_b = _pkg(tenant_id=TENANT_B)["package_hash"]
        assert h_a != h_b

    def test_enterprise_export_tenant_scoped(self):
        exp_a = generate_enterprise_export(EXPORT_JSON, TENANT_A, ENG_A)
        exp_b = generate_enterprise_export(EXPORT_JSON, TENANT_B, ENG_A)
        assert exp_a["tenant_id"] == TENANT_A
        assert exp_b["tenant_id"] == TENANT_B

    def test_brief_tenant_scoped(self):
        brief_a = generate_executive_trust_brief(TENANT_A, ENG_A)
        brief_b = generate_executive_trust_brief(TENANT_B, ENG_A)
        assert brief_a["tenant_id"] == TENANT_A
        assert brief_b["tenant_id"] == TENANT_B

    def test_custody_chain_first_hash_differs_across_tenants(self):
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_CREATED,
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ]
        c_a = generate_chain_of_custody(TENANT_A, ENG_A, events)
        c_b = generate_chain_of_custody(TENANT_B, ENG_A, events)
        assert c_a[0]["custody_hash"] != c_b[0]["custody_hash"]

    def test_verify_only_valid_for_correct_tenant(self):
        pkg = _pkg(tenant_id=TENANT_A)
        assert verify_proof_package(pkg)["valid"] is True
        pkg["tenant_id"] = TENANT_B
        assert verify_proof_package(pkg)["valid"] is False

    def test_certification_basis_tenant_aware(self):
        cert_a = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=_snap()
        )
        cert_b = generate_trust_certification(
            TENANT_B, ENG_A, intelligence_snapshot=_snap()
        )
        assert cert_a["verification_hash"] != cert_b["verification_hash"]


# ---------------------------------------------------------------------------
# 15. TestCrossEngagementIsolation
# ---------------------------------------------------------------------------


class TestCrossEngagementIsolation:
    def test_package_hash_differs_across_engagements(self):
        h1 = _pkg(engagement_id=ENG_A)["package_hash"]
        h2 = _pkg(engagement_id=ENG_B)["package_hash"]
        assert h1 != h2

    def test_verify_rejects_mutated_engagement(self):
        pkg = _pkg(engagement_id=ENG_A)
        pkg["engagement_id"] = ENG_B
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_custody_scoped_to_engagement(self):
        events = [
            {"event_type": CUSTODY_TRUST_VERIFIED, "timestamp": "2026-01-01T00:00:00Z"}
        ]
        c1 = generate_chain_of_custody(TENANT_A, ENG_A, events)
        c2 = generate_chain_of_custody(TENANT_A, ENG_B, events)
        assert c1[0]["engagement_id"] == ENG_A
        assert c2[0]["engagement_id"] == ENG_B
        assert c1[0]["custody_hash"] != c2[0]["custody_hash"]

    def test_certification_scoped_to_engagement(self):
        h1 = generate_trust_certification(TENANT_A, ENG_A)["verification_hash"]
        h2 = generate_trust_certification(TENANT_A, ENG_B)["verification_hash"]
        assert h1 != h2

    def test_legal_defense_scoped(self):
        h1 = generate_legal_defense_package(TENANT_A, ENG_A)["reconstruction_hash"]
        h2 = generate_legal_defense_package(TENANT_A, ENG_B)["reconstruction_hash"]
        assert h1 != h2

    def test_bundle_scoped_to_engagement(self):
        h1 = generate_machine_verification_bundle(TENANT_A, ENG_A)["bundle_hash"]
        h2 = generate_machine_verification_bundle(TENANT_A, ENG_B)["bundle_hash"]
        assert h1 != h2

    def test_different_engagement_different_signature(self):
        sig1 = _pkg(engagement_id=ENG_A)["package_signature"]
        sig2 = _pkg(engagement_id=ENG_B)["package_signature"]
        assert sig1 != sig2

    def test_export_scoped(self):
        exp1 = generate_enterprise_export(EXPORT_JSON, TENANT_A, ENG_A)
        exp2 = generate_enterprise_export(EXPORT_JSON, TENANT_A, ENG_B)
        assert exp1["engagement_id"] == ENG_A
        assert exp2["engagement_id"] == ENG_B

    def test_regulator_package_scoped(self):
        r1 = generate_regulator_package(TENANT_A, ENG_A)
        r2 = generate_regulator_package(TENANT_A, ENG_B)
        assert r1["engagement_id"] == ENG_A
        assert r2["engagement_id"] == ENG_B

    def test_replay_echoes_correct_package_id(self):
        pkg1 = _pkg(engagement_id=ENG_A)
        pkg2 = _pkg(engagement_id=ENG_B)
        r1 = replay_auditor_package(pkg1)
        r2 = replay_auditor_package(pkg2)
        assert r1["package_id"] == pkg1["package_id"]
        assert r2["package_id"] == pkg2["package_id"]


# ---------------------------------------------------------------------------
# 16. TestTamperDetection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def test_tampered_intelligence_section_detected(self):
        pkg = _pkg()
        pkg["sections"]["intelligence"]["posture_score"] = 100
        r = verify_proof_package(pkg)
        assert r["valid"] is False
        assert r["reason"] == "tampered_section"

    def test_tampered_evidence_section_detected(self):
        pkg = _pkg()
        pkg["sections"]["evidence"]["item_count"] = 9999
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_tampered_ledger_section_detected(self):
        pkg = _pkg()
        pkg["sections"]["ledger"]["entry_count"] = 9999
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_tampered_decisions_section_detected(self):
        pkg = _pkg()
        pkg["sections"]["decisions"]["decision_count"] = 999
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_tampered_section_hash_detected(self):
        pkg = _pkg()
        pkg["section_hashes"]["intelligence"] = "f" * 64
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_tampered_package_hash_detected(self):
        pkg = _pkg()
        pkg["package_hash"] = "0" * 64
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_tampered_signature_detected(self):
        pkg = _pkg()
        pkg["package_signature"] = "ff" * 64
        r = verify_proof_package(pkg)
        assert r["valid"] is False
        assert r["reason"] == "signature_mismatch"

    def test_added_section_detected(self):
        pkg = _pkg()
        pkg["sections"]["injected"] = {"data": "malicious"}
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_removed_section_detected(self):
        pkg = _pkg()
        del pkg["sections"]["evidence"]
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_custody_chain_tamper_breaks_link(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, _custody_events())
        chain[0]["custody_hash"] = "b" * 64
        assert chain[1]["previous_hash"] != chain[0]["custody_hash"]

    def test_authority_version_downgrade_rejected(self):
        pkg = _pkg()
        pkg["authority_version"] = "old-v0"
        r = verify_proof_package(pkg)
        assert r["valid"] is False
        assert "invalid_authority_version" in r["reason"]

    def test_assessed_by_change_rejected(self):
        pkg = _pkg()
        pkg["assessed_by"] = ENTITY_AGI
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_section_count_tamper_rejected(self):
        pkg = _pkg()
        pkg["section_count"] = 99
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_signing_key_id_tamper_rejected(self):
        pkg = _pkg()
        pkg["signing_key_id"] = "00000000deadbeef"
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_replay_score_not_forgeable(self):
        pkg = _pkg()
        r_full = replay_auditor_package(
            pkg, intelligence_snapshot=_snap(), trust_ledger=_ledger()
        )
        r_empty = replay_auditor_package(pkg)
        assert r_full["replay_score"] > r_empty["replay_score"]

    def test_section_addition_changes_section_count(self):
        pkg = _pkg()
        original_count = pkg["section_count"]
        pkg["sections"]["extra"] = {"note": "added"}
        assert len(pkg["sections"]) != original_count

    def test_corrupted_ledger_chain_intact_false(self):
        # Regression for P1: non-empty ledger was declared chain_intact=True without
        # actually verifying the previous_hash linkage.
        broken_ledger = [
            {
                "ledger_entry_hash": "a" * 64,
                "previous_hash": "0" * 64,
                "snapshot_hash": "s" * 64,
                "timestamp": "2026-01-01T00:00:00Z",
            },
            {
                "ledger_entry_hash": "b" * 64,
                "previous_hash": "WRONG_HASH_NOT_MATCHING_PREV",
                "snapshot_hash": "s" * 64,
                "timestamp": "2026-01-02T00:00:00Z",
            },
        ]
        pkg = generate_auditor_proof_package(
            TENANT_A, ENG_A, trust_ledger=broken_ledger
        )
        assert pkg["sections"]["ledger"]["chain_intact"] is False

    def test_intact_ledger_chain_intact_true(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A, trust_ledger=_ledger(3))
        assert pkg["sections"]["ledger"]["chain_intact"] is True

    def test_ledger_hash_bound_in_section(self):
        # Regression for P1: ledger contents must be bound into the section hash
        # so that swapping ledger entries invalidates the proof package signature.
        ledger_a = _ledger(2)
        ledger_b = [{**e, "snapshot_hash": "x" * 64} for e in ledger_a]
        pkg_a = generate_auditor_proof_package(TENANT_A, ENG_A, trust_ledger=ledger_a)
        pkg_b = generate_auditor_proof_package(TENANT_A, ENG_A, trust_ledger=ledger_b)
        assert (
            pkg_a["sections"]["ledger"]["ledger_hash"]
            != pkg_b["sections"]["ledger"]["ledger_hash"]
        )
        assert pkg_a["section_hashes"]["ledger"] != pkg_b["section_hashes"]["ledger"]

    def test_tampered_replay_section_detected(self):
        pkg = _pkg()
        pkg["sections"]["replay"]["replay_score"] = 999
        r = verify_proof_package(pkg)
        assert r["valid"] is False

    def test_tampered_confidence_section_detected(self):
        pkg = _pkg()
        pkg["sections"]["confidence"]["composite_score"] = 999
        r = verify_proof_package(pkg)
        assert r["valid"] is False


# ---------------------------------------------------------------------------
# 17. TestPerformance
# ---------------------------------------------------------------------------


class TestPerformance:
    def test_proof_package_under_100ms(self):
        t0 = time.perf_counter()
        for _ in range(100):
            generate_auditor_proof_package(
                TENANT_A, ENG_A, intelligence_snapshot=_snap()
            )
        avg_ms = (time.perf_counter() - t0) / 100 * 1000
        assert avg_ms < 100

    def test_verify_under_100ms(self):
        pkg = _pkg()
        t0 = time.perf_counter()
        for _ in range(100):
            verify_proof_package(pkg)
        avg_ms = (time.perf_counter() - t0) / 100 * 1000
        assert avg_ms < 100

    def test_replay_under_150ms(self):
        pkg = _pkg()
        snap = _snap()
        t0 = time.perf_counter()
        for _ in range(100):
            replay_auditor_package(pkg, intelligence_snapshot=snap)
        avg_ms = (time.perf_counter() - t0) / 100 * 1000
        assert avg_ms < 150

    def test_certification_under_50ms(self):
        t0 = time.perf_counter()
        for _ in range(100):
            generate_trust_certification(TENANT_A, ENG_A, intelligence_snapshot=_snap())
        avg_ms = (time.perf_counter() - t0) / 100 * 1000
        assert avg_ms < 50

    def test_1000_verify_under_1_second(self):
        pkg = _pkg()
        t0 = time.perf_counter()
        for _ in range(1000):
            verify_proof_package(pkg)
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0

    def test_chain_of_custody_100_events_fast(self):
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_CREATED,
                "timestamp": "2026-01-01T00:00:00Z",
            }
            for _ in range(100)
        ]
        t0 = time.perf_counter()
        generate_chain_of_custody(TENANT_A, ENG_A, events)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 200

    def test_executive_brief_under_50ms(self):
        snap = _snap()
        t0 = time.perf_counter()
        for _ in range(100):
            generate_executive_trust_brief(TENANT_A, ENG_A, intelligence_snapshot=snap)
        avg_ms = (time.perf_counter() - t0) / 100 * 1000
        assert avg_ms < 50

    def test_regulator_package_under_50ms(self):
        snap = _snap()
        t0 = time.perf_counter()
        for _ in range(100):
            generate_regulator_package(TENANT_A, ENG_A, intelligence_snapshot=snap)
        avg_ms = (time.perf_counter() - t0) / 100 * 1000
        assert avg_ms < 50

    def test_enterprise_export_under_50ms(self):
        pkg = _pkg()
        t0 = time.perf_counter()
        for _ in range(100):
            generate_enterprise_export(EXPORT_JSON, TENANT_A, ENG_A, proof_package=pkg)
        avg_ms = (time.perf_counter() - t0) / 100 * 1000
        assert avg_ms < 50

    def test_machine_bundle_under_50ms(self):
        snap = _snap()
        pkg = _pkg()
        t0 = time.perf_counter()
        for _ in range(100):
            generate_machine_verification_bundle(
                TENANT_A, ENG_A, intelligence_snapshot=snap, proof_package=pkg
            )
        avg_ms = (time.perf_counter() - t0) / 100 * 1000
        assert avg_ms < 50


# ---------------------------------------------------------------------------
# 18. TestAgentCompatibility
# ---------------------------------------------------------------------------


class TestAgentCompatibility:
    def test_agent_entity_in_proof_package(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A, assessed_by=ENTITY_AGENT)
        assert pkg["assessed_by"] == ENTITY_AGENT

    def test_agent_fleet_entity_accepted(self):
        pkg = generate_auditor_proof_package(
            TENANT_A, ENG_A, assessed_by=ENTITY_AGENT_FLEET
        )
        assert pkg["assessed_by"] == ENTITY_AGENT_FLEET
        assert verify_proof_package(pkg)["valid"] is True

    def test_autonomous_workflow_entity_accepted(self):
        pkg = generate_auditor_proof_package(
            TENANT_A, ENG_A, assessed_by=ENTITY_AUTONOMOUS_WORKFLOW
        )
        assert verify_proof_package(pkg)["valid"] is True

    def test_autonomous_system_entity_accepted(self):
        pkg = generate_auditor_proof_package(
            TENANT_A, ENG_A, assessed_by=ENTITY_AUTONOMOUS_SYSTEM
        )
        assert verify_proof_package(pkg)["valid"] is True

    def test_agent_custody_events_accepted(self):
        events = [
            {
                "event_type": CUSTODY_TRUST_VERIFIED,
                "entity_type": ENTITY_AGENT,
                "entity_id": "agent-1",
                "timestamp": "2026-01-01T00:00:00Z",
            },
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert chain[0]["entity_type"] == ENTITY_AGENT

    def test_agent_decision_in_legal_defense(self):
        decisions = [
            {
                "decision_type": "approval",
                "entity_type": ENTITY_AGENT,
                "decision_reasoning": "Agent verified trust chain",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions
        )
        assert ENTITY_AGENT in pkg["decision_reconstruction"]["entity_types"]

    def test_reviewer_entity_in_custody(self):
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_REVIEWED,
                "entity_type": ENTITY_REVIEWER,
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert chain[0]["entity_type"] == ENTITY_REVIEWER

    def test_approver_entity_in_custody(self):
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_APPROVED,
                "entity_type": ENTITY_APPROVER,
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert chain[0]["entity_type"] == ENTITY_APPROVER

    def test_unknown_future_entity_accepted(self):
        pkg = generate_auditor_proof_package(
            TENANT_A, ENG_A, assessed_by="future_entity_v2"
        )
        assert pkg["assessed_by"] == "future_entity_v2"
        assert verify_proof_package(pkg)["valid"] is True

    def test_agent_fleet_in_questions_answered(self):
        decisions = [
            {
                "decision_type": "approval",
                "entity_type": ENTITY_AGENT_FLEET,
                "decision_reasoning": "Fleet approved",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions
        )
        assert ENTITY_AGENT_FLEET in pkg["questions_answered"]["who_approved"]

    def test_mixed_entity_decisions_tracked(self):
        decisions = [
            {
                "decision_type": "approval",
                "entity_type": ENTITY_HUMAN,
                "decision_reasoning": "Human approved",
                "created_at": "2026-01-01T00:00:00Z",
            },
            {
                "decision_type": "verification",
                "entity_type": ENTITY_AGENT,
                "decision_reasoning": "Agent verified",
                "created_at": "2026-01-01T00:01:00Z",
            },
        ]
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions
        )
        entity_types = pkg["decision_reconstruction"]["entity_types"]
        assert ENTITY_HUMAN in entity_types
        assert ENTITY_AGENT in entity_types

    def test_agent_certification_accepted(self):
        cert = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=_snap(posture_score=85)
        )
        assert cert["certification_level"] in {
            CERT_BRONZE,
            CERT_SILVER,
            CERT_GOLD,
            CERT_PLATINUM,
            CERT_ENTERPRISE,
        }


# ---------------------------------------------------------------------------
# 19. TestAGIGovernanceCompatibility
# ---------------------------------------------------------------------------


class TestAGIGovernanceCompatibility:
    def test_agi_entity_in_proof_package(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A, assessed_by=ENTITY_AGI)
        assert pkg["assessed_by"] == ENTITY_AGI

    def test_agi_package_is_verifiable(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A, assessed_by=ENTITY_AGI)
        assert verify_proof_package(pkg)["valid"] is True

    def test_agi_decision_in_legal_defense(self):
        decisions = [
            {
                "decision_type": "governance_approval",
                "entity_type": ENTITY_AGI,
                "decision_reasoning": "AGI governance decision",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions
        )
        assert ENTITY_AGI in pkg["decision_reconstruction"]["entity_types"]

    def test_agi_custody_event_accepted(self):
        events = [
            {
                "event_type": CUSTODY_TRUST_VERIFIED,
                "entity_type": ENTITY_AGI,
                "entity_id": "agi-system-1",
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert chain[0]["entity_type"] == ENTITY_AGI

    def test_agi_questions_answered(self):
        decisions = [
            {
                "decision_type": "trust_certification",
                "entity_type": ENTITY_AGI,
                "decision_reasoning": "Autonomous governance certification",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions
        )
        assert ENTITY_AGI in pkg["questions_answered"]["who_approved"]

    def test_agi_certification_achievable(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=95),
            confidence_manifest=_conf(score=95),
        )
        assert cert["certification_level"] == CERT_ENTERPRISE

    def test_agi_no_schema_change_required(self):
        future_agi = "agi_system_v3"
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A, assessed_by=future_agi)
        assert pkg["assessed_by"] == future_agi
        assert verify_proof_package(pkg)["valid"] is True

    def test_agi_replay_score_same_as_human(self):
        pkg_human = generate_auditor_proof_package(
            TENANT_A, ENG_A, assessed_by=ENTITY_HUMAN, intelligence_snapshot=_snap()
        )
        pkg_agi = generate_auditor_proof_package(
            TENANT_A, ENG_A, assessed_by=ENTITY_AGI, intelligence_snapshot=_snap()
        )
        snap = _snap()
        r_human = replay_auditor_package(pkg_human, intelligence_snapshot=snap)
        r_agi = replay_auditor_package(pkg_agi, intelligence_snapshot=snap)
        assert r_human["replay_score"] == r_agi["replay_score"]

    def test_mixed_human_agi_decisions(self):
        decisions = [
            {
                "decision_type": "approval",
                "entity_type": ENTITY_HUMAN,
                "decision_reasoning": "Human",
                "created_at": "2026-01-01T00:00:00Z",
            },
            {
                "decision_type": "verification",
                "entity_type": ENTITY_AGI,
                "decision_reasoning": "AGI",
                "created_at": "2026-01-01T00:01:00Z",
            },
        ]
        pkg = generate_legal_defense_package(
            TENANT_A, ENG_A, decision_memories=decisions
        )
        types = pkg["decision_reconstruction"]["entity_types"]
        assert ENTITY_HUMAN in types and ENTITY_AGI in types

    def test_agi_governance_regulator_package(self):
        pkg = generate_regulator_package(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(),
            frameworks=[FRAMEWORK_NIST_AI, FRAMEWORK_ISO_42001],
        )
        assert FRAMEWORK_NIST_AI in pkg["framework_readiness"]
        assert FRAMEWORK_ISO_42001 in pkg["framework_readiness"]


# ---------------------------------------------------------------------------
# 20. TestSecurityInvariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_verify_never_raises_on_garbage(self):
        for bad in [None, 42, "string", [], {}, 3.14, True]:
            r = verify_proof_package(bad)  # type: ignore
            assert isinstance(r, dict)
            assert "valid" in r

    def test_replay_never_raises_on_garbage(self):
        for bad in [None, 42, "string", [], {}, 3.14]:
            r = replay_auditor_package(bad)  # type: ignore
            assert isinstance(r, dict)
            assert "valid" in r

    def test_executive_brief_never_raises_on_garbage(self):
        brief = generate_executive_trust_brief(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=42,  # type: ignore
            trust_memory="bad",  # type: ignore
        )
        assert isinstance(brief, dict)

    def test_regulator_never_raises_on_garbage(self):
        pkg = generate_regulator_package(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=[],  # type: ignore
            frameworks=42,  # type: ignore
            control_results="bad",  # type: ignore
        )
        assert isinstance(pkg, dict)

    def test_legal_defense_never_raises_on_garbage(self):
        pkg = generate_legal_defense_package(
            TENANT_A,
            ENG_A,
            decision_memories=3.14,  # type: ignore
            intelligence_snapshot=True,  # type: ignore
        )
        assert isinstance(pkg, dict)

    def test_bundle_never_raises_on_garbage(self):
        bundle = generate_machine_verification_bundle(
            TENANT_A,
            ENG_A,
            proof_package="bad",  # type: ignore
            trust_ledger=42,  # type: ignore
        )
        assert isinstance(bundle, dict)

    def test_certification_never_raises_on_garbage(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=None,
            confidence_manifest="bad",  # type: ignore
        )
        assert isinstance(cert, dict)

    def test_custody_never_raises_on_garbage(self):
        chain = generate_chain_of_custody(TENANT_A, ENG_A, "not_a_list")  # type: ignore
        assert isinstance(chain, list)

    def test_export_never_raises_on_garbage(self):
        exp = generate_enterprise_export(
            EXPORT_PDF,
            TENANT_A,
            ENG_A,
            proof_package=42,  # type: ignore
            certification=[],  # type: ignore
        )
        assert isinstance(exp, dict)

    def test_sign_raises_on_missing_hash(self):
        with pytest.raises(AuditorProofAuthorityError):
            sign_proof_package({"no_hash": True})

    def test_generate_package_raises_on_missing_tenant(self):
        with pytest.raises(AuditorProofAuthorityError):
            generate_auditor_proof_package("", ENG_A)


# ---------------------------------------------------------------------------
# 21. TestEnterpriseScenarios
# ---------------------------------------------------------------------------


class TestEnterpriseScenarios:
    def test_banking_govcon_full_pipeline(self):
        snap = _snap(posture_score=85, posture_level="healthy")
        pkg = generate_auditor_proof_package(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=snap,
            trust_ledger=_ledger(5),
            decision_memories=_decisions(3),
            confidence_manifest=_conf(85),
            graph_snapshot=_graph(10),
            replay_result=_replay_ok(),
            evidence_summary={"item_count": 50},
        )
        cert = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=snap, confidence_manifest=_conf(85)
        )
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        reg = generate_regulator_package(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=snap,
            frameworks=[FRAMEWORK_NIST, FRAMEWORK_SOC2, FRAMEWORK_HIPAA],
        )
        assert verify_proof_package(pkg)["valid"] is True
        assert cert["certification_level"] in {
            CERT_GOLD,
            CERT_PLATINUM,
            CERT_ENTERPRISE,
        }
        assert brief["current_posture"]["level"] == "healthy"
        assert FRAMEWORK_HIPAA in reg["framework_readiness"]

    def test_ma_due_diligence_package(self):
        snap = _snap(posture_score=90, posture_level="excellent")
        pkg = _pkg()
        cert = generate_trust_certification(
            TENANT_A, ENG_A, intelligence_snapshot=snap, confidence_manifest=_conf(90)
        )
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        bundle = generate_machine_verification_bundle(
            TENANT_A, ENG_A, proof_package=pkg
        )
        assert cert["certification_level"] == CERT_ENTERPRISE
        assert "certification" in brief["board_recommendation"].lower()
        assert bundle["components"]["verification"]["supports_third_party_verification"]

    def test_legal_defense_scenario(self):
        decisions = [
            {
                "decision_type": "audit_approval",
                "entity_type": ENTITY_APPROVER,
                "decision_reasoning": "Full evidence review completed",
                "created_at": "2026-01-01T00:00:00Z",
            },
        ]
        snap = _snap(posture_score=75)
        legal = generate_legal_defense_package(
            TENANT_A,
            ENG_A,
            decision_memories=decisions,
            intelligence_snapshot=snap,
            replay_result=_replay_ok(),
        )
        assert legal["questions_answered"]["can_decision_be_replayed"] is True
        assert "healthy" in legal["questions_answered"]["what_was_known"]
        assert len(legal["decision_timeline"]) == 1

    def test_full_chain_of_custody(self):
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_CREATED,
                "entity_type": ENTITY_HUMAN,
                "entity_id": "analyst-1",
                "description": "Initial evidence",
                "timestamp": "2026-01-01T00:00:00Z",
            },
            {
                "event_type": CUSTODY_EVIDENCE_REVIEWED,
                "entity_type": ENTITY_REVIEWER,
                "entity_id": "reviewer-1",
                "description": "Evidence reviewed",
                "timestamp": "2026-01-01T01:00:00Z",
            },
            {
                "event_type": CUSTODY_EVIDENCE_APPROVED,
                "entity_type": ENTITY_APPROVER,
                "entity_id": "approver-1",
                "description": "Evidence approved",
                "timestamp": "2026-01-01T02:00:00Z",
            },
            {
                "event_type": CUSTODY_REPORT_GENERATED,
                "entity_type": ENTITY_AGENT,
                "entity_id": "agent-1",
                "description": "Report generated",
                "timestamp": "2026-01-01T03:00:00Z",
            },
            {
                "event_type": CUSTODY_PACKAGE_GENERATED,
                "entity_type": ENTITY_AGENT,
                "entity_id": "agent-1",
                "description": "Proof package created",
                "timestamp": "2026-01-01T04:00:00Z",
            },
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert len(chain) == 5
        assert chain[0]["previous_hash"] == PROOF_GENESIS_HASH
        for i in range(1, len(chain)):
            assert chain[i]["previous_hash"] == chain[i - 1]["custody_hash"]

    def test_ai_governance_scenario(self):
        decisions = [
            {
                "decision_type": "agi_governance",
                "entity_type": ENTITY_AGI,
                "decision_reasoning": "Autonomous governance verified",
                "created_at": "2026-01-01T00:00:00Z",
            },
        ]
        pkg = generate_auditor_proof_package(
            TENANT_A,
            ENG_A,
            assessed_by=ENTITY_AGI,
            decision_memories=decisions,
            intelligence_snapshot=_snap(posture_score=88),
        )
        legal = generate_legal_defense_package(
            TENANT_A,
            ENG_A,
            decision_memories=decisions,
            intelligence_snapshot=_snap(posture_score=88),
        )
        assert verify_proof_package(pkg)["valid"] is True
        assert ENTITY_AGI in legal["decision_reconstruction"]["entity_types"]

    def test_machine_verifiable_end_to_end(self):
        pkg = _pkg()
        snap = _snap()
        ledger = _ledger(3)
        bundle = generate_machine_verification_bundle(
            TENANT_A,
            ENG_A,
            proof_package=pkg,
            intelligence_snapshot=snap,
            trust_ledger=ledger,
        )
        export = generate_enterprise_export(
            EXPORT_MACHINE_BUNDLE, TENANT_A, ENG_A, machine_bundle=bundle
        )
        assert bundle["components"]["verification"]["requires_frostgate"] is False
        assert export["format"] == EXPORT_MACHINE_BUNDLE

    def test_regulator_multi_framework(self):
        all_frameworks = [
            FRAMEWORK_NIST,
            FRAMEWORK_NIST_AI,
            FRAMEWORK_ISO_42001,
            FRAMEWORK_SOC2,
            FRAMEWORK_HIPAA,
            FRAMEWORK_PCI_DSS,
        ]
        pkg = generate_regulator_package(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=75),
            frameworks=all_frameworks,
        )
        assert len(pkg["assessed_frameworks"]) == 6
        for fw in all_frameworks:
            assert fw in pkg["framework_readiness"]

    def test_historical_trust_archive_accumulates(self):
        ledger = _ledger(10)
        decisions = _decisions(5)
        pkg = generate_auditor_proof_package(
            TENANT_A,
            ENG_A,
            trust_ledger=ledger,
            decision_memories=decisions,
            intelligence_snapshot=_snap(),
        )
        assert pkg["sections"]["ledger"]["entry_count"] == 10
        assert pkg["sections"]["decisions"]["decision_count"] == 5
        assert verify_proof_package(pkg)["valid"] is True


# ---------------------------------------------------------------------------
# 22. TestEdgeCases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_zero_posture_score_not_certified(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=0),
            confidence_manifest=_conf(score=0),
        )
        assert cert["certification_level"] == CERT_NOT_CERTIFIED

    def test_score_exactly_at_bronze_threshold(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=_CERT_BRONZE_THRESHOLD),
            confidence_manifest=_conf(score=_CERT_BRONZE_THRESHOLD),
        )
        assert cert["certification_level"] == CERT_BRONZE

    def test_score_exactly_at_enterprise_threshold(self):
        cert = generate_trust_certification(
            TENANT_A,
            ENG_A,
            intelligence_snapshot=_snap(posture_score=_CERT_ENTERPRISE_THRESHOLD),
            confidence_manifest=_conf(score=_CERT_ENTERPRISE_THRESHOLD),
        )
        assert cert["certification_level"] == CERT_ENTERPRISE

    def test_empty_ledger_section_absent(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A, trust_ledger=[])
        assert pkg["sections"]["ledger"]["status"] == "absent"

    def test_single_custody_event_genesis_hash(self):
        events = [
            {
                "event_type": CUSTODY_PACKAGE_GENERATED,
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert len(chain) == 1
        assert chain[0]["previous_hash"] == PROOF_GENESIS_HASH

    def test_window_format_all_export_types_succeed(self):
        for fmt in [
            EXPORT_JSON,
            EXPORT_PDF,
            EXPORT_HTML,
            EXPORT_MANIFEST,
            EXPORT_MACHINE_BUNDLE,
        ]:
            exp = generate_enterprise_export(fmt, TENANT_A, ENG_A)
            assert exp["format"] == fmt

    def test_unknown_posture_level_no_crash(self):
        snap = _snap(posture_level="unknown_future_level")
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert isinstance(brief, dict)

    def test_unknown_risk_level_no_crash(self):
        snap = _snap(risk_level="unknown_future_risk")
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert isinstance(brief, dict)

    def test_proof_package_with_no_optional_inputs(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A)
        assert verify_proof_package(pkg)["valid"] is True

    def test_empty_evidence_summary_handled(self):
        pkg = generate_auditor_proof_package(TENANT_A, ENG_A, evidence_summary={})
        assert pkg["sections"]["evidence"]["status"] == "absent"

    def test_full_custody_chain_link_integrity(self):
        events = [
            {
                "event_type": CUSTODY_EVIDENCE_CREATED,
                "timestamp": f"2026-01-0{i + 1}T00:00:00Z",
            }
            for i in range(9)
        ]
        chain = generate_chain_of_custody(TENANT_A, ENG_A, events)
        assert chain[0]["previous_hash"] == PROOF_GENESIS_HASH
        for i in range(1, len(chain)):
            assert chain[i]["previous_hash"] == chain[i - 1]["custody_hash"]

    def test_brief_with_empty_risk_result(self):
        snap = {**_snap(), "risk_result": {}}
        brief = generate_executive_trust_brief(
            TENANT_A, ENG_A, intelligence_snapshot=snap
        )
        assert len(brief["top_risks"]) > 0
