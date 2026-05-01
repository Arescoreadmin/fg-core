"""
PHI Classifier Tests.

Covers:
  Positive:  SSN → HIGH; MRN → HIGH; name+DOB keyword → MODERATE;
             email+medical context → MODERATE; email alone → LOW
  Negative:  random text → NONE; partial patterns → NONE; digits alone → NONE
  Edge:      empty string; non-string input (fail-safe); very long input;
             mixed content (SSN + medical keywords) → HIGH
  Interface: set_classifier() replaces default; classify_phi() delegates
  Audit:     PHI_CLASSIFICATION_DETECTED emitted on PHI;
             PHI_CLASSIFICATION_PERFORMED emitted on clean;
             PHI_CLASSIFICATION_ENFORCED_BLOCK emitted on block;
             blocked payload excludes raw PHI text
  Routing:   PHI + regulated provider (no active BAA) → 403;
             no PHI + any provider → 200;
             PHI + regulated provider with BAA → 200
  RAG:       ingest tags phi_sensitivity_level in safe_metadata;
             clean document → sensitivity 'none'
  Regression: PHI gate is wired into /ui/ai/chat routing path
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import text

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.rag.ingest import CorpusDocument, IngestRequest, ingest_corpus
from services.phi_classifier import (
    REASON_CLEAN,
    REASON_HIGH_RISK,
    PhiClassifier,
    PhiClassificationResult,
    SensitivityLevel,
    classify_phi,
    set_classifier,
)
from services.phi_classifier.classifier import (
    RuleBasedPhiClassifier,
    emit_phi_classification_audit,
    emit_phi_enforcement_block_audit,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SSN_TEXT = "The patient SSN is 123-45-6789 and needs follow-up."
_MRN_TEXT = "MRN: 4872910 — schedule appointment next week."
_DOB_TEXT = "Date of birth: 01/15/1985"
_EMAIL_TEXT = "Contact us at john.doe@example.com"
_EMAIL_MEDICAL = "Send prescription to jane@clinic.org — diagnosis pending."
_NAME_TEXT = "patient: John Smith needs medication dosage review."
_CLEAN_TEXT = "Please summarize the quarterly report."
_MEDICAL_ONLY = "The treatment plan includes healthcare provider consultation."


def _db(tmp_path: Path) -> Any:
    db_path = str(tmp_path / "phi-test.db")
    os.environ["FG_SQLITE_PATH"] = db_path
    os.environ["FG_ENV"] = "test"
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return get_sessionmaker()()


def _insert_baa(
    db: Any,
    *,
    tenant_id: str,
    provider_id: str,
    baa_status: str,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO provider_baa_records
                (tenant_id, provider_id, baa_status, created_at, updated_at)
            VALUES (:tenant_id, :provider_id, :baa_status,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (tenant_id, provider_id) DO UPDATE
                SET baa_status = excluded.baa_status
            """
        ),
        {"tenant_id": tenant_id, "provider_id": provider_id, "baa_status": baa_status},
    )
    db.commit()


# ---------------------------------------------------------------------------
# Section 1: Positive cases — PHI detected
# ---------------------------------------------------------------------------


def test_ssn_detected_high_sensitivity() -> None:
    result = classify_phi(_SSN_TEXT)
    assert result.contains_phi is True
    assert result.sensitivity_level == SensitivityLevel.HIGH
    assert "ssn" in result.phi_types
    assert result.reasoning_code == REASON_HIGH_RISK
    assert result.confidence >= 0.9


def test_mrn_detected_high_sensitivity() -> None:
    result = classify_phi(_MRN_TEXT)
    assert result.contains_phi is True
    assert result.sensitivity_level == SensitivityLevel.HIGH
    assert "mrn" in result.phi_types
    assert result.reasoning_code == REASON_HIGH_RISK


def test_name_dob_moderate_sensitivity() -> None:
    result = classify_phi("patient: Jane Doe, date of birth: 03/22/1990")
    assert result.contains_phi is True
    assert result.sensitivity_level in (
        SensitivityLevel.MODERATE,
        SensitivityLevel.HIGH,
    )
    assert "dob" in result.phi_types or "name" in result.phi_types


def test_email_medical_context_moderate() -> None:
    result = classify_phi(_EMAIL_MEDICAL)
    assert result.contains_phi is True
    assert result.sensitivity_level == SensitivityLevel.MODERATE
    assert "email" in result.phi_types


def test_email_alone_low() -> None:
    result = classify_phi(_EMAIL_TEXT)
    assert result.contains_phi is True
    assert result.sensitivity_level == SensitivityLevel.LOW
    assert "email" in result.phi_types


# ---------------------------------------------------------------------------
# Section 2: Negative cases — no PHI
# ---------------------------------------------------------------------------


def test_random_text_no_phi() -> None:
    result = classify_phi(_CLEAN_TEXT)
    assert result.contains_phi is False
    assert result.sensitivity_level == SensitivityLevel.NONE
    assert result.reasoning_code == REASON_CLEAN


def test_partial_ssn_no_phi() -> None:
    result = classify_phi("reference code 123-45 is not a full SSN")
    assert result.contains_phi is False


def test_medical_keywords_alone_no_phi() -> None:
    result = classify_phi(_MEDICAL_ONLY)
    assert result.contains_phi is False
    assert result.sensitivity_level == SensitivityLevel.NONE


# ---------------------------------------------------------------------------
# Section 3: Edge cases
# ---------------------------------------------------------------------------


def test_empty_string_no_phi() -> None:
    result = classify_phi("")
    assert result.contains_phi is False
    assert result.sensitivity_level == SensitivityLevel.NONE


def test_whitespace_only_no_phi() -> None:
    result = classify_phi("   \n\t  ")
    assert result.contains_phi is False


def test_non_string_input_failsafe() -> None:
    result = classify_phi(None)  # type: ignore[arg-type]
    assert result.contains_phi is True


def test_very_long_input_handled() -> None:
    long_text = "hello world " * 10_000  # 120k chars
    result = classify_phi(long_text)
    assert result.contains_phi is False  # no PHI in repetitive text
    assert result.sensitivity_level == SensitivityLevel.NONE


def test_mixed_content_ssn_and_medical_high() -> None:
    text = "Patient SSN 987-65-4321 — diagnosis: hypertension, prescribed medication."
    result = classify_phi(text)
    assert result.contains_phi is True
    assert result.sensitivity_level == SensitivityLevel.HIGH
    assert "ssn" in result.phi_types


# ---------------------------------------------------------------------------
# Section 4: Classifier interface — replaceable without rewriting routing
# ---------------------------------------------------------------------------


def test_set_classifier_replaces_default() -> None:
    class _AlwaysClean(PhiClassifier):
        def classify(self, text: str) -> PhiClassificationResult:
            return PhiClassificationResult(
                contains_phi=False,
                phi_types=frozenset(),
                confidence=1.0,
                sensitivity_level=SensitivityLevel.NONE,
                redaction_candidates=(),
                reasoning_code=REASON_CLEAN,
            )

    original = RuleBasedPhiClassifier()
    set_classifier(_AlwaysClean())
    try:
        result = classify_phi(_SSN_TEXT)
        assert result.contains_phi is False
    finally:
        set_classifier(original)


def test_set_classifier_restored() -> None:
    set_classifier(RuleBasedPhiClassifier())
    result = classify_phi(_SSN_TEXT)
    assert result.contains_phi is True


# ---------------------------------------------------------------------------
# Section 5: Audit events
# ---------------------------------------------------------------------------


def test_audit_phi_detected_event() -> None:
    captured: list[Any] = []
    with patch(
        "api.security_audit.SecurityAuditor.log_event",
        side_effect=lambda e: captured.append(e),
    ):
        from api.security_audit import EventType

        result = classify_phi(_SSN_TEXT)
        emit_phi_classification_audit(
            result, tenant_id="t1", enforcement_action="allowed"
        )
    assert len(captured) == 1
    assert captured[0].event_type == EventType.PHI_CLASSIFICATION_DETECTED


def test_audit_no_phi_event() -> None:
    captured: list[Any] = []
    with patch(
        "api.security_audit.SecurityAuditor.log_event",
        side_effect=lambda e: captured.append(e),
    ):
        from api.security_audit import EventType

        result = classify_phi(_CLEAN_TEXT)
        emit_phi_classification_audit(
            result, tenant_id="t1", enforcement_action="allowed"
        )
    assert len(captured) == 1
    assert captured[0].event_type == EventType.PHI_CLASSIFICATION_PERFORMED


def test_audit_enforcement_block_event() -> None:
    captured: list[Any] = []
    with patch(
        "api.security_audit.SecurityAuditor.log_event",
        side_effect=lambda e: captured.append(e),
    ):
        from api.security_audit import EventType

        result = classify_phi(_SSN_TEXT)
        emit_phi_enforcement_block_audit(
            result, tenant_id="t1", provider_id="simulated"
        )
    assert len(captured) == 1
    assert captured[0].event_type == EventType.PHI_CLASSIFICATION_ENFORCED_BLOCK


def test_audit_payload_excludes_raw_phi() -> None:
    captured: list[Any] = []
    with patch(
        "api.security_audit.SecurityAuditor.log_event",
        side_effect=lambda e: captured.append(e),
    ):
        result = classify_phi(_SSN_TEXT)
        emit_phi_enforcement_block_audit(
            result, tenant_id="t1", provider_id="simulated"
        )
    assert captured
    details = captured[0].details
    # Must NOT include raw text or extracted PHI values
    for v in details.values():
        if isinstance(v, str):
            assert "123-45-6789" not in v
            assert _SSN_TEXT not in v
    # Must include safe classification metadata
    assert "contains_phi" in details
    assert "sensitivity_level" in details
    assert "phi_types" in details
    # phi_types must be type-names only, not raw values
    assert isinstance(details["phi_types"], list)


# ---------------------------------------------------------------------------
# Section 6: Routing integration
# ---------------------------------------------------------------------------


def test_phi_denied_for_non_baa_provider(build_app, monkeypatch) -> None:
    """PHI in message + regulated provider (no active BAA) → 403."""
    import api.ui_ai_console as ai_console

    monkeypatch.setattr(ai_console, "KNOWN_PROVIDERS", {"simulated", "anthropic"})
    monkeypatch.setattr(
        ai_console, "PROVIDER_MAX_TOKENS", {"simulated": 4096, "anthropic": 4096}
    )
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    monkeypatch.setattr(ai_console, "_provider_env_allowed", lambda p: True)

    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic"]
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }

    exp_resp = client.get("/ui/ai/experience", headers=hdrs)
    assert exp_resp.status_code == 200
    device_id = exp_resp.json()["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "PHI-1"},
    )

    # No BAA record for anthropic — PHI + regulated provider without BAA → 403
    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _MRN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    assert resp.status_code == 403


def test_no_phi_allowed_for_non_baa_provider(build_app, monkeypatch) -> None:
    """No PHI + simulated (non-BAA-eligible) provider → 200."""
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }

    exp_resp = client.get("/ui/ai/experience", headers=hdrs)
    device_id = exp_resp.json()["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "PHI-2"},
    )

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "simulated"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_phi_allowed_for_regulated_provider_with_baa(build_app, monkeypatch) -> None:
    """PHI + configured Azure PHI provider with active BAA → 200."""
    from services.ai.providers.base import ProviderResponse

    import api.ui_ai_console as ai_console

    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic,azure_openai")
    monkeypatch.setenv("FG_AZURE_AI_KEY", "test-azure-key")
    monkeypatch.setenv("FG_AZURE_OPENAI_ENDPOINT", "https://azure.example.test")
    monkeypatch.setenv("FG_AZURE_OPENAI_DEPLOYMENT", "fg-test")

    _fake = ProviderResponse(
        provider_id="azure_openai",
        text="test response",
        model="fg-test",
        input_tokens=10,
        output_tokens=5,
    )
    monkeypatch.setattr(ai_console, "_call_provider", lambda **kw: _fake)

    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic", "azure_openai"]
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }

    exp_resp = client.get("/ui/ai/experience", headers=hdrs)
    device_id = exp_resp.json()["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "PHI-3"},
    )

    # Insert an active BAA using the same DB the app was built against
    db = get_sessionmaker()()
    _insert_baa(
        db, tenant_id="tenant-dev", provider_id="azure_openai", baa_status="active"
    )

    # Use MRN text: detected by PHI classifier (HIGH) but not by the legacy
    # _contains_pii() check (no "ssn" keyword, fewer than 13 digits).
    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _MRN_TEXT, "device_id": device_id},
    )
    assert resp.status_code == 200


def test_phi_quota_not_charged_on_phi_block(build_app, monkeypatch) -> None:
    """PHI+BAA block fires before quota precharge — no quota consumed."""
    import api.ui_ai_console as ai_console

    monkeypatch.setattr(ai_console, "KNOWN_PROVIDERS", {"simulated", "anthropic"})
    monkeypatch.setattr(
        ai_console, "PROVIDER_MAX_TOKENS", {"simulated": 4096, "anthropic": 4096}
    )
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    monkeypatch.setattr(ai_console, "_provider_env_allowed", lambda p: True)

    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic"]
        policy["tenant_max_tokens_per_day"] = 1000
        policy["device_max_tokens_per_day"] = 500
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)

    quota_calls: list[dict] = []
    original = ai_console._consume_quota_atomic

    def _tracked(db, **kw):
        quota_calls.append(kw)
        return original(db, **kw)

    monkeypatch.setattr(ai_console, "_consume_quota_atomic", _tracked)

    client = TestClient(build_app(auth_enabled=True))
    hdrs = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    exp_resp = client.get("/ui/ai/experience", headers=hdrs)
    device_id = exp_resp.json()["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "test", "ticket": "PHI-4"},
    )

    # PHI + regulated provider (no BAA) → 403 before quota
    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": _MRN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )
    assert resp.status_code == 403
    assert quota_calls == [], (
        "quota must not be charged when PHI+BAA enforcement blocks"
    )


# ---------------------------------------------------------------------------
# Section 7: RAG integration
# ---------------------------------------------------------------------------


def test_ingest_tags_phi_sensitivity_high() -> None:
    result = ingest_corpus(
        IngestRequest(
            documents=[
                CorpusDocument(
                    source_id="doc-001",
                    content=_SSN_TEXT,
                )
            ]
        ),
        trusted_tenant_id="t1",
    )
    assert result.records[0].safe_metadata["phi_sensitivity_level"] == "high"
    assert "ssn" in result.records[0].safe_metadata.get("phi_types", [])


def test_ingest_tags_phi_sensitivity_none() -> None:
    result = ingest_corpus(
        IngestRequest(
            documents=[
                CorpusDocument(
                    source_id="doc-002",
                    content=_CLEAN_TEXT,
                )
            ]
        ),
        trusted_tenant_id="t1",
    )
    assert result.records[0].safe_metadata["phi_sensitivity_level"] == "none"
    assert "phi_types" not in result.records[0].safe_metadata


# ---------------------------------------------------------------------------
# Section 8: Regression — classifier must be wired into routing
# ---------------------------------------------------------------------------


def test_phi_gate_is_wired_into_chat_route() -> None:
    """Regression guard: removing BAA gate from chat routing breaks this test."""
    import inspect

    import api.ui_ai_console as ai_console
    from services.provider_baa import gate as baa_gate

    source = inspect.getsource(ai_console)
    gate_source = inspect.getsource(baa_gate)

    assert "enforce_baa_gate_for_route" in source, (
        "BAA gate must be called from chat route source"
    )
    assert "classify_phi" in gate_source, (
        "PHI classifier must be present in gate source"
    )
    assert "enforce_provider_baa_for_route" in gate_source, (
        "BAA enforcement must be present in gate source"
    )
    assert "contains_phi" in gate_source, (
        "BAA enforcement must be conditional on PHI classification in gate"
    )
