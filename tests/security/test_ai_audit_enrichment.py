from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.rag.chunking import ChunkingConfig, CorpusChunk, chunk_ingested_records
from api.rag.ingest import CorpusDocument, IngestRequest, ingest_corpus
from api.security_audit import EventType
from services.ai.audit import build_ai_audit_metadata
from services.ai.policy import AiAuditRules, AiPhiRules, AiPolicy, AiRagRules
from services.ai.providers.base import (
    AI_PROVIDER_CALL_FAILED,
    ProviderCallError,
    ProviderResponse,
)
from services.ai.rag_context import RagContextChunk, RagContextResult
from services.ai.response_validation import (
    NO_ANSWER_TEXT,
    RESPONSE_UNGROUNDED,
    RESPONSE_VALIDATOR_VERSION,
    ResponseValidationResult,
)
from services.phi_classifier.minimizer import PromptMinimizationResult
from services.phi_classifier.models import SensitivityLevel
from services.provider_baa.gate import (
    BaaGateResult,
    GATE_ACTION_ALLOWED,
    GATE_ACTION_DENIED,
)

_CLEAN_TEXT = "Please summarize the quarterly report."
_PHI_TEXT = "SSN 123-45-6789 and MRN 987-65 belong to patient@example.com"
_RAW_RESPONSE = "Patient response contains MRN 987-65."
_MINIMIZATION_TEXT = (
    "Patient John Smith DOB 01/02/1980 has MRN 4872910. "
    "Contact jane@example.com or 555-123-4567."
)
_MINIMIZED_TEXT = (
    "Patient [PATIENT_NAME] DOB [DATE] has MRN [MRN]. Contact [EMAIL] or [PHONE]."
)
_CHUNK_CONFIG = ChunkingConfig(max_chars=180, overlap_chars=0)


def _chunks(tenant_id: str, source_id: str, content: str) -> list[CorpusChunk]:
    result = ingest_corpus(
        IngestRequest(documents=[CorpusDocument(source_id=source_id, content=content)]),
        trusted_tenant_id=tenant_id,
    )
    return chunk_ingested_records(result.records, config=_CHUNK_CONFIG)


def _baa_result(
    *,
    allowed: bool = True,
    contains_phi: bool = False,
    phi_types: frozenset[str] = frozenset(),
    provider_id: str = "simulated",
) -> BaaGateResult:
    return BaaGateResult(
        allowed=allowed,
        contains_phi=contains_phi,
        sensitivity_level=SensitivityLevel.HIGH
        if contains_phi
        else SensitivityLevel.NONE,
        phi_types=phi_types,
        provider_id=provider_id,
        tenant_id="tenant-a",
        reason_code="PHI_DETECTED" if contains_phi else "NO_PHI",
        enforcement_action=GATE_ACTION_ALLOWED if allowed else GATE_ACTION_DENIED,
    )


def _assert_no_raw_values(details: dict[str, object]) -> None:
    payload = str(details)
    forbidden = [
        _CLEAN_TEXT,
        _PHI_TEXT,
        _RAW_RESPONSE,
        "123-45-6789",
        "987-65",
        "patient@example.com",
        "raw provider body",
    ]
    for value in forbidden:
        assert value not in payload


def test_ai_audit_metadata_hashes_are_deterministic_and_safe() -> None:
    provider_response = ProviderResponse(
        provider_id="anthropic",
        text=_RAW_RESPONSE,
        model="claude-haiku-4-5-20251001",
        input_tokens=11,
        output_tokens=7,
    )
    baa_result = _baa_result(
        contains_phi=True,
        phi_types=frozenset({"medical_keyword", "ssn", "email", "mrn"}),
        provider_id="anthropic",
    )

    first = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="anthropic",
        baa_gate_result=baa_result,
        request_text=_PHI_TEXT,
        provider_response=provider_response,
        request_id="req-1",
        device_id="dev-1",
    )
    second = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="anthropic",
        baa_gate_result=baa_result,
        request_text=_PHI_TEXT,
        provider_response=provider_response,
        request_id="req-1",
        device_id="dev-1",
    )
    different = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="anthropic",
        baa_gate_result=baa_result,
        request_text="different request",
        provider_response=provider_response,
    )

    assert first["request_hash"] == second["request_hash"]
    assert first["response_hash"] == second["response_hash"]
    assert first["request_hash"] != different["request_hash"]
    assert str(first["request_hash"]).startswith("sha256:")
    assert str(first["response_hash"]).startswith("sha256:")
    assert first["phi_types"] == ["email", "mrn", "ssn"]
    assert first["phi_detected"] is True
    assert first["provider_id"] == "anthropic"
    assert first["baa_check_result"] == "allowed"
    assert first["model"] == "claude-haiku-4-5-20251001"
    assert first["input_tokens"] == 11
    assert first["output_tokens"] == 7
    _assert_no_raw_values(first)


def test_ai_audit_metadata_response_hash_null_without_response() -> None:
    metadata = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="anthropic",
        baa_gate_result=_baa_result(
            allowed=False,
            contains_phi=True,
            phi_types=frozenset({"mrn"}),
            provider_id="anthropic",
        ),
        request_text=_PHI_TEXT,
        response_text=None,
    )

    assert metadata["response_hash"] is None
    assert metadata["request_hash"]
    assert metadata["phi_types"] == ["mrn"]
    _assert_no_raw_values(metadata)


def test_ai_audit_metadata_includes_safe_rag_fields_without_raw_context() -> None:
    rag_result = RagContextResult(
        chunks=(
            RagContextChunk(
                source_id="src-a",
                chunk_id="chunk-a",
                chunk_index=0,
                text="raw retrieved context with 123-45-6789",
                phi_sensitivity_level="high",
                phi_types=("ssn",),
            ),
        ),
        context_text="raw retrieved context with 123-45-6789",
        chunk_count=1,
        source_ids=("src-a",),
        retrieval_reason_code="RAG_RETRIEVAL_SELECTED",
        query_phi_sensitivity="none",
        max_sensitivity_level="high",
        contains_phi=True,
    )

    metadata = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="azure_openai",
        baa_gate_result=_baa_result(
            contains_phi=True,
            phi_types=frozenset({"ssn"}),
            provider_id="azure_openai",
        ),
        request_text="provider prompt",
        response_text=None,
        rag_context=rag_result,
    )

    assert metadata["rag_used"] is True
    assert metadata["rag_chunk_count"] == 1
    assert metadata["rag_source_ids"] == ["src-a"]
    assert metadata["rag_retrieval_reason_code"] == "RAG_RETRIEVAL_SELECTED"
    assert metadata["rag_query_phi_sensitivity"] == "none"
    assert metadata["rag_max_sensitivity_level"] == "high"
    assert "raw retrieved context" not in str(metadata)
    assert "123-45-6789" not in str(metadata)


def test_ai_audit_metadata_includes_safe_policy_fields_only() -> None:
    ai_policy = AiPolicy(
        version=1,
        allowed_providers=("anthropic", "azure_openai"),
        default_provider="anthropic",
        phi_provider="azure_openai",
        phi_rules=AiPhiRules(
            require_baa=True,
            require_prompt_minimization=True,
            deny_if_phi_provider_unavailable=True,
            deny_explicit_non_phi_provider_for_phi=True,
        ),
        rag_rules=AiRagRules(
            enabled=True,
            require_grounded_response=True,
            no_answer_on_ungrounded=True,
        ),
        audit_rules=AiAuditRules(
            require_request_hash=True,
            require_response_hash=True,
            include_routing_metadata=True,
        ),
        source="contracts/ai/policies/default.json",
        reason_code="AI_POLICY_LOADED",
    )

    metadata = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="anthropic",
        baa_gate_result=_baa_result(provider_id="anthropic"),
        request_text="provider prompt",
        response_text=None,
        ai_policy=ai_policy,
    )

    assert metadata["policy_source"] == "contracts/ai/policies/default.json"
    assert metadata["policy_version"] == 1
    assert metadata["policy_reason_code"] == "AI_POLICY_LOADED"
    assert "allowed_providers" not in str(metadata)
    assert "raw_policy" not in str(metadata)


def test_ai_audit_metadata_uses_final_validated_response_hash() -> None:
    provider_response = ProviderResponse(
        provider_id="simulated",
        text="unsupported raw provider answer 987-65",
        model="SIMULATED_V1",
    )
    response_validation = ResponseValidationResult(
        grounded=False,
        final_text=NO_ANSWER_TEXT,
        reason_code=RESPONSE_UNGROUNDED,
        citation_source_ids=(),
        validator_version=RESPONSE_VALIDATOR_VERSION,
        evidence_count=0,
    )

    metadata = build_ai_audit_metadata(
        tenant_id="tenant-a",
        provider_id="simulated",
        baa_gate_result=_baa_result(provider_id="simulated"),
        request_text="provider prompt",
        provider_response=provider_response,
        response_validation=response_validation,
    )

    assert metadata["response_hash"] == (
        "sha256:" + hashlib.sha256(NO_ANSWER_TEXT.encode("utf-8")).hexdigest()
    )
    assert metadata["response_grounded"] is False
    assert metadata["response_validation_result"] == RESPONSE_UNGROUNDED
    assert metadata["response_validator_version"] == RESPONSE_VALIDATOR_VERSION
    assert metadata["response_citation_source_ids"] == []
    assert metadata["response_evidence_count"] == 0
    assert "unsupported raw provider answer" not in str(metadata)
    assert "987-65" not in str(metadata)


def _setup_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    from api.main import build_app

    db_path = tmp_path / "ai-audit.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated,anthropic,azure_openai")
    monkeypatch.setenv("FG_AZURE_AI_KEY", "test-azure-key")
    monkeypatch.setenv("FG_AZURE_OPENAI_ENDPOINT", "https://azure.example.test")
    monkeypatch.setenv("FG_AZURE_OPENAI_DEPLOYMENT", "fg-test")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return TestClient(build_app(auth_enabled=True))


def _enable_device(client: TestClient, headers: dict[str, str]) -> str:
    exp = client.get("/ui/ai/experience", headers=headers)
    assert exp.status_code == 200
    device_id = exp.json()["device"]["device_id"]
    enabled = client.post(
        f"/ui/devices/{device_id}/enable",
        headers=headers,
        json={"reason": "test", "ticket": "AI-AUDIT"},
    )
    assert enabled.status_code == 200
    return str(device_id)


def _allow_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    import api.ui_ai_console as ai_console

    orig_resolve = ai_console._resolve_experience

    def _patched_resolve(tenant_id: str):
        exp, policy, theme = orig_resolve(tenant_id)
        policy = dict(policy)
        policy["allowed_providers"] = ["simulated", "anthropic", "azure_openai"]
        policy["tenant_max_tokens_per_day"] = 1000
        policy["device_max_tokens_per_day"] = 1000
        return exp, policy, theme

    monkeypatch.setattr(ai_console, "_resolve_experience", _patched_resolve)
    monkeypatch.setattr(ai_console, "_provider_env_allowed", lambda _p: True)


def _insert_baa(db: Any, *, tenant_id: str, provider_id: str) -> None:
    db.execute(
        text(
            """
            INSERT INTO provider_baa_records(
                tenant_id, provider_id, baa_status, expiry_date, created_at, updated_at
            )
            VALUES (:tenant_id, :provider_id, 'active', '2030-01-01',
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """
        ),
        {"tenant_id": tenant_id, "provider_id": provider_id},
    )
    db.commit()


def _captured_admin_details(events: list[Any], reason: str) -> dict[str, object]:
    matches = [
        event.details
        for event in events
        if event.event_type == EventType.ADMIN_ACTION and event.reason == reason
    ]
    assert matches
    return matches[-1]


def test_ui_success_audit_includes_request_and_response_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)
    provider_response = ProviderResponse(
        provider_id="anthropic",
        text=_RAW_RESPONSE,
        model="claude-haiku-4-5-20251001",
        input_tokens=3,
        output_tokens=4,
    )
    monkeypatch.setattr(ai_console, "_call_provider", lambda **_kw: provider_response)
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    response = client.post(
        "/ui/ai/chat",
        headers=headers,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )

    assert response.status_code == 200, response.text
    details = _captured_admin_details(events, "ai_chat")
    assert details["phi_detected"] is False
    assert details["phi_types"] == []
    assert details["provider_id"] == "anthropic"
    assert details["baa_check_result"] == "allowed"
    assert str(details["request_hash"]).startswith("sha256:")
    assert str(details["response_hash"]).startswith("sha256:")
    _assert_no_raw_values(details)


def test_ui_chat_sends_minimized_prompt_and_audits_safe_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)
    monkeypatch.setattr(ai_console, "_contains_pii", lambda _text, _terms: False)
    captured_prompt = ""

    def _provider(**kw: Any) -> ProviderResponse:
        nonlocal captured_prompt
        captured_prompt = str(kw["prompt"])
        return ProviderResponse(
            provider_id="azure_openai",
            text="safe response",
            model="fg-test",
            input_tokens=6,
            output_tokens=2,
        )

    monkeypatch.setattr(ai_console, "_call_provider", _provider)
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    _insert_baa(
        get_sessionmaker()(), tenant_id="tenant-dev", provider_id="azure_openai"
    )
    request_headers = {**headers, "X-Request-ID": "min-req-1"}
    response = client.post(
        "/ui/ai/chat",
        headers=request_headers,
        json={
            "message": _MINIMIZATION_TEXT,
            "device_id": device_id,
        },
    )

    assert response.status_code == 200, response.text
    assert captured_prompt == _MINIMIZED_TEXT
    assert "John Smith" not in captured_prompt
    assert "01/02/1980" not in captured_prompt
    assert "4872910" not in captured_prompt
    assert "jane@example.com" not in captured_prompt
    assert "555-123-4567" not in captured_prompt
    details = _captured_admin_details(events, "ai_chat")
    assert details["prompt_minimized"] is True
    assert details["minimization_replacement_count"] == 5
    assert details["minimization_placeholder_types"] == [
        "DATE",
        "EMAIL",
        "MRN",
        "PATIENT_NAME",
        "PHONE",
    ]
    expected_request_hash = ai_console._build_provider_request_hash(
        tenant_id="tenant-dev",
        device_id=device_id,
        provider="azure_openai",
        model="azure_openai",
        persona="default",
        outgoing_prompt=_MINIMIZED_TEXT,
        request_id="min-req-1",
    )
    assert details["request_hash"] == ("sha256:" + expected_request_hash)
    assert details["request_hash"] != (
        "sha256:" + hashlib.sha256(_MINIMIZED_TEXT.encode("utf-8")).hexdigest()
    )
    assert _MINIMIZATION_TEXT not in str(details)
    assert _MINIMIZED_TEXT not in str(details)


def test_ui_provider_request_hash_includes_safe_request_context() -> None:
    import api.ui_ai_console as ai_console

    first = ai_console._build_provider_request_hash(
        tenant_id="tenant-a",
        device_id="device-a",
        provider="simulated",
        model="SIMULATED_V1",
        persona="default",
        outgoing_prompt=_MINIMIZED_TEXT,
        request_id="req-1",
    )
    second = ai_console._build_provider_request_hash(
        tenant_id="tenant-a",
        device_id="device-a",
        provider="simulated",
        model="SIMULATED_V1",
        persona="default",
        outgoing_prompt=_MINIMIZED_TEXT,
        request_id="req-2",
    )
    different_provider = ai_console._build_provider_request_hash(
        tenant_id="tenant-a",
        device_id="device-a",
        provider="anthropic",
        model="SIMULATED_V1",
        persona="default",
        outgoing_prompt=_MINIMIZED_TEXT,
        request_id="req-1",
    )

    assert first != second
    assert first != different_provider
    assert "John Smith" not in first
    assert "01/02/1980" not in first
    assert "4872910" not in first
    assert "jane@example.com" not in first


def test_ui_phi_baa_denial_audit_has_null_response_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)
    provider_called = False

    def _provider(**_kw):
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(provider_id="azure_openai", text="unused", model="m")

    monkeypatch.setattr(ai_console, "_call_provider", _provider)
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    response = client.post(
        "/ui/ai/chat",
        headers=headers,
        json={"message": _PHI_TEXT, "device_id": device_id},
    )

    assert response.status_code == 403
    assert provider_called is False
    details = _captured_admin_details(events, "PROVIDER_BAA_MISSING")
    assert details["phi_detected"] is True
    assert details["phi_types"] == ["email", "mrn", "ssn"]
    assert details["provider_id"] == "azure_openai"
    assert details["baa_check_result"] == "denied"
    assert details["response_hash"] is None
    assert str(details["request_hash"]).startswith("sha256:")
    _assert_no_raw_values(details)


def test_ui_provider_failure_audit_has_request_hash_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)

    def _fail(**_kw):
        raise ProviderCallError(AI_PROVIDER_CALL_FAILED, "raw provider body")

    monkeypatch.setattr(ai_console, "_call_provider", _fail)
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    response = client.post(
        "/ui/ai/chat",
        headers=headers,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "anthropic"},
    )

    assert response.status_code == 503
    details = _captured_admin_details(events, AI_PROVIDER_CALL_FAILED)
    assert details["request_hash"]
    assert details["response_hash"] is None
    assert "raw provider body" not in str(details)
    _assert_no_raw_values(details)


def test_ui_quota_denial_does_not_call_provider_or_invent_response_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)
    monkeypatch.setattr(
        ai_console,
        "_consume_quota_atomic",
        lambda *_args, **_kw: (_ for _ in ()).throw(
            HTTPException(
                status_code=429,
                detail={"error_code": "AI_QUOTA_EXCEEDED", "message": "quota exceeded"},
            )
        ),
    )
    provider_called = False

    def _provider(**_kw):
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(provider_id="simulated", text="unused", model="m")

    monkeypatch.setattr(ai_console, "_call_provider", _provider)
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    response = client.post(
        "/ui/ai/chat",
        headers=headers,
        json={"message": _CLEAN_TEXT, "device_id": device_id, "provider": "simulated"},
    )

    assert response.status_code == 429
    assert provider_called is False
    details = _captured_admin_details(events, "AI_QUOTA_EXCEEDED")
    assert details["provider_id"] == "simulated"
    assert details["phi_detected"] is False
    assert details["response_hash"] is None
    _assert_no_raw_values(details)


def test_ui_minimization_failure_blocks_provider_and_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import api.ui_ai_console as ai_console

    _allow_providers(monkeypatch)
    monkeypatch.setattr(
        ai_console,
        "minimize_prompt",
        lambda *_args: PromptMinimizationResult(
            minimized_text="",
            changed=True,
            replacements=(),
            replacement_count=0,
            placeholder_types=[],
            minimization_version="prompt_minimization_v1",
            reason_code="PROMPT_MINIMIZATION_NON_STRING",
        ),
    )
    provider_called = False
    quota_called = False

    def _provider(**_kw: Any) -> ProviderResponse:
        nonlocal provider_called
        provider_called = True
        return ProviderResponse(provider_id="azure_openai", text="unused", model="m")

    def _quota(*_args: Any, **_kw: Any) -> None:
        nonlocal quota_called
        quota_called = True

    monkeypatch.setattr(ai_console, "_call_provider", _provider)
    monkeypatch.setattr(ai_console, "_consume_quota_atomic", _quota)

    client = _setup_client(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": mint_key(
            "ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev"
        )
    }
    device_id = _enable_device(client, headers)
    _insert_baa(
        get_sessionmaker()(), tenant_id="tenant-dev", provider_id="azure_openai"
    )
    response = client.post(
        "/ui/ai/chat",
        headers=headers,
        json={
            "message": _MINIMIZATION_TEXT,
            "device_id": device_id,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"]["error_code"] == "AI_PROMPT_MINIMIZATION_FAILED"
    assert provider_called is False
    assert quota_called is False


def test_ai_plane_provider_failure_audit_has_safe_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "plane-audit.db"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    db = get_sessionmaker()()
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "anthropic")
    monkeypatch.setenv("FG_AI_DEFAULT_PROVIDER", "anthropic")
    monkeypatch.setenv("FG_ANTHROPIC_API_KEY", "test-key")

    def _fail(**_kw):
        raise ProviderCallError(AI_PROVIDER_CALL_FAILED, "raw provider body")

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _fail)
    rag_chunks = _chunks(
        "tenant-a", "source-a", "quarterly report evidence for tenant alpha"
    )

    with pytest.raises(ValueError, match=AI_PROVIDER_CALL_FAILED):
        AIPlaneService(rag_chunks=rag_chunks).infer(
            db, "tenant-a", AIInferRequest(query=_CLEAN_TEXT)
        )

    details = _captured_admin_details(events, AI_PROVIDER_CALL_FAILED)
    assert details["provider_id"] == "anthropic"
    assert details["phi_detected"] is False
    assert details["request_hash"]
    assert details["response_hash"] is None
    _assert_no_raw_values(details)


def test_ai_plane_infer_sends_minimized_prompt_and_audits_safe_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.ai_plane_extension.models import AIInferRequest
    from services.ai_plane_extension.service import AIPlaneService

    db_path = tmp_path / "plane-minimization.db"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    db = get_sessionmaker()()
    events: list[Any] = []
    monkeypatch.setattr(
        "api.security_audit.SecurityAuditor.log_event",
        lambda _self, event: events.append(event),
    )
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "azure_openai")
    monkeypatch.setenv("FG_AZURE_AI_KEY", "test-azure-key")
    monkeypatch.setenv("FG_AZURE_OPENAI_ENDPOINT", "https://azure.example.test")
    monkeypatch.setenv("FG_AZURE_OPENAI_DEPLOYMENT", "fg-test")
    _insert_baa(db, tenant_id="tenant-a", provider_id="azure_openai")
    captured_prompt = ""

    def _provider(**kw: Any) -> ProviderResponse:
        nonlocal captured_prompt
        captured_prompt = str(kw["prompt"])
        return ProviderResponse(
            provider_id="azure_openai",
            text="safe response",
            model="fg-test",
            input_tokens=6,
            output_tokens=2,
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)
    rag_chunks = _chunks(
        "tenant-a", "source-a", "Patient contact schedule evidence for tenant alpha"
    )

    result = AIPlaneService(rag_chunks=rag_chunks).infer(
        db, "tenant-a", AIInferRequest(query=_MINIMIZATION_TEXT)
    )

    assert result["ok"] is True
    assert _MINIMIZED_TEXT in captured_prompt
    assert "Retrieved context:" in captured_prompt
    assert _MINIMIZATION_TEXT not in captured_prompt
    details = _captured_admin_details(events, "ai_plane_infer")
    assert details["prompt_minimized"] is True
    assert details["minimization_replacement_count"] == 5
    assert details["request_hash"] == (
        "sha256:" + hashlib.sha256(captured_prompt.encode("utf-8")).hexdigest()
    )
    assert _MINIMIZATION_TEXT not in str(details)
    assert _MINIMIZED_TEXT not in str(details)
