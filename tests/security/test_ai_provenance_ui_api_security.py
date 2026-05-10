from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.main import build_app
from api.rag_corpus_store import create_corpus, create_document, store_chunks
from services.ai.provenance import (
    PROVENANCE_NO_CONTEXT_AVAILABLE,
    PROVENANCE_SOURCE_NOT_RETRIEVED,
    PROVENANCE_VALID,
)
from services.ai.providers.base import ProviderResponse


def _setup_client(tmp_path: Path) -> tuple[TestClient, str, str]:
    db_path = tmp_path / "ai-provenance-ui-security.db"
    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_AUTH_ENABLED"] = "1"
    os.environ["FG_API_KEY"] = ""
    os.environ["FG_AI_PLANE_ENABLED"] = "1"
    os.environ["FG_AI_EXTERNAL_PROVIDER_ENABLED"] = "0"
    os.environ["FG_AI_ALLOWED_PROVIDERS"] = "simulated"
    os.environ["FG_AI_DEFAULT_PROVIDER"] = "simulated"
    os.environ["FG_AI_ENABLE_SIMULATED"] = "1"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    key_a = mint_key(
        "admin:write", "compliance:read", "governance:write", tenant_id="tenant-a"
    )
    key_b = mint_key(
        "admin:write", "compliance:read", "governance:write", tenant_id="tenant-b"
    )
    return TestClient(build_app(auth_enabled=True)), key_a, key_b


def _seed_chunk(
    *,
    tenant_id: str,
    text: str,
    metadata: dict[str, object] | None = None,
) -> str:
    with get_sessionmaker()() as db:
        corpus = create_corpus(db, tenant_id=tenant_id, name=f"{tenant_id} corpus")
        document = create_document(
            db,
            tenant_id=tenant_id,
            corpus_id=corpus["corpus_id"],
            title="Provenance UI API Security",
            source="https://example.test/provenance-ui-security",
        )
        chunks = store_chunks(
            db,
            tenant_id=tenant_id,
            document_id=document["document_id"],
            corpus_id=corpus["corpus_id"],
            chunks=[{"text": text, "ordinal": 0, "metadata": metadata or {}}],
        )
        return str(chunks[0]["chunk_id"])


def test_ai_infer_provenance_ui_security_payload_exposes_safe_metadata_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, key_a, _ = _setup_client(tmp_path)
    raw_chunk_text = (
        "alpha control evidence patientname MRN12345 secretphrase api_key_test_value"
    )
    chunk_id = _seed_chunk(
        tenant_id="tenant-a",
        text=raw_chunk_text,
        metadata={"phi_sensitivity_level": "high", "phi_types": ["mrn"]},
    )
    captured_prompt = ""
    cookie_secret = "session_cookie_secret"

    def _provider(**kwargs: Any) -> ProviderResponse:
        nonlocal captured_prompt
        captured_prompt = str(kwargs["prompt"])
        return ProviderResponse(
            provider_id="simulated",
            text=f"alpha control evidence [chunk_id={chunk_id}]",
            model="SIMULATED_V1",
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)

    response = client.post(
        "/ai/infer",
        json={"query": "alpha control patientname MRN12345 secretphrase"},
        headers={"X-API-Key": key_a, "Cookie": f"fg_session={cookie_secret}"},
    )

    assert response.status_code == 200
    body = response.json()
    provenance = cast(dict[str, Any], body["provenance"])
    assert provenance["provenance_status"] == PROVENANCE_VALID
    assert provenance["source_chunk_ids"] == [chunk_id]

    summaries = cast(list[dict[str, Any]], provenance["source_summaries"])
    assert summaries == [
        {
            "source_id": chunk_id,
            "chunk_id": chunk_id,
            "chunk_index": 0,
            "included_in_prompt": True,
            "phi_sensitivity_level": None,
            "phi_types": [],
        }
    ]
    for summary in summaries:
        assert set(summary) == {
            "source_id",
            "chunk_id",
            "chunk_index",
            "included_in_prompt",
            "phi_sensitivity_level",
            "phi_types",
        }

    why_by_chunk = cast(dict[str, Any], provenance["why_this_chunk"])
    why = cast(dict[str, Any], why_by_chunk[chunk_id])
    assert why["matched_term_count"] == 5
    assert why["matched_term_categories"] == ["letters", "letters_digits"]
    assert "matched_terms" not in why

    serialized = json.dumps(body, sort_keys=True)
    for forbidden in (
        raw_chunk_text,
        captured_prompt,
        "patientname",
        "MRN12345",
        "secretphrase",
        "api_key_test_value",
        key_a,
        cookie_secret,
        "Authorization",
        "Cookie",
        "raw_vector",
        "embedding_vector",
        "[0.1, 0.2, 0.3]",
    ):
        assert forbidden not in serialized


def test_ai_infer_provenance_ui_security_wrong_tenant_empty_context(
    tmp_path: Path,
) -> None:
    client, _, key_b = _setup_client(tmp_path)
    foreign_text = "tenant alpha control evidence secretphrase"
    _seed_chunk(tenant_id="tenant-a", text=foreign_text)

    response = client.post(
        "/ai/infer",
        json={"query": "tenant alpha control secretphrase"},
        headers={"X-API-Key": key_b},
    )

    assert response.status_code == 200
    body = response.json()
    provenance = body["provenance"]
    assert provenance["provenance_status"] == PROVENANCE_NO_CONTEXT_AVAILABLE
    assert provenance["used_rag"] is False
    assert provenance["context_count"] == 0
    assert provenance["source_chunk_ids"] == []
    assert provenance["source_summaries"] == []
    assert provenance["why_this_chunk"] == {}
    assert foreign_text not in json.dumps(body, sort_keys=True)


def test_ai_infer_provenance_ui_security_rejects_fake_source_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, key_a, _ = _setup_client(tmp_path)
    raw_chunk_text = "alpha control evidence patientname MRN12345 secretphrase"
    _seed_chunk(tenant_id="tenant-a", text=raw_chunk_text)
    fake_chunk_id = "ck-fake-provenance-ui"

    def _provider(**_kwargs: Any) -> ProviderResponse:
        return ProviderResponse(
            provider_id="simulated",
            text=f"alpha control evidence [chunk_id={fake_chunk_id}]",
            model="SIMULATED_V1",
        )

    monkeypatch.setattr("services.ai_plane_extension.service._call_provider", _provider)

    response = client.post(
        "/ai/infer",
        json={"query": "alpha control patientname MRN12345 secretphrase"},
        headers={"X-API-Key": key_a},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["response"] == "NO_ANSWER"
    assert body["sources"] == []
    assert body["confidence"] == 0.0
    assert body["provenance"]["provenance_status"] == PROVENANCE_SOURCE_NOT_RETRIEVED

    serialized = json.dumps(body, sort_keys=True)
    for forbidden in (
        raw_chunk_text,
        fake_chunk_id,
        "patientname",
        "MRN12345",
        "secretphrase",
        "raw_vector",
        "embedding_vector",
    ):
        assert forbidden not in serialized
