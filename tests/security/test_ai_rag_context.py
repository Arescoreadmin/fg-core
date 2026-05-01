from __future__ import annotations

import inspect
from typing import Any

import pytest

from api.rag.chunking import ChunkingConfig, CorpusChunk, chunk_ingested_records
from api.rag.ingest import CorpusDocument, IngestRequest, ingest_corpus
from api.rag.retrieval import RetrievalError, RetrievalQuery
from services.ai import rag_context
from services.ai.rag_context import (
    MAX_RAG_CONTEXT_LIMIT,
    RAG_RETRIEVAL_EMPTY,
    RagContextError,
    build_rag_augmented_prompt,
    retrieve_rag_context,
)
from services.ai_plane_extension.service import AIPlaneService

_TENANT_A = "tenant-rag-a"
_TENANT_B = "tenant-rag-b"
_CHUNK_CONFIG = ChunkingConfig(max_chars=180, overlap_chars=0)


def _chunks(
    tenant_id: str,
    source_id: str,
    content: str,
) -> list[CorpusChunk]:
    result = ingest_corpus(
        IngestRequest(documents=[CorpusDocument(source_id=source_id, content=content)]),
        trusted_tenant_id=tenant_id,
    )
    return chunk_ingested_records(result.records, config=_CHUNK_CONFIG)


def test_rag_context_requires_tenant_id() -> None:
    with pytest.raises(RagContextError):
        retrieve_rag_context(
            tenant_id="",
            query_text="authentication",
            chunks=[],
            limit=4,
            phi_detected=False,
        )


def test_rag_context_bounds_limit_and_passes_trusted_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def _search(
        chunks: list[CorpusChunk],
        query: RetrievalQuery,
        trusted_tenant_id: str,
    ) -> list[Any]:
        captured["limit"] = query.limit
        captured["tenant_id"] = trusted_tenant_id
        captured["chunks"] = chunks
        return []

    monkeypatch.setattr(rag_context, "search_chunks", _search)

    result = retrieve_rag_context(
        tenant_id=_TENANT_A,
        query_text="authentication",
        chunks=[],
        limit=999,
        phi_detected=False,
    )

    assert captured["tenant_id"] == _TENANT_A
    assert captured["limit"] == MAX_RAG_CONTEXT_LIMIT
    assert captured["chunks"] == []
    assert result.rag_used is False
    assert result.retrieval_reason_code == RAG_RETRIEVAL_EMPTY


def test_rag_context_is_deterministic_and_uses_ranked_order() -> None:
    chunks = _chunks(
        _TENANT_A, "src-z", "authentication policy reset tokens"
    ) + _chunks(_TENANT_A, "src-a", "authentication policy reset tokens")

    first = retrieve_rag_context(
        tenant_id=_TENANT_A,
        query_text="authentication policy",
        chunks=chunks,
        limit=2,
        phi_detected=False,
    )
    second = retrieve_rag_context(
        tenant_id=_TENANT_A,
        query_text="authentication policy",
        chunks=chunks,
        limit=2,
        phi_detected=False,
    )

    assert first == second
    assert first.chunk_count == 2
    assert first.source_ids == tuple(chunk.source_id for chunk in first.chunks)
    assert first.context_text
    assert "authentication policy reset tokens" in first.context_text


def test_rag_context_filters_cross_tenant_chunks() -> None:
    chunks = _chunks(
        _TENANT_A, "src-a", "authentication policy for tenant alpha"
    ) + _chunks(_TENANT_B, "src-b", "authentication policy for tenant beta")

    result = retrieve_rag_context(
        tenant_id=_TENANT_A,
        query_text="authentication policy",
        chunks=chunks,
        limit=8,
        phi_detected=False,
    )

    assert result.chunk_count == 1
    assert result.source_ids == ("src-a",)
    assert "tenant alpha" in result.context_text
    assert "tenant beta" not in result.context_text


def test_rag_context_ignores_zero_score_unrelated_chunks() -> None:
    result = retrieve_rag_context(
        tenant_id=_TENANT_A,
        query_text="quarterly revenue forecast",
        chunks=_chunks(
            _TENANT_A,
            "src-phi",
            "patient Jane Doe has MRN 4872910 and needs clinical follow up",
        ),
        limit=4,
        phi_detected=False,
    )

    assert result.rag_used is False
    assert result.chunk_count == 0
    assert result.context_text == ""
    assert result.source_ids == ()
    assert result.retrieval_reason_code == RAG_RETRIEVAL_EMPTY


def test_rag_context_search_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fail(
        _chunks: list[CorpusChunk],
        _query: RetrievalQuery,
        trusted_tenant_id: str,
    ) -> list[Any]:
        assert trusted_tenant_id == _TENANT_A
        raise RetrievalError("RAG_RETRIEVAL_TEST_FAILURE", "safe failure")

    monkeypatch.setattr(rag_context, "search_chunks", _fail)

    with pytest.raises(RagContextError, match="safe failure") as exc:
        retrieve_rag_context(
            tenant_id=_TENANT_A,
            query_text="authentication",
            chunks=[],
            limit=4,
            phi_detected=False,
        )

    assert exc.value.error_code == "RAG_RETRIEVAL_TEST_FAILURE"


def test_rag_context_prompt_includes_context_before_query() -> None:
    result = retrieve_rag_context(
        tenant_id=_TENANT_A,
        query_text="authentication",
        chunks=_chunks(_TENANT_A, "src-a", "authentication policy evidence"),
        limit=1,
        phi_detected=False,
    )

    prompt = build_rag_augmented_prompt(query_text="authentication", rag_context=result)

    assert prompt.startswith("Retrieved context:\n")
    assert "authentication policy evidence" in prompt
    assert prompt.endswith("User query:\nauthentication")


def test_ai_plane_execution_path_does_not_call_rag_stub() -> None:
    source = inspect.getsource(AIPlaneService.infer)
    assert "rag_stub" not in source
    assert "search_chunks" not in source
    assert "retrieve_rag_context" in source
