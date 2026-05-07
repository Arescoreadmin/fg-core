"""
tests/test_rag_context_contract.py — Contract validation for RAG context models.

14 tests covering:
- Request validation (query, tenant_id, top_k)
- Chunk field requirements (corpus_id, document_id, chunk_id, text, score)
- Response serialization and ordering
- Schema safety (no secret fields)
- Module isolation (no retrieval or persistence imports)
"""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from api.rag_context import (
    RagChunkProvenance,
    RagContextChunk,
    RagContextRequest,
    RagContextResponse,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provenance(
    corpus_id: str = "corp-1",
    document_id: str = "doc-1",
    chunk_id: str = "chunk-1",
) -> RagChunkProvenance:
    return RagChunkProvenance(
        corpus_id=corpus_id,
        document_id=document_id,
        chunk_id=chunk_id,
    )


def _make_chunk(
    text: str = "Some text",
    score: float = 0.9,
    corpus_id: str = "corp-1",
    document_id: str = "doc-1",
    chunk_id: str = "chunk-1",
) -> RagContextChunk:
    return RagContextChunk(
        text=text,
        score=score,
        provenance=_make_provenance(
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=chunk_id,
        ),
    )


# ---------------------------------------------------------------------------
# RagContextRequest tests
# ---------------------------------------------------------------------------


def test_rag_context_request_accepts_valid_query():
    req = RagContextRequest(query="What is the policy?", tenant_id="tenant-abc")
    assert req.query == "What is the policy?"
    assert req.tenant_id == "tenant-abc"
    assert req.corpus_ids == []
    assert req.top_k == 5


def test_rag_context_request_rejects_blank_query():
    with pytest.raises(ValidationError):
        RagContextRequest(query="", tenant_id="tenant-abc")


def test_rag_context_request_rejects_invalid_top_k():
    with pytest.raises(ValidationError):
        RagContextRequest(query="hello", tenant_id="t1", top_k=0)
    with pytest.raises(ValidationError):
        RagContextRequest(query="hello", tenant_id="t1", top_k=101)


# ---------------------------------------------------------------------------
# RagChunkProvenance / RagContextChunk field requirement tests
# ---------------------------------------------------------------------------


def test_rag_context_chunk_requires_corpus_id():
    with pytest.raises(ValidationError):
        _make_chunk(corpus_id="")


def test_rag_context_chunk_requires_document_id():
    with pytest.raises(ValidationError):
        _make_chunk(document_id="")


def test_rag_context_chunk_requires_chunk_id():
    with pytest.raises(ValidationError):
        _make_chunk(chunk_id="")


def test_rag_context_chunk_requires_text():
    with pytest.raises(ValidationError):
        RagContextChunk(text="", score=0.5, provenance=_make_provenance())


def test_rag_context_chunk_rejects_non_finite_score():
    with pytest.raises(ValidationError):
        RagContextChunk(text="hello", score=math.inf, provenance=_make_provenance())
    with pytest.raises(ValidationError):
        RagContextChunk(text="hello", score=float("nan"), provenance=_make_provenance())


# ---------------------------------------------------------------------------
# RagContextResponse tests
# ---------------------------------------------------------------------------


def test_rag_context_response_serializes_provenance():
    chunk = _make_chunk(corpus_id="corp-x", document_id="doc-x", chunk_id="ck-x")
    resp = RagContextResponse(query="q", chunks=[chunk])
    dumped = resp.chunks[0].model_dump()
    prov = dumped["provenance"]
    assert prov["corpus_id"] == "corp-x"
    assert prov["document_id"] == "doc-x"
    assert prov["chunk_id"] == "ck-x"


def test_rag_context_response_allows_missing_source_title():
    prov = RagChunkProvenance(
        corpus_id="c1", document_id="d1", chunk_id="k1", source=None, title=None
    )
    chunk = RagContextChunk(text="text", score=0.5, provenance=prov)
    resp = RagContextResponse(query="q", chunks=[chunk])
    assert resp.chunks[0].provenance.source is None
    assert resp.chunks[0].provenance.title is None


def test_rag_context_response_preserves_chunk_order():
    chunks = [_make_chunk(text=f"chunk {i}", score=float(i) / 10) for i in range(5)]
    resp = RagContextResponse(query="q", chunks=chunks)
    for i, chunk in enumerate(resp.chunks):
        assert chunk.text == f"chunk {i}"


# ---------------------------------------------------------------------------
# Derived field tests (context_count / used_retrieval)
# ---------------------------------------------------------------------------


def test_rag_context_response_empty_chunks_derives_zero_count():
    resp = RagContextResponse(query="q", chunks=[])
    assert resp.context_count == 0
    assert resp.used_retrieval is False


def test_rag_context_response_one_chunk_derives_count_and_flag():
    resp = RagContextResponse(query="q", chunks=[_make_chunk()])
    assert resp.context_count == 1
    assert resp.used_retrieval is True


def test_rag_context_response_multiple_chunks_derives_correct_count():
    chunks = [_make_chunk(text=f"t{i}", chunk_id=f"ck-{i}") for i in range(4)]
    resp = RagContextResponse(query="q", chunks=chunks)
    assert resp.context_count == 4
    assert resp.used_retrieval is True


def test_rag_context_response_normalizes_contradictory_caller_values():
    # Caller passes context_count=0/used_retrieval=False but chunks is non-empty.
    # Model must normalise to derived truth.
    chunk = _make_chunk()
    resp = RagContextResponse(
        query="q", chunks=[chunk], context_count=0, used_retrieval=False
    )
    assert resp.context_count == 1
    assert resp.used_retrieval is True


# ---------------------------------------------------------------------------
# Safety / isolation tests
# ---------------------------------------------------------------------------


def test_rag_context_schema_has_no_secret_fields():
    forbidden = {"secret", "key", "token", "password"}
    for model in (
        RagContextRequest,
        RagChunkProvenance,
        RagContextChunk,
        RagContextResponse,
    ):
        for field_name in model.model_fields:
            assert not any(word in field_name.lower() for word in forbidden), (
                f"Model {model.__name__} has a field matching a secret keyword: {field_name}"
            )


def test_rag_context_contract_does_not_call_retrieval():
    import api.rag_context as rag_mod

    # The module must not import any retrieval module at the top level
    for attr_val in vars(rag_mod).values():
        mod_name = getattr(attr_val, "__name__", "") or ""
        assert "retrieval" not in mod_name, (
            f"api.rag_context unexpectedly exposes retrieval module: {mod_name}"
        )
    # Check that no retrieval module was pulled in via rag_context's own imports
    import importlib

    spec = importlib.util.find_spec("api.rag_context")
    assert spec is not None
    # Read the raw source lines (not inspect.getsource which includes docstrings)
    assert spec.origin is not None
    with open(spec.origin) as f:
        lines = f.readlines()
    import_lines = [ln for ln in lines if ln.strip().startswith(("import ", "from "))]
    for line in import_lines:
        assert "retrieval" not in line, (
            f"api/rag_context.py must not import any retrieval module; found: {line.strip()}"
        )


def test_rag_context_contract_does_not_touch_persistence():
    import importlib

    spec = importlib.util.find_spec("api.rag_context")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as f:
        lines = f.readlines()
    import_lines = [ln for ln in lines if ln.strip().startswith(("import ", "from "))]
    for line in import_lines:
        for forbidden in ("db", "database", "session", "sqlalchemy", "sqlite"):
            assert forbidden not in line.lower(), (
                f"api/rag_context.py must not import persistence layer: found '{forbidden}' in: {line.strip()}"
            )
