"""
Task 16.1 — Corpus Ingestion Integrity tests.

Selected by: pytest -k 'rag and ingest'
"""

from __future__ import annotations

import pytest

from api.rag.ingest import (
    INGEST_ERR_BLANK_CONTENT,
    INGEST_ERR_CROSS_TENANT,
    INGEST_ERR_EMPTY_DOCUMENTS,
    INGEST_ERR_MISSING_SOURCE,
    INGEST_ERR_MISSING_TENANT,
    CorpusDocument,
    CorpusIngestError,
    IngestRequest,
    IngestStatus,
    ingest_corpus,
)

TENANT_A = "tenant-alpha"
TENANT_B = "tenant-beta"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _doc(
    source_id: str = "doc-001",
    content: str = "This is valid document content.",
    metadata: dict | None = None,
    tenant_hint: str | None = None,
) -> CorpusDocument:
    return CorpusDocument(
        source_id=source_id,
        content=content,
        metadata=metadata or {},
        tenant_hint=tenant_hint,
    )


def _request(*docs: CorpusDocument) -> IngestRequest:
    return IngestRequest(documents=list(docs))


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_rag_ingest_valid_corpus_succeeds() -> None:
    docs = [
        _doc("src-1", "Content for document one."),
        _doc("src-2", "Content for document two."),
    ]
    result = ingest_corpus(_request(*docs), trusted_tenant_id=TENANT_A)

    assert result.status == IngestStatus.SUCCESS
    assert len(result.records) == 2
    assert result.error_code is None

    for record in result.records:
        assert record.tenant_id == TENANT_A
        assert record.status == IngestStatus.SUCCESS
        assert record.document_id
        assert record.content_hash
        assert len(record.document_id) == 64  # SHA-256 hex
        assert len(record.content_hash) == 64


# ---------------------------------------------------------------------------
# Tenant guard: missing trusted tenant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_tenant", ["", "   ", None])
def test_rag_ingest_rejects_missing_trusted_tenant(bad_tenant: str | None) -> None:
    with pytest.raises(CorpusIngestError) as exc_info:
        ingest_corpus(_request(_doc()), trusted_tenant_id=bad_tenant)  # type: ignore[arg-type]

    assert exc_info.value.error_code == INGEST_ERR_MISSING_TENANT


# ---------------------------------------------------------------------------
# Empty document list
# ---------------------------------------------------------------------------


def test_rag_ingest_rejects_empty_documents() -> None:
    with pytest.raises(CorpusIngestError) as exc_info:
        ingest_corpus(IngestRequest(documents=[]), trusted_tenant_id=TENANT_A)

    assert exc_info.value.error_code == INGEST_ERR_EMPTY_DOCUMENTS


# ---------------------------------------------------------------------------
# Blank content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_rag_ingest_rejects_blank_document_content(blank: str) -> None:
    with pytest.raises(CorpusIngestError) as exc_info:
        ingest_corpus(_request(_doc(content=blank)), trusted_tenant_id=TENANT_A)

    assert exc_info.value.error_code == INGEST_ERR_BLANK_CONTENT


# ---------------------------------------------------------------------------
# Cross-tenant: document metadata conflicts with trusted tenant
# ---------------------------------------------------------------------------


def test_rag_ingest_rejects_cross_tenant_document_metadata() -> None:
    doc = _doc(tenant_hint=TENANT_B)  # hint says B, but trusted context is A
    with pytest.raises(CorpusIngestError) as exc_info:
        ingest_corpus(_request(doc), trusted_tenant_id=TENANT_A)

    assert exc_info.value.error_code == INGEST_ERR_CROSS_TENANT


# ---------------------------------------------------------------------------
# Determinism: same input → same document IDs
# ---------------------------------------------------------------------------


def test_rag_ingest_record_ids_are_deterministic() -> None:
    docs = [_doc("src-1", "Deterministic content.")]
    result_1 = ingest_corpus(_request(*docs), trusted_tenant_id=TENANT_A)
    result_2 = ingest_corpus(_request(*docs), trusted_tenant_id=TENANT_A)

    assert result_1.records[0].document_id == result_2.records[0].document_id
    assert result_1.records[0].content_hash == result_2.records[0].content_hash


# ---------------------------------------------------------------------------
# Tenant attribution and safe metadata preservation
# ---------------------------------------------------------------------------


def test_rag_ingest_preserves_tenant_and_safe_metadata() -> None:
    meta = {"category": "finance", "version": 3}
    doc = _doc(metadata=meta, tenant_hint=TENANT_A)
    result = ingest_corpus(_request(doc), trusted_tenant_id=TENANT_A)

    record = result.records[0]
    assert record.tenant_id == TENANT_A
    assert record.safe_metadata["category"] == "finance"
    assert record.safe_metadata["version"] == 3
    # tenant_hint must be stripped from safe_metadata
    assert "tenant_hint" not in record.safe_metadata


# ---------------------------------------------------------------------------
# Error leakage: raw document text must NOT appear in error message
# ---------------------------------------------------------------------------


def test_rag_ingest_error_does_not_leak_raw_document_text() -> None:
    secret_content = "SUPER_SECRET_DOC_CONTENT_XYZ"
    # Force blank content error by passing a blank content doc
    blank_doc = CorpusDocument(source_id="leak-test", content="")
    with pytest.raises(CorpusIngestError) as exc_info:
        ingest_corpus(_request(blank_doc), trusted_tenant_id=TENANT_A)

    assert secret_content not in str(exc_info.value)
    assert secret_content not in exc_info.value.message

    # Also verify cross-tenant error doesn't leak content
    cross_doc = CorpusDocument(
        source_id="cross-test",
        content=secret_content,
        tenant_hint=TENANT_B,
    )
    with pytest.raises(CorpusIngestError) as exc_info2:
        ingest_corpus(_request(cross_doc), trusted_tenant_id=TENANT_A)

    assert secret_content not in str(exc_info2.value)
    assert secret_content not in exc_info2.value.message


# ---------------------------------------------------------------------------
# Failed path has stable error code
# ---------------------------------------------------------------------------


def test_rag_ingest_failed_path_has_stable_error_code() -> None:
    # Each error path must expose a stable error code (not a raw exception string).
    cases: list[tuple[IngestRequest, str, str]] = [
        (IngestRequest(documents=[]), TENANT_A, INGEST_ERR_EMPTY_DOCUMENTS),
        (_request(_doc(content="")), TENANT_A, INGEST_ERR_BLANK_CONTENT),
        (_request(_doc(tenant_hint=TENANT_B)), TENANT_A, INGEST_ERR_CROSS_TENANT),
        (_request(_doc(source_id="")), TENANT_A, INGEST_ERR_MISSING_SOURCE),
    ]
    for req, tenant, expected_code in cases:
        with pytest.raises(CorpusIngestError) as exc_info:
            ingest_corpus(req, trusted_tenant_id=tenant)
        assert exc_info.value.error_code == expected_code, (
            f"Expected {expected_code}, got {exc_info.value.error_code}"
        )
