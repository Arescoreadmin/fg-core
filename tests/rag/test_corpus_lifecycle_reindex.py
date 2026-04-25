"""
Task 16.7 — Corpus Update/Delete/Reindex Lifecycle tests.

Proves that the corpus lifecycle store:
- Replaces stale chunks on document update.
- Removes documents from retrieval on delete.
- Does not resurrect deleted documents during reindex.
- Produces deterministic output for identical inputs.
- Preserves full tenant/source/document metadata.
- Fails closed on missing/invalid trusted tenant.
- Denies or hides cross-tenant update/delete (no side channel).
- Produces auditable structured results for every operation.
- Never leaks raw document text in errors.
- Produces stable active chunk ordering.
- Does not mutate caller-owned inputs.

Selected by: pytest -k 'rag and reindex'
"""

from __future__ import annotations

import pytest

from api.rag.chunking import ChunkingConfig
from api.rag.ingest import CorpusDocument
from api.rag.lifecycle import (
    LIFECYCLE_ERR_DOCUMENT_NOT_FOUND,
    LIFECYCLE_ERR_MISSING_TENANT,
    CorpusLifecycleStore,
    LifecycleError,
    LifecycleOperationResult,
    delete_document,
    list_active_chunks,
    list_active_records,
    reindex,
    upsert_document,
)
from api.rag.retrieval import RetrievalQuery, search_chunks

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TENANT_A = "tenant-rag-a"
_TENANT_B = "tenant-rag-b"

_CHUNK_CONFIG = ChunkingConfig(max_chars=200, overlap_chars=20)

_DOC_A_V1_CONTENT = (
    "FrostGate authentication policy version one. "
    "Authentication tokens expire after fifteen minutes. "
    "All authentication failures must be logged."
)
_DOC_A_V2_CONTENT = (
    "FrostGate authentication policy version two. "
    "Authentication tokens now expire after thirty minutes. "
    "Multi-factor authentication is required for all admin operations."
)
_DOC_B_CONTENT = (
    "FrostGate audit policy for tenant beta. "
    "All access events must be captured in the audit log. "
    "Audit records are tenant-isolated."
)
_SOURCE_A = "src-auth-policy"
_SOURCE_B = "src-audit-policy"


@pytest.fixture()
def store_a():
    """Fresh store with one document for TENANT_A."""
    s = CorpusLifecycleStore()
    upsert_document(
        s,
        CorpusDocument(source_id=_SOURCE_A, content=_DOC_A_V1_CONTENT),
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )
    return s


@pytest.fixture()
def store_ab():
    """Fresh store with one document each for TENANT_A and TENANT_B."""
    s = CorpusLifecycleStore()
    upsert_document(
        s,
        CorpusDocument(source_id=_SOURCE_A, content=_DOC_A_V1_CONTENT),
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )
    upsert_document(
        s,
        CorpusDocument(source_id=_SOURCE_B, content=_DOC_B_CONTENT),
        trusted_tenant_id=_TENANT_B,
        chunk_config=_CHUNK_CONFIG,
    )
    return s


# ---------------------------------------------------------------------------
# test_rag_reindex_update_replaces_stale_chunks
# ---------------------------------------------------------------------------


def test_rag_reindex_update_replaces_stale_chunks(store_a):
    chunks_before = list_active_chunks(store_a, _TENANT_A, _CHUNK_CONFIG)
    v1_texts = {c.text for c in chunks_before}

    # Update with new content
    result = upsert_document(
        store_a,
        CorpusDocument(source_id=_SOURCE_A, content=_DOC_A_V2_CONTENT),
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )
    assert result.operation == "update"

    chunks_after = list_active_chunks(store_a, _TENANT_A, _CHUNK_CONFIG)
    v2_texts = {c.text for c in chunks_after}

    # V1-specific text must not appear in active chunks
    assert "version one" not in " ".join(v2_texts).lower(), (
        "Stale V1 chunk text must not be present after update"
    )
    # V2 content must be present
    assert any("version two" in t.lower() for t in v2_texts), (
        "V2 content must appear in active chunks after update"
    )
    # No overlap with original chunk set (content changed)
    assert v1_texts != v2_texts

    # Old chunks must not surface in retrieval
    all_chunks = list_active_chunks(store_a, _TENANT_A, _CHUNK_CONFIG)
    results = search_chunks(
        all_chunks,
        RetrievalQuery(query_text="version one fifteen minutes", limit=50),
        trusted_tenant_id=_TENANT_A,
    )
    for r in results:
        assert "version one" not in r.text.lower(), (
            "Stale V1 chunk must not appear in retrieval results after update"
        )


# ---------------------------------------------------------------------------
# test_rag_reindex_delete_removes_document_from_retrieval
# ---------------------------------------------------------------------------


def test_rag_reindex_delete_removes_document_from_retrieval(store_a):
    chunks_before = list_active_chunks(store_a, _TENANT_A, _CHUNK_CONFIG)
    assert len(chunks_before) > 0

    del_result = delete_document(store_a, _SOURCE_A, trusted_tenant_id=_TENANT_A)
    assert del_result.operation == "delete"
    assert del_result.status == "ok"
    assert del_result.source_id == _SOURCE_A

    chunks_after = list_active_chunks(store_a, _TENANT_A, _CHUNK_CONFIG)
    assert len(chunks_after) == 0, (
        "No chunks should remain after deleting the only document"
    )

    results = search_chunks(
        chunks_after,
        RetrievalQuery(query_text="authentication", limit=10),
        trusted_tenant_id=_TENANT_A,
    )
    assert len(results) == 0, "Deleted document must not appear in search results"


# ---------------------------------------------------------------------------
# test_rag_reindex_deleted_document_stays_deleted_after_reindex
# ---------------------------------------------------------------------------


def test_rag_reindex_deleted_document_stays_deleted_after_reindex(store_a):
    delete_document(store_a, _SOURCE_A, trusted_tenant_id=_TENANT_A)

    chunks, result = reindex(store_a, _TENANT_A, _CHUNK_CONFIG)

    assert len(chunks) == 0, "Reindex must not resurrect a deleted document"
    assert result.affected_chunk_count == 0
    assert result.operation == "reindex"
    assert result.status == "ok"


# ---------------------------------------------------------------------------
# test_rag_reindex_same_inputs_are_deterministic
# ---------------------------------------------------------------------------


def test_rag_reindex_same_inputs_are_deterministic():
    s1 = CorpusLifecycleStore()
    s2 = CorpusLifecycleStore()

    for s in (s1, s2):
        upsert_document(
            s,
            CorpusDocument(source_id=_SOURCE_A, content=_DOC_A_V1_CONTENT),
            trusted_tenant_id=_TENANT_A,
            chunk_config=_CHUNK_CONFIG,
        )

    chunks_1, _ = reindex(s1, _TENANT_A, _CHUNK_CONFIG)
    chunks_2, _ = reindex(s2, _TENANT_A, _CHUNK_CONFIG)

    assert len(chunks_1) == len(chunks_2)
    for c1, c2 in zip(chunks_1, chunks_2):
        assert c1.chunk_id == c2.chunk_id
        assert c1.text == c2.text
        assert c1.chunk_index == c2.chunk_index


# ---------------------------------------------------------------------------
# test_rag_reindex_preserves_tenant_source_document_metadata
# ---------------------------------------------------------------------------


def test_rag_reindex_preserves_tenant_source_document_metadata(store_a):
    chunks, result = reindex(store_a, _TENANT_A, _CHUNK_CONFIG)

    assert len(chunks) > 0
    for chunk in chunks:
        assert chunk.tenant_id == _TENANT_A
        assert chunk.source_id == _SOURCE_A
        assert chunk.document_id
        assert chunk.parent_content_hash
        assert chunk.chunk_id

    records = list_active_records(store_a, _TENANT_A)
    assert len(records) == 1
    assert records[0].tenant_id == _TENANT_A
    assert records[0].source_id == _SOURCE_A


# ---------------------------------------------------------------------------
# test_rag_reindex_missing_trusted_tenant_fails_closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_tenant", ["", "   ", None, 123, True])
def test_rag_reindex_missing_trusted_tenant_fails_closed(store_a, bad_tenant):
    with pytest.raises(LifecycleError) as exc_info:
        reindex(store_a, trusted_tenant_id=bad_tenant)  # type: ignore[arg-type]
    assert exc_info.value.error_code == LIFECYCLE_ERR_MISSING_TENANT

    with pytest.raises(LifecycleError) as exc_info2:
        list_active_chunks(store_a, trusted_tenant_id=bad_tenant)  # type: ignore[arg-type]
    assert exc_info2.value.error_code == LIFECYCLE_ERR_MISSING_TENANT

    with pytest.raises(LifecycleError) as exc_info3:
        delete_document(store_a, _SOURCE_A, trusted_tenant_id=bad_tenant)  # type: ignore[arg-type]
    assert exc_info3.value.error_code == LIFECYCLE_ERR_MISSING_TENANT


# ---------------------------------------------------------------------------
# test_rag_reindex_cross_tenant_delete_is_denied_or_not_found
# ---------------------------------------------------------------------------


def test_rag_reindex_cross_tenant_delete_is_denied_or_not_found(store_ab):
    # TENANT_A tries to delete TENANT_B's source_id — must get not-found
    with pytest.raises(LifecycleError) as exc_info:
        delete_document(store_ab, _SOURCE_B, trusted_tenant_id=_TENANT_A)

    assert exc_info.value.error_code == LIFECYCLE_ERR_DOCUMENT_NOT_FOUND

    # TENANT_B's document must still be intact
    b_chunks = list_active_chunks(store_ab, _TENANT_B, _CHUNK_CONFIG)
    assert len(b_chunks) > 0, (
        "TENANT_B document must be unaffected by cross-tenant delete attempt"
    )


# ---------------------------------------------------------------------------
# test_rag_reindex_cross_tenant_update_does_not_modify_foreign_record
# ---------------------------------------------------------------------------


def test_rag_reindex_cross_tenant_update_does_not_modify_foreign_record(store_ab):
    # TENANT_A upserts a document with TENANT_B's source_id
    # This must create a separate record for TENANT_A, not overwrite TENANT_B's record
    upsert_document(
        store_ab,
        CorpusDocument(source_id=_SOURCE_B, content="tenant-a injected content"),
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )

    # TENANT_B's record must be unchanged
    b_records = list_active_records(store_ab, _TENANT_B)
    assert len(b_records) == 1
    assert b_records[0].tenant_id == _TENANT_B
    assert b_records[0].source_id == _SOURCE_B

    b_chunks = list_active_chunks(store_ab, _TENANT_B, _CHUNK_CONFIG)
    assert all(c.tenant_id == _TENANT_B for c in b_chunks), (
        "TENANT_B chunks must not contain TENANT_A's injected content"
    )
    assert any("audit" in c.text.lower() for c in b_chunks), (
        "TENANT_B original content must still be present"
    )


# ---------------------------------------------------------------------------
# test_rag_reindex_operation_result_is_auditable
# ---------------------------------------------------------------------------


def test_rag_reindex_operation_result_is_auditable():
    s = CorpusLifecycleStore()

    # Create
    create_result = upsert_document(
        s,
        CorpusDocument(source_id=_SOURCE_A, content=_DOC_A_V1_CONTENT),
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )
    assert isinstance(create_result, LifecycleOperationResult)
    assert create_result.tenant_id == _TENANT_A
    assert create_result.operation == "create"
    assert create_result.status == "ok"
    assert create_result.source_id == _SOURCE_A
    assert create_result.document_id
    assert create_result.new_content_hash
    assert create_result.prior_content_hash is None
    assert create_result.affected_chunk_count > 0

    # Update
    update_result = upsert_document(
        s,
        CorpusDocument(source_id=_SOURCE_A, content=_DOC_A_V2_CONTENT),
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )
    assert update_result.operation == "update"
    assert update_result.prior_content_hash == create_result.new_content_hash
    assert update_result.new_content_hash != create_result.new_content_hash

    # Delete
    delete_result = delete_document(s, _SOURCE_A, trusted_tenant_id=_TENANT_A)
    assert delete_result.operation == "delete"
    assert delete_result.tenant_id == _TENANT_A
    assert delete_result.source_id == _SOURCE_A
    assert delete_result.document_id
    assert delete_result.prior_content_hash == update_result.new_content_hash
    assert delete_result.new_content_hash is None
    assert delete_result.affected_chunk_count == 0

    # Reindex
    _, reindex_result = reindex(s, _TENANT_A, _CHUNK_CONFIG)
    assert reindex_result.operation == "reindex"
    assert reindex_result.tenant_id == _TENANT_A
    assert reindex_result.status == "ok"
    assert reindex_result.affected_chunk_count == 0


# ---------------------------------------------------------------------------
# test_rag_reindex_error_does_not_leak_raw_document_text
# ---------------------------------------------------------------------------


def test_rag_reindex_error_does_not_leak_raw_document_text(store_a):
    secret_text = _DOC_A_V1_CONTENT

    # Delete then try to delete again → not-found error
    delete_document(store_a, _SOURCE_A, trusted_tenant_id=_TENANT_A)

    with pytest.raises(LifecycleError) as exc_info:
        delete_document(store_a, _SOURCE_A, trusted_tenant_id=_TENANT_A)

    err_msg = exc_info.value.message
    assert secret_text not in err_msg, "Error must not contain raw document text"
    assert _TENANT_A not in err_msg, "Error must not contain tenant ID"
    assert _SOURCE_A not in err_msg, "Error must not contain source ID"


# ---------------------------------------------------------------------------
# test_rag_reindex_active_chunk_order_is_stable
# ---------------------------------------------------------------------------


def test_rag_reindex_active_chunk_order_is_stable():
    s = CorpusLifecycleStore()
    # Insert two documents; order of insertion should not affect output order
    upsert_document(
        s,
        CorpusDocument(source_id="src-z", content=_DOC_A_V1_CONTENT),
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )
    upsert_document(
        s,
        CorpusDocument(source_id="src-a", content=_DOC_B_CONTENT),
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )

    chunks_1, _ = reindex(s, _TENANT_A, _CHUNK_CONFIG)
    chunks_2, _ = reindex(s, _TENANT_A, _CHUNK_CONFIG)

    # Output must be identical across calls
    assert [c.chunk_id for c in chunks_1] == [c.chunk_id for c in chunks_2]

    # Output must be sorted: source_id ASC first
    if len(chunks_1) >= 2:
        source_ids = [c.source_id for c in chunks_1]
        assert source_ids == sorted(source_ids) or all(
            source_ids[i] <= source_ids[i + 1] for i in range(len(source_ids) - 1)
        ), "Chunks must be ordered by source_id ASC"

    # "src-a" chunks must come before "src-z" chunks
    src_a_indices = [i for i, c in enumerate(chunks_1) if c.source_id == "src-a"]
    src_z_indices = [i for i, c in enumerate(chunks_1) if c.source_id == "src-z"]
    if src_a_indices and src_z_indices:
        assert max(src_a_indices) < min(src_z_indices), (
            "src-a chunks must precede src-z chunks (source_id ASC sort)"
        )


# ---------------------------------------------------------------------------
# test_rag_reindex_does_not_mutate_caller_inputs
# ---------------------------------------------------------------------------


def test_rag_reindex_does_not_mutate_caller_inputs():
    s = CorpusLifecycleStore()
    original_doc = CorpusDocument(
        source_id=_SOURCE_A,
        content=_DOC_A_V1_CONTENT,
        metadata={"key": "value"},
    )

    # frozen=True means the document itself cannot be mutated; verify the store
    # does not expose a reference to internal state that the caller could mutate
    upsert_document(
        s,
        original_doc,
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )

    # list_active_records returns a copy — mutating it must not affect the store
    records_copy = list_active_records(s, _TENANT_A)
    original_len = len(records_copy)
    records_copy.clear()  # mutate the returned list

    records_again = list_active_records(s, _TENANT_A)
    assert len(records_again) == original_len, (
        "Mutating the returned records list must not affect the store"
    )

    # Original document fields are unchanged (frozen dataclass guarantees this)
    assert original_doc.source_id == _SOURCE_A
    assert original_doc.content == _DOC_A_V1_CONTENT
    assert original_doc.metadata == {"key": "value"}


# ---------------------------------------------------------------------------
# test_rag_reindex_rejects_non_string_source_id
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_source_id", [None, 123, True, b"bytes"])
def test_rag_reindex_rejects_non_string_source_id(bad_source_id):
    from api.rag.lifecycle import LIFECYCLE_ERR_INVALID_DOCUMENT

    s = CorpusLifecycleStore()
    doc = CorpusDocument(source_id=bad_source_id, content=_DOC_A_V1_CONTENT)  # type: ignore[arg-type]

    with pytest.raises(LifecycleError) as exc_info:
        upsert_document(s, doc, trusted_tenant_id=_TENANT_A, chunk_config=_CHUNK_CONFIG)

    assert exc_info.value.error_code == LIFECYCLE_ERR_INVALID_DOCUMENT


# ---------------------------------------------------------------------------
# test_rag_reindex_rejects_non_string_content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_content", [None, 123, True, b"bytes"])
def test_rag_reindex_rejects_non_string_content(bad_content):
    from api.rag.lifecycle import LIFECYCLE_ERR_INVALID_DOCUMENT

    s = CorpusLifecycleStore()
    doc = CorpusDocument(source_id=_SOURCE_A, content=bad_content)  # type: ignore[arg-type]

    with pytest.raises(LifecycleError) as exc_info:
        upsert_document(s, doc, trusted_tenant_id=_TENANT_A, chunk_config=_CHUNK_CONFIG)

    assert exc_info.value.error_code == LIFECYCLE_ERR_INVALID_DOCUMENT


# ---------------------------------------------------------------------------
# test_rag_reindex_list_active_records_returns_detached_metadata
# ---------------------------------------------------------------------------


def test_rag_reindex_list_active_records_returns_detached_metadata():
    s = CorpusLifecycleStore()
    upsert_document(
        s,
        CorpusDocument(source_id=_SOURCE_A, content=_DOC_A_V1_CONTENT),
        trusted_tenant_id=_TENANT_A,
        chunk_config=_CHUNK_CONFIG,
    )

    records = list_active_records(s, _TENANT_A)
    assert len(records) == 1

    # Mutating the returned record's safe_metadata must not affect the store
    records[0].safe_metadata["injected"] = "evil"  # type: ignore[index]

    records_again = list_active_records(s, _TENANT_A)
    assert "injected" not in records_again[0].safe_metadata, (
        "Mutating returned safe_metadata must not affect stored record"
    )
