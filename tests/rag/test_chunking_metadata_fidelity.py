"""
Task 16.2 — Chunking and Metadata Fidelity tests.

Selected by: pytest -k 'rag and chunk'
"""

from __future__ import annotations

import pytest

from api.rag.chunking import (
    CHUNK_ERR_EMPTY_CONTENT,
    CHUNK_ERR_INVALID_CONFIG,
    CHUNK_ERR_MISSING_SOURCE,
    CHUNK_ERR_MISSING_TENANT,
    ChunkingConfig,
    ChunkingError,
    CorpusChunk,
    chunk_ingested_records,
)
from api.rag.ingest import (
    CorpusDocument,
    IngestRequest,
    IngestStatus,
    IngestedCorpusRecord,
    ingest_corpus,
)

TENANT_A = "tenant-alpha"
TENANT_B = "tenant-beta"

# Short fixed content for deterministic fixture assertions.
_FIXTURE_CONTENT = (
    "The quick brown fox jumps over the lazy dog. "
    "Pack my box with five dozen liquor jugs. "
    "How vexingly quick daft zebras jump. "
    "The five boxing wizards jump quickly."
)

# Longer content to force multiple chunks with small max_chars.
_LONG_CONTENT = " ".join([f"word{i}" for i in range(200)])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    tenant_id: str = TENANT_A,
    source_id: str = "src-001",
    content: str = _FIXTURE_CONTENT,
    metadata: dict | None = None,
) -> IngestedCorpusRecord:
    """Build an IngestedCorpusRecord via the real ingest path."""
    doc = CorpusDocument(source_id=source_id, content=content, metadata=metadata or {})
    result = ingest_corpus(IngestRequest(documents=[doc]), trusted_tenant_id=tenant_id)
    assert result.status == IngestStatus.SUCCESS
    return result.records[0]


def _small_config() -> ChunkingConfig:
    """Config that forces multiple chunks on _LONG_CONTENT."""
    return ChunkingConfig(max_chars=60, overlap_chars=10)


# ---------------------------------------------------------------------------
# Happy path: valid ingested record produces chunks
# ---------------------------------------------------------------------------


def test_rag_chunk_valid_ingested_record_produces_chunks() -> None:
    record = _make_record()
    chunks = chunk_ingested_records([record])

    assert len(chunks) >= 1
    for chunk in chunks:
        assert isinstance(chunk, CorpusChunk)
        assert chunk.tenant_id == TENANT_A
        assert chunk.source_id == "src-001"
        assert chunk.document_id == record.document_id
        assert chunk.parent_content_hash == record.content_hash
        assert chunk.text
        assert chunk.chunk_id
        assert len(chunk.chunk_id) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# Determinism: chunk counts and IDs are stable for fixed fixture
# ---------------------------------------------------------------------------


def test_rag_chunk_counts_are_deterministic_for_fixed_fixture() -> None:
    record = _make_record(content=_LONG_CONTENT)
    config = _small_config()

    chunks_1 = chunk_ingested_records([record], config=config)
    chunks_2 = chunk_ingested_records([record], config=config)

    assert len(chunks_1) == len(chunks_2)
    assert len(chunks_1) > 1  # confirm multiple chunks produced


def test_rag_chunk_ids_are_deterministic() -> None:
    record = _make_record(content=_LONG_CONTENT)
    config = _small_config()

    chunks_1 = chunk_ingested_records([record], config=config)
    chunks_2 = chunk_ingested_records([record], config=config)

    for c1, c2 in zip(chunks_1, chunks_2):
        assert c1.chunk_id == c2.chunk_id
        assert c1.text == c2.text
        assert c1.chunk_index == c2.chunk_index


# ---------------------------------------------------------------------------
# Metadata preservation
# ---------------------------------------------------------------------------


def test_rag_chunk_preserves_tenant_source_and_parent_metadata() -> None:
    record = _make_record()
    chunks = chunk_ingested_records([record])

    for chunk in chunks:
        assert chunk.tenant_id == TENANT_A
        assert chunk.source_id == "src-001"
        assert chunk.document_id == record.document_id
        assert chunk.parent_content_hash == record.content_hash


def test_rag_chunk_preserves_safe_metadata() -> None:
    meta = {"category": "legal", "priority": 5}
    record = _make_record(metadata=meta)
    chunks = chunk_ingested_records([record])

    for chunk in chunks:
        assert chunk.safe_metadata["category"] == "legal"
        assert chunk.safe_metadata["priority"] == 5


# ---------------------------------------------------------------------------
# No trailing content dropped
# ---------------------------------------------------------------------------


def test_rag_chunk_does_not_drop_trailing_content() -> None:
    suffix = "TRAILING_SENTINEL_WORD"
    content = _LONG_CONTENT + " " + suffix
    record = _make_record(content=content)
    config = _small_config()

    chunks = chunk_ingested_records([record], config=config)
    all_text = " ".join(c.text for c in chunks)

    assert suffix in all_text


# ---------------------------------------------------------------------------
# Rejection: missing tenant_id
# ---------------------------------------------------------------------------


def test_rag_chunk_rejects_missing_tenant_id() -> None:
    record = _make_record()
    # Construct a record with blank tenant_id (bypasses ingest guards directly)
    bad_record = IngestedCorpusRecord(
        tenant_id="",
        source_id=record.source_id,
        document_id=record.document_id,
        content_hash=record.content_hash,
        content=record.content,
        status=record.status,
        safe_metadata=record.safe_metadata,
    )
    with pytest.raises(ChunkingError) as exc_info:
        chunk_ingested_records([bad_record])

    assert exc_info.value.error_code == CHUNK_ERR_MISSING_TENANT


# ---------------------------------------------------------------------------
# Rejection: missing source_id
# ---------------------------------------------------------------------------


def test_rag_chunk_rejects_missing_source_id() -> None:
    record = _make_record()
    bad_record = IngestedCorpusRecord(
        tenant_id=record.tenant_id,
        source_id="",
        document_id=record.document_id,
        content_hash=record.content_hash,
        content=record.content,
        status=record.status,
        safe_metadata=record.safe_metadata,
    )
    with pytest.raises(ChunkingError) as exc_info:
        chunk_ingested_records([bad_record])

    assert exc_info.value.error_code == CHUNK_ERR_MISSING_SOURCE


# ---------------------------------------------------------------------------
# Rejection: empty record content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_rag_chunk_rejects_empty_record_text(blank: str) -> None:
    record = _make_record()
    bad_record = IngestedCorpusRecord(
        tenant_id=record.tenant_id,
        source_id=record.source_id,
        document_id=record.document_id,
        content_hash=record.content_hash,
        content=blank,
        status=record.status,
        safe_metadata=record.safe_metadata,
    )
    with pytest.raises(ChunkingError) as exc_info:
        chunk_ingested_records([bad_record])

    assert exc_info.value.error_code == CHUNK_ERR_EMPTY_CONTENT


# ---------------------------------------------------------------------------
# Rejection: invalid config
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "max_chars,overlap_chars",
    [
        (0, 0),  # max_chars below minimum
        (-1, 0),  # max_chars negative
        (50, 50),  # overlap == max_chars (must be strictly less)
        (50, 60),  # overlap > max_chars
        (50, -1),  # overlap negative
        (32_769, 0),  # max_chars above maximum
    ],
)
def test_rag_chunk_rejects_invalid_config(max_chars: int, overlap_chars: int) -> None:
    record = _make_record()
    with pytest.raises(ChunkingError) as exc_info:
        chunk_ingested_records(
            [record],
            config=ChunkingConfig(max_chars=max_chars, overlap_chars=overlap_chars),
        )

    assert exc_info.value.error_code == CHUNK_ERR_INVALID_CONFIG


# ---------------------------------------------------------------------------
# Error does not leak raw document text
# ---------------------------------------------------------------------------


def test_rag_chunk_error_does_not_leak_raw_document_text() -> None:
    secret_content = "SUPER_SECRET_CHUNK_CONTENT_XYZ"
    record = _make_record()
    bad_record = IngestedCorpusRecord(
        tenant_id="",  # triggers CHUNK_ERR_MISSING_TENANT
        source_id=record.source_id,
        document_id=record.document_id,
        content_hash=record.content_hash,
        content=secret_content,
        status=record.status,
        safe_metadata=record.safe_metadata,
    )
    with pytest.raises(ChunkingError) as exc_info:
        chunk_ingested_records([bad_record])

    assert secret_content not in str(exc_info.value)
    assert secret_content not in exc_info.value.message

    # Also test empty-content error path
    bad_record2 = IngestedCorpusRecord(
        tenant_id=record.tenant_id,
        source_id=record.source_id,
        document_id=record.document_id,
        content_hash=record.content_hash,
        content="",
        status=record.status,
        safe_metadata=record.safe_metadata,
    )
    with pytest.raises(ChunkingError) as exc_info2:
        chunk_ingested_records([bad_record2])

    assert secret_content not in str(exc_info2.value)
    assert secret_content not in exc_info2.value.message


# ---------------------------------------------------------------------------
# Output order is stable
# ---------------------------------------------------------------------------


def test_rag_chunk_output_order_is_stable() -> None:
    record = _make_record(content=_LONG_CONTENT)
    config = _small_config()

    chunks = chunk_ingested_records([record], config=config)

    # chunk_index must be monotonically increasing from 0
    for expected_idx, chunk in enumerate(chunks):
        assert chunk.chunk_index == expected_idx

    # Two runs produce identical order
    chunks_2 = chunk_ingested_records([record], config=config)
    assert [c.chunk_id for c in chunks] == [c.chunk_id for c in chunks_2]


# ---------------------------------------------------------------------------
# Hardening: overlap seed uses whole words — no word fragments at chunk start
# ---------------------------------------------------------------------------


def test_rag_chunk_overlap_does_not_produce_word_fragments() -> None:
    # Construct content where a character-slice overlap would cut mid-word.
    # With max_chars=10, overlap_chars=4:
    # "hello world" → flush "hello world" (11 chars) when "foo" arrives
    # char-slice: "hello world"[-4:] = "orld" (fragment of "world")
    # whole-word overlap: should re-seed with ["world"] (4 chars, within limit)
    content = "hello world foo bar baz"
    config = ChunkingConfig(max_chars=12, overlap_chars=5)
    record = _make_record(content=content)
    chunks = chunk_ingested_records([record], config=config)

    for chunk in chunks:
        words = chunk.text.split()
        assert len(words) >= 1
        # Every word in every chunk must appear in the original content
        for word in words:
            assert word in content.split(), f"Fragment '{word}' not in original words"


# ---------------------------------------------------------------------------
# Hardening: single word longer than max_chars — no silent drop, no panic
# ---------------------------------------------------------------------------


def test_rag_chunk_single_oversized_word_produces_one_chunk() -> None:
    long_word = "x" * 200
    config = ChunkingConfig(max_chars=50, overlap_chars=0)
    record = _make_record(content=long_word)
    chunks = chunk_ingested_records([record], config=config)

    # Must produce exactly one chunk containing the full word — no silent drop
    assert len(chunks) == 1
    assert long_word in chunks[0].text


# ---------------------------------------------------------------------------
# Hardening: unicode / multi-byte characters
# ---------------------------------------------------------------------------


def test_rag_chunk_unicode_content_is_deterministic() -> None:
    unicode_content = (
        "日本語テスト データ処理 セキュリティ テナント分離 "
        "naïve café résumé façade "
        "emoji 🔐🏢📄 end"
    )
    record = _make_record(content=unicode_content)
    chunks_1 = chunk_ingested_records([record])
    chunks_2 = chunk_ingested_records([record])

    assert len(chunks_1) == len(chunks_2)
    for c1, c2 in zip(chunks_1, chunks_2):
        assert c1.chunk_id == c2.chunk_id
        assert c1.text == c2.text

    # All original words must be present across the chunks
    all_text = " ".join(c.text for c in chunks_1)
    for word in unicode_content.split():
        assert word in all_text


# ---------------------------------------------------------------------------
# Hardening: whitespace collapsing is deterministic and lossless
# ---------------------------------------------------------------------------


def test_rag_chunk_whitespace_is_normalized_deterministically() -> None:
    # Repeated spaces, tabs, and newlines all collapse to single spaces.
    content_varied = "hello   world\t\tfoo\n\nbar"
    content_normal = "hello world foo bar"
    record_varied = _make_record(content=content_varied)
    record_normal = _make_record(source_id="src-normal", content=content_normal)

    chunks_varied = chunk_ingested_records([record_varied])
    chunks_normal = chunk_ingested_records([record_normal])

    # Chunk text should be identical (same words, same canonical spacing)
    texts_varied = [c.text for c in chunks_varied]
    texts_normal = [c.text for c in chunks_normal]
    assert texts_varied == texts_normal

    # No data loss: all words present
    all_text = " ".join(texts_varied)
    for word in ["hello", "world", "foo", "bar"]:
        assert word in all_text


# ---------------------------------------------------------------------------
# Hardening: zero overlap — clean boundaries, no re-seeding
# ---------------------------------------------------------------------------


def test_rag_chunk_zero_overlap_produces_clean_boundaries() -> None:
    content = " ".join([f"word{i}" for i in range(30)])
    config = ChunkingConfig(max_chars=50, overlap_chars=0)
    record = _make_record(content=content)
    chunks = chunk_ingested_records([record], config=config)

    assert len(chunks) > 1

    # With zero overlap, each word should appear in exactly one chunk
    all_texts = [c.text for c in chunks]
    all_words_flat: list[str] = []
    for text in all_texts:
        all_words_flat.extend(text.split())

    # Each word appears exactly once (no duplication from overlap)
    word_counts = {w: all_words_flat.count(w) for w in set(all_words_flat)}
    for word, count in word_counts.items():
        assert count == 1, f"Word '{word}' appeared {count} times with zero overlap"


# ---------------------------------------------------------------------------
# Hardening: safe_metadata is independent per chunk — mutation isolation
# ---------------------------------------------------------------------------


def test_rag_chunk_safe_metadata_is_independent_per_chunk() -> None:
    meta = {"category": "legal", "score": 1}
    record = _make_record(content=_LONG_CONTENT, metadata=meta)
    config = _small_config()
    chunks = chunk_ingested_records([record], config=config)

    assert len(chunks) > 1

    # Mutating one chunk's safe_metadata must not affect other chunks
    chunks[0].safe_metadata["injected"] = "mutation"
    for chunk in chunks[1:]:
        assert "injected" not in chunk.safe_metadata, (
            "safe_metadata is shared across chunks — mutation leaked"
        )
