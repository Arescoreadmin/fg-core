"""
RAG Chunking and Metadata Fidelity — Task 16.2

Deterministic, tenant-bound text chunking of ingested corpus records.
No embeddings, no vector DB, no retrieval, no LLM calls.
Scope: text splitting only; retrieval and reranking are later 16.x tasks.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from api.rag.ingest import IngestedCorpusRecord

log = logging.getLogger("frostgate.rag.chunking")

# ---------------------------------------------------------------------------
# Error codes (stable, never change meaning once published)
# ---------------------------------------------------------------------------

CHUNK_ERR_MISSING_TENANT = "RAG_CHUNK_E001"
CHUNK_ERR_MISSING_SOURCE = "RAG_CHUNK_E002"
CHUNK_ERR_EMPTY_CONTENT = "RAG_CHUNK_E003"
CHUNK_ERR_INVALID_CONFIG = "RAG_CHUNK_E004"
CHUNK_ERR_MALFORMED_RECORD = "RAG_CHUNK_E005"
CHUNK_ERR_EMPTY_OUTPUT = "RAG_CHUNK_E006"
CHUNK_ERR_TOKEN_TOO_LONG = "RAG_CHUNK_E007"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULT_MAX_CHARS = 1000
_DEFAULT_OVERLAP_CHARS = 100
_MIN_CHUNK_SIZE = 1
_MAX_CHUNK_SIZE = 32_768

_CANONICAL_ENCODING = "utf-8"


@dataclass(frozen=True)
class ChunkingConfig:
    """Immutable chunking parameters.

    max_chars: maximum character count per chunk (default 1000).
    overlap_chars: character overlap between consecutive chunks (default 100).
                   Must be < max_chars. Set to 0 to disable overlap.
    """

    max_chars: int = _DEFAULT_MAX_CHARS
    overlap_chars: int = _DEFAULT_OVERLAP_CHARS


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorpusChunk:
    """A single chunk produced from an IngestedCorpusRecord.

    All tenant and source identity fields are propagated from the parent record.
    """

    tenant_id: str
    source_id: str
    document_id: str  # parent record's document_id
    parent_content_hash: str  # parent record's content_hash
    chunk_index: int  # zero-based, deterministic
    chunk_id: (
        str  # deterministic SHA-256 of (tenant_id+document_id+chunk_index+text_hash)
    )
    text: str
    safe_metadata: dict[str, Any]  # forwarded from parent record


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ChunkingError(Exception):
    """Raised for unrecoverable chunking failures.

    error_code is always a stable RAG_CHUNK_Exxx constant.
    message MUST NOT contain raw document body text.
    """

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode(_CANONICAL_ENCODING)).hexdigest()


def _deterministic_chunk_id(
    tenant_id: str, document_id: str, chunk_index: int, text_hash: str
) -> str:
    canonical = json.dumps(
        {
            "tenant_id": tenant_id,
            "document_id": document_id,
            "chunk_index": chunk_index,
            "text_hash": text_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_hex(canonical)


def _normalize_line_endings(text: str) -> str:
    """Normalize CRLF and CR to LF for deterministic splitting."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _split_text(text: str, max_chars: int, overlap_chars: int) -> list[str]:
    """Split text into deterministic chunks of at most max_chars characters.

    Uses word-boundary splitting: accumulates whole words until the next word
    would exceed max_chars, then starts a new chunk, optionally overlapping
    by re-including the last overlap_chars of the previous chunk as a prefix.

    Guarantees:
    - No text is silently discarded.
    - Trailing content always appears in the last chunk.
    - Every emitted chunk satisfies len(chunk) <= max_chars.
    - Output is deterministic for identical (text, max_chars, overlap_chars).
    - Same word order is preserved.
    - No chunk starts with a partial/truncated token.

    Raises:
        ChunkingError(CHUNK_ERR_TOKEN_TOO_LONG): if any single token exceeds
            max_chars.  Callers must pre-process documents with oversized tokens
            before chunking.
    """
    words = text.split()
    if not words:
        return []

    # Pre-pass: reject any token that cannot fit in a single chunk.
    # Checked before emitting anything so the caller gets a clean failure.
    # Token text is NOT included in the message (raw document text must not leak).
    for w in words:
        if len(w) > max_chars:
            raise ChunkingError(
                CHUNK_ERR_TOKEN_TOO_LONG,
                f"A token of length {len(w)} exceeds max_chars={max_chars}; "
                "split or pre-process the document to remove oversized tokens",
            )

    chunks: list[str] = []
    current_words: list[str] = []
    current_len = 0

    for word in words:
        # +1 for the space separator (except at start of chunk)
        needed = len(word) if not current_words else len(word) + 1
        if current_words and current_len + needed > max_chars:
            # Flush current chunk
            chunks.append(" ".join(current_words))
            # Compute overlap prefix from whole words at the end of the flushed
            # chunk.  Walk backwards through current_words and accumulate words
            # until adding the next word would exceed overlap_chars.  This
            # guarantees the seed for the next chunk never contains a word
            # fragment (a character-slice would risk splitting mid-word).
            if overlap_chars > 0:
                overlap_words_rev: list[str] = []
                overlap_len = 0
                for w in reversed(current_words):
                    # +1 for the space separator between words
                    needed_for_word = len(w) + (1 if overlap_words_rev else 0)
                    if overlap_len + needed_for_word <= overlap_chars:
                        overlap_words_rev.append(w)
                        overlap_len += needed_for_word
                    else:
                        break
                current_words = list(reversed(overlap_words_rev))
                current_len = overlap_len
            else:
                current_words = []
                current_len = 0

            # Safety: if the overlap seed is so large that appending the
            # current word would still exceed max_chars, discard the overlap
            # and start fresh.  This can happen when overlap_chars is close to
            # max_chars and the next token is long.  Without this guard the
            # emitted chunk could exceed max_chars.
            new_needed = len(word) if not current_words else len(word) + 1
            if current_words and current_len + new_needed > max_chars:
                current_words = []
                current_len = 0

        current_words.append(word)
        current_len += len(word) if len(current_words) == 1 else len(word) + 1

    # Always flush remaining content (no trailing drop)
    if current_words:
        chunks.append(" ".join(current_words))

    return chunks


def _validate_config(config: ChunkingConfig) -> None:
    if config.max_chars < _MIN_CHUNK_SIZE or config.max_chars > _MAX_CHUNK_SIZE:
        raise ChunkingError(
            CHUNK_ERR_INVALID_CONFIG,
            f"max_chars must be between {_MIN_CHUNK_SIZE} and {_MAX_CHUNK_SIZE}",
        )
    if config.overlap_chars < 0:
        raise ChunkingError(
            CHUNK_ERR_INVALID_CONFIG,
            "overlap_chars must be >= 0",
        )
    if config.overlap_chars >= config.max_chars:
        raise ChunkingError(
            CHUNK_ERR_INVALID_CONFIG,
            "overlap_chars must be strictly less than max_chars",
        )


def _validate_record(record: IngestedCorpusRecord) -> None:
    if not record.tenant_id or not record.tenant_id.strip():
        raise ChunkingError(
            CHUNK_ERR_MISSING_TENANT,
            "IngestedCorpusRecord is missing a non-blank tenant_id",
        )
    if not record.source_id or not record.source_id.strip():
        raise ChunkingError(
            CHUNK_ERR_MISSING_SOURCE,
            f"Record with document_id '{record.document_id}' is missing source_id",
        )
    if not record.content or not record.content.strip():
        raise ChunkingError(
            CHUNK_ERR_EMPTY_CONTENT,
            f"Record '{record.source_id}' has blank or missing content",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG = ChunkingConfig()


def chunk_ingested_records(
    records: list[IngestedCorpusRecord],
    config: ChunkingConfig | None = None,
) -> list[CorpusChunk]:
    """Chunk a list of ingested corpus records into deterministic text chunks.

    Args:
        records: List of IngestedCorpusRecord from a prior ingest_corpus() call.
        config: ChunkingConfig controlling chunk size and overlap. Defaults to
                ChunkingConfig() (max_chars=1000, overlap_chars=100).

    Returns:
        List of CorpusChunk in stable (record_order, chunk_index) order.

    Raises:
        ChunkingError: On any validation failure or empty output.

    Security invariants:
        - tenant_id propagated from trusted ingested record only.
        - Raw document text never appears in error messages.
        - Missing/blank tenant_id on any record → CHUNK_ERR_MISSING_TENANT.
        - Empty content on any record → CHUNK_ERR_EMPTY_CONTENT.
        - Invalid config → CHUNK_ERR_INVALID_CONFIG.
        - Empty output for non-empty valid input → CHUNK_ERR_EMPTY_OUTPUT.
    """
    effective_config = config if config is not None else _DEFAULT_CONFIG
    _validate_config(effective_config)

    all_chunks: list[CorpusChunk] = []

    for record in records:
        _validate_record(record)

        normalized = _normalize_line_endings(record.content)
        raw_chunks = _split_text(
            normalized, effective_config.max_chars, effective_config.overlap_chars
        )

        if not raw_chunks:
            # Content was non-blank but produced no chunks — defensive guard.
            log.error(
                "rag.chunk: empty split output for non-empty record",
                extra={
                    "tenant_id": record.tenant_id,
                    "source_id": record.source_id,
                    "document_id": record.document_id,
                    "error_code": CHUNK_ERR_EMPTY_OUTPUT,
                },
            )
            raise ChunkingError(
                CHUNK_ERR_EMPTY_OUTPUT,
                f"Chunking produced no chunks for record '{record.source_id}'",
            )

        for idx, chunk_text in enumerate(raw_chunks):
            text_hash = _sha256_hex(chunk_text)
            chunk_id = _deterministic_chunk_id(
                record.tenant_id, record.document_id, idx, text_hash
            )
            all_chunks.append(
                CorpusChunk(
                    tenant_id=record.tenant_id,
                    source_id=record.source_id,
                    document_id=record.document_id,
                    parent_content_hash=record.content_hash,
                    chunk_index=idx,
                    chunk_id=chunk_id,
                    text=chunk_text,
                    # Shallow copy: prevents caller mutation of one chunk's
                    # safe_metadata from silently affecting sibling chunks or
                    # the parent record (all share the same underlying dict
                    # object without this copy).
                    safe_metadata=dict(record.safe_metadata),
                )
            )
            log.debug(
                "rag.chunk: chunk produced",
                extra={
                    "tenant_id": record.tenant_id,
                    "source_id": record.source_id,
                    "document_id": record.document_id,
                    "chunk_index": idx,
                    "chunk_id": chunk_id,
                },
            )

    return all_chunks
