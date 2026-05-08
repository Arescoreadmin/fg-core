"""
api/rag_retrieval.py — Tenant-scoped persisted RAG lexical retrieval.

Internal service over PR 14 persisted corpus chunks.  Lexical retrieval only:
no embeddings, no vector DB, no provider calls, no AI-plane routing changes.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from api.rag_context import (
    RagChunkProvenance,
    RagContextChunk,
    RagContextRequest,
    RagContextResponse,
)

logger = logging.getLogger("frostgate.rag_retrieval")

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def _require_tenant(tenant_id: Optional[str]) -> str:
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id is required and must not be blank")
    return str(tenant_id).strip()


def _decode_metadata(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return {}
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        logger.warning(
            "rag_retrieval: unparseable metadata value; using empty metadata"
        )
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _tokenize(value: str) -> list[str]:
    return _TOKEN_RE.findall(value.lower())


def _score_text(query_terms: list[str], chunk_text: str) -> float:
    if not query_terms:
        return 0.0
    chunk_terms = _tokenize(chunk_text)
    if not chunk_terms:
        return 0.0

    query_unique = tuple(dict.fromkeys(query_terms))
    chunk_counts = {term: chunk_terms.count(term) for term in set(chunk_terms)}
    matched_terms = [term for term in query_unique if chunk_counts.get(term, 0) > 0]
    if not matched_terms:
        return 0.0

    occurrence_count = sum(chunk_counts[term] for term in matched_terms)
    occurrence_weight = occurrence_count / (len(chunk_terms) + 1)
    return float(len(matched_terms) + occurrence_weight)


def _metadata_string(metadata: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _metadata_int(metadata: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return None


def retrieve_rag_context(
    conn: Session,
    request: RagContextRequest,
) -> RagContextResponse:
    """
    Return ranked persisted RAG chunks for the request tenant.

    Ranking is deterministic lexical scoring:
    score DESC → corpus_id ASC → document_id ASC → ordinal ASC → chunk_id ASC.
    Non-matching chunks are excluded.
    """
    tenant_id = _require_tenant(request.tenant_id)
    query_terms = _tokenize(request.query)
    if not query_terms:
        return RagContextResponse(query=request.query, chunks=[])

    corpus_ids = [corpus_id for corpus_id in request.corpus_ids if corpus_id.strip()]
    stmt = text(
        """
        SELECT
            c.chunk_id,
            c.document_id,
            c.corpus_id,
            c.text,
            c.ordinal,
            c.metadata AS chunk_metadata,
            d.title,
            d.source,
            d.metadata AS document_metadata
        FROM rag_chunks c
        JOIN rag_documents d
          ON d.document_id = c.document_id
         AND d.corpus_id = c.corpus_id
         AND d.tenant_id = c.tenant_id
        JOIN rag_corpora corp
          ON corp.corpus_id = c.corpus_id
         AND corp.tenant_id = c.tenant_id
        WHERE c.tenant_id = :tenant_id
          AND (:use_corpus_filter = 0 OR c.corpus_id IN :corpus_ids)
        """
    ).bindparams(bindparam("corpus_ids", expanding=True))

    rows = (
        conn.execute(
            stmt,
            {
                "tenant_id": tenant_id,
                "use_corpus_filter": 1 if corpus_ids else 0,
                "corpus_ids": corpus_ids or ["__unused__"],
            },
        )
        .mappings()
        .fetchall()
    )

    ranked: list[tuple[float, str, str, int, str, RagContextChunk]] = []
    for row in rows:
        row_dict = dict(row)
        score = _score_text(query_terms, str(row_dict["text"]))
        if score <= 0.0:
            continue

        chunk_metadata = _decode_metadata(row_dict.get("chunk_metadata"))
        document_metadata = _decode_metadata(row_dict.get("document_metadata"))
        uri = _metadata_string(chunk_metadata, "uri", "source_uri") or _metadata_string(
            document_metadata, "uri", "source_uri"
        )
        page = _metadata_int(chunk_metadata, "page", "source_page") or _metadata_int(
            document_metadata, "page", "source_page"
        )

        chunk = RagContextChunk(
            text=str(row_dict["text"]),
            score=score,
            provenance=RagChunkProvenance(
                corpus_id=str(row_dict["corpus_id"]),
                document_id=str(row_dict["document_id"]),
                chunk_id=str(row_dict["chunk_id"]),
                source=row_dict.get("source"),
                title=row_dict.get("title"),
                uri=uri,
                page=page,
            ),
        )
        ranked.append(
            (
                score,
                str(row_dict["corpus_id"]),
                str(row_dict["document_id"]),
                int(row_dict["ordinal"]),
                str(row_dict["chunk_id"]),
                chunk,
            )
        )

    ranked.sort(key=lambda item: (-item[0], item[1], item[2], item[3], item[4]))
    chunks = [item[5] for item in ranked[: request.top_k]]
    return RagContextResponse(query=request.query, chunks=chunks)
