"""
api/rag_retrieval.py — Tenant-scoped persisted RAG lexical retrieval.

Internal service over PR 14 persisted corpus chunks.  Lexical retrieval only:
no embeddings, no vector DB, no provider calls, no AI-plane routing changes.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Optional

from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from api.rag_context import (
    RagChunkProvenance,
    RagContextChunk,
    RagContextRequest,
    RagContextResponse,
    RagRetrievalTrace,
)
from api.rag_observability import (
    confidence_from_scores,
    matched_terms,
    new_retrieval_trace_id,
    why_this_chunk,
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


def _normalise_corpus_ids(corpus_ids: list[str] | None) -> tuple[list[str], bool]:
    """Return trimmed corpus IDs and whether an explicit invalid filter was provided."""
    if corpus_ids is None:
        return [], False
    trimmed = [str(corpus_id).strip() for corpus_id in corpus_ids]
    valid = [corpus_id for corpus_id in trimmed if corpus_id]
    return valid, bool(trimmed) and not valid


def _escape_like_term(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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


def _table_columns(conn: Session, table: str) -> set[str]:
    bind = conn.get_bind()
    dialect = bind.dialect.name if bind is not None else ""
    if dialect == "sqlite":
        rows = list(conn.execute(text(f"PRAGMA table_info({table})")))
        return {str(row[1]) for row in rows}
    rows = list(
        conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = :table"
            ),
            {"table": table},
        )
    )
    return {str(row[0]) for row in rows}


def _lifecycle_filter(conn: Session) -> str:
    doc_cols = _table_columns(conn, "rag_documents")
    chunk_cols = _table_columns(conn, "rag_chunks")
    clauses: list[str] = []
    if "is_active" in chunk_cols:
        clauses.append("COALESCE(c.is_active, TRUE) = TRUE")
    if "ingestion_status" in doc_cols:
        clauses.append("COALESCE(d.ingestion_status, 'indexed') = 'indexed'")
    if "is_current" in doc_cols:
        clauses.append("COALESCE(d.is_current, TRUE) = TRUE")
    return "\n          AND ".join(clauses)


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
    start = time.monotonic()
    retrieval_trace_id = new_retrieval_trace_id()
    tenant_id = _require_tenant(request.tenant_id)
    query_terms = _tokenize(request.query)
    if not query_terms:
        return _response_with_trace(
            query=request.query,
            chunks=[],
            retrieval_trace_id=retrieval_trace_id,
            candidate_count=0,
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    corpus_ids, invalid_explicit_filter = _normalise_corpus_ids(request.corpus_ids)
    if invalid_explicit_filter:
        return _response_with_trace(
            query=request.query,
            chunks=[],
            retrieval_trace_id=retrieval_trace_id,
            candidate_count=0,
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    unique_query_terms = list(dict.fromkeys(query_terms))
    lifecycle_filter = _lifecycle_filter(conn)
    lifecycle_sql = f"AND {lifecycle_filter}" if lifecycle_filter else ""
    like_clauses = []
    params: dict[str, Any] = {
        "tenant_id": tenant_id,
        "use_corpus_filter": 1 if corpus_ids else 0,
        "corpus_ids": corpus_ids or ["__unused__"],
    }
    for index, term in enumerate(unique_query_terms):
        param_name = f"term_{index}"
        like_clauses.append(f"LOWER(c.text) LIKE :{param_name} ESCAPE '\\'")
        params[param_name] = f"%{_escape_like_term(term)}%"

    lexical_prefilter = " OR ".join(like_clauses)
    stmt = text(
        f"""
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
          {lifecycle_sql}
          AND ({lexical_prefilter})
        ORDER BY c.corpus_id ASC, c.document_id ASC, c.ordinal ASC, c.chunk_id ASC
        """
    ).bindparams(bindparam("corpus_ids", expanding=True))

    ranked: list[tuple[float, str, str, int, str, RagContextChunk]] = []
    candidate_count = 0
    for row in conn.execute(stmt, params).mappings():
        row_dict = dict(row)
        score = _score_text(query_terms, str(row_dict["text"]))
        if score <= 0.0:
            continue
        candidate_count += 1

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
                ordinal=int(row_dict["ordinal"]),
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
        if len(ranked) > request.top_k:
            ranked.pop()

    chunks = [item[5] for item in ranked]
    duration_ms = int((time.monotonic() - start) * 1000)
    response = _response_with_trace(
        query=request.query,
        chunks=chunks,
        retrieval_trace_id=retrieval_trace_id,
        candidate_count=candidate_count,
        duration_ms=duration_ms,
    )
    logger.info(
        "rag_retrieval.retrieved",
        extra={
            "event": "rag_retrieval.retrieved",
            "tenant_id": tenant_id,
            "retrieval_trace_id": retrieval_trace_id,
            "retrieval_strategy": "lexical",
            "candidate_count": candidate_count,
            "returned_count": len(chunks),
            "duration_ms": duration_ms,
            "confidence": response.retrieval_trace.confidence
            if response.retrieval_trace is not None
            else 0.0,
            "confidence_reason": response.retrieval_trace.confidence_reason
            if response.retrieval_trace is not None
            else "no_positive_scores",
        },
    )
    return response


def _response_with_trace(
    *,
    query: str,
    chunks: list[RagContextChunk],
    retrieval_trace_id: str,
    candidate_count: int,
    duration_ms: int,
) -> RagContextResponse:
    confidence, confidence_reason = confidence_from_scores(
        [chunk.score for chunk in chunks]
    )
    returned_count = len(chunks)
    for rank, chunk in enumerate(chunks, start=1):
        chunk.retrieval_trace_id = retrieval_trace_id
        chunk.retrieval_strategy = "lexical"
        chunk.candidate_count = candidate_count
        chunk.returned_count = returned_count
        chunk.lexical_rank = rank
        chunk.semantic_rank = None
        chunk.rrf_rank = None
        chunk.lexical_score = chunk.score
        chunk.combined_score = chunk.score
        chunk.confidence = confidence
        chunk.confidence_reason = confidence_reason
        chunk.why_this_chunk = why_this_chunk(
            matched_query_terms=matched_terms(
                query_terms_from_query(query), chunk.text
            ),
            lexical_score=chunk.lexical_score,
            semantic_score=chunk.semantic_score,
            combined_score=chunk.combined_score,
            rank_reason="lexical_score_desc_then_stable_ids",
            corpus_id=chunk.provenance.corpus_id,
            document_id=chunk.provenance.document_id,
            chunk_id=chunk.provenance.chunk_id,
        )
    return RagContextResponse(
        query=query,
        chunks=chunks,
        retrieval_trace=RagRetrievalTrace(
            retrieval_trace_id=retrieval_trace_id,
            retrieval_strategy="lexical",
            candidate_count=candidate_count,
            returned_count=returned_count,
            duration_ms=duration_ms,
            confidence=confidence,
            confidence_reason=confidence_reason,
        ),
    )


def query_terms_from_query(query: str) -> list[str]:
    return _tokenize(query)
