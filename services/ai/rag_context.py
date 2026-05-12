from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.rag.chunking import CorpusChunk
from api.rag.retrieval import RetrievalError, RetrievalQuery, search_chunks
from api.rag_context import RagContextRequest, RagContextResponse, RetrievalStrategy
from api.rag_hybrid_retrieval import retrieve_rag_context_hybrid_rrf
from api.rag_retrieval import retrieve_rag_context as retrieve_persisted_context
from api.rag_reranking import RerankConfig, Reranker, rerank_response
from api.rag_semantic_retrieval import retrieve_rag_context_hybrid
from services.ai.policy import AiRagRules
from services.ai.retrieval_policy import (
    RETRIEVAL_POLICY_NO_CONTEXT_DENIED,
    RetrievalPolicyDecision,
    evaluate_retrieval_policy,
    no_context_allowed,
)

if TYPE_CHECKING:
    from api.embeddings.providers import EmbeddingProvider

RAG_RETRIEVAL_EMPTY = "RAG_RETRIEVAL_EMPTY"
RAG_RETRIEVAL_SELECTED = "RAG_RETRIEVAL_SELECTED"
RAG_RETRIEVAL_FAILED = "RAG_RETRIEVAL_FAILED"

DEFAULT_RAG_CONTEXT_LIMIT = 4
MAX_RAG_CONTEXT_LIMIT = 8
MAX_RAG_CONTEXT_CHARS = 4000
MAX_RAG_CHUNK_CHARS = 1200
MIN_RAG_RELEVANCE_SCORE = 0.0

_SENSITIVITY_ORDER = {
    "none": 0,
    "low": 1,
    "moderate": 2,
    "high": 3,
}


@dataclass(frozen=True)
class RagContextChunk:
    source_id: str
    chunk_id: str
    chunk_index: int
    text: str
    phi_sensitivity_level: str | None
    phi_types: tuple[str, ...]
    why_this_chunk: dict[str, Any] | None = None


@dataclass(frozen=True)
class RagContextResult:
    chunks: tuple[RagContextChunk, ...]
    context_text: str
    chunk_count: int
    source_ids: tuple[str, ...]
    retrieval_reason_code: str
    query_phi_sensitivity: str | None
    max_sensitivity_level: str | None
    contains_phi: bool
    source_chunk_ids: tuple[str, ...] = ()
    retrieved_source_chunk_ids: tuple[str, ...] = ()
    retrieval_trace_id: str | None = None
    retrieval_strategy: str | None = None
    candidate_count: int | None = None
    returned_count: int | None = None
    confidence: float | None = None
    confidence_reason: str | None = None
    retrieval_policy_reason_code: str | None = None
    retrieval_policy_metadata: dict[str, object] | None = None

    @property
    def rag_used(self) -> bool:
        return self.chunk_count > 0


class RagContextError(Exception):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


def retrieve_rag_context(
    *,
    tenant_id: str,
    query_text: str,
    chunks: Iterable[CorpusChunk],
    limit: int = DEFAULT_RAG_CONTEXT_LIMIT,
    phi_detected: bool,
    allowed_sensitivity_levels: set[str] | frozenset[str] | None = None,
    query_phi_sensitivity: str | None = None,
) -> RagContextResult:
    tenant = _require_tenant(tenant_id)
    bounded_limit = _bound_limit(limit)
    corpus = list(chunks)

    try:
        results = search_chunks(
            corpus,
            RetrievalQuery(query_text=query_text, limit=bounded_limit),
            trusted_tenant_id=tenant,
        )
    except RetrievalError as exc:
        raise RagContextError(exc.error_code, exc.message) from exc

    allowed_levels = (
        frozenset(str(item).strip().lower() for item in allowed_sensitivity_levels)
        if allowed_sensitivity_levels is not None
        else None
    )
    selected: list[RagContextChunk] = []
    for result in results:
        if result.tenant_id != tenant:
            raise RagContextError(
                RAG_RETRIEVAL_FAILED,
                "retrieval returned a chunk outside the trusted tenant boundary",
            )
        if result.score <= MIN_RAG_RELEVANCE_SCORE:
            continue
        sensitivity = _metadata_sensitivity(result.safe_metadata)
        if allowed_levels is not None and (sensitivity or "none") not in allowed_levels:
            continue
        selected.append(
            RagContextChunk(
                source_id=result.source_id,
                chunk_id=result.chunk_id,
                chunk_index=result.chunk_index,
                text=_bound_chunk_text(result.text),
                phi_sensitivity_level=sensitivity,
                phi_types=_metadata_phi_types(result.safe_metadata),
            )
        )

    context_text = _build_context_text(selected)
    source_ids = tuple(dict.fromkeys(chunk.source_id for chunk in selected))
    retrieved_source_chunk_ids = tuple(chunk.chunk_id for chunk in selected)
    source_chunk_ids = _included_chunk_ids(context_text, selected)
    max_sensitivity = _max_sensitivity(
        chunk.phi_sensitivity_level for chunk in selected
    )
    contains_phi = bool(phi_detected) or any(
        (chunk.phi_sensitivity_level or "none") != "none" or chunk.phi_types
        for chunk in selected
    )
    return RagContextResult(
        chunks=tuple(selected),
        context_text=context_text,
        chunk_count=len(selected),
        source_ids=source_ids,
        source_chunk_ids=source_chunk_ids,
        retrieved_source_chunk_ids=retrieved_source_chunk_ids,
        retrieval_reason_code=RAG_RETRIEVAL_SELECTED
        if selected
        else RAG_RETRIEVAL_EMPTY,
        query_phi_sensitivity=query_phi_sensitivity,
        max_sensitivity_level=max_sensitivity,
        contains_phi=contains_phi,
        retrieval_strategy="legacy_in_memory",
        candidate_count=len(corpus),
        returned_count=len(selected),
    )


def retrieve_persisted_rag_context(
    *,
    db: Session,
    tenant_id: str,
    query_text: str,
    limit: int = DEFAULT_RAG_CONTEXT_LIMIT,
    phi_detected: bool,
    query_phi_sensitivity: str | None = None,
    corpus_ids: list[str] | None = None,
    requested_strategy: str = "lexical",
    rag_rules: AiRagRules | None = None,
    embedding_provider: "EmbeddingProvider | None" = None,
    embedding_model: str | None = None,
    reranker: Reranker | None = None,
    rerank_config: RerankConfig | None = None,
) -> RagContextResult:
    tenant = _require_tenant(tenant_id)
    bounded_limit = _bound_limit(limit)
    decision: RetrievalPolicyDecision | None = None
    effective_corpus_ids = list(corpus_ids or [])
    effective_limit = bounded_limit
    if rag_rules is not None:
        try:
            decision = evaluate_retrieval_policy(
                db,
                tenant_id=tenant,
                corpus_ids=corpus_ids,
                top_k=bounded_limit,
                requested_strategy=requested_strategy,
                rag_rules=rag_rules,
            )
        except ValueError as exc:
            raise RagContextError(
                RAG_RETRIEVAL_FAILED, "retrieval policy evaluation failed"
            ) from exc
        if not decision.allowed:
            raise RagContextError(decision.reason_code, "retrieval policy denied")
        effective_limit = decision.effective_top_k
        effective_corpus_ids = list(decision.effective_corpus_ids)
        policy_scoped = bool(
            decision.requested_corpus_ids
            or decision.allowed_corpus_ids
            or decision.denied_corpus_ids
        )
        if policy_scoped and not effective_corpus_ids:
            result = _empty_persisted_result(
                query_phi_sensitivity=query_phi_sensitivity,
                phi_detected=phi_detected,
                decision=decision,
            )
            if not no_context_allowed(decision):
                raise RagContextError(
                    RETRIEVAL_POLICY_NO_CONTEXT_DENIED,
                    "retrieval policy requires grounded context",
                )
            return result
    try:
        effective_strategy = (
            decision.effective_strategy if decision is not None else "lexical"
        )
        response = _retrieve_persisted_context_by_strategy(
            db,
            request=RagContextRequest(
                query=query_text,
                tenant_id=tenant,
                corpus_ids=effective_corpus_ids,
                top_k=effective_limit,
            ),
            strategy=effective_strategy,
            provider=embedding_provider,
            embedding_model=embedding_model,
        )
        response = rerank_response(
            response,
            query=query_text,
            reranker=reranker,
            config=rerank_config,
        )
    except (SQLAlchemyError, ValidationError, ValueError) as exc:
        raise RagContextError(
            RAG_RETRIEVAL_FAILED, "persisted retrieval failed"
        ) from exc

    selected = [
        RagContextChunk(
            source_id=chunk.provenance.chunk_id,
            chunk_id=chunk.provenance.chunk_id,
            chunk_index=index,
            text=_bound_chunk_text(chunk.text),
            phi_sensitivity_level=None,
            phi_types=(),
            why_this_chunk=chunk.why_this_chunk,
        )
        for index, chunk in enumerate(response.chunks)
    ]
    context_text = _build_context_text(selected)
    retrieved_source_chunk_ids = tuple(chunk.chunk_id for chunk in selected)
    source_chunk_ids = _included_chunk_ids(context_text, selected)
    trace = response.retrieval_trace
    executed_strategy = _executed_retrieval_strategy(response, decision)
    result = RagContextResult(
        chunks=tuple(selected),
        context_text=context_text,
        chunk_count=len(selected),
        source_ids=source_chunk_ids,
        source_chunk_ids=source_chunk_ids,
        retrieved_source_chunk_ids=retrieved_source_chunk_ids,
        retrieval_reason_code=RAG_RETRIEVAL_SELECTED
        if selected
        else RAG_RETRIEVAL_EMPTY,
        query_phi_sensitivity=query_phi_sensitivity,
        max_sensitivity_level=None,
        contains_phi=bool(phi_detected),
        retrieval_trace_id=trace.retrieval_trace_id if trace is not None else None,
        retrieval_strategy=executed_strategy,
        candidate_count=trace.candidate_count if trace is not None else None,
        returned_count=trace.returned_count if trace is not None else None,
        confidence=trace.confidence if trace is not None else None,
        confidence_reason=trace.confidence_reason if trace is not None else None,
        retrieval_policy_reason_code=decision.reason_code
        if decision is not None
        else None,
        retrieval_policy_metadata=decision.audit_metadata()
        if decision is not None
        else None,
    )
    if (
        decision is not None
        and not result.rag_used
        and not no_context_allowed(decision)
    ):
        raise RagContextError(
            RETRIEVAL_POLICY_NO_CONTEXT_DENIED,
            "retrieval policy requires grounded context",
        )
    return result


def _retrieve_persisted_context_by_strategy(
    db: Session,
    *,
    request: RagContextRequest,
    strategy: str | None,
    provider: "EmbeddingProvider | None",
    embedding_model: str | None,
) -> RagContextResponse:
    if strategy == "lexical" or strategy is None:
        return retrieve_persisted_context(db, request)
    if strategy == "semantic":
        _require_embedding_provider(provider, strategy)
        response = retrieve_rag_context_hybrid(
            db,
            request,
            provider=provider,
            embedding_model=embedding_model,
            lexical_weight=0.0,
            semantic_weight=1.0,
        )
        return _force_retrieval_strategy(response, "semantic")
    if strategy == "hybrid":
        _require_embedding_provider(provider, strategy)
        return retrieve_rag_context_hybrid(
            db,
            request,
            provider=provider,
            embedding_model=embedding_model,
        )
    if strategy == "hybrid_rrf":
        _require_embedding_provider(provider, strategy)
        return retrieve_rag_context_hybrid_rrf(
            db,
            request,
            provider=provider,
            embedding_model=embedding_model,
        )
    raise ValueError(f"unsupported retrieval strategy: {strategy}")


def _require_embedding_provider(
    provider: "EmbeddingProvider | None", strategy: str
) -> None:
    if provider is None:
        raise ValueError(f"embedding provider is required for {strategy} retrieval")


def _force_retrieval_strategy(
    response: RagContextResponse, strategy: RetrievalStrategy
) -> RagContextResponse:
    if response.retrieval_trace is not None:
        response.retrieval_trace.retrieval_strategy = strategy
    for chunk in response.chunks:
        chunk.retrieval_strategy = strategy
    return response


def _executed_retrieval_strategy(
    response: RagContextResponse, decision: RetrievalPolicyDecision | None
) -> str | None:
    if response.retrieval_trace is not None:
        return response.retrieval_trace.retrieval_strategy
    for chunk in response.chunks:
        if chunk.retrieval_strategy:
            return chunk.retrieval_strategy
    if decision is not None:
        return decision.effective_strategy
    return None


def _empty_persisted_result(
    *,
    query_phi_sensitivity: str | None,
    phi_detected: bool,
    decision: RetrievalPolicyDecision,
) -> RagContextResult:
    return RagContextResult(
        chunks=(),
        context_text="",
        chunk_count=0,
        source_ids=(),
        source_chunk_ids=(),
        retrieved_source_chunk_ids=(),
        retrieval_reason_code=RAG_RETRIEVAL_EMPTY,
        query_phi_sensitivity=query_phi_sensitivity,
        max_sensitivity_level=None,
        contains_phi=bool(phi_detected),
        retrieval_strategy=decision.effective_strategy,
        candidate_count=0,
        returned_count=0,
        retrieval_policy_reason_code=decision.reason_code,
        retrieval_policy_metadata=decision.audit_metadata(),
    )


def build_rag_augmented_prompt(
    *,
    query_text: str,
    rag_context: RagContextResult,
) -> str:
    if not rag_context.rag_used:
        return query_text
    return (
        f"Retrieved context:\n{rag_context.context_text}\n\nUser query:\n{query_text}"
    )


def _require_tenant(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise RagContextError(
            RAG_RETRIEVAL_FAILED, "tenant_id is required and must not be blank"
        )
    return tenant_id.strip()


def _bound_limit(limit: int) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise RagContextError(RAG_RETRIEVAL_FAILED, "limit must be an integer")
    return max(1, min(limit, MAX_RAG_CONTEXT_LIMIT))


def _bound_chunk_text(text: str) -> str:
    normalized = " ".join(str(text).split())
    return normalized[:MAX_RAG_CHUNK_CHARS]


def _build_context_text(chunks: list[RagContextChunk]) -> str:
    parts: list[str] = []
    total = 0
    for chunk in chunks:
        part = f"[chunk_id={chunk.chunk_id}]\n{chunk.text}"
        remaining = MAX_RAG_CONTEXT_CHARS - total
        if remaining <= 0:
            break
        if len(part) > remaining:
            part = part[:remaining]
        parts.append(part)
        total += len(part)
    return "\n\n".join(parts)


def _included_chunk_ids(
    context_text: str, chunks: list[RagContextChunk]
) -> tuple[str, ...]:
    included: list[str] = []
    for chunk in chunks:
        if f"[chunk_id={chunk.chunk_id}]" in context_text:
            included.append(chunk.chunk_id)
    return tuple(included)


def _metadata_sensitivity(metadata: dict[str, object]) -> str | None:
    value = metadata.get("phi_sensitivity_level")
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    return cleaned or None


def _metadata_phi_types(metadata: dict[str, object]) -> tuple[str, ...]:
    raw = metadata.get("phi_types")
    if not isinstance(raw, list):
        return ()
    return tuple(sorted(str(item).strip() for item in raw if str(item).strip()))


def _max_sensitivity(values: Iterable[str | None]) -> str | None:
    max_value: str | None = None
    max_rank = -1
    for value in values:
        if value is None:
            continue
        rank = _SENSITIVITY_ORDER.get(value, -1)
        if rank > max_rank:
            max_value = value
            max_rank = rank
    return max_value
