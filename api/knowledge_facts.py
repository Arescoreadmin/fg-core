from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, NoReturn

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("frostgate.knowledge_facts")

CONFIDENCE_MIN = 0.0
CONFIDENCE_MAX = 1.0
CONTRADICTION_THRESHOLD = 0.70
RETRIEVAL_CONFIDENCE_THRESHOLD = 0.70

STATUS_ACTIVE = "active"
STATUS_CONTRADICTED = "contradicted"
STATUS_NEEDS_REVIEW = "needs_review"
STATUS_SUPERSEDED = "superseded"
STATUS_EXPIRED = "expired"
USABLE_RETRIEVAL_STATUSES = {STATUS_ACTIVE}

ERR_MISSING_TENANT = "KNOWLEDGE_FACT_MISSING_TENANT"
ERR_EMPTY_SUBJECT = "KNOWLEDGE_FACT_EMPTY_SUBJECT"
ERR_EMPTY_PREDICATE = "KNOWLEDGE_FACT_EMPTY_PREDICATE"
ERR_EMPTY_OBJECT = "KNOWLEDGE_FACT_EMPTY_OBJECT"
ERR_INVALID_CONFIDENCE = "KNOWLEDGE_FACT_INVALID_CONFIDENCE"
ERR_MISSING_SOURCE_DOC = "KNOWLEDGE_FACT_MISSING_SOURCE_DOC"
ERR_MISSING_SOURCE_CHUNK = "KNOWLEDGE_FACT_MISSING_SOURCE_CHUNK"
ERR_MISSING_SOURCE_HASH = "KNOWLEDGE_FACT_MISSING_SOURCE_HASH"
ERR_SOURCE_NOT_FOUND = "KNOWLEDGE_FACT_SOURCE_NOT_FOUND"
ERR_SOURCE_HASH_MISMATCH = "KNOWLEDGE_FACT_SOURCE_HASH_MISMATCH"
ERR_SOURCE_QUARANTINED = "KNOWLEDGE_FACT_SOURCE_QUARANTINED"
ERR_SOURCE_NOT_CURRENT = "KNOWLEDGE_FACT_SOURCE_NOT_CURRENT"
ERR_SOURCE_POLICY_DENIED = "KNOWLEDGE_FACT_SOURCE_POLICY_DENIED"
ERR_INVALID_VALIDITY_WINDOW = "KNOWLEDGE_FACT_INVALID_VALIDITY_WINDOW"

_UUID_NAMESPACE = uuid.UUID("4d3ab05d-c43f-5fa2-8773-8b88e30833cf")
_SPACE_RE = re.compile(r"\s+")


class KnowledgeFactError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VerifiedFactInput:
    tenant_id: str
    subject: str
    predicate: str
    object: str
    confidence: float
    source_doc_id: str
    source_chunk_id: str
    source_hash: str
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    allowed_corpus_ids: tuple[str, ...] | None = None
    allow_historical_source: bool = False


def create_verified_fact(conn: Session, fact: VerifiedFactInput) -> dict[str, Any]:
    tenant_id = _require_text(fact.tenant_id, ERR_MISSING_TENANT)
    subject = _require_text(fact.subject, ERR_EMPTY_SUBJECT)
    predicate = _require_text(fact.predicate, ERR_EMPTY_PREDICATE)
    obj = _require_text(fact.object, ERR_EMPTY_OBJECT)
    confidence = _validate_confidence(fact.confidence)
    source_doc_id = _require_text(fact.source_doc_id, ERR_MISSING_SOURCE_DOC)
    source_chunk_id = _require_text(fact.source_chunk_id, ERR_MISSING_SOURCE_CHUNK)
    source_hash = _require_text(fact.source_hash, ERR_MISSING_SOURCE_HASH)
    _validate_window(fact.valid_from, fact.valid_to)
    db_valid_from = _db_time(fact.valid_from)
    db_valid_to = _db_time(fact.valid_to)

    source = _validate_source_binding(
        conn,
        tenant_id=tenant_id,
        source_doc_id=source_doc_id,
        source_chunk_id=source_chunk_id,
        source_hash=source_hash,
        allowed_corpus_ids=fact.allowed_corpus_ids,
        allow_historical_source=fact.allow_historical_source,
    )

    normalized_subject = normalize_fact_text(subject)
    normalized_predicate = normalize_fact_text(predicate)
    normalized_object = normalize_fact_text(obj)
    fact_id = deterministic_fact_id(
        tenant_id=tenant_id,
        source_doc_id=source_doc_id,
        source_chunk_id=source_chunk_id,
        source_hash=source_hash,
        normalized_subject=normalized_subject,
        normalized_predicate=normalized_predicate,
        normalized_object=normalized_object,
    )

    existing = _get_fact_by_id(conn, tenant_id=tenant_id, fact_id=fact_id)
    if existing is not None:
        return existing

    contradiction = _find_contradiction(
        conn,
        tenant_id=tenant_id,
        normalized_subject=normalized_subject,
        normalized_predicate=normalized_predicate,
        normalized_object=normalized_object,
        confidence=confidence,
        valid_from=fact.valid_from,
        valid_to=fact.valid_to,
    )
    review_status = STATUS_NEEDS_REVIEW if contradiction is not None else STATUS_ACTIVE
    now = _utc_now()

    conn.execute(
        text(
            """
            INSERT INTO knowledge_facts (
                id, tenant_id, subject, predicate, object,
                normalized_subject, normalized_predicate, normalized_object,
                confidence, source_doc_id, source_chunk_id, source_hash,
                valid_from, valid_to, review_status, contradiction_of_fact_id,
                created_at, updated_at
            )
            VALUES (
                :id, :tenant_id, :subject, :predicate, :object,
                :normalized_subject, :normalized_predicate, :normalized_object,
                :confidence, :source_doc_id, :source_chunk_id, :source_hash,
                :valid_from, :valid_to, :review_status, :contradiction_of_fact_id,
                :created_at, :updated_at
            )
            """
        ),
        {
            "id": fact_id,
            "tenant_id": tenant_id,
            "subject": subject,
            "predicate": predicate,
            "object": obj,
            "normalized_subject": normalized_subject,
            "normalized_predicate": normalized_predicate,
            "normalized_object": normalized_object,
            "confidence": confidence,
            "source_doc_id": source_doc_id,
            "source_chunk_id": source_chunk_id,
            "source_hash": source_hash,
            "valid_from": db_valid_from,
            "valid_to": db_valid_to,
            "review_status": review_status,
            "contradiction_of_fact_id": contradiction["id"] if contradiction else None,
            "created_at": _db_time(now),
            "updated_at": _db_time(now),
        },
    )
    conn.commit()

    _audit(
        "knowledge_fact.contradiction_detected"
        if contradiction is not None
        else "knowledge_fact.created",
        tenant_id=tenant_id,
        fact_id=fact_id,
        source_doc_id=source_doc_id,
        source_chunk_id=source_chunk_id,
        corpus_id=str(source["corpus_id"]),
        review_status=review_status,
        contradiction_of_fact_id=contradiction["id"] if contradiction else None,
    )
    return _get_fact_by_id(conn, tenant_id=tenant_id, fact_id=fact_id) or {}


def list_current_facts(
    conn: Session,
    *,
    tenant_id: str,
    min_confidence: float = CONFIDENCE_MIN,
) -> list[dict[str, Any]]:
    tid = _require_text(tenant_id, ERR_MISSING_TENANT)
    rows = conn.execute(
        text(
            """
            SELECT *
            FROM knowledge_facts
            WHERE tenant_id = :tenant_id
              AND confidence >= :min_confidence
              AND review_status = :status
              AND (valid_from IS NULL OR valid_from <= :now)
              AND (valid_to IS NULL OR valid_to > :now)
            ORDER BY normalized_subject ASC, normalized_predicate ASC, id ASC
            """
        ),
        {
            "tenant_id": tid,
            "min_confidence": _validate_confidence(min_confidence),
            "status": STATUS_ACTIVE,
            "now": _db_time(_utc_now()),
        },
    ).mappings()
    return [_fact_row(row) for row in rows]


def list_historical_facts(conn: Session, *, tenant_id: str) -> list[dict[str, Any]]:
    tid = _require_text(tenant_id, ERR_MISSING_TENANT)
    rows = conn.execute(
        text(
            """
            SELECT *
            FROM knowledge_facts
            WHERE tenant_id = :tenant_id
            ORDER BY created_at ASC, id ASC
            """
        ),
        {"tenant_id": tid},
    ).mappings()
    return [_fact_row(row) for row in rows]


def inspect_contradiction_state(
    conn: Session, *, tenant_id: str, fact_id: str
) -> dict[str, Any] | None:
    tid = _require_text(tenant_id, ERR_MISSING_TENANT)
    fact = _get_fact_by_id(conn, tenant_id=tid, fact_id=fact_id)
    if fact is None:
        return None
    related: list[dict[str, Any]] = []
    contradiction_of = fact.get("contradiction_of_fact_id")
    if contradiction_of:
        related_fact = _get_fact_by_id(
            conn, tenant_id=tid, fact_id=str(contradiction_of)
        )
        if related_fact is not None:
            related.append(related_fact)
    rows = conn.execute(
        text(
            """
            SELECT *
            FROM knowledge_facts
            WHERE tenant_id = :tenant_id
              AND contradiction_of_fact_id = :fact_id
            ORDER BY created_at ASC, id ASC
            """
        ),
        {"tenant_id": tid, "fact_id": fact_id},
    ).mappings()
    related.extend(_fact_row(row) for row in rows)
    return {
        "fact_id": fact["id"],
        "tenant_id": tid,
        "review_status": fact["review_status"],
        "has_contradiction": bool(related),
        "related_fact_ids": [item["id"] for item in related],
    }


def list_entities(conn: Session, *, tenant_id: str) -> list[dict[str, Any]]:
    tid = _require_text(tenant_id, ERR_MISSING_TENANT)
    rows = conn.execute(
        text(
            """
            SELECT id, tenant_id, label, normalized_label, entity_type,
                   confidence, source_doc_id, source_chunk_id, source_hash,
                   created_at, updated_at
            FROM knowledge_entities
            WHERE tenant_id = :tenant_id
            ORDER BY normalized_label ASC, id ASC
            """
        ),
        {"tenant_id": tid},
    ).mappings()
    return [dict(row) for row in rows]


def list_relationships(conn: Session, *, tenant_id: str) -> list[dict[str, Any]]:
    tid = _require_text(tenant_id, ERR_MISSING_TENANT)
    rows = conn.execute(
        text(
            """
            SELECT id, tenant_id, subject_entity_id, predicate, object_entity_id,
                   object_literal, confidence, source_doc_id, source_chunk_id,
                   source_hash, valid_from, valid_to, review_status,
                   created_at, updated_at
            FROM knowledge_relationships
            WHERE tenant_id = :tenant_id
            ORDER BY subject_entity_id ASC, predicate ASC, id ASC
            """
        ),
        {"tenant_id": tid},
    ).mappings()
    return [dict(row) for row in rows]


def list_retrieval_safe_current_facts(
    conn: Session,
    *,
    tenant_id: str,
    min_confidence: float = RETRIEVAL_CONFIDENCE_THRESHOLD,
    allowed_corpus_ids: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    tid = _require_text(tenant_id, ERR_MISSING_TENANT)
    allowed_corpus_tuple = (
        tuple(allowed_corpus_ids) if allowed_corpus_ids is not None else None
    )
    safe: list[dict[str, Any]] = []
    for fact in list_current_facts(
        conn, tenant_id=tid, min_confidence=_validate_confidence(min_confidence)
    ):
        try:
            _validate_source_binding(
                conn,
                tenant_id=tid,
                source_doc_id=str(fact["source_doc_id"]),
                source_chunk_id=str(fact["source_chunk_id"]),
                source_hash=str(fact["source_hash"]),
                allowed_corpus_ids=allowed_corpus_tuple,
                allow_historical_source=False,
            )
        except KnowledgeFactError as exc:
            _audit(
                "knowledge_fact.retrieval_excluded",
                tenant_id=tid,
                fact_id=str(fact["id"]),
                reason_code=exc.code,
                source_doc_id=str(fact["source_doc_id"]),
                source_chunk_id=str(fact["source_chunk_id"]),
            )
            continue
        safe.append(fact)
    return safe


def inspect_fact_proof(
    conn: Session, *, tenant_id: str, fact_id: str
) -> dict[str, Any] | None:
    tid = _require_text(tenant_id, ERR_MISSING_TENANT)
    fact = _get_fact_by_id(conn, tenant_id=tid, fact_id=fact_id)
    if fact is None:
        return None
    valid = True
    reason_code = "SOURCE_PROOF_VALID"
    try:
        source = _validate_source_binding(
            conn,
            tenant_id=tid,
            source_doc_id=str(fact["source_doc_id"]),
            source_chunk_id=str(fact["source_chunk_id"]),
            source_hash=str(fact["source_hash"]),
            allowed_corpus_ids=None,
            allow_historical_source=True,
        )
    except KnowledgeFactError as exc:
        valid = False
        reason_code = exc.code
        source = None
    return {
        "fact_id": fact["id"],
        "tenant_id": tid,
        "source_doc_id": fact["source_doc_id"],
        "source_chunk_id": fact["source_chunk_id"],
        "source_hash": fact["source_hash"],
        "source_valid": valid,
        "reason_code": reason_code,
        "corpus_id": source["corpus_id"] if source is not None else None,
    }


def normalize_fact_text(value: str) -> str:
    return _SPACE_RE.sub(" ", str(value).strip().casefold())


def deterministic_fact_id(
    *,
    tenant_id: str,
    source_doc_id: str,
    source_chunk_id: str,
    source_hash: str,
    normalized_subject: str,
    normalized_predicate: str,
    normalized_object: str,
) -> str:
    payload = json.dumps(
        {
            "tenant_id": tenant_id,
            "source_doc_id": source_doc_id,
            "source_chunk_id": source_chunk_id,
            "source_hash": source_hash,
            "subject": normalized_subject,
            "predicate": normalized_predicate,
            "object": normalized_object,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return str(uuid.uuid5(_UUID_NAMESPACE, payload))


def _validate_source_binding(
    conn: Session,
    *,
    tenant_id: str,
    source_doc_id: str,
    source_chunk_id: str,
    source_hash: str,
    allowed_corpus_ids: tuple[str, ...] | None,
    allow_historical_source: bool,
) -> dict[str, Any]:
    row = (
        conn.execute(
            text(
                """
                SELECT
                    d.document_id,
                    d.corpus_id,
                    d.tenant_id AS document_tenant_id,
                    d.source_hash AS document_source_hash,
                    d.ingestion_status,
                    d.is_current,
                    c.chunk_id,
                    c.tenant_id AS chunk_tenant_id,
                    c.source_hash AS chunk_source_hash,
                    c.is_active
                FROM rag_documents d
                JOIN rag_chunks c
                  ON c.document_id = d.document_id
                 AND c.corpus_id = d.corpus_id
                WHERE d.document_id = :source_doc_id
                  AND c.chunk_id = :source_chunk_id
                  AND d.tenant_id = :tenant_id
                  AND c.tenant_id = :tenant_id
                """
            ),
            {
                "source_doc_id": source_doc_id,
                "source_chunk_id": source_chunk_id,
                "tenant_id": tenant_id,
            },
        )
        .mappings()
        .fetchone()
    )
    if row is None:
        _reject(ERR_SOURCE_NOT_FOUND, tenant_id, source_doc_id, source_chunk_id)
    source = dict(row)
    if (
        source["document_tenant_id"] != tenant_id
        or source["chunk_tenant_id"] != tenant_id
    ):
        _reject(ERR_SOURCE_NOT_FOUND, tenant_id, source_doc_id, source_chunk_id)
    if allowed_corpus_ids is not None and str(source["corpus_id"]) not in {
        str(corpus_id).strip()
        for corpus_id in allowed_corpus_ids
        if str(corpus_id).strip()
    }:
        _reject(ERR_SOURCE_POLICY_DENIED, tenant_id, source_doc_id, source_chunk_id)
    if str(source.get("chunk_source_hash") or "") != source_hash:
        _reject(ERR_SOURCE_HASH_MISMATCH, tenant_id, source_doc_id, source_chunk_id)
    document_hash = source.get("document_source_hash")
    if document_hash is not None and str(document_hash) != source_hash:
        _reject(ERR_SOURCE_HASH_MISMATCH, tenant_id, source_doc_id, source_chunk_id)
    if str(source.get("ingestion_status") or "indexed") == "quarantined":
        _reject(ERR_SOURCE_QUARANTINED, tenant_id, source_doc_id, source_chunk_id)
    if not allow_historical_source:
        if str(source.get("ingestion_status") or "indexed") != "indexed":
            _reject(ERR_SOURCE_NOT_CURRENT, tenant_id, source_doc_id, source_chunk_id)
        if not _truthy(source.get("is_current")) or not _truthy(
            source.get("is_active")
        ):
            _reject(ERR_SOURCE_NOT_CURRENT, tenant_id, source_doc_id, source_chunk_id)
    return source


def _find_contradiction(
    conn: Session,
    *,
    tenant_id: str,
    normalized_subject: str,
    normalized_predicate: str,
    normalized_object: str,
    confidence: float,
    valid_from: datetime | None,
    valid_to: datetime | None,
) -> dict[str, Any] | None:
    if confidence < CONTRADICTION_THRESHOLD:
        return None
    rows = conn.execute(
        text(
            """
            SELECT *
            FROM knowledge_facts
            WHERE tenant_id = :tenant_id
              AND normalized_subject = :normalized_subject
              AND normalized_predicate = :normalized_predicate
              AND normalized_object <> :normalized_object
              AND confidence >= :threshold
              AND review_status IN ('active', 'needs_review')
            ORDER BY created_at ASC, id ASC
            """
        ),
        {
            "tenant_id": tenant_id,
            "normalized_subject": normalized_subject,
            "normalized_predicate": normalized_predicate,
            "normalized_object": normalized_object,
            "threshold": CONTRADICTION_THRESHOLD,
        },
    ).mappings()
    for row in rows:
        fact = _fact_row(row)
        if _windows_overlap(
            valid_from,
            valid_to,
            fact.get("valid_from"),
            fact.get("valid_to"),
        ):
            try:
                _validate_source_binding(
                    conn,
                    tenant_id=tenant_id,
                    source_doc_id=str(fact["source_doc_id"]),
                    source_chunk_id=str(fact["source_chunk_id"]),
                    source_hash=str(fact["source_hash"]),
                    allowed_corpus_ids=None,
                    allow_historical_source=True,
                )
            except KnowledgeFactError:
                continue
            return fact
    return None


def _get_fact_by_id(
    conn: Session, *, tenant_id: str, fact_id: str
) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(
                "SELECT * FROM knowledge_facts WHERE tenant_id = :tenant_id AND id = :id"
            ),
            {"tenant_id": tenant_id, "id": fact_id},
        )
        .mappings()
        .fetchone()
    )
    return _fact_row(row) if row is not None else None


def _fact_row(row: Any) -> dict[str, Any]:
    result = dict(row)
    result["confidence"] = float(result["confidence"])
    return result


def _validate_confidence(value: float) -> float:
    confidence = float(value)
    if confidence < CONFIDENCE_MIN or confidence > CONFIDENCE_MAX:
        raise KnowledgeFactError(ERR_INVALID_CONFIDENCE)
    return confidence


def _validate_window(valid_from: datetime | None, valid_to: datetime | None) -> None:
    if valid_from is not None and valid_to is not None and valid_to <= valid_from:
        raise KnowledgeFactError(ERR_INVALID_VALIDITY_WINDOW)


def _windows_overlap(
    a_from: datetime | None,
    a_to: datetime | None,
    b_from: datetime | None,
    b_to: datetime | None,
) -> bool:
    low_a = _as_datetime(a_from) or datetime.min.replace(tzinfo=timezone.utc)
    high_a = _as_datetime(a_to) or datetime.max.replace(tzinfo=timezone.utc)
    low_b = _as_datetime(b_from) or datetime.min.replace(tzinfo=timezone.utc)
    high_b = _as_datetime(b_to) or datetime.max.replace(tzinfo=timezone.utc)
    return low_a < high_b and low_b < high_a


def _require_text(value: str, code: str) -> str:
    if not value or not str(value).strip():
        raise KnowledgeFactError(code)
    return str(value).strip()


def _reject(
    code: str, tenant_id: str, source_doc_id: str, source_chunk_id: str
) -> NoReturn:
    _audit(
        "knowledge_fact.source_proof_failed",
        tenant_id=tenant_id,
        reason_code=code,
        source_doc_id=source_doc_id,
        source_chunk_id=source_chunk_id,
    )
    raise KnowledgeFactError(code)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _db_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _as_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return (
            parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
        )
    return None


def _audit(event: str, **payload: Any) -> None:
    logger.info(event, extra={"event": event, **payload})
