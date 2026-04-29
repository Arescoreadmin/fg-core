"""
RAG Corpus Ingestion Integrity — Task 16.1

Tenant-bound, deterministic, fail-closed ingestion surface.
No external services, no vector DB, no LLM calls.
Scope: local/in-memory ingestion only; chunking, retrieval, and reranking are
later 16.x tasks.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger("frostgate.rag.ingest")

# ---------------------------------------------------------------------------
# Error codes (stable, never change meaning once published)
# ---------------------------------------------------------------------------

INGEST_ERR_MISSING_TENANT = "RAG_INGEST_E001"
INGEST_ERR_EMPTY_DOCUMENTS = "RAG_INGEST_E002"
INGEST_ERR_BLANK_CONTENT = "RAG_INGEST_E003"
INGEST_ERR_MISSING_SOURCE = "RAG_INGEST_E004"
INGEST_ERR_CROSS_TENANT = "RAG_INGEST_E005"
INGEST_ERR_MALFORMED_DOCUMENT = "RAG_INGEST_E006"


class IngestStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorpusDocument:
    """A single document proposed for ingestion."""

    source_id: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    # Optional: if caller includes a tenant hint in metadata, it will be
    # validated against trusted_tenant_id and rejected if mismatched.
    tenant_hint: str | None = None


@dataclass(frozen=True)
class IngestRequest:
    """Ingestion request.  tenant_id must come from trusted execution context."""

    documents: list[CorpusDocument]


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IngestedCorpusRecord:
    """Auditable record produced for each successfully ingested document."""

    tenant_id: str
    source_id: str
    document_id: str  # deterministic SHA-256 based hash
    content_hash: str  # SHA-256 of raw content
    content: str  # normalized document text; required for downstream chunking
    status: IngestStatus
    safe_metadata: dict[str, Any]  # metadata stripped of raw content / secrets


@dataclass(frozen=True)
class IngestResult:
    """Aggregate result returned from ingest_corpus()."""

    status: IngestStatus
    records: list[IngestedCorpusRecord]
    error_code: str | None = None
    error_message: str | None = None  # MUST NOT contain raw document text


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CorpusIngestError(Exception):
    """Raised for unrecoverable ingestion failures.

    error_code is always a stable RAG_INGEST_Exxx constant.
    message MUST NOT contain raw document body text.
    """

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_CANONICAL_ENCODING = "utf-8"


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode(_CANONICAL_ENCODING)).hexdigest()


def _deterministic_document_id(
    tenant_id: str, source_id: str, content_hash: str
) -> str:
    """Stable, deterministic document identity: tenant + source + content."""
    canonical = json.dumps(
        {"tenant_id": tenant_id, "source_id": source_id, "content_hash": content_hash},
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_hex(canonical)


def _safe_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    """Return metadata with tenant_hint stripped (internal binding only)."""
    return {k: v for k, v in raw.items() if k != "tenant_hint"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ingest_corpus(
    request: IngestRequest,
    trusted_tenant_id: str,
) -> IngestResult:
    """Ingest a corpus request under a trusted tenant identity.

    Args:
        request: IngestRequest containing documents to ingest.
        trusted_tenant_id: Tenant identity from the trusted execution context
            (e.g. auth token, OIDC claim).  MUST NOT be sourced from request body.

    Returns:
        IngestResult with per-document records and aggregate status.

    Raises:
        CorpusIngestError: On unrecoverable precondition failures.

    Security invariants:
        - Missing/blank trusted_tenant_id → INGEST_ERR_MISSING_TENANT
        - Empty documents list → INGEST_ERR_EMPTY_DOCUMENTS
        - Blank content → INGEST_ERR_BLANK_CONTENT
        - Missing source_id → INGEST_ERR_MISSING_SOURCE
        - Document tenant_hint conflicts with trusted_tenant_id → INGEST_ERR_CROSS_TENANT
        - Raw document text never appears in error payloads or log output
    """
    # --- Guard: trusted tenant must be present and non-blank ---
    if not trusted_tenant_id or not trusted_tenant_id.strip():
        log.warning(
            "rag.ingest: rejected — missing trusted tenant",
            extra={"error_code": INGEST_ERR_MISSING_TENANT},
        )
        raise CorpusIngestError(
            INGEST_ERR_MISSING_TENANT,
            "trusted_tenant_id is required and must not be blank",
        )

    tenant_id = trusted_tenant_id.strip()

    # --- Guard: documents must be present ---
    if not request.documents:
        log.warning(
            "rag.ingest: rejected — empty document list",
            extra={"tenant_id": tenant_id, "error_code": INGEST_ERR_EMPTY_DOCUMENTS},
        )
        raise CorpusIngestError(
            INGEST_ERR_EMPTY_DOCUMENTS,
            "IngestRequest must contain at least one document",
        )

    records: list[IngestedCorpusRecord] = []

    for idx, doc in enumerate(request.documents):
        # --- Guard: source_id must be present ---
        if not isinstance(doc.source_id, str) or not doc.source_id.strip():
            log.warning(
                "rag.ingest: rejected document — missing source_id",
                extra={
                    "tenant_id": tenant_id,
                    "doc_index": idx,
                    "error_code": INGEST_ERR_MISSING_SOURCE,
                },
            )
            raise CorpusIngestError(
                INGEST_ERR_MISSING_SOURCE,
                f"Document at index {idx} is missing a non-blank source_id",
            )

        # --- Guard: content must be present and non-blank ---
        if not isinstance(doc.content, str) or not doc.content.strip():
            log.warning(
                "rag.ingest: rejected document — blank content",
                extra={
                    "tenant_id": tenant_id,
                    "source_id": doc.source_id,
                    "error_code": INGEST_ERR_BLANK_CONTENT,
                },
            )
            raise CorpusIngestError(
                INGEST_ERR_BLANK_CONTENT,
                f"Document '{doc.source_id}' has blank or missing content",
            )

        # --- Guard: cross-tenant protection ---
        if doc.tenant_hint is not None and doc.tenant_hint.strip() != tenant_id:
            log.warning(
                "rag.ingest: rejected document — cross-tenant metadata conflict",
                extra={
                    "tenant_id": tenant_id,
                    "source_id": doc.source_id,
                    "error_code": INGEST_ERR_CROSS_TENANT,
                },
            )
            raise CorpusIngestError(
                INGEST_ERR_CROSS_TENANT,
                f"Document '{doc.source_id}' tenant_hint conflicts with trusted tenant",
            )

        content_hash = _sha256_hex(doc.content)
        document_id = _deterministic_document_id(tenant_id, doc.source_id, content_hash)

        from services.phi_classifier.classifier import classify_phi as _classify_phi  # noqa: PLC0415

        phi_result = _classify_phi(doc.content)
        phi_meta: dict[str, Any] = {
            "phi_sensitivity_level": phi_result.sensitivity_level.value,
        }
        safe_phi_types = sorted(phi_result.phi_types - {"medical_keyword"})
        if safe_phi_types:
            phi_meta["phi_types"] = safe_phi_types
        log.info(
            "rag.ingest: document phi classification",
            extra={
                "tenant_id": tenant_id,
                "source_id": doc.source_id,
                "phi_sensitivity_level": phi_result.sensitivity_level.value,
            },
        )

        record = IngestedCorpusRecord(
            tenant_id=tenant_id,
            source_id=doc.source_id,
            document_id=document_id,
            content_hash=content_hash,
            content=doc.content,
            status=IngestStatus.SUCCESS,
            safe_metadata={**_safe_metadata(doc.metadata), **phi_meta},
        )
        records.append(record)
        log.info(
            "rag.ingest: document ingested",
            extra={
                "tenant_id": tenant_id,
                "source_id": doc.source_id,
                "document_id": document_id,
                "content_hash": content_hash,
            },
        )

    return IngestResult(
        status=IngestStatus.SUCCESS,
        records=records,
    )
