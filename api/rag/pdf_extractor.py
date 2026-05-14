"""
api/rag/pdf_extractor.py — Enterprise PDF security validation and text extraction.

Security invariants:
- Validates magic bytes, MIME, size, page count, embedded scripts.
- Rejects encrypted, malformed, script-embedded, and oversized PDFs.
- Extraction is deterministic: pages returned in document order (1-based).
- Raw document content MUST NOT appear in error messages or logs.
- Client-declared MIME type is never trusted; magic bytes are authoritative.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
from dataclasses import dataclass
from typing import Final

log = logging.getLogger("frostgate.rag.pdf_extractor")

# ---------------------------------------------------------------------------
# Error codes (stable; never change meaning once published)
# ---------------------------------------------------------------------------

PDF_ERR_MISSING_BYTES = "PDF_E001"
PDF_ERR_INVALID_MAGIC = "PDF_E002"
PDF_ERR_ENCRYPTED = "PDF_E003"
PDF_ERR_MALFORMED = "PDF_E004"
PDF_ERR_TOO_MANY_PAGES = "PDF_E005"
PDF_ERR_OVERSIZED_PAGE = "PDF_E006"
PDF_ERR_EMBEDDED_SCRIPT = "PDF_E007"
PDF_ERR_EXTRACTION_FAILED = "PDF_E008"
PDF_ERR_EMPTY_EXTRACT = "PDF_E009"
PDF_ERR_LIBRARY_MISSING = "PDF_E010"

# ---------------------------------------------------------------------------
# Limits (all overridable via env for air-gapped / regulated deployment)
# ---------------------------------------------------------------------------

_PDF_MAGIC: Final[bytes] = b"%PDF"
_MAX_PDF_PAGES: Final[int] = int(os.getenv("FG_PDF_MAX_PAGES", "500"))
_MAX_PAGE_TEXT_BYTES: Final[int] = int(
    os.getenv("FG_PDF_MAX_PAGE_TEXT_BYTES", str(500_000))
)

# Markers that indicate embedded JavaScript or action trees.
# Checked in raw bytes as a fast pre-parse guard before handing to pypdf.
_JS_MARKERS: Final[frozenset[bytes]] = frozenset(
    {
        b"/JavaScript",
        b"/JS ",
        b"/JS\n",
        b"/JS\r",
        b"/OpenAction",
        b"/Launch",
        b"/SubmitForm",
        b"/ImportData",
    }
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PDFExtractionError(Exception):
    """Raised for any PDF validation or extraction failure.

    error_code is always a stable PDF_Exxx constant.
    message MUST NOT contain raw document content.
    """

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PDFPageText:
    page_number: int  # 1-based
    text: str
    char_count: int


@dataclass(frozen=True)
class PDFExtractionResult:
    pages: list[PDFPageText]
    page_count: int
    extraction_version: str
    source_hash: str  # SHA-256 of the raw PDF bytes — stable document identity
    has_text: bool  # False if all pages are blank (scanned/image-only document)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _pdf_extraction_version() -> str:
    try:
        import importlib.metadata

        ver = importlib.metadata.version("pypdf")
        return f"pypdf-{ver}"
    except Exception:
        return "pypdf-unknown"


_EXTRACTION_VERSION: str = _pdf_extraction_version()


def _check_magic(raw_bytes: bytes) -> None:
    if not raw_bytes:
        raise PDFExtractionError(PDF_ERR_MISSING_BYTES, "PDF content is empty")
    if not raw_bytes[:8].lstrip(b"\x00").startswith(_PDF_MAGIC):
        raise PDFExtractionError(
            PDF_ERR_INVALID_MAGIC,
            "File does not begin with PDF magic bytes (%PDF); client MIME type rejected",
        )


def _check_embedded_scripts(raw_bytes: bytes) -> bool:
    """Return True if any JavaScript/action marker is found in the raw PDF bytes."""
    return any(marker in raw_bytes for marker in _JS_MARKERS)


def _normalize_page_text(raw: str) -> str:
    return raw.replace("\r\n", "\n").replace("\r", "\n").strip()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_pdf_pages(raw_bytes: bytes) -> PDFExtractionResult:
    """Validate and extract text from a PDF document, page by page.

    Args:
        raw_bytes: Raw PDF bytes. Must not exceed the upload size cap
                   (enforced by the upload handler before calling this function).

    Returns:
        PDFExtractionResult with per-page text in deterministic page order.

    Raises:
        PDFExtractionError: On any validation or extraction failure.

    Security invariants:
        - Magic bytes validated before any library parsing.
        - Embedded script markers checked in raw bytes (fast path, pre-parse).
        - Encrypted PDFs rejected before any content is read.
        - Malformed PDFs caught; error message does not include document content.
        - Page count and per-page text size capped against DoS.
        - Raw text never logged or included in error messages.
    """
    _check_magic(raw_bytes)

    source_hash = hashlib.sha256(raw_bytes).hexdigest()

    if _check_embedded_scripts(raw_bytes):
        log.warning(
            "pdf_extractor.embedded_script_rejected",
            extra={
                "event": "pdf.embedded_script_rejected",
                "source_hash_prefix": source_hash[:12],
            },
        )
        raise PDFExtractionError(
            PDF_ERR_EMBEDDED_SCRIPT,
            "PDF contains embedded scripts or action markers; document rejected",
        )

    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise PDFExtractionError(
            PDF_ERR_LIBRARY_MISSING,
            "pypdf is not installed; PDF extraction is unavailable",
        ) from exc

    try:
        reader = PdfReader(io.BytesIO(raw_bytes), strict=False)
    except Exception as exc:
        log.warning(
            "pdf_extractor.malformed_pdf",
            extra={
                "event": "pdf.malformed_rejected",
                "source_hash_prefix": source_hash[:12],
            },
        )
        raise PDFExtractionError(
            PDF_ERR_MALFORMED,
            "PDF is malformed and could not be parsed",
        ) from exc

    if reader.is_encrypted:
        log.warning(
            "pdf_extractor.encrypted_pdf",
            extra={
                "event": "pdf.encrypted_rejected",
                "source_hash_prefix": source_hash[:12],
            },
        )
        raise PDFExtractionError(
            PDF_ERR_ENCRYPTED,
            "PDF is password-protected; encrypted PDFs are not supported",
        )

    page_count = len(reader.pages)
    if page_count > _MAX_PDF_PAGES:
        log.warning(
            "pdf_extractor.page_limit_exceeded",
            extra={
                "event": "pdf.page_limit_rejected",
                "page_count": page_count,
                "max_pages": _MAX_PDF_PAGES,
                "source_hash_prefix": source_hash[:12],
            },
        )
        raise PDFExtractionError(
            PDF_ERR_TOO_MANY_PAGES,
            f"PDF has {page_count} pages; maximum allowed is {_MAX_PDF_PAGES}",
        )

    pages: list[PDFPageText] = []
    for page_num, page in enumerate(reader.pages, start=1):
        try:
            raw_text = page.extract_text() or ""
        except Exception:
            log.warning(
                "pdf_extractor.page_extraction_error",
                extra={
                    "event": "pdf.page_extraction_error",
                    "page_number": page_num,
                    "source_hash_prefix": source_hash[:12],
                },
            )
            raw_text = ""

        text = _normalize_page_text(raw_text)
        text_bytes = len(text.encode("utf-8"))
        if text_bytes > _MAX_PAGE_TEXT_BYTES:
            raise PDFExtractionError(
                PDF_ERR_OVERSIZED_PAGE,
                f"Page {page_num} extracted text exceeds the per-page size limit "
                f"({text_bytes} bytes > {_MAX_PAGE_TEXT_BYTES} bytes)",
            )

        pages.append(
            PDFPageText(
                page_number=page_num,
                text=text,
                char_count=len(text),
            )
        )

    has_text = any(p.text.strip() for p in pages)

    log.info(
        "pdf_extractor.extraction_complete",
        extra={
            "event": "pdf.extraction_complete",
            "page_count": page_count,
            "has_text": has_text,
            "extraction_version": _EXTRACTION_VERSION,
            "source_hash_prefix": source_hash[:12],
        },
    )

    return PDFExtractionResult(
        pages=pages,
        page_count=page_count,
        extraction_version=_EXTRACTION_VERSION,
        source_hash=source_hash,
        has_text=has_text,
    )


def build_pdf_chunk_payloads(
    *,
    tenant_id: str,
    document_id: str,
    version_id: str,
    source_hash: str,
    pdf_result: PDFExtractionResult,
    max_chars: int = 1000,
) -> list[dict]:
    """Produce page-aware, deterministic chunk payloads from a PDF extraction result.

    Each chunk carries:
      - source_page: 1-based page number where this chunk begins
      - extraction_version: version string of the PDF extraction library used
      - chunk_hash (content_hash): SHA-256 of the chunk text
      - All existing provenance fields (document_version_id, source_hash)

    Chunks never cross page boundaries.
    """
    from api.rag_corpus_store import (
        canonical_source_hash,
        deterministic_chunk_id,
    )

    payloads: list[dict] = []
    global_ordinal = 0

    for page in pdf_result.pages:
        if not page.text.strip():
            continue

        words = page.text.split()
        page_chunks: list[str] = []
        current: list[str] = []
        current_len = 0

        for word in words:
            word_len = len(word)
            if word_len > max_chars:
                word = word[:max_chars]
                word_len = max_chars
            needed = word_len if not current else word_len + 1
            if current and current_len + needed > max_chars:
                page_chunks.append(" ".join(current))
                current = []
                current_len = 0
            current.append(word)
            current_len += word_len if len(current) == 1 else word_len + 1

        if current:
            page_chunks.append(" ".join(current))

        for chunk_text in page_chunks:
            content_hash = canonical_source_hash(chunk_text)
            chunk_id = deterministic_chunk_id(
                tenant_id=tenant_id,
                document_id=document_id,
                version_id=version_id,
                ordinal=global_ordinal,
                text=chunk_text,
            )
            payloads.append(
                {
                    "chunk_id": chunk_id,
                    "text": chunk_text,
                    "ordinal": global_ordinal,
                    "document_version_id": version_id,
                    "source_hash": source_hash,
                    "content_hash": content_hash,
                    "source_page": page.page_number,
                    "extraction_version": pdf_result.extraction_version,
                    "metadata": {
                        "document_version_id": version_id,
                        "source_hash": source_hash,
                        "chunk_index": global_ordinal,
                        "source_page": page.page_number,
                        "extraction_version": pdf_result.extraction_version,
                        "chunk_hash": content_hash,
                        "evidence_graph_ready": True,
                        "verified_fact_binding_ready": True,
                        "rag_evaluation_ready": True,
                    },
                }
            )
            global_ordinal += 1

    return payloads
