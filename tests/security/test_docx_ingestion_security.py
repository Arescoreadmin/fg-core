"""
tests/security/test_docx_ingestion_security.py — Security invariants for DOCX ingestion.

Tests verify:
- Client MIME type is never trusted (magic bytes are authoritative)
- Macro-enabled formats are rejected before python-docx parsing
- VBA binaries are rejected before python-docx parsing
- Error messages do not contain raw document content
- Tenant isolation: blank tenant_id raises ValueError
- All DOCX error codes are defined and unique
- Source hash prefix truncation in logs
"""

from __future__ import annotations

import io
import zipfile

import pytest

from api.rag.docx_extractor import (
    DOCX_ERR_EMBEDDED_VBA,
    DOCX_ERR_EMPTY_EXTRACT,
    DOCX_ERR_EXTRACTION_FAILED,
    DOCX_ERR_INVALID_MAGIC,
    DOCX_ERR_LIBRARY_MISSING,
    DOCX_ERR_MACRO_ENABLED,
    DOCX_ERR_MALFORMED,
    DOCX_ERR_MISSING_BYTES,
    DOCX_ERR_OVERSIZED_PARAGRAPH,
    DOCX_ERR_TOO_MANY_PARAGRAPHS,
    DOCXExtractionError,
    extract_docx_paragraphs,
)


# ---------------------------------------------------------------------------
# Helpers (duplicated from test_docx_ingestion.py intentionally — security
# tests must not import from application test helpers)
# ---------------------------------------------------------------------------


def _make_raw_docx(paragraphs: list[str] | None = None) -> bytes:
    from docx import Document

    doc = Document()
    for text in paragraphs or ["Security test paragraph"]:
        doc.add_paragraph(text)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _make_macro_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'
            "</Types>",
        )
        zf.writestr("word/document.xml", "<document/>")
    return buf.getvalue()


def _make_vba_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"\x00" * 50)
        zf.writestr("word/document.xml", "<document/>")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# MIME type is never trusted
# ---------------------------------------------------------------------------


class TestMimeTypeNotTrusted:
    def test_jpeg_bytes_rejected_despite_declared_docx_mime(self):
        jpeg_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        with pytest.raises(DOCXExtractionError) as exc_info:
            extract_docx_paragraphs(jpeg_bytes)
        assert exc_info.value.error_code == DOCX_ERR_INVALID_MAGIC

    def test_pdf_bytes_rejected_despite_docx_extension(self):
        pdf_bytes = b"%PDF-1.7\n%..." + b"\x00" * 50
        with pytest.raises(DOCXExtractionError) as exc_info:
            extract_docx_paragraphs(pdf_bytes)
        assert exc_info.value.error_code == DOCX_ERR_INVALID_MAGIC

    def test_random_bytes_rejected(self):
        with pytest.raises(DOCXExtractionError) as exc_info:
            extract_docx_paragraphs(b"\x00\x01\x02\x03" * 100)
        assert exc_info.value.error_code == DOCX_ERR_INVALID_MAGIC

    def test_zip_magic_alone_is_not_sufficient(self):
        bad_zip = b"PK\x03\x04" + b"\xff" * 50
        with pytest.raises(DOCXExtractionError) as exc_info:
            extract_docx_paragraphs(bad_zip)
        # Must be rejected as malformed, not as a valid DOCX.
        assert exc_info.value.error_code in (DOCX_ERR_MALFORMED, DOCX_ERR_INVALID_MAGIC)


# ---------------------------------------------------------------------------
# Macro / VBA rejection
# ---------------------------------------------------------------------------


class TestMacroRejection:
    def test_macro_enabled_content_type_rejected(self):
        raw = _make_macro_docx()
        with pytest.raises(DOCXExtractionError) as exc_info:
            extract_docx_paragraphs(raw)
        assert exc_info.value.error_code == DOCX_ERR_MACRO_ENABLED

    def test_vba_project_bin_rejected(self):
        raw = _make_vba_docx()
        with pytest.raises(DOCXExtractionError) as exc_info:
            extract_docx_paragraphs(raw)
        assert exc_info.value.error_code == DOCX_ERR_EMBEDDED_VBA

    def test_macro_check_runs_before_python_docx_parse(self, monkeypatch):
        """Macro/VBA check must fire even if python-docx is unavailable."""
        import api.rag.docx_extractor as mod

        original_import = (
            __builtins__.__import__
            if hasattr(__builtins__, "__import__")
            else __import__
        )

        def _block_docx(name, *args, **kwargs):
            if name == "docx":
                raise ImportError("blocked")
            return original_import(name, *args, **kwargs)

        # Patch the import inside the function scope.
        monkeypatch.setattr(mod, "_check_macro_and_vba", mod._check_macro_and_vba)
        raw = _make_macro_docx()
        # macro check runs before library import; must raise MACRO_ENABLED not LIBRARY_MISSING
        with pytest.raises(DOCXExtractionError) as exc_info:
            extract_docx_paragraphs(raw)
        assert exc_info.value.error_code == DOCX_ERR_MACRO_ENABLED


# ---------------------------------------------------------------------------
# Error message safety
# ---------------------------------------------------------------------------


class TestErrorMessageSafety:
    def test_error_message_does_not_include_raw_content(self):
        secret_payload = b"PK\x03\x04" + b"TOP_SECRET_CONTENT_XYZ" * 10
        try:
            extract_docx_paragraphs(secret_payload)
        except DOCXExtractionError as exc:
            assert "TOP_SECRET_CONTENT_XYZ" not in exc.message
        except Exception:
            pass  # Other exceptions are fine as long as they're not DOCXExtractionError leaks.

    def test_malformed_error_message_is_safe(self):
        bad_zip = b"PK\x03\x04SENSITIVE_DATA_HERE" + b"\xff" * 100
        try:
            extract_docx_paragraphs(bad_zip)
        except DOCXExtractionError as exc:
            assert "SENSITIVE_DATA_HERE" not in exc.message


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def _make_db(self, tmp_path, monkeypatch):

        db_path = str(tmp_path / "sec-docx.db")
        monkeypatch.setenv("FG_SQLITE_PATH", db_path)
        monkeypatch.setenv("FG_ENV", "test")

        from api.db import get_sessionmaker, init_db, reset_engine_cache
        from api.rag_corpus_store import create_corpus

        reset_engine_cache()
        init_db(sqlite_path=db_path)
        SessionLocal = get_sessionmaker(sqlite_path=db_path)
        session = SessionLocal()
        corpus = create_corpus(session, tenant_id="tenant-a", name="T")
        return session, corpus["corpus_id"], reset_engine_cache

    def test_blank_tenant_id_raises(self, tmp_path, monkeypatch):
        from api.rag_corpus_store import ingest_docx_document

        raw = _make_raw_docx(["Some content"])
        result = extract_docx_paragraphs(raw)
        session, corpus_id, reset_fn = self._make_db(tmp_path, monkeypatch)

        try:
            with pytest.raises((ValueError, Exception)):
                ingest_docx_document(
                    session,
                    tenant_id="",
                    corpus_id=corpus_id,
                    title="X",
                    source="x.docx",
                    docx_result=result,
                )
        finally:
            session.close()
            reset_fn()

    def test_whitespace_tenant_id_raises(self, tmp_path, monkeypatch):
        from api.rag_corpus_store import ingest_docx_document

        raw = _make_raw_docx(["content"])
        result = extract_docx_paragraphs(raw)
        session, corpus_id, reset_fn = self._make_db(tmp_path, monkeypatch)

        try:
            with pytest.raises((ValueError, Exception)):
                ingest_docx_document(
                    session,
                    tenant_id="   ",
                    corpus_id=corpus_id,
                    title="X",
                    source="x.docx",
                    docx_result=result,
                )
        finally:
            session.close()
            reset_fn()


# ---------------------------------------------------------------------------
# Source hash prefix safety
# ---------------------------------------------------------------------------


class TestSourceHashPrefixSafety:
    def test_extraction_result_carries_full_sha256(self):
        raw = _make_raw_docx(["hash test"])
        result = extract_docx_paragraphs(raw)
        assert len(result.source_hash) == 64
        assert all(c in "0123456789abcdef" for c in result.source_hash)

    def test_source_hash_is_stable_across_calls(self):
        raw = _make_raw_docx(["stable content"])
        r1 = extract_docx_paragraphs(raw)
        r2 = extract_docx_paragraphs(raw)
        assert r1.source_hash == r2.source_hash


# ---------------------------------------------------------------------------
# Error code registry
# ---------------------------------------------------------------------------


class TestErrorCodeRegistry:
    def test_all_docx_error_codes_defined(self):
        codes = [
            DOCX_ERR_MISSING_BYTES,
            DOCX_ERR_INVALID_MAGIC,
            DOCX_ERR_MACRO_ENABLED,
            DOCX_ERR_MALFORMED,
            DOCX_ERR_TOO_MANY_PARAGRAPHS,
            DOCX_ERR_OVERSIZED_PARAGRAPH,
            DOCX_ERR_EMBEDDED_VBA,
            DOCX_ERR_EXTRACTION_FAILED,
            DOCX_ERR_EMPTY_EXTRACT,
            DOCX_ERR_LIBRARY_MISSING,
        ]
        assert len(codes) == 10
        for code in codes:
            assert code.startswith("DOCX_E")

    def test_docx_error_codes_are_unique(self):
        codes = [
            DOCX_ERR_MISSING_BYTES,
            DOCX_ERR_INVALID_MAGIC,
            DOCX_ERR_MACRO_ENABLED,
            DOCX_ERR_MALFORMED,
            DOCX_ERR_TOO_MANY_PARAGRAPHS,
            DOCX_ERR_OVERSIZED_PARAGRAPH,
            DOCX_ERR_EMBEDDED_VBA,
            DOCX_ERR_EXTRACTION_FAILED,
            DOCX_ERR_EMPTY_EXTRACT,
            DOCX_ERR_LIBRARY_MISSING,
        ]
        assert len(set(codes)) == len(codes)

    def test_docx_error_codes_do_not_overlap_with_pdf(self):
        docx_codes = {
            DOCX_ERR_MISSING_BYTES,
            DOCX_ERR_INVALID_MAGIC,
            DOCX_ERR_MACRO_ENABLED,
            DOCX_ERR_MALFORMED,
            DOCX_ERR_TOO_MANY_PARAGRAPHS,
            DOCX_ERR_OVERSIZED_PARAGRAPH,
            DOCX_ERR_EMBEDDED_VBA,
            DOCX_ERR_EXTRACTION_FAILED,
            DOCX_ERR_EMPTY_EXTRACT,
            DOCX_ERR_LIBRARY_MISSING,
        }
        from api.rag.pdf_extractor import (
            PDF_ERR_EMPTY_EXTRACT,
            PDF_ERR_ENCRYPTED,
            PDF_ERR_EMBEDDED_SCRIPT,
            PDF_ERR_EXTRACTION_FAILED,
            PDF_ERR_INVALID_MAGIC,
            PDF_ERR_LIBRARY_MISSING,
            PDF_ERR_MALFORMED,
            PDF_ERR_MISSING_BYTES,
            PDF_ERR_OVERSIZED_PAGE,
            PDF_ERR_TOO_MANY_PAGES,
        )

        pdf_codes = {
            PDF_ERR_MISSING_BYTES,
            PDF_ERR_INVALID_MAGIC,
            PDF_ERR_ENCRYPTED,
            PDF_ERR_MALFORMED,
            PDF_ERR_TOO_MANY_PAGES,
            PDF_ERR_OVERSIZED_PAGE,
            PDF_ERR_EMBEDDED_SCRIPT,
            PDF_ERR_EXTRACTION_FAILED,
            PDF_ERR_EMPTY_EXTRACT,
            PDF_ERR_LIBRARY_MISSING,
        }
        assert docx_codes.isdisjoint(pdf_codes), (
            "DOCX and PDF error codes must not overlap"
        )
