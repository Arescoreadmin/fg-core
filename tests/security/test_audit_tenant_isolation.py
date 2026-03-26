"""
Tenant isolation tests for audit engine surfaces.

Proves that every read/export/reproduce path in the audit engine enforces
tenant_id strictly: missing tenant fails, wrong tenant returns not-found,
correct tenant succeeds.

No network calls. No external services.
"""

from __future__ import annotations

import pytest

from api.db import init_db, reset_engine_cache
from services.audit_engine.engine import (
    AuditEngine,
    AuditTamperDetected,
    InvariantResult,
)

_HMAC_KEY = "test-audit-key-test-audit-key-te"
_HMAC_KEY_ID = "ak-test"


@pytest.fixture()
def audit_eng(tmp_path, monkeypatch):
    db_path = tmp_path / "audit_iso.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_CURRENT", _HMAC_KEY)
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", _HMAC_KEY_ID)
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return AuditEngine()


# ---------------------------------------------------------------------------
# export_bundle
# ---------------------------------------------------------------------------


def test_export_bundle_empty_tenant_raises(audit_eng):
    with pytest.raises(AuditTamperDetected, match="tenant_context_required"):
        audit_eng.export_bundle(
            start="2026-01-01T00:00:00Z",
            end="2026-01-02T00:00:00Z",
            app_openapi={},
            tenant_id="",
        )


def test_export_bundle_whitespace_tenant_raises(audit_eng):
    with pytest.raises(AuditTamperDetected, match="tenant_context_required"):
        audit_eng.export_bundle(
            start="2026-01-01T00:00:00Z",
            end="2026-01-02T00:00:00Z",
            app_openapi={},
            tenant_id="   ",
        )


# ---------------------------------------------------------------------------
# reproduce_session
# ---------------------------------------------------------------------------


def test_reproduce_session_empty_tenant_raises(audit_eng):
    with pytest.raises(AuditTamperDetected, match="tenant_context_required"):
        audit_eng.reproduce_session("any-session-id", tenant_id="")


def test_reproduce_session_wrong_tenant_returns_not_found(audit_eng, monkeypatch):
    monkeypatch.setattr(
        audit_eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    session_id = audit_eng.run_cycle("light")

    result = audit_eng.reproduce_session(session_id, tenant_id="tenant-b")

    assert result["ok"] is False
    assert result["reason"] == "session_not_found"


def test_reproduce_session_correct_tenant_succeeds(audit_eng, monkeypatch):
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "tenant-a")
    monkeypatch.setattr(
        audit_eng, "_invariants", lambda: [InvariantResult("inv-1", "pass", "ok")]
    )
    session_id = audit_eng.run_cycle("light")

    result = audit_eng.reproduce_session(session_id, tenant_id="tenant-a")

    assert result["ok"] is True


# ---------------------------------------------------------------------------
# export_exam_bundle
# ---------------------------------------------------------------------------


def test_export_exam_bundle_wrong_tenant_raises(audit_eng):
    exam_id = audit_eng.create_exam(
        tenant_id="tenant-a",
        name="iso-test",
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-02T00:00:00Z",
    )

    with pytest.raises(AuditTamperDetected, match="exam_session_not_found"):
        audit_eng.export_exam_bundle(
            exam_id=exam_id, app_openapi={}, tenant_id="tenant-b"
        )


def test_export_exam_bundle_empty_tenant_raises(audit_eng):
    exam_id = audit_eng.create_exam(
        tenant_id="tenant-a",
        name="iso-test-empty",
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-02T00:00:00Z",
    )

    with pytest.raises(AuditTamperDetected, match="tenant_context_required"):
        audit_eng.export_exam_bundle(exam_id=exam_id, app_openapi={}, tenant_id="")


def test_export_exam_bundle_correct_tenant_finds_exam(audit_eng, monkeypatch, tmp_path):
    """Correct tenant reaches export_bundle (mocked to avoid full I/O)."""
    exam_id = audit_eng.create_exam(
        tenant_id="tenant-a",
        name="iso-test-ok",
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-02T00:00:00Z",
    )

    captured: list[str] = []

    def _fake_export_bundle(**kwargs: object) -> dict:
        captured.append(str(kwargs.get("tenant_id")))
        dummy = tmp_path / "dummy.json"
        dummy.write_text(
            '{"bundle":{"signed_evidence_checksum":"ak-test:aabbcc"},'
            '"manifest":{"bundle_sha256":"aabbcc"}}'
        )
        return {"path": str(dummy), "manifest": {"bundle_sha256": "aabbcc"}}

    monkeypatch.setattr(audit_eng, "export_bundle", _fake_export_bundle)
    monkeypatch.setattr(audit_eng, "_write_deterministic_archive", lambda *a, **k: None)

    result = audit_eng.export_exam_bundle(
        exam_id=exam_id, app_openapi={}, tenant_id="tenant-a"
    )

    assert result["exam_id"] == exam_id
    assert captured == ["tenant-a"]


# ---------------------------------------------------------------------------
# reproduce_exam
# ---------------------------------------------------------------------------


def test_reproduce_exam_empty_tenant_raises(audit_eng):
    exam_id = audit_eng.create_exam(
        tenant_id="tenant-a",
        name="repro-empty",
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-02T00:00:00Z",
    )

    with pytest.raises(AuditTamperDetected, match="tenant_context_required"):
        audit_eng.reproduce_exam(exam_id, tenant_id="")


def test_reproduce_exam_wrong_tenant_returns_not_found(audit_eng):
    exam_id = audit_eng.create_exam(
        tenant_id="tenant-a",
        name="repro-wrong",
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-02T00:00:00Z",
    )

    result = audit_eng.reproduce_exam(exam_id, tenant_id="tenant-b")

    assert result["ok"] is False
    assert result["reason"] == "exam_session_not_found"


def test_reproduce_exam_correct_tenant_not_found_is_empty_window(audit_eng):
    """Correct tenant, no ledger records in window → exam_window_empty (not a leak)."""
    exam_id = audit_eng.create_exam(
        tenant_id="tenant-a",
        name="repro-ok",
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-02T00:00:00Z",
    )

    result = audit_eng.reproduce_exam(exam_id, tenant_id="tenant-a")

    assert result["ok"] is False
    assert result["reason"] == "exam_window_empty"
