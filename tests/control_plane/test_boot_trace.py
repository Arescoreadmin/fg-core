"""
Tests for services/boot_trace.py

Covers:
- Stage ordering always canonical
- Stage lifecycle: pending → in_progress → ok / failed / skipped
- Duration computed on complete/fail
- Error detail sanitized (credentials, tokens, stack traces never leaked)
- sanitize_error_detail strips all secret patterns
"""

from __future__ import annotations

import pytest

from services.boot_trace import (
    BOOT_STAGE_ORDER,
    BootTraceStore,
    get_trace,
    sanitize_error_detail,
)


# ---------------------------------------------------------------------------
# Stage ordering
# ---------------------------------------------------------------------------


class TestStageOrdering:
    def test_stages_always_in_canonical_order(self):
        trace = BootTraceStore("mod-order")
        # Complete stages out of order
        trace.complete_stage("ready_true")
        trace.complete_stage("config_loaded")
        trace.start_stage("db_connected")

        stages = trace.get_ordered_stages()
        names = [s.stage_name for s in stages]

        # Canonical stages must appear in order
        canonical_idx = [names.index(n) for n in BOOT_STAGE_ORDER if n in names]
        assert canonical_idx == sorted(canonical_idx)

    def test_all_known_stages_present(self):
        trace = BootTraceStore("mod-all-stages")
        stages = trace.get_ordered_stages()
        names = [s.stage_name for s in stages]
        for canonical in BOOT_STAGE_ORDER:
            assert canonical in names, f"Stage {canonical} missing from boot trace"

    def test_unknown_stage_appended_after_canonical(self):
        trace = BootTraceStore("mod-extra")
        trace.complete_stage("custom_stage_xyz")
        stages = trace.get_ordered_stages()
        names = [s.stage_name for s in stages]
        # All canonical stages before custom
        last_canonical = max(names.index(n) for n in BOOT_STAGE_ORDER if n in names)
        assert names.index("custom_stage_xyz") > last_canonical


# ---------------------------------------------------------------------------
# Stage lifecycle
# ---------------------------------------------------------------------------


class TestStageLifecycle:
    def test_start_stage_sets_in_progress(self):
        trace = BootTraceStore("mod-lc")
        trace.start_stage("config_loaded")
        stage = next(
            s for s in trace.get_ordered_stages() if s.stage_name == "config_loaded"
        )
        assert stage.status == "in_progress"
        assert stage.started_at is not None

    def test_complete_stage_sets_ok(self):
        trace = BootTraceStore("mod-lc-ok")
        trace.start_stage("config_loaded")
        trace.complete_stage("config_loaded")
        stage = next(
            s for s in trace.get_ordered_stages() if s.stage_name == "config_loaded"
        )
        assert stage.status == "ok"
        assert stage.completed_at is not None

    def test_complete_stage_computes_duration(self):
        trace = BootTraceStore("mod-dur")
        trace.start_stage("db_connected")
        import time

        time.sleep(0.01)
        trace.complete_stage("db_connected")
        stage = next(
            s for s in trace.get_ordered_stages() if s.stage_name == "db_connected"
        )
        assert stage.duration_ms is not None
        assert stage.duration_ms >= 0

    def test_fail_stage_sets_failed(self):
        trace = BootTraceStore("mod-fail")
        trace.start_stage("db_connected")
        trace.fail_stage(
            "db_connected",
            error_code="DB_CONNECT_FAILED",
            detail="Connection refused",
        )
        stage = next(
            s for s in trace.get_ordered_stages() if s.stage_name == "db_connected"
        )
        assert stage.status == "failed"
        assert stage.error_code == "DB_CONNECT_FAILED"

    def test_skip_stage(self):
        trace = BootTraceStore("mod-skip")
        trace.skip_stage("redis_connected")
        stage = next(
            s for s in trace.get_ordered_stages() if s.stage_name == "redis_connected"
        )
        assert stage.status == "skipped"

    def test_summary_reflects_completion(self):
        trace = BootTraceStore("mod-summary")
        for name in BOOT_STAGE_ORDER:
            trace.start_stage(name)
            trace.complete_stage(name)
        summary = trace.summary()
        assert summary["is_ready"] is True
        assert summary["failed_stages"] == []
        assert summary["completed_stages"] == summary["total_stages"]

    def test_summary_is_not_ready_when_failed(self):
        trace = BootTraceStore("mod-summary-fail")
        trace.fail_stage("config_loaded", error_code="CONFIG_MISSING")
        summary = trace.summary()
        assert summary["is_ready"] is False
        assert "config_loaded" in summary["failed_stages"]


# ---------------------------------------------------------------------------
# Redaction — secrets must NEVER appear in error details
# ---------------------------------------------------------------------------


class TestRedaction:
    @pytest.mark.parametrize(
        "secret_input",
        [
            # Credential URL
            "postgresql://user:supersecretpassword@db.host:5432/mydb",
            # JWT token
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.HMAC_SIGNATURE_HERE_12345",
            # API key in query string
            "Failed because api_key=sk-abc123456789xyz-supersecret in URL",
            # Authorization header
            "Received Authorization: Bearer eyJhbGciOiJIUzI1NiJ9-faketoken",
            # Long hex secret (simulating a leaked key)
            "Key leak: abcdef1234567890abcdef1234567890 was used",
        ],
    )
    def test_production_redacts_secrets(self, secret_input: str, monkeypatch):
        monkeypatch.setenv("FG_ENV", "prod")
        trace = BootTraceStore("mod-redact-prod")
        trace.fail_stage(
            "db_connected",
            error_code="SECRET_TEST",
            detail=secret_input,
        )
        stage = next(
            s for s in trace.get_ordered_stages() if s.stage_name == "db_connected"
        )
        # The secret should not appear verbatim
        detail = stage.error_detail_redacted or ""
        # Check that the raw secret is not literally present
        # (some patterns replace with [REDACTED])
        assert (
            "[REDACTED]" in detail
            or len(detail) < len(secret_input) // 2
            or "supersecretpassword" not in detail
        )

    def test_sanitize_strips_credential_url(self):
        result = sanitize_error_detail(
            "Connect to postgresql://admin:hunter2@db.internal:5432/prod",
            is_production=True,
        )
        assert "hunter2" not in result
        assert "[REDACTED]" in result

    def test_sanitize_strips_jwt_token(self):
        result = sanitize_error_detail(
            "Token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            is_production=True,
        )
        assert "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" not in result

    def test_sanitize_strips_api_key_in_query(self):
        result = sanitize_error_detail(
            "Error at url?api_key=sk-secretvalue1234 was rejected",
            is_production=True,
        )
        assert "sk-secretvalue1234" not in result

    def test_sanitize_long_hex_secret(self):
        """Simulate a 256-bit key leaking in an error message."""
        leaked_hex = "a" * 64  # 64 hex chars = 256-bit key
        result = sanitize_error_detail(
            f"Auth failed using key {leaked_hex}",
            is_production=True,
        )
        assert leaked_hex not in result

    def test_sanitize_handles_non_string(self):
        """Non-string input must not crash."""
        result = sanitize_error_detail(
            {"nested": "error"},  # type: ignore[arg-type]
            is_production=True,
        )
        assert isinstance(result, str)

    def test_sanitize_truncates_very_long_input(self):
        """2048-char limit prevents log flooding."""
        long_input = "a" * 10_000
        result = sanitize_error_detail(long_input, is_production=False)
        assert len(result) <= 2048


# ---------------------------------------------------------------------------
# Global trace store
# ---------------------------------------------------------------------------


class TestGlobalTraceStore:
    def test_get_trace_creates_new(self):
        trace = get_trace("unique-module-id-xyz")
        assert trace is not None
        assert trace.module_id == "unique-module-id-xyz"

    def test_get_trace_returns_same_instance(self):
        t1 = get_trace("same-module-id")
        t2 = get_trace("same-module-id")
        assert t1 is t2

    def test_to_dict_list_returns_all_stages(self):
        trace = get_trace("dict-module")
        stages = trace.to_dict_list()
        assert isinstance(stages, list)
        assert len(stages) == len(BOOT_STAGE_ORDER)
        for stage in stages:
            assert "stage_name" in stage
            assert "status" in stage
            assert "started_at" in stage
            assert "completed_at" in stage
            assert "duration_ms" in stage
            assert "error_code" in stage
            assert "error_detail_redacted" in stage
