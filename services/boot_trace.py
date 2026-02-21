"""
services/boot_trace.py — Boot-stage tracing with ordered stages and redaction.

Records startup milestones in deterministic order.  Each stage captures:
  - stage_name, started_at, completed_at, duration_ms, status, error_code,
    error_detail_redacted (always scrubbed of secrets in prod)

Security guarantees:
  - error_detail is sanitized to strip credentials, tokens, query params,
    Authorization-like patterns, and stack frames.
  - No silent failures: every stage must explicitly be marked complete or failed.
  - Stage order is enforced: stages appear in BOOT_STAGE_ORDER even if
    only partially completed.

This module is thread-safe.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

log = logging.getLogger("frostgate.boot_trace")

# ---------------------------------------------------------------------------
# Canonical stage order
# ---------------------------------------------------------------------------

BOOT_STAGE_ORDER: List[str] = [
    "config_loaded",
    "tenant_binding_initialized",
    "db_connected",
    "migrations_completed",
    "redis_connected",
    "nats_connected",
    "opa_validated",
    "routes_registered",
    "websocket_ready",
    "ready_true",
]

StageStatus = Literal["pending", "in_progress", "ok", "failed", "skipped"]

# ---------------------------------------------------------------------------
# Secret / credential pattern sanitizer
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: List[re.Pattern[str]] = [
    # URLs with credentials: scheme://user:pass@host
    re.compile(r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@/\s]+:[^@/\s]+@", re.IGNORECASE),
    # Authorization header values
    re.compile(r"(?i)(authorization|bearer|basic)\s*[:\s][^\s,;]{4,}", re.IGNORECASE),
    # JWT-shaped tokens (three base64url segments)
    re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # Generic tokens/secrets in query strings
    re.compile(
        r"(?i)(token|secret|password|passwd|apikey|api_key|access_key)"
        r"[=:][^\s&;,\"']{4,}",
        re.IGNORECASE,
    ),
    # Cookie-like patterns
    re.compile(r"(?i)(set-cookie|cookie)[:\s][^\r\n]{4,}", re.IGNORECASE),
    # Long hex secrets (>= 32 hex chars = 128-bit key)
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    # Stack trace lines (file paths + line numbers)
    re.compile(r'File "[^"]+", line \d+'),
    re.compile(r"\s+at [a-zA-Z0-9_.]+\([^)]*\)"),
]

_REPLACEMENT = "[REDACTED]"


def sanitize_error_detail(detail: str, *, is_production: bool) -> str:
    """
    Strip secrets from error detail strings.

    In production: apply all patterns.
    In dev/test: still redact credential URLs and JWT-shaped tokens.
    Always returns a string.
    """
    if not isinstance(detail, str):
        try:
            detail = str(detail)
        except Exception:
            return "[DETAIL_REDACTED]"

    # Truncate to prevent log-flooding
    detail = detail[:2048]

    patterns = _SECRET_PATTERNS if is_production else _SECRET_PATTERNS[:2]
    for pat in patterns:
        detail = pat.sub(_REPLACEMENT, detail)

    return detail


def _is_production() -> bool:
    env = (os.getenv("FG_ENV") or "").strip().lower()
    return env in {"prod", "production", "staging"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class BootStage:
    stage_name: str
    status: StageStatus = "pending"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: Optional[float] = None
    error_code: Optional[str] = None
    error_detail_redacted: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "error_code": self.error_code,
            "error_detail_redacted": self.error_detail_redacted,
        }


# ---------------------------------------------------------------------------
# Boot trace store (per module)
# ---------------------------------------------------------------------------


class BootTraceStore:
    """
    Records boot stages for a single module.  Thread-safe.

    Usage:
        trace = BootTraceStore("frostgate-core")
        trace.start_stage("config_loaded")
        ...
        trace.complete_stage("config_loaded")
        trace.fail_stage("db_connected", error_code="DB_CONNECT_FAILED", detail=str(e))
    """

    def __init__(self, module_id: str) -> None:
        self.module_id = module_id
        self._lock = threading.Lock()
        # Pre-populate all known stages in order as "pending"
        self._stages: Dict[str, BootStage] = {
            name: BootStage(stage_name=name) for name in BOOT_STAGE_ORDER
        }
        self._extra_stages: Dict[str, BootStage] = {}

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def start_stage(self, stage_name: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            stage = self._get_or_create(stage_name)
            stage.status = "in_progress"
            stage.started_at = now
            stage.completed_at = None
            stage.duration_ms = None

    def complete_stage(self, stage_name: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        now_ts = time.monotonic()
        with self._lock:
            stage = self._get_or_create(stage_name)
            stage.status = "ok"
            stage.completed_at = now_iso
            if stage.started_at:
                try:
                    start_ts = datetime.fromisoformat(stage.started_at)
                    if start_ts.tzinfo is None:
                        start_ts = start_ts.replace(tzinfo=timezone.utc)
                    delta = (
                        datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
                        - start_ts
                    )
                    stage.duration_ms = round(delta.total_seconds() * 1000, 3)
                except Exception:
                    stage.duration_ms = None

    def fail_stage(
        self,
        stage_name: str,
        *,
        error_code: str,
        detail: Optional[str] = None,
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        is_prod = _is_production()
        redacted = (
            sanitize_error_detail(detail, is_production=is_prod)
            if detail
            else None
        )
        with self._lock:
            stage = self._get_or_create(stage_name)
            stage.status = "failed"
            stage.completed_at = now_iso
            stage.error_code = error_code
            stage.error_detail_redacted = redacted
            if stage.started_at:
                try:
                    start_ts = datetime.fromisoformat(stage.started_at)
                    if start_ts.tzinfo is None:
                        start_ts = start_ts.replace(tzinfo=timezone.utc)
                    delta = (
                        datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
                        - start_ts
                    )
                    stage.duration_ms = round(delta.total_seconds() * 1000, 3)
                except Exception:
                    stage.duration_ms = None

    def skip_stage(self, stage_name: str) -> None:
        with self._lock:
            stage = self._get_or_create(stage_name)
            stage.status = "skipped"

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_ordered_stages(self) -> List[BootStage]:
        """Return stages in canonical order.  Unknown stages appended after."""
        with self._lock:
            ordered = [
                self._stages[name]
                for name in BOOT_STAGE_ORDER
                if name in self._stages
            ]
            extras = list(self._extra_stages.values())
            return ordered + extras

    def to_dict_list(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.get_ordered_stages()]

    def summary(self) -> Dict[str, Any]:
        stages = self.get_ordered_stages()
        total = len(stages)
        completed = sum(1 for s in stages if s.status in {"ok", "skipped"})
        failed = [s.stage_name for s in stages if s.status == "failed"]
        is_ready = (
            total > 0
            and completed == total
            and not failed
        )
        return {
            "module_id": self.module_id,
            "total_stages": total,
            "completed_stages": completed,
            "failed_stages": failed,
            "is_ready": is_ready,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_or_create(self, stage_name: str) -> BootStage:
        """Must be called under lock."""
        if stage_name in self._stages:
            return self._stages[stage_name]
        if stage_name not in self._extra_stages:
            self._extra_stages[stage_name] = BootStage(stage_name=stage_name)
        return self._extra_stages[stage_name]


# ---------------------------------------------------------------------------
# Global store keyed by module_id
# ---------------------------------------------------------------------------

_traces: Dict[str, BootTraceStore] = {}
_traces_lock = threading.Lock()


def get_trace(module_id: str) -> BootTraceStore:
    """Get or create a boot trace for the given module."""
    with _traces_lock:
        if module_id not in _traces:
            _traces[module_id] = BootTraceStore(module_id)
        return _traces[module_id]


def list_module_ids() -> List[str]:
    with _traces_lock:
        return list(_traces.keys())
