"""
FrostGate Control Plane - Boot Trace Service

Ordered startup stage tracing with deterministic error codes.
Records each stage with timing, status, and (redacted-in-prod) error details.

No silent failures allowed. Every stage must be explicitly recorded.
Fail-closed: missing/incomplete traces are surfaced, never hidden.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

log = logging.getLogger("frostgate.control_plane.boot_trace")


# ---------------------------------------------------------------------------
# Deterministic error codes
# ---------------------------------------------------------------------------
ERR_STAGE_ALREADY_STARTED = "CP-BOOT-001"
ERR_STAGE_NOT_STARTED = "CP-BOOT-002"
ERR_STAGE_UNKNOWN = "CP-BOOT-003"
ERR_TRACE_ALREADY_EXISTS = "CP-BOOT-004"


# ---------------------------------------------------------------------------
# Canonical boot stage ordering
# ---------------------------------------------------------------------------

class BootStage(str, Enum):
    CONFIG_LOADED = "config_loaded"
    TENANT_BINDING_INITIALIZED = "tenant_binding_initialized"
    DB_CONNECTED = "db_connected"
    MIGRATIONS_COMPLETED = "migrations_completed"
    REDIS_CONNECTED = "redis_connected"
    NATS_CONNECTED = "nats_connected"
    OPA_VALIDATED = "opa_validated"
    ROUTES_REGISTERED = "routes_registered"
    WEBSOCKET_READY = "websocket_ready"
    READY_TRUE = "ready_true"


BOOT_STAGE_ORDER: List[BootStage] = [
    BootStage.CONFIG_LOADED,
    BootStage.TENANT_BINDING_INITIALIZED,
    BootStage.DB_CONNECTED,
    BootStage.MIGRATIONS_COMPLETED,
    BootStage.REDIS_CONNECTED,
    BootStage.NATS_CONNECTED,
    BootStage.OPA_VALIDATED,
    BootStage.ROUTES_REGISTERED,
    BootStage.WEBSOCKET_READY,
    BootStage.READY_TRUE,
]


class StageStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    OK = "ok"
    SKIPPED = "skipped"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Stage record
# ---------------------------------------------------------------------------

@dataclass
class StageRecord:
    stage_name: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: Optional[float] = None
    status: StageStatus = StageStatus.PENDING
    error_code: Optional[str] = None
    error_detail_raw: Optional[str] = None  # never exposed in prod

    def to_dict(self, redact: bool = False) -> dict:
        return {
            "stage_name": self.stage_name,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "error_code": self.error_code,
            "error_detail_redacted": None if redact else self.error_detail_raw,
        }


# ---------------------------------------------------------------------------
# Boot trace for a single module
# ---------------------------------------------------------------------------

@dataclass
class BootTrace:
    module_id: str
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    completed: bool = False

    _stages: Dict[str, StageRecord] = field(default_factory=dict, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        with self._lock:
            for stage in BOOT_STAGE_ORDER:
                self._stages[stage.value] = StageRecord(stage_name=stage.value)

    def start_stage(self, stage: str) -> None:
        with self._lock:
            rec = self._stages.get(stage)
            if rec is None:
                log.warning(
                    "boot_trace start_stage unknown stage=%s module=%s",
                    stage,
                    self.module_id,
                )
                # Still record it - no silent failures
                rec = StageRecord(stage_name=stage)
                self._stages[stage] = rec

            if rec.status == StageStatus.IN_PROGRESS:
                log.warning(
                    "boot_trace stage already in progress stage=%s module=%s",
                    stage,
                    self.module_id,
                )

            rec.status = StageStatus.IN_PROGRESS
            rec.started_at = _utc_now_iso()

    def complete_stage(
        self,
        stage: str,
        status: StageStatus = StageStatus.OK,
        error_code: Optional[str] = None,
        error_detail: Optional[str] = None,
    ) -> None:
        with self._lock:
            rec = self._stages.get(stage)
            if rec is None:
                log.warning(
                    "boot_trace complete_stage: stage not found stage=%s module=%s",
                    stage,
                    self.module_id,
                )
                rec = StageRecord(stage_name=stage)
                self._stages[stage] = rec

            now = _utc_now_iso()
            rec.completed_at = now
            rec.status = status
            rec.error_code = error_code
            rec.error_detail_raw = error_detail

            # Calculate duration
            if rec.started_at:
                try:
                    started = datetime.fromisoformat(
                        rec.started_at.replace("Z", "+00:00")
                    )
                    completed = datetime.fromisoformat(now.replace("Z", "+00:00"))
                    rec.duration_ms = round(
                        (completed - started).total_seconds() * 1000, 2
                    )
                except Exception:
                    rec.duration_ms = None
            else:
                # Stage completed without being started - warn but record
                rec.started_at = now
                rec.duration_ms = 0.0

            if status == StageStatus.FAILED:
                log.error(
                    "boot_stage_failed stage=%s module=%s error_code=%s",
                    stage,
                    self.module_id,
                    error_code,
                )
            else:
                log.info(
                    "boot_stage_ok stage=%s module=%s duration_ms=%.2f",
                    stage,
                    self.module_id,
                    rec.duration_ms or 0,
                )

    def skip_stage(self, stage: str, reason: str = "") -> None:
        self.complete_stage(stage, status=StageStatus.SKIPPED, error_detail=reason)

    def mark_ready(self) -> None:
        self.complete_stage(BootStage.READY_TRUE.value)
        with self._lock:
            self.completed = True

    def to_dict(self, redact: bool = False) -> dict:
        with self._lock:
            # Return stages in canonical order, then any extras
            ordered: list[dict] = []
            seen: set[str] = set()

            for stage in BOOT_STAGE_ORDER:
                rec = self._stages.get(stage.value)
                if rec:
                    ordered.append(rec.to_dict(redact=redact))
                    seen.add(stage.value)

            # Any extra stages recorded that aren't in canonical order
            for name, rec in self._stages.items():
                if name not in seen:
                    ordered.append(rec.to_dict(redact=redact))

            failed = [s for s in ordered if s["status"] == "failed"]
            return {
                "module_id": self.module_id,
                "created_at": self.created_at,
                "completed": self.completed,
                "stages": ordered,
                "failed_stage_count": len(failed),
                "failed_stages": [s["stage_name"] for s in failed],
            }


# ---------------------------------------------------------------------------
# Boot Trace Registry singleton
# ---------------------------------------------------------------------------

class BootTraceRegistry:
    """
    Singleton registry of boot traces for all modules.
    Thread-safe. Fail-closed.
    """

    _instance: Optional["BootTraceRegistry"] = None
    _init_lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "BootTraceRegistry":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._traces: Dict[str, BootTrace] = {}
                    obj._lock = threading.RLock()
                    cls._instance = obj
        return cls._instance

    def create_trace(self, module_id: str) -> BootTrace:
        with self._lock:
            if module_id in self._traces:
                log.warning(
                    "boot_trace already exists for module_id=%s - overwriting",
                    module_id,
                )
            trace = BootTrace(module_id=module_id)
            self._traces[module_id] = trace
            log.info("boot_trace_created module_id=%s", module_id)
            return trace

    def get_trace(self, module_id: str) -> Optional[BootTrace]:
        with self._lock:
            return self._traces.get(module_id)

    def get_trace_dict(self, module_id: str, redact: bool = True) -> Optional[dict]:
        trace = self.get_trace(module_id)
        if trace is None:
            return None
        return trace.to_dict(redact=redact)

    def list_traces(self, redact: bool = True) -> list[dict]:
        with self._lock:
            return [t.to_dict(redact=redact) for t in self._traces.values()]

    def _reset(self) -> None:
        """For testing only."""
        with self._lock:
            self._traces.clear()


# ---------------------------------------------------------------------------
# Context manager for stage tracing
# ---------------------------------------------------------------------------

class StageContext:
    """
    Context manager for safe stage recording.

    Usage:
        trace = BootTraceRegistry().get_trace("mymodule")
        with StageContext(trace, "db_connected", error_code="CP-DB-001"):
            db.connect()
    """

    def __init__(
        self,
        trace: BootTrace,
        stage: str,
        error_code: str = "CP-BOOT-ERR",
    ) -> None:
        self._trace = trace
        self._stage = stage
        self._error_code = error_code

    def __enter__(self) -> "StageContext":
        self._trace.start_stage(self._stage)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is None:
            self._trace.complete_stage(self._stage, status=StageStatus.OK)
        else:
            self._trace.complete_stage(
                self._stage,
                status=StageStatus.FAILED,
                error_code=self._error_code,
                error_detail=f"{exc_type.__name__}: {exc_val}",
            )
        # Never suppress exceptions
        return False


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
