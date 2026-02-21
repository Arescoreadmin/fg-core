"""
FrostGate Control Plane - Module Registry Service

Central in-process registry for all runtime modules.
Thread-safe, fail-closed, tenant-safe, redaction-aware.

Modules self-register at startup using register_module().
The registry is observable via list_modules() and query_module().
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

log = logging.getLogger("frostgate.control_plane.module_registry")

# ---------------------------------------------------------------------------
# Deterministic error codes
# ---------------------------------------------------------------------------
ERR_MODULE_NOT_FOUND = "CP-MOD-001"
ERR_MODULE_ALREADY_REGISTERED = "CP-MOD-002"
ERR_INVALID_MODULE_STATE = "CP-MOD-003"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ModuleState(str, Enum):
    STARTING = "starting"
    READY = "ready"
    DEGRADED = "degraded"
    FAILED = "failed"
    STOPPED = "stopped"


class DependencyStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class BreakerState(str, Enum):
    CLOSED = "closed"      # normal operation
    OPEN = "open"          # tripped, rejecting requests
    HALF_OPEN = "half_open"  # testing recovery


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DependencyProbe:
    """Live state of a single dependency."""
    name: str
    status: DependencyStatus = DependencyStatus.UNKNOWN
    latency_ms: Optional[float] = None
    last_check_ts: Optional[str] = None
    error_code: Optional[str] = None
    error_detail: Optional[str] = None  # redacted in prod

    def to_dict(self, redact: bool = False) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "latency_ms": self.latency_ms,
            "last_check_ts": self.last_check_ts,
            "error_code": self.error_code,
            "error_detail_redacted": None if redact else self.error_detail,
        }


@dataclass
class ModuleRegistration:
    """Runtime metadata for a registered module."""
    module_id: str
    name: str
    version: str
    commit_hash: str
    build_timestamp: str
    node_id: str
    registered_at: str

    # Mutable state (guarded by lock)
    state: ModuleState = ModuleState.STARTING
    last_state_change_ts: str = ""
    health_summary: str = ""
    last_error_code: Optional[str] = None
    breaker_state: Optional[BreakerState] = None
    queue_depth: Optional[int] = None

    # Dependencies map: dep_name -> DependencyProbe
    dependencies: Dict[str, DependencyProbe] = field(default_factory=dict)

    # Internal
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def update_state(
        self,
        state: ModuleState,
        health_summary: str = "",
        last_error_code: Optional[str] = None,
    ) -> None:
        with self._lock:
            self.state = state
            self.last_state_change_ts = _utc_now_iso()
            self.health_summary = health_summary
            if last_error_code is not None:
                self.last_error_code = last_error_code

    def update_dependency(self, probe: DependencyProbe) -> None:
        with self._lock:
            self.dependencies[probe.name] = probe

    def uptime_seconds(self) -> float:
        try:
            registered = datetime.fromisoformat(
                self.registered_at.replace("Z", "+00:00")
            )
            now = datetime.now(timezone.utc)
            return (now - registered).total_seconds()
        except Exception:
            return 0.0

    def to_dict(self, redact: bool = False) -> dict:
        with self._lock:
            return {
                "module_id": self.module_id,
                "name": self.name,
                "version": self.version,
                "commit_hash": self.commit_hash,
                "build_timestamp": self.build_timestamp,
                "node_id": self.node_id,
                "registered_at": self.registered_at,
                "uptime_seconds": round(self.uptime_seconds(), 1),
                "state": self.state.value,
                "last_state_change_ts": self.last_state_change_ts,
                "health_summary": self.health_summary,
                "last_error_code": self.last_error_code,
                "breaker_state": self.breaker_state.value
                if self.breaker_state
                else None,
                "queue_depth": self.queue_depth,
                "dependency_count": len(self.dependencies),
                "dependency_statuses": {
                    name: probe.status.value
                    for name, probe in self.dependencies.items()
                },
            }

    def dependency_list(self, redact: bool = False) -> list[dict]:
        with self._lock:
            return [probe.to_dict(redact=redact) for probe in self.dependencies.values()]


# ---------------------------------------------------------------------------
# Registry singleton
# ---------------------------------------------------------------------------

class ModuleRegistry:
    """
    Thread-safe singleton registry for all runtime modules.

    Fail-closed: reads return empty/error rather than leaking internal state.
    No subprocess. No shell execution. Pure in-process state.
    """

    _instance: Optional["ModuleRegistry"] = None
    _init_lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "ModuleRegistry":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._modules: Dict[str, ModuleRegistration] = {}
                    obj._lock = threading.RLock()
                    cls._instance = obj
        return cls._instance

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        *,
        module_id: str,
        name: str,
        version: str,
        commit_hash: str = "unknown",
        build_timestamp: str = "",
        node_id: str = "",
        initial_state: ModuleState = ModuleState.STARTING,
    ) -> ModuleRegistration:
        """Register a module at startup. Returns the registration object."""
        if not module_id or not name:
            raise ValueError("module_id and name are required")

        with self._lock:
            if module_id in self._modules:
                log.warning(
                    "module_already_registered module_id=%s - overwriting",
                    module_id,
                )

            reg = ModuleRegistration(
                module_id=module_id,
                name=name,
                version=version,
                commit_hash=commit_hash,
                build_timestamp=build_timestamp or _utc_now_iso(),
                node_id=node_id or _node_id(),
                registered_at=_utc_now_iso(),
                state=initial_state,
                last_state_change_ts=_utc_now_iso(),
            )
            self._modules[module_id] = reg
            log.info(
                "module_registered module_id=%s name=%s version=%s state=%s",
                module_id,
                name,
                version,
                initial_state.value,
            )
            return reg

    def deregister(self, module_id: str) -> None:
        with self._lock:
            self._modules.pop(module_id, None)

    # ------------------------------------------------------------------
    # State updates (called by modules themselves)
    # ------------------------------------------------------------------

    def set_state(
        self,
        module_id: str,
        state: ModuleState,
        health_summary: str = "",
        last_error_code: Optional[str] = None,
    ) -> None:
        reg = self._get(module_id)
        if reg is None:
            log.warning("set_state: unknown module_id=%s", module_id)
            return
        reg.update_state(state, health_summary, last_error_code)
        log.info(
            "module_state_changed module_id=%s state=%s error_code=%s",
            module_id,
            state.value,
            last_error_code,
        )

    def set_dependency(self, module_id: str, probe: DependencyProbe) -> None:
        reg = self._get(module_id)
        if reg is None:
            log.warning("set_dependency: unknown module_id=%s", module_id)
            return
        reg.update_dependency(probe)

    def set_breaker_state(
        self, module_id: str, breaker_state: BreakerState
    ) -> None:
        reg = self._get(module_id)
        if reg is None:
            return
        with reg._lock:
            reg.breaker_state = breaker_state

    def set_queue_depth(self, module_id: str, depth: int) -> None:
        reg = self._get(module_id)
        if reg is None:
            return
        with reg._lock:
            reg.queue_depth = depth

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_modules(self, redact: bool = True) -> List[dict]:
        with self._lock:
            return [reg.to_dict(redact=redact) for reg in self._modules.values()]

    def get_module(
        self, module_id: str, redact: bool = True
    ) -> Optional[dict]:
        reg = self._get(module_id)
        if reg is None:
            return None
        return reg.to_dict(redact=redact)

    def get_dependencies(
        self, module_id: str, redact: bool = True
    ) -> Optional[List[dict]]:
        reg = self._get(module_id)
        if reg is None:
            return None
        return reg.dependency_list(redact=redact)

    def module_exists(self, module_id: str) -> bool:
        with self._lock:
            return module_id in self._modules

    def get_registration(self, module_id: str) -> Optional[ModuleRegistration]:
        return self._get(module_id)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get(self, module_id: str) -> Optional[ModuleRegistration]:
        with self._lock:
            return self._modules.get(module_id)

    def _reset(self) -> None:
        """For testing only."""
        with self._lock:
            self._modules.clear()


# ---------------------------------------------------------------------------
# Module-local convenience helper for self-registration
# ---------------------------------------------------------------------------

def register_module(
    *,
    module_id: str,
    name: str,
    version: str,
    commit_hash: str = "unknown",
    build_timestamp: str = "",
    node_id: str = "",
    initial_state: ModuleState = ModuleState.STARTING,
) -> ModuleRegistration:
    """
    Convenience wrapper for modules to self-register at startup.

    Usage:
        from services.module_registry import register_module, ModuleState
        reg = register_module(
            module_id="audit_engine",
            name="Audit Engine",
            version="1.0.0",
        )
        reg.update_state(ModuleState.READY)
    """
    return ModuleRegistry().register(
        module_id=module_id,
        name=name,
        version=version,
        commit_hash=commit_hash,
        build_timestamp=build_timestamp,
        node_id=node_id,
        initial_state=initial_state,
    )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _node_id() -> str:
    raw = os.getenv("FG_NODE_ID", "").strip()
    if raw:
        return raw
    import socket
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _is_prod_like() -> bool:
    return (os.getenv("FG_ENV") or "").strip().lower() in {
        "prod", "production", "staging"
    }
