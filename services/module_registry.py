"""
FrostGate Control Plane - Module Registry Service

Central in-process registry for all runtime modules.
Thread-safe, fail-closed, tenant-safe, redaction-aware.

Modules self-register at startup using register_module().
The registry is observable via list_modules() and query_module().

P2 Liveness: heartbeat TTL, stale detection, node_id conflict tracking,
             last_seen_ts with monotonic uptime.
P2 DependencyProbe: measured_at_ts, timeout_ms, negative latency guards.
P1 Redaction: sanitize_error_detail() applied before any error is stored.
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

from services.error_sanitizer import sanitize_error_detail

log = logging.getLogger("frostgate.control_plane.module_registry")

# ---------------------------------------------------------------------------
# Deterministic error codes
# ---------------------------------------------------------------------------
ERR_MODULE_NOT_FOUND = "CP-MOD-001"
ERR_MODULE_ALREADY_REGISTERED = "CP-MOD-002"
ERR_INVALID_MODULE_STATE = "CP-MOD-003"
ERR_NODE_ID_CONFLICT = "CP-MOD-004"


# ---------------------------------------------------------------------------
# Heartbeat TTL (configurable)
# ---------------------------------------------------------------------------

def _heartbeat_ttl_s() -> int:
    return int(os.getenv("FG_CP_MODULE_HEARTBEAT_TTL_S", "60"))


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ModuleState(str, Enum):
    STARTING = "starting"
    READY = "ready"
    DEGRADED = "degraded"
    FAILED = "failed"
    STOPPED = "stopped"
    STALE = "stale"      # heartbeat TTL exceeded


class DependencyStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class BreakerState(str, Enum):
    CLOSED = "closed"        # normal operation
    OPEN = "open"            # tripped, rejecting requests
    HALF_OPEN = "half_open"  # testing recovery


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DependencyProbe:
    """
    Live state of a single dependency.

    P2 correctness: measured_at_ts and timeout_ms are required for
    meaningful SLO tracking. Negative/nonsense latency values are guarded.
    P1 redaction: error_detail is sanitized via sanitize_error_detail()
    before storage.
    """
    name: str
    status: DependencyStatus = DependencyStatus.UNKNOWN
    latency_ms: Optional[float] = None
    last_check_ts: Optional[str] = None
    measured_at_ts: Optional[str] = None   # when the probe measurement started
    timeout_ms: Optional[float] = None     # probe timeout budget in ms
    error_code: Optional[str] = None
    error_detail: Optional[str] = None    # sanitized on store; never exposed in prod

    def __post_init__(self) -> None:
        # P2: Guard against negative or nonsense latency values
        if self.latency_ms is not None:
            if self.latency_ms < 0:
                log.warning(
                    "DependencyProbe latency_ms is negative (%.3f) for dep=%s — clamping to 0",
                    self.latency_ms,
                    self.name,
                )
                self.latency_ms = 0.0
            elif self.latency_ms > 3_600_000:
                # More than 1 hour is clearly a bug (clock skew, overflow, etc.)
                log.warning(
                    "DependencyProbe latency_ms is implausibly large (%.3f) for dep=%s — clamping to None",
                    self.latency_ms,
                    self.name,
                )
                self.latency_ms = None

        # P2: Guard against non-positive timeout values
        if self.timeout_ms is not None and self.timeout_ms <= 0:
            log.warning(
                "DependencyProbe timeout_ms is non-positive (%.3f) for dep=%s — clamping to None",
                self.timeout_ms,
                self.name,
            )
            self.timeout_ms = None

        # P2: Set measured_at_ts to now if not provided
        if self.measured_at_ts is None:
            self.measured_at_ts = _utc_now_iso()

        # P1: Sanitize error_detail before storage to strip secrets/stack traces
        if self.error_detail is not None:
            self.error_detail = sanitize_error_detail(self.error_detail)

    def to_dict(self, redact: bool = False) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "latency_ms": self.latency_ms,
            "last_check_ts": self.last_check_ts,
            "measured_at_ts": self.measured_at_ts,
            "timeout_ms": self.timeout_ms,
            "error_code": self.error_code,
            # Sanitizer already ran at init; redact flag controls whether to
            # include even the sanitized version in responses.
            "error_detail_redacted": None if redact else self.error_detail,
        }


@dataclass
class ModuleRegistration:
    """
    Runtime metadata for a registered module.

    P2 Liveness: last_seen_ts, is_stale(), heartbeat().
    P0 Tenant scoping: tenant_id stored and exposed for filtering.
    """
    module_id: str
    name: str
    version: str
    commit_hash: str
    build_timestamp: str
    node_id: str
    registered_at: str
    tenant_id: str = ""

    # Mutable state (guarded by lock)
    state: ModuleState = ModuleState.STARTING
    last_state_change_ts: str = ""
    health_summary: str = ""
    last_error_code: Optional[str] = None
    breaker_state: Optional[BreakerState] = None
    queue_depth: Optional[int] = None
    last_seen_ts: Optional[str] = None  # updated by heartbeat()

    # Dependencies map: dep_name -> DependencyProbe
    dependencies: Dict[str, DependencyProbe] = field(default_factory=dict)

    # Internal
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    # ------------------------------------------------------------------
    # Liveness
    # ------------------------------------------------------------------

    def heartbeat(self) -> None:
        """Record that this module is still alive. Updates last_seen_ts."""
        with self._lock:
            self.last_seen_ts = _utc_now_iso()

    def is_stale(self, ttl_s: Optional[int] = None) -> bool:
        """
        Returns True if this module has not sent a heartbeat within ttl_s seconds.
        Returns False if heartbeat has never been set (freshly registered).
        """
        if self.last_seen_ts is None:
            return False
        ttl = ttl_s if ttl_s is not None else _heartbeat_ttl_s()
        try:
            last = datetime.fromisoformat(self.last_seen_ts.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            return (now - last).total_seconds() > ttl
        except Exception:
            return False

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

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
            stale = self.is_stale()
            # Effective state: if stale and not already terminal, surface STALE
            effective_state = self.state.value
            if stale and self.state not in (
                ModuleState.STOPPED,
                ModuleState.FAILED,
                ModuleState.STALE,
            ):
                effective_state = ModuleState.STALE.value

            return {
                "module_id": self.module_id,
                "name": self.name,
                "version": self.version,
                "commit_hash": self.commit_hash,
                "build_timestamp": self.build_timestamp,
                "node_id": self.node_id,
                "tenant_id": self.tenant_id if not redact else None,
                "registered_at": self.registered_at,
                "uptime_seconds": round(self.uptime_seconds(), 1),
                "state": effective_state,
                "stale": stale,
                "last_seen_ts": self.last_seen_ts,
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

    P0: tenant_id stored per module; list_modules() filters by tenant.
    P2: node_id uniqueness tracked; warns on conflict.
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
                    # node_id → set[module_id] for conflict detection (P2)
                    obj._node_registry: Dict[str, set] = {}
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
        tenant_id: str = "",
        initial_state: ModuleState = ModuleState.STARTING,
    ) -> ModuleRegistration:
        """Register a module at startup. Returns the registration object."""
        if not module_id or not name:
            raise ValueError("module_id and name are required")

        resolved_node_id = node_id or _node_id()

        with self._lock:
            if module_id in self._modules:
                log.warning(
                    "module_already_registered module_id=%s — overwriting",
                    module_id,
                )

            # P2: node_id uniqueness enforcement
            existing_modules_for_node = self._node_registry.get(resolved_node_id, set())
            if existing_modules_for_node and module_id not in existing_modules_for_node:
                log.warning(
                    "node_id_conflict node_id=%s already used by modules=%s; "
                    "new registration module_id=%s — possible duplicate deployment",
                    resolved_node_id,
                    existing_modules_for_node,
                    module_id,
                )
            existing_modules_for_node.add(module_id)
            self._node_registry[resolved_node_id] = existing_modules_for_node

            now = _utc_now_iso()
            reg = ModuleRegistration(
                module_id=module_id,
                name=name,
                version=version,
                commit_hash=commit_hash,
                build_timestamp=build_timestamp or now,
                node_id=resolved_node_id,
                registered_at=now,
                tenant_id=tenant_id,
                state=initial_state,
                last_state_change_ts=now,
                last_seen_ts=now,  # freshly registered = freshly seen
            )
            self._modules[module_id] = reg
            log.info(
                "module_registered module_id=%s name=%s version=%s tenant=%s state=%s",
                module_id,
                name,
                version,
                tenant_id or "(none)",
                initial_state.value,
            )
            return reg

    def deregister(self, module_id: str) -> None:
        with self._lock:
            reg = self._modules.pop(module_id, None)
            if reg:
                node_mods = self._node_registry.get(reg.node_id)
                if node_mods:
                    node_mods.discard(module_id)

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

    def heartbeat(self, module_id: str) -> None:
        """Record heartbeat for a module. Updates last_seen_ts."""
        reg = self._get(module_id)
        if reg is not None:
            reg.heartbeat()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_modules(
        self,
        redact: bool = True,
        tenant_id: Optional[str] = None,
    ) -> List[dict]:
        """
        List registered modules.

        P0 Tenant scoping: if tenant_id is provided, only return modules
        belonging to that tenant. If tenant_id is None (global admin), return all.
        """
        with self._lock:
            regs = list(self._modules.values())

        if tenant_id:
            regs = [r for r in regs if r.tenant_id == tenant_id]

        return [reg.to_dict(redact=redact) for reg in regs]

    def get_module(
        self,
        module_id: str,
        redact: bool = True,
        tenant_id: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Get a single module.

        P0 Tenant scoping: if tenant_id is provided and module belongs to a
        different tenant, return None (treated as not found — no cross-tenant
        information disclosure).
        """
        reg = self._get(module_id)
        if reg is None:
            return None
        if tenant_id and reg.tenant_id and reg.tenant_id != tenant_id:
            # Cross-tenant access denied — return None (not found semantics)
            log.warning(
                "cross_tenant_module_access denied module_id=%s module_tenant=%s "
                "requesting_tenant=%s",
                module_id,
                reg.tenant_id,
                tenant_id,
            )
            return None
        return reg.to_dict(redact=redact)

    def get_dependencies(
        self,
        module_id: str,
        redact: bool = True,
        tenant_id: Optional[str] = None,
    ) -> Optional[List[dict]]:
        """
        Get dependency probes for a module.

        P0 Tenant scoping: same cross-tenant guard as get_module().
        """
        reg = self._get(module_id)
        if reg is None:
            return None
        if tenant_id and reg.tenant_id and reg.tenant_id != tenant_id:
            log.warning(
                "cross_tenant_dep_access denied module_id=%s requesting_tenant=%s",
                module_id,
                tenant_id,
            )
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
            self._node_registry.clear()


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
    tenant_id: str = "",
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
            tenant_id="tenant-abc",
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
        tenant_id=tenant_id,
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
