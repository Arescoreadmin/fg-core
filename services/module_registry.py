"""
services/module_registry.py — Central runtime module registry.

Every module self-registers at startup.  Heartbeats keep records live; missing
heartbeats transition the module to "stale" automatically.

Thread-safe: all mutations go through _RegistryStore which holds a single RLock.
Tenant-safe: GET /control-plane/modules returns all modules for platform-admins
and only tenant-scoped modules for tenant-admins.  Sensitive fields are never
exposed in list payloads.

Dependency probes are stored alongside the module record and include:
  status, latency_ms, last_check_ts, error_code, measured_at_ts, timeout_ms

No subprocess. No shell execution. No fail-open.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

log = logging.getLogger("frostgate.module_registry")

# ---------------------------------------------------------------------------
# Typing helpers
# ---------------------------------------------------------------------------

ModuleState = Literal["starting", "ready", "degraded", "failed", "stopped", "stale"]
DepStatus = Literal["ok", "degraded", "failed", "unknown"]

# How long (seconds) before a module without a heartbeat is marked stale.
DEFAULT_HEARTBEAT_TTL: int = int(os.getenv("FG_CP_MODULE_HEARTBEAT_TTL", "60"))

# Maximum dependency probe latency sanity cap (ms).
_MAX_LATENCY_MS: int = 300_000


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DependencyProbe:
    name: str  # e.g. "db", "redis", "nats", "opa", "ai", "storage"
    status: DepStatus = "unknown"
    latency_ms: Optional[float] = None  # None until first probe
    measured_at_ts: Optional[str] = None
    last_check_ts: Optional[str] = None
    timeout_ms: Optional[int] = None
    error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "latency_ms": self._safe_latency(),
            "measured_at_ts": self.measured_at_ts,
            "last_check_ts": self.last_check_ts,
            "timeout_ms": self.timeout_ms,
            "error_code": self.error_code,
        }

    def _safe_latency(self) -> Optional[float]:
        """Prevent negative or nonsense latency values."""
        if self.latency_ms is None:
            return None
        v = float(self.latency_ms)
        if v < 0:
            return 0.0
        if v > _MAX_LATENCY_MS:
            return float(_MAX_LATENCY_MS)
        return round(v, 3)


@dataclass
class ModuleRecord:
    module_id: str
    name: str
    version: str
    commit_hash: str
    build_timestamp: str
    node_id: str

    # mutable runtime state
    state: ModuleState = "starting"
    last_state_change_ts: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    health_summary: str = ""
    last_error_code: Optional[str] = None
    breaker_state: Optional[str] = None  # "open"|"closed"|"half-open"|None
    queue_depth: Optional[int] = None

    # registration + liveness
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen_ts: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    uptime_seconds: float = 0.0

    # tenant scoping
    tenant_id: Optional[str] = None  # None = platform-level module

    # dependency probes
    dependencies: Dict[str, DependencyProbe] = field(default_factory=dict)

    # monotonic uptime tracking
    _started_at: float = field(default_factory=time.monotonic, repr=False)

    def heartbeat(self) -> None:
        """Touch liveness and recalculate uptime."""
        now = datetime.now(timezone.utc).isoformat()
        self.last_seen_ts = now
        self.uptime_seconds = round(time.monotonic() - self._started_at, 3)

    def set_state(self, new_state: ModuleState, error_code: Optional[str] = None) -> None:
        self.state = new_state
        self.last_state_change_ts = datetime.now(timezone.utc).isoformat()
        if error_code is not None:
            self.last_error_code = error_code

    def is_stale(self, ttl: int = DEFAULT_HEARTBEAT_TTL) -> bool:
        try:
            last = datetime.fromisoformat(self.last_seen_ts)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - last
            return delta.total_seconds() > ttl
        except Exception:
            return True

    def to_dict(self, *, redact: bool = False) -> Dict[str, Any]:
        state = self.state
        if state != "stale" and self.is_stale():
            state = "stale"

        base: Dict[str, Any] = {
            "module_id": self.module_id,
            "name": self.name,
            "version": self.version,
            "commit_hash": self.commit_hash if not redact else self.commit_hash[:8] + "...",
            "build_timestamp": self.build_timestamp,
            "node_id": self.node_id if not redact else "redacted",
            "state": state,
            "last_state_change_ts": self.last_state_change_ts,
            "health_summary": self.health_summary,
            "last_error_code": self.last_error_code,
            "breaker_state": self.breaker_state,
            "queue_depth": self.queue_depth,
            "registered_at": self.registered_at,
            "last_seen_ts": self.last_seen_ts,
            "uptime_seconds": self.uptime_seconds,
            "tenant_id": self.tenant_id,
            "dependency_summary": {
                name: dep.status for name, dep in self.dependencies.items()
            },
        }
        return base


# ---------------------------------------------------------------------------
# Registry store
# ---------------------------------------------------------------------------


class _RegistryStore:
    """Thread-safe, in-memory module registry with TTL enforcement."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._modules: Dict[str, ModuleRecord] = {}

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def register(self, record: ModuleRecord) -> None:
        """Register or re-register a module.  Idempotent on module_id."""
        with self._lock:
            existing = self._modules.get(record.module_id)
            if existing is not None:
                # Preserve runtime state, update metadata
                existing.version = record.version
                existing.commit_hash = record.commit_hash
                existing.build_timestamp = record.build_timestamp
                existing.node_id = record.node_id
                existing.tenant_id = record.tenant_id
                existing.heartbeat()
                log.info(
                    "module_registry.re_registered module_id=%s version=%s",
                    record.module_id,
                    record.version,
                )
            else:
                self._modules[record.module_id] = record
                log.info(
                    "module_registry.registered module_id=%s version=%s",
                    record.module_id,
                    record.version,
                )

    def heartbeat(self, module_id: str) -> bool:
        """Update last_seen_ts. Returns False if module not found."""
        with self._lock:
            rec = self._modules.get(module_id)
            if rec is None:
                return False
            rec.heartbeat()
            return True

    def set_state(
        self,
        module_id: str,
        state: ModuleState,
        *,
        error_code: Optional[str] = None,
        health_summary: str = "",
    ) -> bool:
        with self._lock:
            rec = self._modules.get(module_id)
            if rec is None:
                return False
            rec.set_state(state, error_code=error_code)
            if health_summary:
                rec.health_summary = health_summary
            return True

    def update_dependency(
        self,
        module_id: str,
        dep_name: str,
        *,
        status: DepStatus,
        latency_ms: Optional[float],
        error_code: Optional[str] = None,
        timeout_ms: Optional[int] = None,
    ) -> bool:
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            rec = self._modules.get(module_id)
            if rec is None:
                return False
            probe = rec.dependencies.get(dep_name)
            if probe is None:
                probe = DependencyProbe(name=dep_name)
                rec.dependencies[dep_name] = probe
            probe.status = status
            probe.latency_ms = latency_ms
            probe.measured_at_ts = now_ts
            probe.last_check_ts = now_ts
            probe.timeout_ms = timeout_ms
            probe.error_code = error_code
            return True

    def set_breaker_state(
        self, module_id: str, breaker_state: Optional[str]
    ) -> bool:
        with self._lock:
            rec = self._modules.get(module_id)
            if rec is None:
                return False
            rec.breaker_state = breaker_state
            return True

    def set_queue_depth(self, module_id: str, depth: int) -> bool:
        with self._lock:
            rec = self._modules.get(module_id)
            if rec is None:
                return False
            rec.queue_depth = max(0, int(depth))
            return True

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get(self, module_id: str) -> Optional[ModuleRecord]:
        with self._lock:
            return self._modules.get(module_id)

    def list_all(self) -> List[ModuleRecord]:
        with self._lock:
            return list(self._modules.values())

    def list_for_tenant(self, tenant_id: str) -> List[ModuleRecord]:
        """Return modules owned by this tenant OR platform-level modules."""
        with self._lock:
            return [
                r
                for r in self._modules.values()
                if r.tenant_id is None or r.tenant_id == tenant_id
            ]

    def get_dependencies(
        self, module_id: str
    ) -> Optional[Dict[str, DependencyProbe]]:
        with self._lock:
            rec = self._modules.get(module_id)
            if rec is None:
                return None
            return dict(rec.dependencies)

    def snapshot_for_api(
        self,
        *,
        tenant_id: Optional[str],
        is_global_admin: bool,
        redact: bool,
    ) -> List[Dict[str, Any]]:
        """Tenant-safe snapshot.  Global admins see all; tenant admins see their scope."""
        with self._lock:
            if is_global_admin:
                records = list(self._modules.values())
            elif tenant_id:
                records = [
                    r
                    for r in self._modules.values()
                    if r.tenant_id is None or r.tenant_id == tenant_id
                ]
            else:
                records = []
            return [r.to_dict(redact=redact) for r in records]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_store: Optional[_RegistryStore] = None
_store_lock = threading.Lock()


def get_registry() -> _RegistryStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = _RegistryStore()
    return _store


# ---------------------------------------------------------------------------
# Helper: canonical registration ID (deterministic from module_id + version + node_id)
# ---------------------------------------------------------------------------


def make_registration_hash(module_id: str, version: str, node_id: str) -> str:
    payload = {"module_id": module_id, "version": version, "node_id": node_id}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Self-registration helper for modules
# ---------------------------------------------------------------------------


def register_module(
    *,
    module_id: str,
    name: str,
    version: str,
    commit_hash: str,
    build_timestamp: str,
    node_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    initial_state: ModuleState = "starting",
) -> ModuleRecord:
    """
    Convenience helper for modules to self-register.

    Call this at startup before serving traffic.
    """
    if node_id is None:
        node_id = os.getenv("FG_NODE_ID", f"node-{uuid.uuid4().hex[:8]}")

    record = ModuleRecord(
        module_id=module_id,
        name=name,
        version=version,
        commit_hash=commit_hash,
        build_timestamp=build_timestamp,
        node_id=node_id,
        state=initial_state,
        tenant_id=tenant_id,
    )
    get_registry().register(record)
    return record
