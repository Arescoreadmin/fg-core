"""
FrostGate Control Plane - Locker Command Bus

Safe in-process command bus for locker runtime control.

SECURITY INVARIANTS:
- Zero subprocess / shell execution. All control is in-process via queues.
- Idempotency enforced per composite key (tenant_id + locker_id + cmd + user_key).
- Cooldown per locker enforced (configurable, default 60s).
- Every command produces a deterministic audit ledger entry.
- Fail-closed: unknown lockers or expired keys always return error.
- Rate limiting enforced at the API layer; bus enforces cooldown.

P1 Hardening:
- Reason charset: printable ASCII only (0x20–0x7E). Blank or control chars rejected.
- Idempotency: composite key = SHA-256(tenant_id + locker_id + cmd + user_key).
  Same user-supplied key across different tenants CANNOT collide.
- Hash-chained audit: each tenant's audit chain carries prev_audit_hash so entries
  are tamper-evident within a process lifetime.
"""
from __future__ import annotations

import hashlib
import logging
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("frostgate.control_plane.locker_command_bus")


# ---------------------------------------------------------------------------
# Deterministic error codes
# ---------------------------------------------------------------------------
ERR_LOCKER_NOT_FOUND = "CP-LOCK-001"
ERR_LOCKER_COOLDOWN = "CP-LOCK-002"
ERR_IDEMPOTENT_REPLAY = "CP-LOCK-003"
ERR_COMMAND_REJECTED = "CP-LOCK-004"
ERR_BUS_FULL = "CP-LOCK-005"
ERR_INVALID_COMMAND = "CP-LOCK-006"
ERR_QUARANTINE_ACTIVE = "CP-LOCK-007"
ERR_INVALID_REASON = "CP-LOCK-008"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class LockerCommand(str, Enum):
    RESTART = "restart"
    PAUSE = "pause"
    RESUME = "resume"
    QUARANTINE = "quarantine"


class LockerState(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    RESTARTING = "restarting"
    QUARANTINED = "quarantined"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class CommandResult(str, Enum):
    ACCEPTED = "accepted"
    IDEMPOTENT = "idempotent"   # same key, same result
    REJECTED = "rejected"
    COOLDOWN = "cooldown"
    NOT_FOUND = "not_found"


# ---------------------------------------------------------------------------
# Command request
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LockerCommandRequest:
    locker_id: str
    command: LockerCommand
    reason: str
    actor_id: str
    idempotency_key: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "unknown"
    issued_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass
class CommandOutcome:
    request_id: str
    locker_id: str
    command: LockerCommand
    result: CommandResult
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    cooldown_remaining_s: Optional[int] = None
    issued_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "locker_id": self.locker_id,
            "command": self.command.value,
            "result": self.result.value,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "cooldown_remaining_s": self.cooldown_remaining_s,
            "issued_at": self.issued_at,
        }


# ---------------------------------------------------------------------------
# Locker runtime record (managed by the bus)
# ---------------------------------------------------------------------------

@dataclass
class LockerRuntime:
    locker_id: str
    name: str
    version: str
    tenant_id: str
    state: LockerState = LockerState.UNKNOWN
    last_heartbeat_ts: Optional[str] = None
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    last_command: Optional[str] = None
    last_command_ts: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Internal - command channel for this locker
    _command_queue: queue.Queue = field(
        default_factory=lambda: queue.Queue(maxsize=16), repr=False
    )
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def heartbeat(self) -> None:
        with self._lock:
            self.last_heartbeat_ts = _utc_now_iso()

    def to_dict(self, redact: bool = False) -> dict:
        with self._lock:
            return {
                "locker_id": self.locker_id,
                "name": self.name,
                "version": self.version,
                "tenant_id": self.tenant_id if not redact else None,
                "state": self.state.value,
                "last_heartbeat_ts": self.last_heartbeat_ts,
                "registered_at": self.registered_at,
                "last_command": self.last_command,
                "last_command_ts": self.last_command_ts,
            }


# ---------------------------------------------------------------------------
# Idempotency store (P1: tenant-scoped composite keys)
# ---------------------------------------------------------------------------

class IdempotencyStore:
    """
    In-memory idempotency key store with TTL.
    Keys expire after TTL (default 86400s = 24h).

    P1: Keys are composite — callers should pass a tenant-scoped key via
    _idempotency_composite_key(). The store itself is key-agnostic.
    """

    def __init__(self, ttl_seconds: int = 86400) -> None:
        self._store: Dict[str, tuple[str, float]] = {}  # key -> (request_id, expiry)
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def check_and_set(
        self, idempotency_key: str, request_id: str
    ) -> tuple[bool, Optional[str]]:
        """
        Returns (is_new, existing_request_id).
        If is_new=True, the key was fresh and has been recorded.
        If is_new=False, returns the original request_id (idempotent replay).
        """
        now = time.time()
        with self._lock:
            self._evict_expired(now)
            existing = self._store.get(idempotency_key)
            if existing is not None:
                stored_request_id, expiry = existing
                if now < expiry:
                    return False, stored_request_id

            self._store[idempotency_key] = (request_id, now + self._ttl)
            return True, None

    def _evict_expired(self, now: float) -> None:
        expired = [k for k, (_, expiry) in self._store.items() if now >= expiry]
        for k in expired:
            del self._store[k]


def _idempotency_composite_key(cmd: "LockerCommandRequest") -> str:
    """
    Build a tenant-scoped composite idempotency key.

    P1: Ensures same user-supplied key across different tenants
    cannot collide in the idempotency store.

    Key input: tenant_id + locker_id + command + user_idempotency_key
    """
    raw = f"{cmd.tenant_id}:{cmd.locker_id}:{cmd.command.value}:{cmd.idempotency_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Cooldown tracker
# ---------------------------------------------------------------------------

class CooldownTracker:
    """
    Per-locker command cooldown enforcement.
    Default cooldown: FG_CP_LOCKER_COOLDOWN_S env (default 60s).
    """

    def __init__(self) -> None:
        self._last_command: Dict[str, float] = {}
        self._lock = threading.Lock()

    def cooldown_seconds(self) -> int:
        return int(os.getenv("FG_CP_LOCKER_COOLDOWN_S", "60"))

    def check(self, locker_id: str) -> tuple[bool, int]:
        """Returns (allowed, remaining_seconds)."""
        now = time.time()
        cooldown = self.cooldown_seconds()
        with self._lock:
            last = self._last_command.get(locker_id)
            if last is None:
                return True, 0
            elapsed = now - last
            if elapsed >= cooldown:
                return True, 0
            remaining = int(cooldown - elapsed) + 1
            return False, remaining

    def record(self, locker_id: str) -> None:
        with self._lock:
            self._last_command[locker_id] = time.time()


# ---------------------------------------------------------------------------
# Reason charset validation (P1)
# ---------------------------------------------------------------------------

def _validate_reason(reason: str) -> Optional[str]:
    """
    Validate that reason contains only printable ASCII characters (0x20–0x7E).
    Returns an error message string if invalid, or None if valid.
    """
    if not reason or not reason.strip():
        return "reason is required and must not be blank"
    for idx, ch in enumerate(reason):
        code = ord(ch)
        if code < 0x20 or code > 0x7E:
            return (
                f"reason contains invalid character at position {idx} "
                f"(U+{code:04X}); only printable ASCII (0x20–0x7E) is allowed"
            )
    return None


# ---------------------------------------------------------------------------
# Hash-chained audit ledger (P1)
# ---------------------------------------------------------------------------

class AuditChain:
    """
    Per-tenant hash chain for tamper-evident audit entries within a session.

    Each entry carries:
      - prev_audit_hash: SHA-256 of the previous entry (or "genesis" for first)
      - audit_chain_hash: SHA-256 of this entry's content + prev_audit_hash

    Provides tamper evidence within a process lifetime. Not persistent across
    restarts (an out-of-band audit export system handles persistence).
    """

    def __init__(self) -> None:
        self._chain: Dict[str, str] = {}  # tenant_id -> last_hash
        self._lock = threading.Lock()

    def record(
        self,
        *,
        tenant_id: str,
        action: str,
        result: str,
        actor: str,
        timestamp: str,
    ) -> tuple[str, str]:
        """
        Returns (prev_hash, new_hash) and advances the chain.
        Thread-safe.
        """
        with self._lock:
            prev = self._chain.get(tenant_id, "genesis")
            raw = f"{tenant_id}:{action}:{result}:{actor}:{timestamp}:{prev}"
            new_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self._chain[tenant_id] = new_hash
            return prev, new_hash

    def _reset(self) -> None:
        with self._lock:
            self._chain.clear()


# ---------------------------------------------------------------------------
# Audit ledger entry emitter
# ---------------------------------------------------------------------------

def emit_command_audit(
    *,
    command: "LockerCommandRequest",
    outcome: CommandOutcome,
    audit_chain: Optional["AuditChain"] = None,
    config_hash: str = "",
) -> None:
    """
    Emit a deterministic audit ledger entry for every control action.
    No control action without audit. This is a hard invariant.

    P1: Includes prev_audit_hash and audit_chain_hash for tamper evidence.
    """
    from api.security_audit import audit_admin_action

    now = _utc_now_iso()
    prev_hash = "genesis"
    chain_hash = ""

    if audit_chain is not None:
        prev_hash, chain_hash = audit_chain.record(
            tenant_id=command.tenant_id,
            action=command.command.value,
            result=outcome.result.value,
            actor=command.actor_id,
            timestamp=now,
        )

    try:
        audit_admin_action(
            action=f"locker_{command.command.value}",
            tenant_id=command.tenant_id,
            details={
                "audit_type": "locker_control",
                "actor": command.actor_id,
                "target_module": "locker",
                "target_id": command.locker_id,
                "reason": command.reason,
                "request_id": command.request_id,
                "tenant_id": command.tenant_id,
                "result": outcome.result.value,
                "error_code": outcome.error_code,
                "config_hash": config_hash or _config_hash(),
                "idempotency_key": command.idempotency_key,
                "command": command.command.value,
                # P1: Hash chain fields
                "prev_audit_hash": prev_hash,
                "audit_chain_hash": chain_hash,
            },
        )
    except Exception as e:
        log.error(
            "command_audit_emit_failed command=%s locker=%s error=%s",
            command.command.value,
            command.locker_id,
            e,
        )
        # In production: re-raise to enforce no-audit = no-action
        if _is_prod_like():
            raise


# ---------------------------------------------------------------------------
# Command Bus
# ---------------------------------------------------------------------------

class LockerCommandBus:
    """
    Singleton in-process command bus for locker runtime control.

    NO subprocess. NO shell. Pure queue-based in-process control.
    Lockers subscribe via register_locker() and poll their command queues.

    P1 Hardening:
    - Reason must be printable ASCII, max 512 chars.
    - Idempotency keys are tenant-scoped composites (cross-tenant isolation).
    - Audit entries are hash-chained per tenant for tamper evidence.
    """

    _instance: Optional["LockerCommandBus"] = None
    _init_lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "LockerCommandBus":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._lockers: Dict[str, LockerRuntime] = {}
                    obj._lock = threading.RLock()
                    obj._idempotency = IdempotencyStore()
                    obj._cooldown = CooldownTracker()
                    obj._audit_chain = AuditChain()  # P1: hash-chained audit
                    cls._instance = obj
        return cls._instance

    # ------------------------------------------------------------------
    # Locker registration (called by locker at startup)
    # ------------------------------------------------------------------

    def register_locker(
        self,
        *,
        locker_id: str,
        name: str,
        version: str,
        tenant_id: str,
        initial_state: LockerState = LockerState.RUNNING,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LockerRuntime:
        with self._lock:
            runtime = LockerRuntime(
                locker_id=locker_id,
                name=name,
                version=version,
                tenant_id=tenant_id,
                state=initial_state,
                metadata=metadata or {},
            )
            self._lockers[locker_id] = runtime
            log.info(
                "locker_registered locker_id=%s tenant_id=%s",
                locker_id,
                tenant_id,
            )
            return runtime

    def deregister_locker(self, locker_id: str) -> None:
        with self._lock:
            self._lockers.pop(locker_id, None)

    # ------------------------------------------------------------------
    # Command dispatch (called by API)
    # ------------------------------------------------------------------

    def dispatch(
        self,
        cmd: LockerCommandRequest,
    ) -> CommandOutcome:
        """
        Dispatch a command to the target locker.

        Enforces (in order):
        1. Reason validation: not blank, printable ASCII, max 512 chars
        2. Locker existence
        3. Quarantine guard
        4. Idempotency (tenant-scoped composite key)
        5. Cooldown
        6. Queue delivery
        7. Record cooldown + update runtime state
        All paths call emit_command_audit() before returning.
        """
        # 1. Validate reason: required, printable ASCII, max 512 chars
        reason_error = _validate_reason(cmd.reason)
        if reason_error:
            outcome = CommandOutcome(
                request_id=cmd.request_id,
                locker_id=cmd.locker_id,
                command=cmd.command,
                result=CommandResult.REJECTED,
                error_code=ERR_INVALID_REASON,
                error_message=reason_error,
                issued_at=_utc_now_iso(),
            )
            emit_command_audit(
                command=cmd, outcome=outcome, audit_chain=self._audit_chain
            )
            return outcome

        if len(cmd.reason) > 512:
            outcome = CommandOutcome(
                request_id=cmd.request_id,
                locker_id=cmd.locker_id,
                command=cmd.command,
                result=CommandResult.REJECTED,
                error_code=ERR_INVALID_REASON,
                error_message="reason exceeds maximum length of 512 characters",
                issued_at=_utc_now_iso(),
            )
            emit_command_audit(
                command=cmd, outcome=outcome, audit_chain=self._audit_chain
            )
            return outcome

        # 2. Locker existence check
        runtime = self._get_locker(cmd.locker_id)
        if runtime is None:
            outcome = CommandOutcome(
                request_id=cmd.request_id,
                locker_id=cmd.locker_id,
                command=cmd.command,
                result=CommandResult.NOT_FOUND,
                error_code=ERR_LOCKER_NOT_FOUND,
                error_message="locker not registered",
                issued_at=_utc_now_iso(),
            )
            emit_command_audit(
                command=cmd, outcome=outcome, audit_chain=self._audit_chain
            )
            return outcome

        # 3. Quarantine guard: quarantined lockers reject non-resume commands
        with runtime._lock:
            if (
                runtime.state == LockerState.QUARANTINED
                and cmd.command != LockerCommand.RESUME
            ):
                outcome = CommandOutcome(
                    request_id=cmd.request_id,
                    locker_id=cmd.locker_id,
                    command=cmd.command,
                    result=CommandResult.REJECTED,
                    error_code=ERR_QUARANTINE_ACTIVE,
                    error_message="locker is quarantined; only resume is allowed",
                    issued_at=_utc_now_iso(),
                )
                emit_command_audit(
                    command=cmd, outcome=outcome, audit_chain=self._audit_chain
                )
                return outcome

        # 4. Idempotency check (P1: tenant-scoped composite key)
        composite_key = _idempotency_composite_key(cmd)
        is_new, existing_request_id = self._idempotency.check_and_set(
            composite_key, cmd.request_id
        )
        if not is_new:
            log.info(
                "idempotent_replay idempotency_key=%s locker_id=%s tenant=%s",
                cmd.idempotency_key,
                cmd.locker_id,
                cmd.tenant_id,
            )
            outcome = CommandOutcome(
                request_id=existing_request_id or cmd.request_id,
                locker_id=cmd.locker_id,
                command=cmd.command,
                result=CommandResult.IDEMPOTENT,
                error_code=ERR_IDEMPOTENT_REPLAY,
                error_message="idempotent: already processed",
                issued_at=_utc_now_iso(),
            )
            # Still emit audit for idempotent replays
            emit_command_audit(
                command=cmd, outcome=outcome, audit_chain=self._audit_chain
            )
            return outcome

        # 5. Cooldown check
        allowed, remaining = self._cooldown.check(cmd.locker_id)
        if not allowed:
            outcome = CommandOutcome(
                request_id=cmd.request_id,
                locker_id=cmd.locker_id,
                command=cmd.command,
                result=CommandResult.COOLDOWN,
                error_code=ERR_LOCKER_COOLDOWN,
                error_message=f"cooldown active: {remaining}s remaining",
                cooldown_remaining_s=remaining,
                issued_at=_utc_now_iso(),
            )
            emit_command_audit(
                command=cmd, outcome=outcome, audit_chain=self._audit_chain
            )
            return outcome

        # 6. Queue delivery (no subprocess)
        try:
            runtime._command_queue.put_nowait(cmd)
        except queue.Full:
            outcome = CommandOutcome(
                request_id=cmd.request_id,
                locker_id=cmd.locker_id,
                command=cmd.command,
                result=CommandResult.REJECTED,
                error_code=ERR_BUS_FULL,
                error_message="locker command queue full",
                issued_at=_utc_now_iso(),
            )
            emit_command_audit(
                command=cmd, outcome=outcome, audit_chain=self._audit_chain
            )
            return outcome

        # 7. Record cooldown & update runtime state
        self._cooldown.record(cmd.locker_id)
        with runtime._lock:
            runtime.last_command = cmd.command.value
            runtime.last_command_ts = _utc_now_iso()
            if cmd.command == LockerCommand.PAUSE:
                runtime.state = LockerState.PAUSED
            elif cmd.command == LockerCommand.RESUME:
                runtime.state = LockerState.RUNNING
            elif cmd.command == LockerCommand.RESTART:
                runtime.state = LockerState.RESTARTING
            elif cmd.command == LockerCommand.QUARANTINE:
                runtime.state = LockerState.QUARANTINED

        log.info(
            "locker_command_dispatched locker_id=%s command=%s actor=%s tenant=%s",
            cmd.locker_id,
            cmd.command.value,
            cmd.actor_id,
            cmd.tenant_id,
        )

        outcome = CommandOutcome(
            request_id=cmd.request_id,
            locker_id=cmd.locker_id,
            command=cmd.command,
            result=CommandResult.ACCEPTED,
            issued_at=_utc_now_iso(),
        )
        emit_command_audit(
            command=cmd, outcome=outcome, audit_chain=self._audit_chain
        )
        return outcome

    # ------------------------------------------------------------------
    # Locker-side: poll for commands (called by locker worker threads)
    # ------------------------------------------------------------------

    def poll_command(
        self,
        locker_id: str,
        timeout_s: float = 1.0,
    ) -> Optional[LockerCommandRequest]:
        """
        Called by locker worker threads to receive commands.
        Returns None if no command within timeout.
        NO subprocess. Lockers self-execute controlled actions.
        """
        runtime = self._get_locker(locker_id)
        if runtime is None:
            return None
        try:
            return runtime._command_queue.get(timeout=timeout_s)
        except queue.Empty:
            return None

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def heartbeat(self, locker_id: str) -> None:
        runtime = self._get_locker(locker_id)
        if runtime:
            runtime.heartbeat()

    def update_locker_state(self, locker_id: str, state: LockerState) -> None:
        runtime = self._get_locker(locker_id)
        if runtime:
            with runtime._lock:
                runtime.state = state

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_lockers(self, tenant_id: Optional[str] = None) -> List[dict]:
        with self._lock:
            runtimes = list(self._lockers.values())
        if tenant_id:
            runtimes = [r for r in runtimes if r.tenant_id == tenant_id]
        return [r.to_dict() for r in runtimes]

    def get_locker(self, locker_id: str) -> Optional[dict]:
        runtime = self._get_locker(locker_id)
        if runtime is None:
            return None
        return runtime.to_dict()

    def locker_exists(self, locker_id: str) -> bool:
        with self._lock:
            return locker_id in self._lockers

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_locker(self, locker_id: str) -> Optional[LockerRuntime]:
        with self._lock:
            return self._lockers.get(locker_id)

    def _reset(self) -> None:
        """For testing only."""
        with self._lock:
            self._lockers.clear()
            self._idempotency = IdempotencyStore()
            self._cooldown = CooldownTracker()
            self._audit_chain = AuditChain()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_prod_like() -> bool:
    return (os.getenv("FG_ENV") or "").strip().lower() in {
        "prod", "production", "staging"
    }


def _config_hash() -> str:
    """Deterministic hash of relevant config for audit."""
    keys = ["FG_ENV", "FG_SERVICE", "FG_CP_LOCKER_COOLDOWN_S"]
    raw = "|".join(f"{k}={os.getenv(k, '')}" for k in keys)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
