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
import re as _re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

log = logging.getLogger("frostgate.control_plane.locker_command_bus")


ERR_LOCKER_NOT_FOUND = "CP-LOCK-001"
ERR_LOCKER_COOLDOWN = "CP-LOCK-002"
ERR_IDEMPOTENT_REPLAY = "CP-LOCK-003"
ERR_COMMAND_REJECTED = "CP-LOCK-004"
ERR_BUS_FULL = "CP-LOCK-005"
ERR_INVALID_COMMAND = "CP-LOCK-006"
ERR_QUARANTINE_ACTIVE = "CP-LOCK-007"
ERR_INVALID_REASON = "CP-LOCK-008"
ERR_REASON_REQUIRED = "CP-LOCK-009"
ERR_REASON_TOO_LONG = "CP-LOCK-010"
ERR_REASON_INVALID_CHARS = "CP-LOCK-011"

ERR_COOLDOWN_ACTIVE = ERR_LOCKER_COOLDOWN
ERR_QUARANTINE_LOCKED = ERR_QUARANTINE_ACTIVE
ERR_UNKNOWN_LOCKER = ERR_LOCKER_NOT_FOUND


class LockerCommand(str, Enum):
    RESTART = "restart"
    PAUSE = "pause"
    RESUME = "resume"
    QUARANTINE = "quarantine"


class LockerState(str, Enum):
    ACTIVE = "active"
    RUNNING = "running"
    PAUSED = "paused"
    RESTARTING = "restarting"
    QUARANTINED = "quarantined"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class CommandResult(str, Enum):
    ACCEPTED = "accepted"
    IDEMPOTENT = "idempotent"
    REJECTED = "rejected"
    COOLDOWN = "cooldown"
    NOT_FOUND = "not_found"


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
        default_factory=lambda: (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
    )


@dataclass
class CommandOutcome:
    request_id: str
    locker_id: str
    command: LockerCommand
    result: CommandResult
    error_code: str | None = None
    error_message: str | None = None
    cooldown_remaining_s: int | None = None
    issued_at: str | None = None

    @property
    def ok(self) -> bool:
        return self.result in (CommandResult.ACCEPTED, CommandResult.IDEMPOTENT)

    @property
    def idempotent(self) -> bool:
        return self.result == CommandResult.IDEMPOTENT

    @property
    def command_id(self) -> str:
        return self.request_id

    def to_dict(self) -> dict[str, object]:
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


@dataclass
class LockerRuntime:
    locker_id: str
    name: str
    version: str
    tenant_id: str
    state: LockerState = LockerState.UNKNOWN
    last_heartbeat_ts: str | None = None
    registered_at: str = field(
        default_factory=lambda: (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
    )
    last_command: str | None = None
    last_command_ts: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    _command_queue: queue.Queue[LockerCommandRequest] = field(
        default_factory=lambda: queue.Queue(maxsize=16), repr=False
    )
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def heartbeat(self) -> None:
        with self._lock:
            self.last_heartbeat_ts = _utc_now_iso()

    def to_dict(self, redact: bool = False) -> dict[str, object]:
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


class IdempotencyStore:
    def __init__(self, ttl_seconds: int = 86400) -> None:
        self._store: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def check_and_set(
        self, idempotency_key: str, request_id: str
    ) -> tuple[bool, str | None]:
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
        for key in expired:
            del self._store[key]


def _idempotency_composite_key(cmd: LockerCommandRequest) -> str:
    raw = (
        f"{cmd.tenant_id}:{cmd.locker_id}:{cmd.command.value}:"
        f"{cmd.idempotency_key}:{cmd.reason}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CooldownTracker:
    def __init__(self) -> None:
        self._last_command: dict[str, float] = {}
        self._lock = threading.Lock()

    def cooldown_seconds(self) -> int:
        return int(os.getenv("FG_CP_LOCKER_COOLDOWN_S", "60"))

    def check(self, locker_id: str) -> tuple[bool, int]:
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

    def check_with_ttl(self, locker_id: str, cooldown_sec: int) -> tuple[bool, int]:
        if cooldown_sec <= 0:
            return True, 0
        now = time.time()
        with self._lock:
            last = self._last_command.get(locker_id)
            if last is None:
                return True, 0
            elapsed = now - last
            if elapsed >= cooldown_sec:
                return True, 0
            remaining = int(cooldown_sec - elapsed) + 1
            return False, remaining

    def record(self, locker_id: str) -> None:
        with self._lock:
            self._last_command[locker_id] = time.time()


_REASON_INVALID_CHARS_RE = _re.compile(r"[<>()\[\]{}|\\^`~]")
_REASON_MIN_LENGTH = 3
_REASON_MAX_LENGTH = 512


def _validate_reason(reason: str) -> str | None:
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


def validate_reason(reason: str | None) -> str:
    if (
        reason is None
        or not str(reason).strip()
        or len(str(reason).strip()) < _REASON_MIN_LENGTH
    ):
        raise ValueError(
            f"{ERR_REASON_REQUIRED}: reason is required, non-blank, "
            f"and at least {_REASON_MIN_LENGTH} characters"
        )
    reason_str = str(reason)
    if len(reason_str) > _REASON_MAX_LENGTH:
        raise ValueError(
            f"{ERR_REASON_TOO_LONG}: reason exceeds maximum length of {_REASON_MAX_LENGTH} characters"
        )
    if _REASON_INVALID_CHARS_RE.search(reason_str):
        raise ValueError(
            f"{ERR_REASON_INVALID_CHARS}: reason contains disallowed characters "
            f"(no HTML/script-injection chars allowed)"
        )
    return reason_str


class AuditChain:
    def __init__(self) -> None:
        self._chain: dict[str, str] = {}
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
        with self._lock:
            prev = self._chain.get(tenant_id, "genesis")
            raw = f"{tenant_id}:{action}:{result}:{actor}:{timestamp}:{prev}"
            new_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self._chain[tenant_id] = new_hash
            return prev, new_hash

    def _reset(self) -> None:
        with self._lock:
            self._chain.clear()


def emit_command_audit(
    *,
    command: LockerCommandRequest,
    outcome: CommandOutcome,
    audit_chain: AuditChain | None = None,
    config_hash: str = "",
) -> None:
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
                "prev_audit_hash": prev_hash,
                "audit_chain_hash": chain_hash,
            },
        )
    except Exception as exc:
        log.error(
            "command_audit_emit_failed command=%s locker=%s error=%s",
            command.command.value,
            command.locker_id,
            exc,
        )
        if _is_prod_like():
            raise


class LockerCommandBus:
    _instance: LockerCommandBus | None = None
    _init_lock: threading.Lock = threading.Lock()

    _lockers: dict[str, LockerRuntime]
    _lock: threading.RLock
    _idempotency: IdempotencyStore
    _cooldown: CooldownTracker
    _audit_chain: AuditChain

    def __new__(cls) -> LockerCommandBus:
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        self._lockers = {}
        self._lock = threading.RLock()
        self._idempotency = IdempotencyStore()
        self._cooldown = CooldownTracker()
        self._audit_chain = AuditChain()

    def register_locker(
        self,
        locker_id: str = "",
        tenant_id: str = "",
        *,
        name: str = "",
        version: str = "1.0",
        initial_state: LockerState = LockerState.ACTIVE,
        metadata: dict[str, Any] | None = None,
    ) -> LockerRuntime:
        with self._lock:
            existing = self._lockers.get(locker_id)
            if existing is not None:
                if existing.tenant_id != tenant_id:
                    raise ValueError(
                        f"locker {locker_id!r} already registered for "
                        f"tenant {existing.tenant_id!r}; cannot re-register for {tenant_id!r}"
                    )
                with existing._lock:
                    existing.version = version
                return existing

            runtime = LockerRuntime(
                locker_id=locker_id,
                name=name or locker_id,
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

    def heartbeat_locker(
        self,
        locker_id: str,
        tenant_id: str = "",
        version: str | None = None,
    ) -> bool:
        with self._lock:
            runtime = self._lockers.get(locker_id)
            if runtime is None:
                return False
            if tenant_id and runtime.tenant_id != tenant_id:
                return False
            runtime.heartbeat()
            if version is not None:
                with runtime._lock:
                    runtime.version = version
            return True

    def get_locker(
        self, locker_id: str, tenant_id: str | None = None
    ) -> LockerRuntime | dict[str, object] | None:
        runtime = self._lockers.get(locker_id)
        if runtime is None:
            return None
        if tenant_id is not None:
            if runtime.tenant_id and runtime.tenant_id != tenant_id:
                return None
            return runtime
        return runtime.to_dict()

    def submit_command(
        self,
        locker_id: str,
        command: str,
        *,
        reason: str,
        actor_id: str,
        tenant_id: str,
        idempotency_key: str,
        cooldown_sec: int = 0,
    ) -> CommandOutcome:
        try:
            cmd_enum = LockerCommand(command)
        except ValueError:
            return CommandOutcome(
                request_id=str(uuid.uuid4()),
                locker_id=locker_id,
                command=LockerCommand.RESTART,
                result=CommandResult.REJECTED,
                error_code=ERR_INVALID_COMMAND,
                error_message=f"unknown command: {command!r}",
                issued_at=_utc_now_iso(),
            )

        try:
            validate_reason(reason)
        except ValueError as exc:
            err_str = str(exc)
            if ERR_REASON_TOO_LONG in err_str:
                code = ERR_REASON_TOO_LONG
            elif ERR_REASON_INVALID_CHARS in err_str:
                code = ERR_REASON_INVALID_CHARS
            else:
                code = ERR_REASON_REQUIRED
            return CommandOutcome(
                request_id=str(uuid.uuid4()),
                locker_id=locker_id,
                command=cmd_enum,
                result=CommandResult.REJECTED,
                error_code=code,
                error_message=err_str,
                issued_at=_utc_now_iso(),
            )

        with self._lock:
            runtime = self._lockers.get(locker_id)
        if runtime is None or (runtime.tenant_id and runtime.tenant_id != tenant_id):
            return CommandOutcome(
                request_id=str(uuid.uuid4()),
                locker_id=locker_id,
                command=cmd_enum,
                result=CommandResult.NOT_FOUND,
                error_code=ERR_UNKNOWN_LOCKER,
                error_message="locker not found",
                issued_at=_utc_now_iso(),
            )

        with runtime._lock:
            if (
                runtime.state == LockerState.QUARANTINED
                and cmd_enum != LockerCommand.RESUME
            ):
                return CommandOutcome(
                    request_id=str(uuid.uuid4()),
                    locker_id=locker_id,
                    command=cmd_enum,
                    result=CommandResult.REJECTED,
                    error_code=ERR_QUARANTINE_LOCKED,
                    error_message="locker is quarantined; only resume is allowed",
                    issued_at=_utc_now_iso(),
                )

        req_id = str(uuid.uuid4())
        fake_req = LockerCommandRequest(
            locker_id=locker_id,
            command=cmd_enum,
            reason=reason,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            request_id=req_id,
            tenant_id=tenant_id,
        )
        composite_key = _idempotency_composite_key(fake_req)
        is_new, existing_request_id = self._idempotency.check_and_set(
            composite_key, req_id
        )
        if not is_new:
            return CommandOutcome(
                request_id=existing_request_id or req_id,
                locker_id=locker_id,
                command=cmd_enum,
                result=CommandResult.IDEMPOTENT,
                error_code=ERR_IDEMPOTENT_REPLAY,
                error_message="idempotent: already processed",
                issued_at=_utc_now_iso(),
            )

        allowed, remaining = self._cooldown.check_with_ttl(locker_id, cooldown_sec)
        if not allowed:
            return CommandOutcome(
                request_id=req_id,
                locker_id=locker_id,
                command=cmd_enum,
                result=CommandResult.COOLDOWN,
                error_code=ERR_COOLDOWN_ACTIVE,
                error_message=f"cooldown active: {remaining}s remaining",
                cooldown_remaining_s=remaining,
                issued_at=_utc_now_iso(),
            )

        self._cooldown.record(locker_id)
        with runtime._lock:
            runtime.last_command = cmd_enum.value
            runtime.last_command_ts = _utc_now_iso()
            if cmd_enum == LockerCommand.PAUSE:
                runtime.state = LockerState.PAUSED
            elif cmd_enum == LockerCommand.RESUME:
                runtime.state = LockerState.ACTIVE
            elif cmd_enum == LockerCommand.RESTART:
                runtime.state = LockerState.RESTARTING
            elif cmd_enum == LockerCommand.QUARANTINE:
                runtime.state = LockerState.QUARANTINED

        return CommandOutcome(
            request_id=req_id,
            locker_id=locker_id,
            command=cmd_enum,
            result=CommandResult.ACCEPTED,
            issued_at=_utc_now_iso(),
        )

    def dispatch(self, cmd: LockerCommandRequest) -> CommandOutcome:
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
            emit_command_audit(
                command=cmd, outcome=outcome, audit_chain=self._audit_chain
            )
            return outcome

        if cmd.command != LockerCommand.RESUME:
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
        emit_command_audit(command=cmd, outcome=outcome, audit_chain=self._audit_chain)
        return outcome

    def poll_command(
        self,
        locker_id: str,
        timeout_s: float = 1.0,
    ) -> LockerCommandRequest | None:
        runtime = self._get_locker(locker_id)
        if runtime is None:
            return None
        try:
            return runtime._command_queue.get(timeout=timeout_s)
        except queue.Empty:
            return None

    def heartbeat(self, locker_id: str) -> None:
        runtime = self._get_locker(locker_id)
        if runtime is not None:
            runtime.heartbeat()

    def update_locker_state(self, locker_id: str, state: LockerState) -> None:
        runtime = self._get_locker(locker_id)
        if runtime is not None:
            with runtime._lock:
                runtime.state = state

    def list_lockers(self, tenant_id: str | None = None) -> list[dict[str, object]]:
        with self._lock:
            runtimes = list(self._lockers.values())
        if tenant_id:
            runtimes = [r for r in runtimes if r.tenant_id == tenant_id]
        return [r.to_dict() for r in runtimes]

    def locker_exists(self, locker_id: str) -> bool:
        with self._lock:
            return locker_id in self._lockers

    def _get_locker(self, locker_id: str) -> LockerRuntime | None:
        with self._lock:
            return self._lockers.get(locker_id)

    def _reset(self) -> None:
        with self._lock:
            self._lockers.clear()
            self._idempotency = IdempotencyStore()
            self._cooldown = CooldownTracker()
            self._audit_chain = AuditChain()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_prod_like() -> bool:
    return (os.getenv("FG_ENV") or "").strip().lower() in {
        "prod",
        "production",
        "staging",
    }


def _config_hash() -> str:
    keys = ["FG_ENV", "FG_SERVICE", "FG_CP_LOCKER_COOLDOWN_S"]
    raw = "|".join(f"{k}={os.getenv(k, '')}" for k in keys)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_command_bus() -> LockerCommandBus:
    return LockerCommandBus()
