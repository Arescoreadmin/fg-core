# api/graceful_shutdown.py
"""
Graceful Shutdown Handling for Kubernetes/Docker.

Provides production-grade shutdown handling:
- SIGTERM/SIGINT signal handling
- Graceful connection draining
- Health check status updates
- Configurable shutdown timeout
- Cleanup hooks for resources
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional

log = logging.getLogger("frostgate.shutdown")

# =============================================================================
# Configuration
# =============================================================================


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default


# Shutdown configuration
SHUTDOWN_TIMEOUT = _env_int("FG_SHUTDOWN_TIMEOUT", 30)  # seconds
DRAIN_TIMEOUT = _env_int("FG_DRAIN_TIMEOUT", 10)  # seconds for connection draining


class ShutdownState(str, Enum):
    """Server shutdown states."""

    RUNNING = "running"
    DRAINING = "draining"  # Accepting no new requests, finishing current ones
    SHUTTING_DOWN = "shutting_down"  # Executing cleanup hooks
    STOPPED = "stopped"


@dataclass
class ShutdownStatus:
    """Current shutdown status."""

    state: ShutdownState
    started_at: Optional[float] = None
    drain_started_at: Optional[float] = None
    active_connections: int = 0
    pending_tasks: int = 0
    message: Optional[str] = None


class GracefulShutdownManager:
    """
    Manages graceful shutdown for the application.

    Features:
    - Signal handling (SIGTERM, SIGINT)
    - Connection draining period
    - Cleanup hooks for resources
    - Health check integration

    Usage:
        manager = GracefulShutdownManager()
        manager.register_cleanup_hook(cleanup_database)
        manager.register_cleanup_hook(cleanup_redis)
        await manager.setup()

        # In health check:
        if manager.is_shutting_down:
            return {"status": "draining"}
    """

    def __init__(
        self,
        shutdown_timeout: int = SHUTDOWN_TIMEOUT,
        drain_timeout: int = DRAIN_TIMEOUT,
    ):
        self.shutdown_timeout = shutdown_timeout
        self.drain_timeout = drain_timeout

        self._state = ShutdownState.RUNNING
        self._shutdown_event = asyncio.Event()
        self._drain_complete_event = asyncio.Event()
        self._cleanup_hooks: List[Callable] = []
        self._active_connections = 0
        self._started_at: Optional[float] = None
        self._drain_started_at: Optional[float] = None
        self._shutdown_reason: Optional[str] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def state(self) -> ShutdownState:
        """Current shutdown state."""
        return self._state

    @property
    def is_running(self) -> bool:
        """Check if server is running normally."""
        return self._state == ShutdownState.RUNNING

    @property
    def is_draining(self) -> bool:
        """Check if server is draining connections."""
        return self._state == ShutdownState.DRAINING

    @property
    def is_shutting_down(self) -> bool:
        """Check if server is shutting down (draining or later)."""
        return self._state in (
            ShutdownState.DRAINING,
            ShutdownState.SHUTTING_DOWN,
            ShutdownState.STOPPED,
        )

    @property
    def is_healthy(self) -> bool:
        """Check if server is healthy (for readiness probe)."""
        return self._state == ShutdownState.RUNNING

    def get_status(self) -> ShutdownStatus:
        """Get current shutdown status."""
        return ShutdownStatus(
            state=self._state,
            started_at=self._started_at,
            drain_started_at=self._drain_started_at,
            active_connections=self._active_connections,
            pending_tasks=len(asyncio.all_tasks()) if self._loop else 0,
            message=self._shutdown_reason,
        )

    def register_cleanup_hook(self, hook: Callable) -> None:
        """
        Register a cleanup hook to run during shutdown.

        Hooks are run in reverse order of registration (LIFO).
        Hooks can be sync or async functions.
        """
        self._cleanup_hooks.append(hook)
        log.debug(f"Registered cleanup hook: {hook.__name__}")

    def increment_connections(self) -> None:
        """Increment active connection count."""
        self._active_connections += 1

    def decrement_connections(self) -> None:
        """Decrement active connection count."""
        self._active_connections = max(0, self._active_connections - 1)

        # Check if drain is complete
        if self._state == ShutdownState.DRAINING and self._active_connections == 0:
            self._drain_complete_event.set()

    async def setup(self) -> None:
        """
        Set up signal handlers for graceful shutdown.

        Call this during application startup.
        """
        self._loop = asyncio.get_event_loop()

        # Register signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                self._loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(self._handle_signal(s)),
                )
                log.info(f"Registered signal handler for {sig.name}")
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                log.warning(f"Signal handler not supported for {sig.name}")

    async def _handle_signal(self, sig: signal.Signals) -> None:
        """Handle shutdown signal."""
        log.info(f"Received {sig.name}, initiating graceful shutdown")
        self._shutdown_reason = f"Signal {sig.name}"
        await self.initiate_shutdown()

    async def initiate_shutdown(self, reason: Optional[str] = None) -> None:
        """
        Initiate graceful shutdown.

        1. Enter DRAINING state (stop accepting new requests)
        2. Wait for connections to drain (or timeout)
        3. Run cleanup hooks
        4. Enter STOPPED state
        """
        if self._state != ShutdownState.RUNNING:
            log.warning(f"Shutdown already in progress (state={self._state.value})")
            return

        self._started_at = time.time()
        self._shutdown_reason = reason or self._shutdown_reason
        log.info(f"Initiating graceful shutdown: {self._shutdown_reason}")

        # Enter draining state
        await self._drain_connections()

        # Run cleanup hooks
        await self._run_cleanup_hooks()

        # Enter stopped state
        self._state = ShutdownState.STOPPED
        self._shutdown_event.set()
        log.info("Graceful shutdown complete")

    async def _drain_connections(self) -> None:
        """Drain active connections."""
        self._state = ShutdownState.DRAINING
        self._drain_started_at = time.time()

        log.info(
            f"Draining connections (active={self._active_connections}, "
            f"timeout={self.drain_timeout}s)"
        )

        if self._active_connections == 0:
            log.info("No active connections to drain")
            return

        try:
            await asyncio.wait_for(
                self._drain_complete_event.wait(),
                timeout=self.drain_timeout,
            )
            log.info("All connections drained successfully")
        except asyncio.TimeoutError:
            log.warning(
                f"Drain timeout reached with {self._active_connections} "
                f"active connections"
            )

    async def _run_cleanup_hooks(self) -> None:
        """Run registered cleanup hooks."""
        self._state = ShutdownState.SHUTTING_DOWN

        # Run hooks in reverse order (LIFO)
        for hook in reversed(self._cleanup_hooks):
            hook_name = getattr(hook, "__name__", str(hook))
            try:
                log.info(f"Running cleanup hook: {hook_name}")
                if asyncio.iscoroutinefunction(hook):
                    await asyncio.wait_for(
                        hook(),
                        timeout=self.shutdown_timeout / len(self._cleanup_hooks)
                        if self._cleanup_hooks
                        else self.shutdown_timeout,
                    )
                else:
                    hook()
                log.info(f"Cleanup hook completed: {hook_name}")
            except asyncio.TimeoutError:
                log.error(f"Cleanup hook timed out: {hook_name}")
            except Exception as e:
                log.exception(f"Cleanup hook failed: {hook_name}: {e}")

    async def wait_for_shutdown(self) -> None:
        """Wait for shutdown to complete."""
        await self._shutdown_event.wait()


# Global shutdown manager
_shutdown_manager: Optional[GracefulShutdownManager] = None


def get_shutdown_manager() -> GracefulShutdownManager:
    """Get the global shutdown manager."""
    global _shutdown_manager
    if _shutdown_manager is None:
        _shutdown_manager = GracefulShutdownManager()
    return _shutdown_manager


def is_shutting_down() -> bool:
    """Check if the application is shutting down."""
    global _shutdown_manager
    if _shutdown_manager is None:
        return False
    return _shutdown_manager.is_shutting_down


def is_healthy() -> bool:
    """Check if the application is healthy (for readiness probes)."""
    global _shutdown_manager
    if _shutdown_manager is None:
        return True
    return _shutdown_manager.is_healthy


# =============================================================================
# Middleware for connection tracking
# =============================================================================


class ConnectionTrackingMiddleware:
    """
    ASGI middleware to track active connections for graceful shutdown.

    Usage:
        app.add_middleware(ConnectionTrackingMiddleware)
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        manager = get_shutdown_manager()

        # Reject new requests during drain
        if manager.is_draining:
            response = {
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"connection", b"close"],
                    [b"x-fg-shutdown", b"draining"],
                ],
            }
            await send(response)
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"detail": "Service is shutting down"}',
                }
            )
            return

        manager.increment_connections()
        try:
            await self.app(scope, receive, send)
        finally:
            manager.decrement_connections()


__all__ = [
    "ShutdownState",
    "ShutdownStatus",
    "GracefulShutdownManager",
    "get_shutdown_manager",
    "is_shutting_down",
    "is_healthy",
    "ConnectionTrackingMiddleware",
    "SHUTDOWN_TIMEOUT",
    "DRAIN_TIMEOUT",
]
