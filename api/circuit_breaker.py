# api/circuit_breaker.py
"""
Circuit Breaker Pattern Implementation.

Provides production-grade resilience for external service calls:
- Automatic failure detection
- Fast-fail during outages
- Automatic recovery with half-open testing
- Metrics and monitoring hooks
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Callable, Dict, Optional

log = logging.getLogger("frostgate.circuit_breaker")

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


def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return float(v)
    except ValueError:
        return default


# Default circuit breaker settings
DEFAULT_FAILURE_THRESHOLD = _env_int("FG_CB_FAILURE_THRESHOLD", 5)
DEFAULT_RECOVERY_TIMEOUT = _env_int("FG_CB_RECOVERY_TIMEOUT", 30)  # seconds
DEFAULT_HALF_OPEN_MAX_CALLS = _env_int("FG_CB_HALF_OPEN_MAX_CALLS", 3)
DEFAULT_SUCCESS_THRESHOLD = _env_int("FG_CB_SUCCESS_THRESHOLD", 2)
DEFAULT_TIMEOUT = _env_float("FG_CB_CALL_TIMEOUT", 10.0)  # seconds


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing fast, not calling service
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerStats:
    """Statistics for a circuit breaker."""

    name: str
    state: CircuitState
    failure_count: int
    success_count: int
    total_calls: int
    total_failures: int
    total_successes: int
    last_failure_time: Optional[float]
    last_success_time: Optional[float]
    last_state_change: float
    half_open_successes: int = 0


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker."""

    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
    recovery_timeout: int = DEFAULT_RECOVERY_TIMEOUT
    half_open_max_calls: int = DEFAULT_HALF_OPEN_MAX_CALLS
    success_threshold: int = DEFAULT_SUCCESS_THRESHOLD
    timeout: float = DEFAULT_TIMEOUT
    excluded_exceptions: tuple = ()  # Exceptions that don't count as failures


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""

    def __init__(self, name: str, message: str = "Circuit breaker is open"):
        self.name = name
        self.message = message
        super().__init__(f"{name}: {message}")


class CircuitBreaker:
    """
    Circuit breaker implementation.

    States:
    - CLOSED: Normal operation, tracking failures
    - OPEN: Service is failing, reject all calls immediately
    - HALF_OPEN: Testing recovery, allow limited calls

    Usage:
        cb = CircuitBreaker("external_api")

        @cb.protect
        def call_external_api():
            ...

        # Or async
        @cb.protect
        async def call_external_api_async():
            ...
    """

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
        on_state_change: Optional[
            Callable[[str, CircuitState, CircuitState], None]
        ] = None,
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.on_state_change = on_state_change

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_successes = 0
        self._half_open_calls = 0
        self._last_failure_time: Optional[float] = None
        self._last_success_time: Optional[float] = None
        self._last_state_change = time.time()
        self._total_calls = 0
        self._total_failures = 0
        self._total_successes = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        return self._state

    def _set_state(self, new_state: CircuitState) -> None:
        """Change circuit state with logging."""
        if new_state == self._state:
            return

        old_state = self._state
        self._state = new_state
        self._last_state_change = time.time()

        log.info(
            f"Circuit breaker '{self.name}' state change: {old_state.value} -> {new_state.value}"
        )

        if self.on_state_change:
            try:
                self.on_state_change(self.name, old_state, new_state)
            except Exception as e:
                log.exception(f"Error in circuit breaker state change callback: {e}")

    def _check_state_transition(self) -> None:
        """Check if state should transition based on current conditions."""
        now = time.time()

        if self._state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if self._last_failure_time is not None:
                elapsed = now - self._last_failure_time
                if elapsed >= self.config.recovery_timeout:
                    self._half_open_calls = 0
                    self._half_open_successes = 0
                    self._set_state(CircuitState.HALF_OPEN)

    def _record_success(self) -> None:
        """Record a successful call."""
        self._success_count += 1
        self._total_successes += 1
        self._last_success_time = time.time()

        if self._state == CircuitState.HALF_OPEN:
            self._half_open_successes += 1
            if self._half_open_successes >= self.config.success_threshold:
                # Service recovered, close circuit
                self._failure_count = 0
                self._set_state(CircuitState.CLOSED)

    def _record_failure(self, error: Exception) -> None:
        """Record a failed call."""
        # Check if this exception should be excluded
        if isinstance(error, self.config.excluded_exceptions):
            return

        self._failure_count += 1
        self._total_failures += 1
        self._last_failure_time = time.time()

        if self._state == CircuitState.HALF_OPEN:
            # Failure during recovery, open circuit again
            self._set_state(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED:
            if self._failure_count >= self.config.failure_threshold:
                self._set_state(CircuitState.OPEN)

    def _can_execute(self) -> bool:
        """Check if a call can be executed."""
        self._check_state_transition()

        if self._state == CircuitState.CLOSED:
            return True

        if self._state == CircuitState.OPEN:
            return False

        if self._state == CircuitState.HALF_OPEN:
            # Allow limited calls during half-open
            if self._half_open_calls < self.config.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False

        return False

    def get_stats(self) -> CircuitBreakerStats:
        """Get current circuit breaker statistics."""
        return CircuitBreakerStats(
            name=self.name,
            state=self._state,
            failure_count=self._failure_count,
            success_count=self._success_count,
            total_calls=self._total_calls,
            total_failures=self._total_failures,
            total_successes=self._total_successes,
            last_failure_time=self._last_failure_time,
            last_success_time=self._last_success_time,
            last_state_change=self._last_state_change,
            half_open_successes=self._half_open_successes,
        )

    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_successes = 0
        self._half_open_calls = 0
        self._last_state_change = time.time()
        log.info(f"Circuit breaker '{self.name}' manually reset")

    def protect(self, func: Callable) -> Callable:
        """
        Decorator to protect a function with the circuit breaker.

        Works with both sync and async functions.
        """
        if asyncio.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                self._total_calls += 1

                if not self._can_execute():
                    raise CircuitBreakerError(
                        self.name,
                        f"Circuit open, rejecting call (failures={self._failure_count})",
                    )

                try:
                    if self.config.timeout > 0:
                        result = await asyncio.wait_for(
                            func(*args, **kwargs),
                            timeout=self.config.timeout,
                        )
                    else:
                        result = await func(*args, **kwargs)
                    self._record_success()
                    return result
                except asyncio.TimeoutError as e:
                    self._record_failure(e)
                    raise
                except Exception as e:
                    self._record_failure(e)
                    raise

            return async_wrapper
        else:

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                self._total_calls += 1

                if not self._can_execute():
                    raise CircuitBreakerError(
                        self.name,
                        f"Circuit open, rejecting call (failures={self._failure_count})",
                    )

                try:
                    result = func(*args, **kwargs)
                    self._record_success()
                    return result
                except Exception as e:
                    self._record_failure(e)
                    raise

            return sync_wrapper

    def __call__(self, func: Callable) -> Callable:
        """Allow using as @circuit_breaker decorator."""
        return self.protect(func)


# =============================================================================
# Circuit Breaker Registry
# =============================================================================


class CircuitBreakerRegistry:
    """
    Registry for managing multiple circuit breakers.

    Usage:
        registry = CircuitBreakerRegistry()
        cb = registry.get_or_create("redis")

        @cb.protect
        def call_redis():
            ...
    """

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._default_config = CircuitBreakerConfig()

    def set_default_config(self, config: CircuitBreakerConfig) -> None:
        """Set default configuration for new circuit breakers."""
        self._default_config = config

    def get_or_create(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
        on_state_change: Optional[
            Callable[[str, CircuitState, CircuitState], None]
        ] = None,
    ) -> CircuitBreaker:
        """Get existing circuit breaker or create new one."""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(
                name,
                config or self._default_config,
                on_state_change,
            )
        return self._breakers[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name."""
        return self._breakers.get(name)

    def get_all_stats(self) -> Dict[str, CircuitBreakerStats]:
        """Get statistics for all circuit breakers."""
        return {name: cb.get_stats() for name, cb in self._breakers.items()}

    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for cb in self._breakers.values():
            cb.reset()


# Global registry
_circuit_breaker_registry: Optional[CircuitBreakerRegistry] = None


def get_circuit_breaker_registry() -> CircuitBreakerRegistry:
    """Get the global circuit breaker registry."""
    global _circuit_breaker_registry
    if _circuit_breaker_registry is None:
        _circuit_breaker_registry = CircuitBreakerRegistry()
    return _circuit_breaker_registry


def circuit_breaker(
    name: str,
    config: Optional[CircuitBreakerConfig] = None,
) -> CircuitBreaker:
    """
    Get or create a circuit breaker from the global registry.

    Usage:
        @circuit_breaker("redis")
        def call_redis():
            ...
    """
    return get_circuit_breaker_registry().get_or_create(name, config)


__all__ = [
    "CircuitState",
    "CircuitBreakerStats",
    "CircuitBreakerConfig",
    "CircuitBreakerError",
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "get_circuit_breaker_registry",
    "circuit_breaker",
]
