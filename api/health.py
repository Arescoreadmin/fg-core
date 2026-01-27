"""
Enhanced Health Check Module for FrostGate Core.

Provides production-grade health checks:
- Liveness probes (is the service running?)
- Readiness probes (can the service handle traffic?)
- Dependency health checks (database, redis, etc.)
- Detailed diagnostic information for operators
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

log = logging.getLogger("frostgate.health")


class HealthStatus(str, Enum):
    """Health status values."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class DependencyCheck:
    """Result of a dependency health check."""

    name: str
    status: HealthStatus
    latency_ms: Optional[float] = None
    message: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "latency_ms": self.latency_ms,
            "message": self.message,
            "details": self.details if self.details else None,
        }


@dataclass
class HealthReport:
    """Complete health report for the service."""

    status: HealthStatus
    checks: list[DependencyCheck] = field(default_factory=list)
    version: Optional[str] = None
    uptime_seconds: Optional[float] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "checks": [c.to_dict() for c in self.checks],
            "version": self.version,
            "uptime_seconds": self.uptime_seconds,
            "timestamp": self.timestamp,
        }


class HealthChecker:
    """
    Health checker for FrostGate Core.

    Performs comprehensive health checks:
    - Database connectivity
    - Redis connectivity (if configured)
    - Disk space
    - Memory usage
    """

    def __init__(self):
        self._start_time = time.time()

    def check_database(self) -> DependencyCheck:
        """Check database connectivity and health."""
        start = time.time()
        try:
            from api.db import get_engine
            from sqlalchemy import text

            engine = get_engine()
            with engine.connect() as conn:
                # Simple query to verify connectivity
                result = conn.execute(text("SELECT 1"))
                result.fetchone()

            latency = (time.time() - start) * 1000

            # Check if latency is acceptable
            if latency > 1000:  # > 1 second is degraded
                return DependencyCheck(
                    name="database",
                    status=HealthStatus.DEGRADED,
                    latency_ms=latency,
                    message="Database response time is slow",
                )

            return DependencyCheck(
                name="database",
                status=HealthStatus.HEALTHY,
                latency_ms=latency,
            )

        except Exception as e:
            latency = (time.time() - start) * 1000
            return DependencyCheck(
                name="database",
                status=HealthStatus.UNHEALTHY,
                latency_ms=latency,
                message=f"Database connection failed: {type(e).__name__}",
            )

    def check_redis(self) -> Optional[DependencyCheck]:
        """Check Redis connectivity (if configured)."""
        redis_url = os.getenv("FG_REDIS_URL", "").strip()
        rl_enabled = os.getenv("FG_RL_ENABLED", "true").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        rl_backend = os.getenv("FG_RL_BACKEND", "redis").strip().lower()

        # Skip if Redis is not configured for rate limiting
        if not rl_enabled or rl_backend != "redis":
            return None

        if not redis_url:
            return DependencyCheck(
                name="redis",
                status=HealthStatus.DEGRADED,
                message="Redis URL not configured but Redis backend selected",
            )

        start = time.time()
        try:
            import redis

            client = redis.Redis.from_url(redis_url, socket_timeout=2.0)
            client.ping()
            latency = (time.time() - start) * 1000

            if latency > 500:  # > 500ms is degraded
                return DependencyCheck(
                    name="redis",
                    status=HealthStatus.DEGRADED,
                    latency_ms=latency,
                    message="Redis response time is slow",
                )

            return DependencyCheck(
                name="redis",
                status=HealthStatus.HEALTHY,
                latency_ms=latency,
            )

        except ImportError:
            return DependencyCheck(
                name="redis",
                status=HealthStatus.DEGRADED,
                message="Redis package not installed",
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return DependencyCheck(
                name="redis",
                status=HealthStatus.UNHEALTHY,
                latency_ms=latency,
                message=f"Redis connection failed: {type(e).__name__}",
            )

    def check_disk_space(self) -> DependencyCheck:
        """Check available disk space."""
        try:
            import shutil

            # Check the state directory
            state_dir = os.getenv("FG_STATE_DIR", "state")
            if not os.path.exists(state_dir):
                state_dir = "."

            total, used, free = shutil.disk_usage(state_dir)
            free_pct = (free / total) * 100 if total > 0 else 0

            details = {
                "total_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "free_gb": round(free / (1024**3), 2),
                "free_percent": round(free_pct, 1),
            }

            if free_pct < 5:
                return DependencyCheck(
                    name="disk",
                    status=HealthStatus.UNHEALTHY,
                    message="Disk space critically low",
                    details=details,
                )
            elif free_pct < 15:
                return DependencyCheck(
                    name="disk",
                    status=HealthStatus.DEGRADED,
                    message="Disk space running low",
                    details=details,
                )

            return DependencyCheck(
                name="disk",
                status=HealthStatus.HEALTHY,
                details=details,
            )

        except Exception as e:
            return DependencyCheck(
                name="disk",
                status=HealthStatus.DEGRADED,
                message=f"Could not check disk space: {type(e).__name__}",
            )

    def get_uptime_seconds(self) -> float:
        """Get service uptime in seconds."""
        return time.time() - self._start_time

    def check_all(self, include_details: bool = False) -> HealthReport:
        """
        Run all health checks and return a comprehensive report.

        Args:
            include_details: Include detailed information in checks
        """
        checks: list[DependencyCheck] = []

        # Always check database
        db_check = self.check_database()
        checks.append(db_check)

        # Check Redis if configured
        redis_check = self.check_redis()
        if redis_check:
            checks.append(redis_check)

        # Check disk space if detailed
        if include_details:
            disk_check = self.check_disk_space()
            checks.append(disk_check)

        # Determine overall status
        if any(c.status == HealthStatus.UNHEALTHY for c in checks):
            overall_status = HealthStatus.UNHEALTHY
        elif any(c.status == HealthStatus.DEGRADED for c in checks):
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY

        # Get version from main module
        try:
            from api.main import APP_VERSION

            version = APP_VERSION
        except Exception:
            version = "unknown"

        return HealthReport(
            status=overall_status,
            checks=checks,
            version=version,
            uptime_seconds=round(self.get_uptime_seconds(), 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


# Global health checker instance
_health_checker: Optional[HealthChecker] = None


def get_health_checker() -> HealthChecker:
    """Get the global health checker instance."""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker


def check_liveness() -> dict[str, Any]:
    """Simple liveness check - is the service running?"""
    return {"status": "live"}


def check_readiness() -> dict[str, Any]:
    """
    Readiness check - can the service handle traffic?

    Checks database connectivity.
    """
    checker = get_health_checker()
    db_check = checker.check_database()

    if db_check.status == HealthStatus.UNHEALTHY:
        return {
            "status": "not_ready",
            "reason": db_check.message,
        }

    return {"status": "ready"}


def check_health_detailed() -> dict[str, Any]:
    """Detailed health check with all dependencies."""
    checker = get_health_checker()
    report = checker.check_all(include_details=True)
    return report.to_dict()
