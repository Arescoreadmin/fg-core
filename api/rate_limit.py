"""
Backwards compatibility shim - redirects to api.ratelimit module.

The actual implementation is in api/ratelimit.py.
"""

from __future__ import annotations

# Re-export from the actual implementation
from api.ratelimit import (
    rate_limit_guard,
    load_config,
    RLConfig,
    MemoryRateLimiter,
    MemoryBucket,
)

__all__ = [
    "rate_limit_guard",
    "load_config",
    "RLConfig",
    "MemoryRateLimiter",
    "MemoryBucket",
]
