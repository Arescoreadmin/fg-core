"""RBAC scopes for human users.

Defines scope hierarchy and enforcement utilities.
"""

from __future__ import annotations

from enum import Enum
from functools import wraps
from typing import Callable, Set


class Scope(str, Enum):
    """Authorization scopes for admin operations.

    Scope hierarchy:
    - console:admin includes all other scopes
    - *:write includes corresponding *:read
    """

    # Full admin access
    CONSOLE_ADMIN = "console:admin"

    # Product management
    PRODUCT_READ = "product:read"
    PRODUCT_WRITE = "product:write"

    # API key management
    KEYS_READ = "keys:read"
    KEYS_WRITE = "keys:write"

    # Policy management
    POLICIES_WRITE = "policies:write"

    # Audit log access
    AUDIT_READ = "audit:read"


# Scope hierarchy: write scopes imply read scopes
SCOPE_HIERARCHY: dict[Scope, Set[Scope]] = {
    Scope.CONSOLE_ADMIN: {
        Scope.PRODUCT_READ,
        Scope.PRODUCT_WRITE,
        Scope.KEYS_READ,
        Scope.KEYS_WRITE,
        Scope.POLICIES_WRITE,
        Scope.AUDIT_READ,
    },
    Scope.PRODUCT_WRITE: {Scope.PRODUCT_READ},
    Scope.KEYS_WRITE: {Scope.KEYS_READ},
}


def expand_scopes(scopes: Set[str]) -> Set[str]:
    """Expand scopes based on hierarchy.

    For example, console:admin expands to include all scopes.
    """
    expanded = set(scopes)

    for scope_str in list(expanded):
        try:
            scope = Scope(scope_str)
            if scope in SCOPE_HIERARCHY:
                expanded.update(s.value for s in SCOPE_HIERARCHY[scope])
        except ValueError:
            # Unknown scope, keep as-is
            pass

    return expanded


def has_scope(user_scopes: Set[str], required_scope: str | Scope) -> bool:
    """Check if user has the required scope (including hierarchy).

    Args:
        user_scopes: Set of scope strings the user has
        required_scope: The scope to check for

    Returns:
        True if user has the scope (directly or via hierarchy)
    """
    if isinstance(required_scope, Scope):
        required_scope = required_scope.value

    expanded = expand_scopes(user_scopes)
    return required_scope in expanded


def require_scope(scope: str | Scope) -> Callable:
    """Decorator factory to require a specific scope.

    Usage:
        @require_scope(Scope.KEYS_WRITE)
        async def create_key(session: Session, ...):
            ...

    The decorated function must accept a `session` argument.
    """
    if isinstance(scope, Scope):
        scope_str = scope.value
    else:
        scope_str = scope

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find session in kwargs or args
            session = kwargs.get("session")
            if session is None:
                # Check first positional arg after self/cls
                for arg in args:
                    if hasattr(arg, "scopes"):
                        session = arg
                        break

            if session is None:
                raise ValueError("No session found in function arguments")

            if not has_scope(session.scopes, scope_str):
                from fastapi import HTTPException

                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions: requires {scope_str}",
                )

            return await func(*args, **kwargs)

        # Store required scope for introspection
        wrapper._required_scope = scope_str
        return wrapper

    return decorator


def get_all_scopes() -> list[str]:
    """Get list of all available scopes."""
    return [s.value for s in Scope]
