"""FA-ACTOR-001 canonical Field Assessment actor authority proof."""

from __future__ import annotations

from typing import Any, cast

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from api.actor_context import ActorContext
from api.field_assessment import (
    _actor_from_context,
    _actor_type_from_context,
    _resolve_caller_tenant,
)


def _context(**overrides: object) -> ActorContext:
    values: dict[str, Any] = {
        "subject": "auth0|alice-706",
        "email": "alice@example.test",
        "name": "Alice Example",
        "permissions": frozenset({"assessment.create"}),
        "roles": ["assessor"],
        "auth_source": "oidc_auth0",
        "tenant_id": "tenant-a",
        "membership_id": "membership-a",
    }
    values.update(overrides)
    return ActorContext(**values)


def test_material_actor_uses_canonical_subject_not_display_metadata() -> None:
    actor = _context(name="Caller-controlled display name")
    assert _actor_from_context(actor) == "auth0|alice-706"


def test_missing_or_anonymous_actor_fails_closed() -> None:
    for subject in ("", "anonymous", "unknown"):
        with pytest.raises(HTTPException) as exc_info:
            _actor_from_context(_context(subject=subject))
        assert exc_info.value.status_code == 401
        assert (
            cast(dict[str, object], exc_info.value.detail)["code"]
            == "CANONICAL_ACTOR_REQUIRED"
        )


def test_actor_type_preserves_human_service_boundary() -> None:
    assert _actor_type_from_context(_context()) == "human"
    assert (
        _actor_type_from_context(
            _context(
                subject="tenant-key-prefix",
                auth_source="api_key",
                service_principal_id="service-1",
            )
        )
        == "service"
    )


def test_unknown_auth_source_is_not_promoted_to_human() -> None:
    assert _actor_type_from_context(_context(auth_source="unknown")) == "unknown"


def test_tenant_context_cannot_override_canonical_actor_tenant() -> None:
    request: Request = Request({"type": "http", "headers": []})
    request.state.tenant_id = "tenant-b"
    with pytest.raises(HTTPException) as exc_info:
        _resolve_caller_tenant(request, _context(tenant_id="tenant-a"))
    assert exc_info.value.status_code == 403
    assert (
        cast(dict[str, object], exc_info.value.detail)["code"]
        == "ACTOR_TENANT_MISMATCH"
    )


def test_delegated_actor_roles_do_not_inherit_gateway_platform_admin() -> None:
    from types import SimpleNamespace

    from sqlalchemy.orm import Session
    from api.identity_providers.api_key import _resolve_delegated_actor_roles

    request = SimpleNamespace(
        headers={"X-Tenant-ID": "tenant-a"},
        state=SimpleNamespace(_delegated_actor_authority="internal_console"),
    )

    class _Result:
        def fetchall(self):
            return [("FieldAssessor",)]

    class _Conn:
        def execute(self, _statement, _params):
            return _Result()

    roles = _resolve_delegated_actor_roles(
        cast(Request, request), cast(Session, _Conn()), "auth0|assessor"
    )
    assert roles == ["assessor"]

    from api.actor_context import ALL_PERMISSIONS, roles_to_permissions

    assert roles_to_permissions(roles) != ALL_PERMISSIONS
    assert "report.qa_approve" not in roles_to_permissions(roles)


def test_unbound_internal_actor_cannot_mutate_field_assessment() -> None:
    from sqlalchemy.orm import Session
    from api.auth_scopes.definitions import AuthResult
    from api.identity_providers.api_key import extract_api_key_actor

    request: Request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/field-assessment/engagements/e1/observations",
            "headers": [(b"x-tenant-id", b"tenant-a")],
        }
    )
    request.state.auth = AuthResult(
        valid=True,
        reason="canonical_platform_admin",
        key_prefix="gateway",
        tenant_id="frostgate-internal",
    )
    request.state._delegated_actor_subject = "auth0|unbound"
    request.state._delegated_actor_authority = "internal_console"

    class _Result:
        def fetchall(self):
            return []

    class _Conn:
        def execute(self, _statement, _params):
            return _Result()

    actor = extract_api_key_actor(request, cast(Session, _Conn()))
    assert actor is not None
    assert actor.permissions == frozenset()
