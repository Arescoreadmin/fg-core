"""FA-ACTOR-001 canonical Field Assessment actor authority proof."""

from __future__ import annotations

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
    values: dict[str, object] = {
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
        assert exc_info.value.detail["code"] == "CANONICAL_ACTOR_REQUIRED"


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
    request = Request({"type": "http", "headers": []})
    request.state.tenant_id = "tenant-b"
    with pytest.raises(HTTPException) as exc_info:
        _resolve_caller_tenant(request, _context(tenant_id="tenant-a"))
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["code"] == "ACTOR_TENANT_MISMATCH"
