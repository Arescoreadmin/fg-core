"""Connector bridge registry for Field Assessment imports."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session


@dataclass(frozen=True)
class BridgeContext:
    db: Session
    tenant_id: str
    engagement_id: str
    actor: str


BridgeHandler = Callable[[BridgeContext, Any], Any]

_BRIDGES: dict[str, BridgeHandler] = {}


def register_bridge(connector_type: str, handler: BridgeHandler) -> None:
    _BRIDGES[connector_type] = handler


def get_bridge(connector_type: str) -> BridgeHandler:
    return _BRIDGES[connector_type]


def supported_bridges() -> tuple[str, ...]:
    return tuple(sorted(_BRIDGES))
