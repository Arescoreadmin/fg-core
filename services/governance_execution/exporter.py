"""Replay-safe deep-frozen export for the Governance Execution Engine."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any

from services.governance_digital_twin.immutability import deep_freeze
from services.governance_execution.models import ExecutionReplayPackage


_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "secret",
        "token",
        "password",
        "api_key",
        "auth_header",
        "authorization",
        "raw_prompt",
        "raw_vector",
        "embedding",
        "provider_payload",
        "private_key",
        "session",
        "cookie",
    }
)


def _scrub(payload: Any) -> Any:
    """Recursively remove forbidden keys from dicts."""
    if isinstance(payload, dict):
        return {k: _scrub(v) for k, v in payload.items() if k not in _FORBIDDEN_KEYS}
    if isinstance(payload, (list, tuple)):
        cleaned = [_scrub(item) for item in payload]
        return type(payload)(cleaned)
    return payload


def export_execution_replay_package(
    package: ExecutionReplayPackage,
) -> Mapping[str, Any]:
    """Export an ExecutionReplayPackage as a deep-frozen, scrubbed Mapping.

    Steps:
      1. dataclasses.asdict(package)
      2. Scrub forbidden keys
      3. Inject replay_instructions
      4. deep_freeze the result
    """
    raw: dict[str, Any] = dataclasses.asdict(package)
    scrubbed = _scrub(raw)

    scrubbed["replay_instructions"] = {
        "schema_version": package.schema_version,
        "replay_version": package.replay_version,
        "fingerprint": package.fingerprint,
        "execution_fingerprint": package.execution_fingerprint,
        "plan_id": package.plan_id,
        "run_id": package.run_id,
        "tenant_id": package.tenant_id,
        "note": (
            "To replay: provide identical SimulationResult and re-run plan_execution() "
            "with the same plan_name, authority, and approval_type. "
            "Verify execution_fingerprint matches."
        ),
    }

    return deep_freeze(scrubbed)
