from __future__ import annotations

import json
from pathlib import Path

from api.security.public_paths import PUBLIC_PATHS_EXACT, PUBLIC_PATHS_PREFIX


def test_openapi_agent_auth_responses_present() -> None:
    spec = json.loads(Path("contracts/core/openapi.json").read_text())
    hb = spec["paths"]["/agent/heartbeat"]["post"]["responses"]
    en = spec["paths"]["/agent/enroll"]["post"]["responses"]
    rot = spec["paths"]["/agent/key/rotate"]["post"]["responses"]

    assert {"401", "403", "429"}.issubset(set(hb.keys()))
    assert {"401"}.issubset(set(en.keys()))
    assert {"401", "403"}.issubset(set(rot.keys()))


def test_public_allowlist_no_agent_wildcards() -> None:
    spec = json.loads(Path("contracts/core/openapi.json").read_text())
    agent_paths = {p for p in spec["paths"].keys() if p.startswith("/agent/")}
    assert agent_paths.issubset(set(PUBLIC_PATHS_EXACT))
    assert all(not p.startswith("/agent") for p in PUBLIC_PATHS_PREFIX)
