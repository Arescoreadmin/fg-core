"""
Task 5.3 — Plane boundary enforcement.

Static regression tests proving:

A) direct_core_blocked: frostgate-core is NOT attached to the public network
   in any supported compose file. Core must be reachable only via the internal
   compose network (by admin-gateway over service DNS), never via the public
   network that exposes gateway/IdP/console to the host.

B) plane_boundary: check_plane_boundaries.py CI script passes (no forbidden
   service-layer imports of core internals, no public network on core).

C) gateway_only: (regression guard for task 2.2) — admin /admin routes in
   hosted profiles still require an internal gateway token, not direct human
   auth. Delegated to test_gateway_only_admin_access.py; confirmed selectable
   by the pytest -k gateway_only selector.

Rationale for static-only approach:
- Docker compose smoke tests require live containers. Those belong in the
  integration/docker CI lane. Static analysis of compose files provides a
  deterministic, always-runnable guard that fails the CI fast lane before
  any containers are built.
"""

from __future__ import annotations

from pathlib import Path

import pytest

try:
    import yaml  # type: ignore[import-untyped]

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

ROOT = Path(__file__).resolve().parents[2]

_COMPOSE_FILES = {
    "docker-compose.yml": ROOT / "docker-compose.yml",
    "docker-compose.lockdown.yml": ROOT / "docker-compose.lockdown.yml",
}

# frostgate-core must never be on the public network.
_CORE_SERVICE = "frostgate-core"
_FORBIDDEN_NETWORK = "public"


# ---------------------------------------------------------------------------
# A) direct_core_blocked — compose network isolation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _YAML_AVAILABLE, reason="PyYAML not installed")
@pytest.mark.parametrize("filename,compose_path", list(_COMPOSE_FILES.items()))
def test_direct_core_blocked_core_not_on_public_network(
    filename: str, compose_path: Path
) -> None:
    """frostgate-core must not be attached to the public compose network.

    Placing core on the public network allows containers on that network
    (e.g., a compromised console or fg-idp container) to reach core directly,
    bypassing the admin-gateway's auth and tenant isolation.

    core must be internal-only; admin-gateway reaches it via internal service DNS.
    """
    if not compose_path.exists():
        pytest.skip(f"{filename} not present in this environment")

    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        pytest.skip(f"{filename} is not a valid YAML mapping")

    services: dict = data.get("services") or {}
    core_cfg = services.get(_CORE_SERVICE)
    if core_cfg is None:
        pytest.skip(f"{_CORE_SERVICE!r} not defined in {filename}")

    networks_cfg = core_cfg.get("networks") or {}
    if isinstance(networks_cfg, dict):
        attached = set(networks_cfg.keys())
    elif isinstance(networks_cfg, list):
        attached = set(networks_cfg)
    else:
        attached = set()

    assert _FORBIDDEN_NETWORK not in attached, (
        f"{filename}: {_CORE_SERVICE!r} is attached to the {_FORBIDDEN_NETWORK!r} "
        f"network. Core must be on the 'internal' network only. "
        f"Currently attached to: {sorted(attached)}. "
        f"Direct access to core from the public compose network bypasses "
        f"admin-gateway auth — remove 'public' from frostgate-core's networks."
    )


@pytest.mark.skipif(not _YAML_AVAILABLE, reason="PyYAML not installed")
def test_direct_core_blocked_core_has_no_host_port_bindings() -> None:
    """frostgate-core must not publish any host port bindings.

    A host port binding makes core reachable from the host network, completely
    bypassing compose network isolation and the admin-gateway boundary.
    """
    compose_path = _COMPOSE_FILES["docker-compose.yml"]
    if not compose_path.exists():
        pytest.skip("docker-compose.yml not present")

    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        pytest.skip("docker-compose.yml is not a valid YAML mapping")

    services: dict = data.get("services") or {}
    core_cfg = services.get(_CORE_SERVICE)
    if core_cfg is None:
        pytest.skip(f"{_CORE_SERVICE!r} not defined in docker-compose.yml")

    ports = core_cfg.get("ports") or []
    assert not ports, (
        f"frostgate-core must not publish host ports. "
        f"Found: {ports}. "
        f"Host port bindings expose core directly on the host network, "
        f"bypassing admin-gateway entirely."
    )


@pytest.mark.skipif(not _YAML_AVAILABLE, reason="PyYAML not installed")
def test_direct_core_blocked_admin_gateway_on_public_network() -> None:
    """admin-gateway must be on the public network (it is the supported human ingress).

    This is the positive control: if admin-gateway is NOT on public, the
    boundary architecture is misconfigured the other way. Validates the
    model is internally consistent.
    """
    compose_path = _COMPOSE_FILES["docker-compose.yml"]
    if not compose_path.exists():
        pytest.skip("docker-compose.yml not present")

    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        pytest.skip("docker-compose.yml is not a valid YAML mapping")

    services: dict = data.get("services") or {}
    gw_cfg = services.get("admin-gateway")
    if gw_cfg is None:
        pytest.skip("'admin-gateway' not defined in docker-compose.yml")

    networks_cfg = gw_cfg.get("networks") or {}
    if isinstance(networks_cfg, dict):
        attached = set(networks_cfg.keys())
    elif isinstance(networks_cfg, list):
        attached = set(networks_cfg)
    else:
        attached = set()

    assert "public" in attached, (
        "admin-gateway must be on the 'public' network — it is the supported "
        f"human-facing ingress. Currently attached to: {sorted(attached)}."
    )
    assert "internal" in attached, (
        "admin-gateway must be on the 'internal' network to reach frostgate-core "
        f"via internal service DNS. Currently attached to: {sorted(attached)}."
    )


# ---------------------------------------------------------------------------
# B) plane_boundary — CI check script passes
# ---------------------------------------------------------------------------


def test_plane_boundary_ci_script_passes() -> None:
    """check_plane_boundaries.py must pass with no violations.

    This is a wrapper that proves the CI script itself reflects the current
    composed state of all boundary checks (import boundaries + compose network
    isolation). It is the authoritative boundary gate.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "tools/ci/check_plane_boundaries.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"check_plane_boundaries.py failed:\n{result.stdout}{result.stderr}"
    )
    assert "plane boundaries: OK" in result.stdout
