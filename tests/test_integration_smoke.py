from __future__ import annotations

import os

import httpx
import pytest

pytestmark = pytest.mark.integration


def _base_url() -> str:
    base_url = os.environ.get("BASE_URL") or os.environ.get("FG_BASE_URL")
    if not base_url:
        pytest.skip("integration tests require BASE_URL (or FG_BASE_URL)")
    return base_url.rstrip("/")


def test_integration_health_ready() -> None:
    base_url = _base_url()
    with httpx.Client(timeout=5.0) as client:
        r = client.get(f"{base_url}/health")
        assert r.status_code == 200, (
            f"/health expected 200 got {r.status_code}: {r.text}"
        )

        r = client.get(f"{base_url}/health/ready")
        assert r.status_code == 200, (
            f"/health/ready expected 200 got {r.status_code}: {r.text}"
        )
