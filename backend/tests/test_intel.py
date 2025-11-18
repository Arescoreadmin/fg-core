"""Tests for the intel endpoint."""

import pytest

from app.api.routes import intel


@pytest.mark.anyio("asyncio")
async def test_intel_returns_reports() -> None:
    payload = await intel()
    assert isinstance(payload, list)
    assert {report.id for report in payload} == {
        "intel-001",
        "intel-002",
        "intel-003",
    }
    assert all(report.threat_level in {"low", "medium", "high"} for report in payload)
