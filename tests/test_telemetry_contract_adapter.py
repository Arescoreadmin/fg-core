from __future__ import annotations

from api.schemas import TelemetryInput
from contracts.engine_types import TelemetryInput as ContractTelemetryInput


def test_telemetry_input_to_contract():
    payload = {"event_type": "auth", "src_ip": "192.0.2.1"}
    telemetry = TelemetryInput(
        source="edge",
        tenant_id="tenant-a",
        timestamp="2024-01-01T00:00:00Z",
        payload=payload,
        event={"event_type": "auth"},
        event_type="auth",
        src_ip="192.0.2.1",
    )

    contract = telemetry.to_contract()

    assert isinstance(contract, ContractTelemetryInput)
    assert contract.source == "edge"
    assert contract.tenant_id == "tenant-a"
    assert contract.payload == payload
    assert contract.event_type == "auth"
