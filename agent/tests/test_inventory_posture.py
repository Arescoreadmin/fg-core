from agent.app.telemetry.inventory import collect_inventory
from agent.app.telemetry.posture import collect_posture


def test_inventory_and_posture_shapes():
    inv = collect_inventory("1.0", "device-1")
    pos = collect_posture()
    assert {
        "platform",
        "os_version",
        "agent_version",
        "device_id",
        "capabilities",
    }.issubset(inv.keys())
    assert {"os_version", "root_or_jailbreak_signals", "compliance_status"}.issubset(
        pos.keys()
    )
