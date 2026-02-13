from __future__ import annotations

import platform
import socket


def collect_inventory(agent_version: str, device_id: str, mobile_device_model: str | None = None) -> dict:
    return {
        "platform": platform.system().lower(),
        "os_version": platform.version(),
        "agent_version": agent_version,
        "hostname": socket.gethostname(),
        "mobile_device_model": mobile_device_model,
        "device_id": device_id,
        "capabilities": ["telemetry", "commands", "receipts"],
    }
