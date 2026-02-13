from __future__ import annotations

from agent.app.attestation.appattest_stub import appattest_result
from agent.app.attestation.devicecheck_stub import devicecheck_result


def collect_compliance() -> dict:
    return {
        "attestation": {
            "devicecheck": devicecheck_result(),
            "appattest": appattest_result(),
        }
    }
