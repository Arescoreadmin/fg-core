from __future__ import annotations

import os
import sys
from typing import Any

from agent.main import main as run_agent

if sys.platform == "win32":
    import servicemanager  # type: ignore[import-not-found]
    import win32event  # type: ignore[import-not-found]
    import win32service  # type: ignore[import-not-found]
    import win32serviceutil  # type: ignore[import-not-found]
else:
    servicemanager = None
    win32event = None
    win32service = None
    win32serviceutil = None


if sys.platform == "win32":

    class FrostGateAgentService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = "FrostGateAgent"
        _svc_display_name_ = "FrostGate Agent"

        def __init__(self, args: Any) -> None:
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg("FrostGate Agent service starting (phase2)")
            os.environ.setdefault("FG_AGENT_ENABLE_UPDATE", "1")
            os.environ.setdefault("FG_AGENT_ENABLE_POLICY", "1")
            os.environ.setdefault("FG_AGENT_ENABLE_QUARANTINE", "1")
            run_agent()

else:

    class FrostGateAgentService:  # pragma: no cover
        def __init__(self, args: Any) -> None:
            raise RuntimeError("FrostGateAgentService is only supported on Windows")


if __name__ == "__main__":
    if sys.platform != "win32":
        raise SystemExit("windows_service.py can only be run on Windows")
    win32serviceutil.HandleCommandLine(FrostGateAgentService)
