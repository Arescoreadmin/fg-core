from __future__ import annotations

import os

import servicemanager
import win32event
import win32service
import win32serviceutil

from agent.main import main as run_agent


class FrostGateAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "FrostGateAgent"
    _svc_display_name_ = "FrostGate Agent"

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("FrostGate Agent service starting (phase2)")
        os.environ.setdefault("FG_AGENT_ENABLE_UPDATE", "1")
        os.environ.setdefault("FG_AGENT_ENABLE_POLICY", "1")
        os.environ.setdefault("FG_AGENT_ENABLE_QUARANTINE", "1")
        run_agent()


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(FrostGateAgentService)
