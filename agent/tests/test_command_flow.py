from agent.app.commands.executor import CommandExecutor
from agent.app.commands.poller import CommandPoller
from agent.core_client import CoreClientError


class RetryPollClient:
    def __init__(self):
        self.agent_id = "agent-1"
        self.request_ids = []
        self.calls = 0

    def poll_commands(self, agent_id, cursor, request_id=None):
        self.request_ids.append(request_id)
        self.calls += 1
        if self.calls == 1:
            raise CoreClientError(429, "RATE_LIMITED", "slow", {}, "r")
        return {"commands": [], "next_cursor": "c2"}


class NoopReceipts:
    def send(self, receipt):
        return None


def test_executor_allowlist_and_receipt_shape():
    ex = CommandExecutor()
    ok = ex.execute({"command_id": "c1", "command_type": "noop"})
    bad = ex.execute({"command_id": "c2", "command_type": "shell"})
    assert ok["status"] == "succeeded"
    assert bad["status"] == "rejected"
    for key in ["command_id", "status", "started_at", "completed_at", "result_summary"]:
        assert key in ok


def test_poller_reuses_request_id_within_retry_chain():
    client = RetryPollClient()
    poller = CommandPoller(client=client)
    poller.receipts = NoopReceipts()
    poller.poll_once()
    assert len(client.request_ids) == 2
    assert client.request_ids[0] == client.request_ids[1]
