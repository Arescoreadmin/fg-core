from agent.app.config import deterministic_event_id
from agent.app.commands.receipts import ReceiptSender
from agent.core_client import CoreClientError


class FakeClient:
    def __init__(self):
        self.count = 0

    def send_receipt(self, receipt, request_id=None):
        self.count += 1
        return {"ok": True}


class ReplayClient:
    def __init__(self):
        self.count = 0

    def send_receipt(self, receipt, request_id=None):
        self.count += 1
        raise CoreClientError(409, "RECEIPT_REPLAY", "duplicate", {}, "r")


class RetryReceiptClient:
    def __init__(self):
        self.count = 0
        self.request_ids = []

    def send_receipt(self, receipt, request_id=None):
        self.count += 1
        self.request_ids.append(request_id)
        if self.count == 1:
            raise CoreClientError(429, "RATE_LIMITED", "slow", {}, "r")
        return {"ok": True}


def test_deterministic_event_id_stable(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "legacy")
    f = {"alive": True}
    a = deterministic_event_id("t", "a", "heartbeat", "s", "b", f)
    b = deterministic_event_id("t", "a", "heartbeat", "s", "b", {"alive": True})
    assert a == b


def test_receipt_idempotent_send():
    client = FakeClient()
    sender = ReceiptSender(client)
    receipt = {"command_id": "c1", "status": "succeeded"}
    sender.send(receipt)
    sender.send(receipt)
    assert client.count == 1


def test_receipt_replay_not_retried_indefinitely():
    client = ReplayClient()
    sender = ReceiptSender(client)
    receipt = {"command_id": "c-replay", "status": "succeeded"}
    sender.send(receipt)
    sender.send(receipt)
    assert client.count == 1


def test_receipt_reuses_request_id_within_retry_chain():
    client = RetryReceiptClient()
    sender = ReceiptSender(client)
    receipt = {"command_id": "c-retry", "status": "succeeded"}
    sender.send(receipt)
    assert client.count == 2
    assert client.request_ids[0] == client.request_ids[1]
