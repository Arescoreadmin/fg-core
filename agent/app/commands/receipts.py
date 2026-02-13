from __future__ import annotations

import uuid

from agent.core_client import CoreClient, CoreClientError


class ReceiptSender:
    def __init__(self, client: CoreClient):
        self.client = client
        self.sent: set[str] = set()

    def send(self, receipt: dict) -> None:
        cid = receipt["command_id"]
        if cid in self.sent:
            return

        request_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"receipt:{cid}"))
        attempts = 0
        while True:
            try:
                self.client.send_receipt(receipt, request_id=request_id)
                self.sent.add(cid)
                return
            except CoreClientError as err:
                if err.code in {"RECEIPT_REPLAY", "COMMAND_TERMINAL"}:
                    self.sent.add(cid)
                    return
                attempts += 1
                if attempts >= 2 or not err.transient:
                    return
