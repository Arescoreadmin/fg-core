from __future__ import annotations

import uuid

from agent.app.commands.executor import CommandExecutor
from agent.app.commands.receipts import ReceiptSender
from agent.core_client import CoreClient, CoreClientError


class CommandPoller:
    def __init__(self, client: CoreClient | None = None):
        self.client = client or CoreClient.from_env()
        self.executor = CommandExecutor()
        self.receipts = ReceiptSender(self.client)
        self.cursor = None
        self.seen: set[str] = set()

    def poll_once(self) -> None:
        request_id = str(uuid.uuid4())
        attempts = 0
        while True:
            try:
                data = self.client.poll_commands(
                    self.client.agent_id,
                    self.cursor,
                    request_id=request_id,
                )
                break
            except CoreClientError as err:
                attempts += 1
                if attempts >= 2 or not err.transient:
                    return

        self.cursor = data.get("next_cursor")
        for cmd in data.get("commands", []):
            cid = cmd["command_id"]
            if cid in self.seen:
                continue
            self.seen.add(cid)
            receipt = self.executor.execute(cmd)
            self.receipts.send(receipt)
