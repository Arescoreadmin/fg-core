from __future__ import annotations

from agent.core_client import CoreClient


class HTTPSender:
    def __init__(self, client: CoreClient | None = None):
        self.client = client or CoreClient.from_env()

    def send_events(self, events: list[dict], request_id: str | None = None) -> dict:
        return self.client.send_events(events, request_id=request_id)
