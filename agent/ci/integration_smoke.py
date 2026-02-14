from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.app import agent_main


class _State:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.receipts: list[dict] = []
        self.command = {
            "command_id": "cmd-1",
            "command_type": "noop",
            "status": "pending",
        }


class _MockCoreHandler(BaseHTTPRequestHandler):
    state = _State()

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def _write(self, status: int, payload: dict) -> None:
        blob = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def log_message(self, *_args):
        return

    def do_POST(self):
        if self.path == "/v1/agent/events":
            body = self._read_json()
            self.state.events.extend(body.get("events", []))
            self._write(200, {"ok": True})
            return

        if self.path == "/v1/agent/receipts":
            body = self._read_json()
            receipt = body.get("receipt", {})
            self.state.receipts.append(receipt)
            if receipt.get("command_id") == self.state.command["command_id"]:
                self.state.command["status"] = "terminal"
            self._write(200, {"ok": True})
            return

        self._write(
            404,
            {
                "code": "NOT_FOUND",
                "message": "missing",
                "details": {},
                "request_id": "mock",
            },
        )

    def do_GET(self):
        if self.path.startswith("/v1/agent/commands"):
            commands = []
            if self.state.command["status"] == "pending":
                commands = [
                    {
                        "command_id": self.state.command["command_id"],
                        "command_type": self.state.command["command_type"],
                    }
                ]
            self._write(200, {"commands": commands, "next_cursor": None})
            return

        if self.path == "/_state":
            self._write(
                200,
                {
                    "events": self.state.events,
                    "receipts": self.state.receipts,
                    "command_status": self.state.command["status"],
                },
            )
            return

        self._write(
            404,
            {
                "code": "NOT_FOUND",
                "message": "missing",
                "details": {},
                "request_id": "mock",
            },
        )


class _DummyRedisServer(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.running = True

    def run(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
                conn.close()
            except OSError:
                return

    def stop(self) -> None:
        self.running = False
        self.sock.close()


def main() -> None:
    core = ThreadingHTTPServer(("127.0.0.1", 0), _MockCoreHandler)
    core_thread = threading.Thread(target=core.serve_forever, daemon=True)
    core_thread.start()

    redis = _DummyRedisServer()
    redis.start()

    queue_path = Path("/tmp/fg-agent-smoke.db")
    if queue_path.exists():
        queue_path.unlink()

    os.environ["FG_CORE_BASE_URL"] = f"http://127.0.0.1:{core.server_port}"
    os.environ["FG_AGENT_KEY"] = "smoke-key"
    os.environ["FG_TENANT_ID"] = "tenant-smoke"
    os.environ["FG_AGENT_ID"] = "agent-smoke"
    os.environ["FG_CONTRACT_VERSION"] = "2025-01-01"
    os.environ["FG_QUEUE_PATH"] = str(queue_path)
    os.environ["FG_FLUSH_INTERVAL_SECONDS"] = "0.2"
    os.environ["FG_BATCH_SIZE"] = "20"
    os.environ["FG_COMMAND_POLL_INTERVAL_SECONDS"] = "0.2"
    os.environ["FG_REDIS_URL"] = f"redis://127.0.0.1:{redis.port}/0"

    agent_thread = threading.Thread(
        target=lambda: agent_main.run(max_loops=60), daemon=True
    )
    agent_thread.start()
    agent_thread.join(timeout=20)

    state = _MockCoreHandler.state
    event_types = {e.get("event_type") for e in state.events}

    assert "agent_boot" in event_types, "agent_boot not received"
    assert "heartbeat" in event_types, "heartbeat not received"
    assert state.receipts, "no receipt received"
    assert state.command["status"] == "terminal", "command did not become terminal"

    core.shutdown()
    core.server_close()
    redis.stop()
    if queue_path.exists():
        queue_path.unlink()

    print("integration smoke passed")


if __name__ == "__main__":
    main()
