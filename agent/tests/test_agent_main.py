from agent.app import agent_main


class CrashySender:
    def __init__(self, *args, **kwargs):
        self.last_success_at = None
        self.rate_limited_count = 0

    def flush_once(self):
        raise RuntimeError("network down")


class NoopPoller:
    def poll_once(self):
        return None


class TinyQueue:
    def __init__(self, *args, **kwargs):
        self._size = 0

    def enqueue(self, event):
        return True

    def size(self):
        return self._size


def test_agent_survives_network_outage(monkeypatch):
    monkeypatch.setenv("FG_TENANT_ID", "t")
    monkeypatch.setenv("FG_AGENT_ID", "a")
    monkeypatch.setenv("FG_CORE_BASE_URL", "http://x")
    monkeypatch.setenv("FG_ALLOW_INSECURE_HTTP", "1")
    monkeypatch.setenv("FG_AGENT_KEY", "k")
    monkeypatch.setenv("FG_EVENT_ID_KEY_CURRENT", "test-key")

    monkeypatch.setattr(agent_main, "BatchSender", CrashySender)
    monkeypatch.setattr(agent_main, "CommandPoller", lambda: NoopPoller())
    monkeypatch.setattr(agent_main, "SQLiteQueue", TinyQueue)
    monkeypatch.setattr(agent_main.time, "sleep", lambda _: None)

    agent_main.run(max_loops=2)
