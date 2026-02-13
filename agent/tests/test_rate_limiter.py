from agent.app.rate_limit.keys import rate_limit_key
from agent.app.rate_limit.memory_fallback import MemoryLimiter


def test_rate_limit_key_format():
    key = rate_limit_key("t", "a", "/v1/agent/events", "secret")
    assert key.startswith("tenant:t|agent:a|route:/v1/agent/events|api_key_hash:")
    assert "secret" not in key


def test_memory_limiter_window():
    lim = MemoryLimiter()
    key = "k"
    assert lim.allow(key, 1, 30) is True
    assert lim.allow(key, 1, 30) is False
