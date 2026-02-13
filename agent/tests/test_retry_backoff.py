from agent.app.queue.backoff import backoff_delay


def test_backoff_growth():
    assert backoff_delay(1, base=1, cap=100) >= 2
    assert backoff_delay(3, base=1, cap=100) >= 8
