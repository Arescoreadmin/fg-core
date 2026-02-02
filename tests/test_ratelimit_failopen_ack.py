import os
import importlib

import pytest


def reload_ratelimit():
    import api.ratelimit as rl
    importlib.reload(rl)
    return rl


@pytest.mark.parametrize(
    "fail_open,ack,expected_ack",
    [
        ("true", "true", True),
        ("true", "false", False),
        ("false", "true", False),
        ("false", "false", False),
    ],
)
def test_fail_open_ack_requires_both(monkeypatch, fail_open, ack, expected_ack):
    monkeypatch.setenv("FG_RL_ENABLED", "true")
    monkeypatch.setenv("FG_RL_BACKEND", "redis")
    monkeypatch.setenv("FG_RL_FAIL_OPEN", fail_open)
    monkeypatch.setenv("FG_RL_FAIL_OPEN_ACKNOWLEDGED", ack)

    rl = reload_ratelimit()
    cfg = rl.load_config()

    assert bool(cfg.fail_open and cfg.fail_open_acknowledged) is expected_ack
