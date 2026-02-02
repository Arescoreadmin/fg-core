import importlib
from unittest.mock import patch


def test_ratelimit_failopen_requires_acknowledgment():
    """
    Ensure rate limiter fail-open requires explicit acknowledgement.
    """
    # Import module fresh to ensure env patches apply cleanly
    rl = importlib.import_module("api.ratelimit")
    importlib.reload(rl)

    with patch.dict(
        "os.environ",
        {
            "FG_RATE_LIMIT_FAIL_OPEN": "true",
            "FG_RATE_LIMIT_FAIL_OPEN_ACKNOWLEDGED": "false",
        },
        clear=False,
    ):
        importlib.reload(rl)
        assert rl._fail_open_acknowledged() is False, (
            "Fail-open should not be acknowledged without explicit ACK"
        )

    with patch.dict(
        "os.environ",
        {
            "FG_RATE_LIMIT_FAIL_OPEN": "true",
            "FG_RATE_LIMIT_FAIL_OPEN_ACKNOWLEDGED": "true",
        },
        clear=False,
    ):
        importlib.reload(rl)
        assert rl._fail_open_acknowledged() is True, (
            "Fail-open should be acknowledged when ACK is explicitly set"
        )
