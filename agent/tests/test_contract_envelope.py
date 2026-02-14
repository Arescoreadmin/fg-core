from unittest.mock import patch

import requests

from agent.core_client import CoreClient


class DummyResp:
    def __init__(self, status_code, body, headers=None):
        self.status_code = status_code
        self._body = body
        self.content = b"x"
        self.headers = headers or {}

    def json(self):
        return self._body


def test_contract_headers_and_envelope_parsing():
    client = CoreClient("http://x", "k", "t", "a", "2025-01-01")

    def fake_request(method, url, headers=None, **kwargs):
        assert "X-Contract-Version" in headers
        assert "X-Request-ID" in headers
        return DummyResp(
            429,
            {
                "code": "RATE_LIMITED",
                "message": "slow",
                "details": {},
                "request_id": "r",
            },
            {"Retry-After": "5"},
        )

    with patch.object(requests, "request", side_effect=fake_request):
        try:
            client.send_events([])
            assert False
        except Exception as exc:
            assert "RATE_LIMITED" in str(exc)


def test_request_id_can_be_reused_for_logical_retry():
    client = CoreClient("http://x", "k", "t", "a", "2025-01-01")
    seen = []

    def fake_request(method, url, headers=None, **kwargs):
        seen.append(headers["X-Request-ID"])
        return DummyResp(200, {"ok": True})

    with patch.object(requests, "request", side_effect=fake_request):
        client.send_events([], request_id="fixed-request")
        client.send_events([], request_id="fixed-request")

    assert seen == ["fixed-request", "fixed-request"]
