from __future__ import annotations

from pathlib import Path
import socket
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.core_client import CoreClient


def main() -> None:
    with patch.object(socket, "getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 0))]):
        client = CoreClient("https://example", "k", "t", "a", "2025-01-01")
    headers = client._headers(request_id="fixed")
    assert "X-Contract-Version" in headers
    assert headers["X-Request-ID"] == "fixed"
    assert headers["Content-Type"] == "application/json"
    print("agent contracts verified")


if __name__ == "__main__":
    main()
