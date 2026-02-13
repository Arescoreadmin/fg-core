from __future__ import annotations

import socket


def desktop_hostname() -> str:
    return socket.gethostname()
