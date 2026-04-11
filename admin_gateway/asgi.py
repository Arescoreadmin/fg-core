"""ASGI entrypoint for Admin Gateway runtime.

This file exists solely to avoid import-time side effects in admin_gateway.main.
Use this in uvicorn/gunicorn:  admin_gateway.asgi:app
"""

from __future__ import annotations

from admin_gateway.logging_config import configure_gateway_logging
from admin_gateway.main import build_app

configure_gateway_logging()
app = build_app()
