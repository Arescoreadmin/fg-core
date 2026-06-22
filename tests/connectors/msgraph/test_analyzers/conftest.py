"""Shared fixtures for analyzer tests."""

from __future__ import annotations

from unittest.mock import MagicMock


TENANT_ID = "11111111-2222-3333-4444-555555555555"


def make_client(get_all_map: dict, get_one_map: dict | None = None):
    """Build a mock GraphClient with canned responses."""
    client = MagicMock()
    client.get_all.side_effect = lambda path, **kwargs: get_all_map.get(path, [])
    if get_one_map:
        client.get_one.side_effect = lambda path: get_one_map.get(path, {})
    else:
        client.get_one.return_value = {}
    return client
