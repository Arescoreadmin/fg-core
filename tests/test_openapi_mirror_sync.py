from __future__ import annotations

from pathlib import Path


def test_core_openapi_mirror_files_match_exactly() -> None:
    core = Path("contracts/core/openapi.json").read_bytes()
    mirror = Path("schemas/api/openapi.json").read_bytes()
    assert core == mirror
