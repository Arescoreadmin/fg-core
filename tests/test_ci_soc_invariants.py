from __future__ import annotations

from pathlib import Path

from tools.ci.check_soc_invariants import _is_excluded_path


def test_excluded_path_filters_site_packages() -> None:
    path = Path("admin_gateway/.venv/lib/python3.12/site-packages/x.py")
    assert _is_excluded_path(path) is True


def test_excluded_path_allows_repo_module() -> None:
    path = Path("api/security_alerts.py")
    assert _is_excluded_path(path) is False
