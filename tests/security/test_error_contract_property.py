from __future__ import annotations

from api.middleware.exception_shield import _safe_detail, _stable_error_code


def test_stable_error_code_slug_rules() -> None:
    code = _stable_error_code(400, "  Invalid API Key!!! \n\t")
    assert code == "E400_invalid_api_key"


def test_stable_error_code_caps_slug_length() -> None:
    code = _stable_error_code(429, "a" * 200)
    assert code.startswith("E429_")
    slug = code.split("_", 1)[1]
    assert len(slug) <= 64


def test_stable_error_code_falls_back_to_error_for_empty_slug() -> None:
    code = _stable_error_code(500, "!!!@@@###")
    assert code == "E500_error"


def test_safe_detail_redacts_url_userinfo() -> None:
    detail = _safe_detail("bad upstream: https://user:pass@example.com/path")
    assert "user:pass" not in detail
    assert "***@example.com" in detail
