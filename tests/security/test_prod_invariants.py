from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.prod_invariants import ProdInvariantViolation, assert_prod_invariants
from api.main import build_app


def test_prod_invariants_fail_on_auth_disabled() -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": "prod",
                "FG_AUTH_ENABLED": "0",
                "FG_DB_URL": "postgresql://x",
                "FG_DB_BACKEND": "postgres",
                "FG_ENFORCEMENT_MODE": "enforce",
            }
        )
    assert exc.value.code == "FG-PROD-001"


def test_prod_invariants_fail_on_missing_db_url() -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": "staging",
                "FG_AUTH_ENABLED": "1",
                "FG_DB_BACKEND": "postgres",
                "FG_ENFORCEMENT_MODE": "enforce",
            }
        )
    assert exc.value.code == "FG-PROD-003"


@pytest.mark.parametrize("fg_env", ["prod", "staging"])
def test_prod_invariants_fail_when_enforcement_mode_unset(fg_env: str) -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": fg_env,
                "FG_AUTH_ENABLED": "1",
                "FG_DB_URL": "postgresql://x",
                "FG_DB_BACKEND": "postgres",
            }
        )
    assert exc.value.code == "FG-PROD-007"


@pytest.mark.parametrize("fg_env", ["prod", "staging"])
def test_prod_invariants_fail_when_enforcement_mode_observe(fg_env: str) -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": fg_env,
                "FG_AUTH_ENABLED": "1",
                "FG_DB_URL": "postgresql://x",
                "FG_DB_BACKEND": "postgres",
                "FG_ENFORCEMENT_MODE": "observe",
            }
        )
    assert exc.value.code == "FG-PROD-007"


@pytest.mark.parametrize("fg_env", ["prod", "staging"])
def test_prod_invariants_allow_enforcement_mode_enforce(fg_env: str) -> None:
    assert_prod_invariants(
        {
            "FG_ENV": fg_env,
            "FG_AUTH_ENABLED": "1",
            "FG_DB_URL": "postgresql://x",
            "FG_DB_BACKEND": "postgres",
            "FG_ENFORCEMENT_MODE": "enforce",
        }
    )


def test_dev_allows_local_bypass_flags() -> None:
    assert_prod_invariants({"FG_ENV": "dev", "FG_AUTH_ENABLED": "0"})


def test_prod_startup_crashes_on_unsafe_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_DB_BACKEND", "postgres")
    monkeypatch.setenv("FG_DB_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("FG_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv("FG_AUTH_ALLOW_FALLBACK", "true")

    with pytest.raises(ProdInvariantViolation) as exc:
        with TestClient(build_app()):
            pass

    assert exc.value.code == "FG-PROD-002"


def test_prod_invariants_fail_when_audit_verify_disabled() -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": "prod",
                "FG_AUTH_ENABLED": "1",
                "FG_DB_URL": "postgresql://x",
                "FG_DB_BACKEND": "postgres",
                "FG_ENFORCEMENT_MODE": "enforce",
                "FG_AUDIT_VERIFY_REQUIRED": "0",
            }
        )
    assert exc.value.code == "FG-PROD-008"


def test_prod_invariants_fail_when_ed25519_keys_missing() -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": "prod",
                "FG_AUTH_ENABLED": "1",
                "FG_DB_URL": "postgresql://x",
                "FG_DB_BACKEND": "postgres",
                "FG_ENFORCEMENT_MODE": "enforce",
                "FG_AUDIT_VERIFY_REQUIRED": "1",
                "FG_AUDIT_EXPORT_SIGNING_MODE": "ed25519",
            }
        )
    assert exc.value.code == "FG-PROD-009"
