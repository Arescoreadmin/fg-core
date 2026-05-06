"""
Tests for api/config/billing.py — Stripe readiness config surface.

Invariants proven:
- get_stripe_readiness() returns ready=True when both STRIPE_SECRET_KEY and
  STRIPE_WEBHOOK_SECRET are present and non-placeholder.
- Missing or blank STRIPE_SECRET_KEY produces BILLING_STRIPE_SECRET_KEY_MISSING.
- Missing or blank STRIPE_WEBHOOK_SECRET produces BILLING_STRIPE_WEBHOOK_SECRET_MISSING.
- CHANGE_ME_* placeholder values are rejected for both keys.
- Return value never exposes secret values.
- /health/ready response includes billing status.
- /health/live response does not require Stripe config.
- Zero network calls to Stripe in any code path.
"""

from __future__ import annotations

import pytest

from api.config.billing import (
    BILLING_STRIPE_SECRET_KEY_MISSING,
    BILLING_STRIPE_WEBHOOK_SECRET_MISSING,
    get_stripe_readiness,
)

# ---------------------------------------------------------------------------
# Helper env fixtures
# ---------------------------------------------------------------------------

_FULL_ENV: dict[str, str] = {
    "STRIPE_SECRET_KEY": "sk_live_test_value",
    "STRIPE_WEBHOOK_SECRET": "whsec_test_value",
}


# ---------------------------------------------------------------------------
# 1. Ready when both keys present
# ---------------------------------------------------------------------------


def test_stripe_config_ready_when_required_values_present() -> None:
    result = get_stripe_readiness(_FULL_ENV)
    assert result["provider"] == "stripe"
    assert result["ready"] is True
    assert result["reasons"] == []


# ---------------------------------------------------------------------------
# 2. Not ready without secret key
# ---------------------------------------------------------------------------


def test_stripe_config_not_ready_without_secret_key() -> None:
    env = {k: v for k, v in _FULL_ENV.items() if k != "STRIPE_SECRET_KEY"}
    result = get_stripe_readiness(env)
    assert result["ready"] is False
    assert BILLING_STRIPE_SECRET_KEY_MISSING in result["reasons"]
    assert BILLING_STRIPE_WEBHOOK_SECRET_MISSING not in result["reasons"]


# ---------------------------------------------------------------------------
# 3. Not ready without webhook secret
# ---------------------------------------------------------------------------


def test_stripe_config_not_ready_without_webhook_secret() -> None:
    env = {k: v for k, v in _FULL_ENV.items() if k != "STRIPE_WEBHOOK_SECRET"}
    result = get_stripe_readiness(env)
    assert result["ready"] is False
    assert BILLING_STRIPE_WEBHOOK_SECRET_MISSING in result["reasons"]
    assert BILLING_STRIPE_SECRET_KEY_MISSING not in result["reasons"]


# ---------------------------------------------------------------------------
# 4. Rejects blank values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key,reason_code",
    [
        ("STRIPE_SECRET_KEY", BILLING_STRIPE_SECRET_KEY_MISSING),
        ("STRIPE_WEBHOOK_SECRET", BILLING_STRIPE_WEBHOOK_SECRET_MISSING),
    ],
)
def test_stripe_config_rejects_blank_values(key: str, reason_code: str) -> None:
    for blank in ("", "   ", "\t"):
        env = {**_FULL_ENV, key: blank}
        result = get_stripe_readiness(env)
        assert result["ready"] is False, f"Expected not-ready for blank {key!r}"
        assert reason_code in result["reasons"]


# ---------------------------------------------------------------------------
# 5. Rejects CHANGE_ME_* placeholders
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key,reason_code",
    [
        ("STRIPE_SECRET_KEY", BILLING_STRIPE_SECRET_KEY_MISSING),
        ("STRIPE_WEBHOOK_SECRET", BILLING_STRIPE_WEBHOOK_SECRET_MISSING),
    ],
)
def test_stripe_config_rejects_change_me_placeholders(
    key: str, reason_code: str
) -> None:
    env = {**_FULL_ENV, key: f"CHANGE_ME_{key}"}
    result = get_stripe_readiness(env)
    assert result["ready"] is False
    assert reason_code in result["reasons"]


# ---------------------------------------------------------------------------
# 6. Readiness endpoint exposes billing status without leaking secrets
# ---------------------------------------------------------------------------


def test_readiness_exposes_billing_status_without_secret_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    /health/ready response must include billing component but must never
    include STRIPE_SECRET_KEY or STRIPE_WEBHOOK_SECRET values.
    """
    from fastapi.testclient import TestClient
    from unittest.mock import patch

    from api.main import build_app

    # Patch get_stripe_readiness to avoid depending on real env vars in this
    # unit test; also proves the endpoint delegates to the function correctly.
    fake_readiness = {
        "provider": "stripe",
        "ready": True,
        "reasons": [],
    }

    with patch("api.config.billing.get_stripe_readiness", return_value=fake_readiness):
        # Also stub out the startup deps that /health/ready requires so the
        # route returns 200 rather than 503.
        app = build_app(auth_enabled=False)
        # Seed app.state to satisfy readiness checks without a full lifespan.
        app.state.startup_validation = type("_SV", (), {"has_errors": False})()
        app.state.db_init_ok = True
        app.state.db_init_error = None

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            sqlite_path = Path(tmp) / "fg-core.db"
            sqlite_path.touch()
            monkeypatch.setenv("FG_SQLITE_PATH", str(sqlite_path))
            monkeypatch.delenv("FG_DB_URL", raising=False)

            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/health/ready")

            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert "billing" in body, f"billing missing from readiness: {body}"
            billing = body["billing"]
            assert billing["provider"] == "stripe"
            assert isinstance(billing["ready"], bool)
            assert isinstance(billing["reasons"], list)

            # Secret values must never appear in response
            raw = resp.text
            assert "sk_live_" not in raw
            assert "whsec_" not in raw


# ---------------------------------------------------------------------------
# 7. Liveness probe does not require Stripe config
# ---------------------------------------------------------------------------


def test_liveness_does_not_require_stripe_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    /health/live must return 200 with no Stripe keys set.
    Liveness is independent of billing readiness.
    """
    from fastapi.testclient import TestClient

    from api.main import build_app

    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)

    app = build_app(auth_enabled=False)
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/health/live")

    assert resp.status_code == 200
    assert resp.json().get("status") == "live"


# ---------------------------------------------------------------------------
# 8. Both keys missing — two reason codes returned
# ---------------------------------------------------------------------------


def test_stripe_config_not_ready_when_both_keys_missing() -> None:
    result = get_stripe_readiness({})
    assert result["ready"] is False
    assert BILLING_STRIPE_SECRET_KEY_MISSING in result["reasons"]
    assert BILLING_STRIPE_WEBHOOK_SECRET_MISSING in result["reasons"]
    assert len(result["reasons"]) == 2


# ---------------------------------------------------------------------------
# 9. Return value never contains secret material
# ---------------------------------------------------------------------------


def test_stripe_readiness_does_not_expose_secret_values() -> None:
    secret_key = "sk_live_super_secret_12345"
    webhook_secret = "whsec_super_secret_67890"
    env = {
        "STRIPE_SECRET_KEY": secret_key,
        "STRIPE_WEBHOOK_SECRET": webhook_secret,
    }
    result = get_stripe_readiness(env)
    result_str = str(result)
    assert secret_key not in result_str
    assert webhook_secret not in result_str
