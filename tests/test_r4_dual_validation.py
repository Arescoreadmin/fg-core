# tests/test_r4_dual_validation.py
"""
R4.7 — Dual-validation (Deploy 1) tests.

Verifies that verify_api_key_detailed tries the canonical authority first
for fgk. keys on a Postgres backend and falls back to the legacy api_keys
path on miss or error.  Tests call the function directly with monkeypatched
imports and env vars.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from api.auth_scopes.resolution import verify_api_key_detailed
from api.credential_authority import CredentialNotFoundError, CredentialPrincipal


def _make_principal(
    tenant_id: str = "tenant-alpha",
    scopes: frozenset[str] = frozenset(),
) -> CredentialPrincipal:
    return CredentialPrincipal(
        tenant_id=tenant_id,
        credential_id="cred-00000001",
        credential_type="tenant_api_key",
        credential_slot="prod",
        generation=1,
        scopes=scopes,
        issued_at=datetime.now(timezone.utc),
    )


_FGK_KEY = "fgk.eyJ0IjoidGVuYW50LWFscGhhIn0.fakesecret"
_LEGACY_KEY = "prefix.token.fakesecret"


# ---------------------------------------------------------------------------
# A — Canonical path hit
# ---------------------------------------------------------------------------


class TestA_CanonicalHit:
    def test_fgk_key_returns_canonical_validated(self, monkeypatch) -> None:
        monkeypatch.setenv("FG_DB_BACKEND", "postgres")
        principal = _make_principal(scopes=frozenset(["api:read"]))

        with patch("api.credential_authority.validate_credential", return_value=principal):
            with patch("api.db.get_engine", return_value=MagicMock()):
                result = verify_api_key_detailed(raw=_FGK_KEY)

        assert result.valid is True
        assert result.reason == "canonical_validated"
        assert result.tenant_id == "tenant-alpha"
        assert "api:read" in result.scopes
        assert result.key_prefix == "fgk"

    def test_fgk_key_returns_correct_tenant(self, monkeypatch) -> None:
        monkeypatch.setenv("FG_DB_BACKEND", "postgres")
        principal = _make_principal(tenant_id="tenant-beta")

        with patch("api.credential_authority.validate_credential", return_value=principal):
            with patch("api.db.get_engine", return_value=MagicMock()):
                result = verify_api_key_detailed(raw=_FGK_KEY)

        assert result.tenant_id == "tenant-beta"


# ---------------------------------------------------------------------------
# B — Canonical miss falls through to legacy
# ---------------------------------------------------------------------------


class TestB_CanonicalMiss:
    def test_canonical_miss_falls_to_legacy_key_not_found(self, monkeypatch) -> None:
        """CredentialNotFoundError → falls through; legacy also fails → key_not_found."""
        monkeypatch.setenv("FG_DB_BACKEND", "postgres")

        with patch(
            "api.credential_authority.validate_credential",
            side_effect=CredentialNotFoundError("not found"),
        ):
            with patch("api.db.get_engine", return_value=MagicMock()):
                with patch(
                    "api.auth_scopes.store.get_key_row",
                    return_value=(None, None, set()),
                ):
                    result = verify_api_key_detailed(raw=_FGK_KEY)

        assert result.valid is False
        assert result.reason == "key_not_found"

    def test_canonical_error_falls_to_legacy(self, monkeypatch) -> None:
        """Unexpected error in canonical path falls back without raising."""
        monkeypatch.setenv("FG_DB_BACKEND", "postgres")

        with patch(
            "api.credential_authority.validate_credential",
            side_effect=RuntimeError("db timeout"),
        ):
            with patch("api.db.get_engine", return_value=MagicMock()):
                with patch(
                    "api.auth_scopes.store.get_key_row",
                    return_value=(None, None, set()),
                ):
                    result = verify_api_key_detailed(raw=_FGK_KEY)

        assert result.valid is False
        assert result.reason == "key_not_found"


# ---------------------------------------------------------------------------
# C — Non-fgk. keys bypass canonical entirely
# ---------------------------------------------------------------------------


class TestC_LegacyBypass:
    def test_legacy_key_never_calls_canonical(self, monkeypatch) -> None:
        monkeypatch.setenv("FG_DB_BACKEND", "postgres")

        with patch("api.credential_authority.validate_credential") as mock_ca:
            with patch(
                "api.auth_scopes.store.get_key_row",
                return_value=(None, None, set()),
            ):
                result = verify_api_key_detailed(raw=_LEGACY_KEY)

        mock_ca.assert_not_called()
        assert result.valid is False

    def test_sqlite_backend_skips_canonical(self, monkeypatch) -> None:
        monkeypatch.setenv("FG_DB_BACKEND", "sqlite")
        monkeypatch.setenv("FG_SQLITE_PATH", "/tmp/nonexistent_r47_test.db")

        with patch("api.credential_authority.validate_credential") as mock_ca:
            result = verify_api_key_detailed(raw=_FGK_KEY)

        mock_ca.assert_not_called()
        # SQLite path: key not found in (nonexistent) db → valid=False
        assert result.valid is False


# ---------------------------------------------------------------------------
# D — Scope enforcement on canonical path
# ---------------------------------------------------------------------------


class TestD_ScopeCheck:
    def test_required_scope_present_passes(self, monkeypatch) -> None:
        monkeypatch.setenv("FG_DB_BACKEND", "postgres")
        principal = _make_principal(scopes=frozenset(["api:read", "api:write"]))

        with patch("api.credential_authority.validate_credential", return_value=principal):
            with patch("api.db.get_engine", return_value=MagicMock()):
                result = verify_api_key_detailed(
                    raw=_FGK_KEY, required_scopes={"api:read"}
                )

        assert result.valid is True
        assert result.reason == "canonical_validated"

    def test_required_scope_missing_returns_invalid(self, monkeypatch) -> None:
        monkeypatch.setenv("FG_DB_BACKEND", "postgres")
        principal = _make_principal(scopes=frozenset(["api:read"]))

        with patch("api.credential_authority.validate_credential", return_value=principal):
            with patch("api.db.get_engine", return_value=MagicMock()):
                result = verify_api_key_detailed(
                    raw=_FGK_KEY, required_scopes={"api:write"}
                )

        assert result.valid is False
        assert "missing_scopes" in result.reason
        assert result.tenant_id == "tenant-alpha"
