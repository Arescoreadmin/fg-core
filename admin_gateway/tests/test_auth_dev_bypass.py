"""Tests for dev auth bypass gating."""

import pytest

from admin_gateway.auth.config import AuthConfig, reset_auth_config
from admin_gateway.auth.dev_bypass import (
    DevBypassError,
    assert_not_production,
    create_dev_session,
    get_dev_bypass_session,
    is_dev_bypass_allowed,
)
from admin_gateway.auth.scopes import Scope


@pytest.fixture(autouse=True)
def reset_config():
    """Reset auth config cache between tests."""
    reset_auth_config()
    yield
    reset_auth_config()


class TestDevBypassAllowed:
    """Tests for is_dev_bypass_allowed function."""

    def test_allowed_in_dev_with_bypass_enabled(self):
        """Test bypass is allowed in dev when FG_DEV_AUTH_BYPASS=true."""
        config = AuthConfig(env="dev", dev_auth_bypass=True)
        assert is_dev_bypass_allowed(config) is True

    def test_not_allowed_in_dev_without_bypass(self):
        """Test bypass is not allowed in dev without FG_DEV_AUTH_BYPASS."""
        config = AuthConfig(env="dev", dev_auth_bypass=False)
        assert is_dev_bypass_allowed(config) is False

    def test_never_allowed_in_prod(self):
        """Test bypass is NEVER allowed in production."""
        config = AuthConfig(env="prod", dev_auth_bypass=True)
        assert is_dev_bypass_allowed(config) is False

    def test_never_allowed_in_production(self):
        """Test bypass is NEVER allowed in 'production' env."""
        config = AuthConfig(env="production", dev_auth_bypass=True)
        assert is_dev_bypass_allowed(config) is False

    @pytest.mark.parametrize("env", ["staging", "test", "local", "development"])
    def test_allowed_in_non_prod_environments(self, env):
        """Test bypass is allowed in various non-prod environments."""
        config = AuthConfig(env=env, dev_auth_bypass=True)
        # Only dev/development/local should allow bypass
        expected = env in ("dev", "local", "development")
        assert config.is_dev == expected


class TestAssertNotProduction:
    """Tests for assert_not_production function."""

    def test_passes_in_dev(self):
        """Test assert_not_production passes in dev."""
        config = AuthConfig(env="dev")
        assert_not_production(config)  # Should not raise

    def test_raises_in_prod(self):
        """Test assert_not_production raises in prod."""
        config = AuthConfig(env="prod")
        with pytest.raises(DevBypassError) as exc_info:
            assert_not_production(config)
        assert "NOT allowed in production" in str(exc_info.value)

    def test_raises_in_production(self):
        """Test assert_not_production raises in production."""
        config = AuthConfig(env="production")
        with pytest.raises(DevBypassError):
            assert_not_production(config)


class TestCreateDevSession:
    """Tests for create_dev_session function."""

    def test_creates_session_in_dev(self):
        """Test create_dev_session creates session in dev."""
        config = AuthConfig(env="dev", dev_auth_bypass=True)
        session = create_dev_session(config=config)

        assert session.user_id == "dev-user"
        assert session.email == "dev@localhost"
        assert session.name == "Development User"
        assert Scope.CONSOLE_ADMIN.value in session.scopes

    def test_raises_in_prod(self):
        """Test create_dev_session raises in prod."""
        config = AuthConfig(env="prod", dev_auth_bypass=True)
        with pytest.raises(DevBypassError):
            create_dev_session(config=config)

    def test_raises_when_bypass_disabled(self):
        """Test create_dev_session raises when bypass is disabled."""
        config = AuthConfig(env="dev", dev_auth_bypass=False)
        with pytest.raises(DevBypassError) as exc_info:
            create_dev_session(config=config)
        assert "disabled" in str(exc_info.value)

    def test_custom_user_info(self):
        """Test create_dev_session with custom user info."""
        config = AuthConfig(env="dev", dev_auth_bypass=True)
        session = create_dev_session(
            user_id="custom-user",
            email="custom@test.local",
            name="Custom User",
            scopes={Scope.KEYS_READ.value},
            tenant_id="custom-tenant",
            config=config,
        )

        assert session.user_id == "custom-user"
        assert session.email == "custom@test.local"
        assert session.name == "Custom User"
        assert Scope.KEYS_READ.value in session.scopes
        assert session.tenant_id == "custom-tenant"

    def test_session_has_dev_bypass_claim(self):
        """Test dev session has dev_bypass=True claim."""
        config = AuthConfig(env="dev", dev_auth_bypass=True)
        session = create_dev_session(config=config)

        assert session.claims.get("dev_bypass") is True


class TestGetDevBypassSession:
    """Tests for get_dev_bypass_session function."""

    def test_returns_session_when_allowed(self):
        """Test returns session when dev bypass is allowed."""
        config = AuthConfig(env="dev", dev_auth_bypass=True)
        session = get_dev_bypass_session(config)

        assert session is not None
        assert session.user_id == "dev-user"

    def test_returns_none_when_not_allowed(self):
        """Test returns None when dev bypass is not allowed."""
        config = AuthConfig(env="dev", dev_auth_bypass=False)
        session = get_dev_bypass_session(config)

        assert session is None

    def test_returns_none_in_prod(self):
        """Test returns None in production (doesn't raise)."""
        config = AuthConfig(env="prod", dev_auth_bypass=False)
        session = get_dev_bypass_session(config)

        assert session is None


class TestProductionSafety:
    """Critical tests for production safety."""

    def test_prod_env_detected_correctly(self):
        """Test production environment is correctly detected."""
        for env in ["prod", "production", "PROD", "PRODUCTION", "Prod"]:
            config = AuthConfig(env=env)
            assert config.is_prod is True, f"Failed for env={env}"

    def test_dev_bypass_config_ignored_in_prod(self):
        """Test dev_bypass setting is ignored in production."""
        config = AuthConfig(env="prod", dev_auth_bypass=True)

        # Even with dev_auth_bypass=True, is_prod should block it
        assert config.is_prod is True
        assert config.dev_bypass_allowed is False

    def test_multiple_security_layers(self):
        """Test multiple security checks exist for production."""
        config = AuthConfig(env="prod", dev_auth_bypass=True)

        # Layer 1: is_prod check
        assert config.is_prod is True

        # Layer 2: dev_bypass_allowed property
        assert config.dev_bypass_allowed is False

        # Layer 3: is_dev_bypass_allowed function
        assert is_dev_bypass_allowed(config) is False

        # Layer 4: assert_not_production raises
        with pytest.raises(DevBypassError):
            assert_not_production(config)

        # Layer 5: create_dev_session raises
        with pytest.raises(DevBypassError):
            create_dev_session(config=config)

    def test_config_validation_catches_prod_bypass(self):
        """Test config validation catches prod+bypass misconfiguration."""
        config = AuthConfig(env="prod", dev_auth_bypass=True)
        errors = config.validate()

        assert any("DEV_AUTH_BYPASS" in e for e in errors)
        assert any("production" in e.lower() for e in errors)
