"""Tests for CSRF protection."""

import time

import pytest

from admin_gateway.auth.csrf import (
    CSRFProtection,
    STATE_CHANGING_METHODS,
    CSRF_EXEMPT_PATHS,
    requires_csrf_protection,
)
from admin_gateway.auth.config import AuthConfig


@pytest.fixture
def csrf():
    """Create CSRF protection instance with test config."""
    config = AuthConfig(
        session_secret="test-secret-key-for-csrf-testing",
        csrf_cookie_name="test_csrf",
        csrf_header_name="X-Test-CSRF",
    )
    return CSRFProtection(config)


class TestCSRFTokenGeneration:
    """Tests for CSRF token generation."""

    def test_generate_token_format(self, csrf):
        """Test token has correct format: random.timestamp.signature."""
        token = csrf._generate_token()
        parts = token.split(".")
        assert len(parts) == 3
        assert len(parts[0]) > 20  # Random part
        assert parts[1].isdigit()  # Timestamp
        assert len(parts[2]) == 16  # Signature

    def test_generate_unique_tokens(self, csrf):
        """Test each generated token is unique."""
        tokens = [csrf._generate_token() for _ in range(100)]
        assert len(set(tokens)) == 100

    def test_token_timestamp_is_current(self, csrf):
        """Test token timestamp is close to current time."""
        token = csrf._generate_token()
        timestamp = int(token.split(".")[1])
        assert abs(time.time() - timestamp) < 5


class TestCSRFTokenValidation:
    """Tests for CSRF token validation."""

    def test_validate_valid_token(self, csrf):
        """Test valid token passes validation."""
        token = csrf._generate_token()
        assert csrf._validate_token(token) is True

    def test_validate_invalid_format(self, csrf):
        """Test invalid format fails validation."""
        assert csrf._validate_token("not-a-valid-token") is False
        # "only.two.parts" has 3 parts but invalid signature
        assert csrf._validate_token("only.two.parts") is False
        assert csrf._validate_token("single") is False
        assert csrf._validate_token("") is False

    def test_validate_wrong_signature(self, csrf):
        """Test wrong signature fails validation."""
        token = csrf._generate_token()
        parts = token.split(".")
        bad_token = f"{parts[0]}.{parts[1]}.wrongsignature!"
        assert csrf._validate_token(bad_token) is False

    def test_validate_expired_token(self, csrf):
        """Test expired token fails validation."""
        # Create token with old timestamp
        random_part = "test-random-value-here"
        old_timestamp = str(int(time.time()) - csrf.TOKEN_TTL - 100)
        import hashlib
        import hmac

        data = f"{random_part}.{old_timestamp}".encode()
        sig = hmac.new(csrf._secret, data, hashlib.sha256).hexdigest()[:16]
        old_token = f"{random_part}.{old_timestamp}.{sig}"

        assert csrf._validate_token(old_token) is False

    def test_validate_tampered_timestamp(self, csrf):
        """Test tampered timestamp fails due to signature mismatch."""
        token = csrf._generate_token()
        parts = token.split(".")
        # Tamper with timestamp
        tampered = f"{parts[0]}.9999999999.{parts[2]}"
        assert csrf._validate_token(tampered) is False


class TestCSRFProtectionRequired:
    """Tests for determining when CSRF protection is required."""

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_state_changing_methods_require_csrf(self, method):
        """Test state-changing methods require CSRF protection."""
        assert requires_csrf_protection(method, "/some/path") is True

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
    def test_safe_methods_skip_csrf(self, method):
        """Test safe methods skip CSRF protection."""
        assert requires_csrf_protection(method, "/some/path") is False

    @pytest.mark.parametrize("path", list(CSRF_EXEMPT_PATHS))
    def test_exempt_paths_skip_csrf(self, path):
        """Test exempt paths skip CSRF protection."""
        assert requires_csrf_protection("POST", path) is False

    def test_state_changing_methods_constant(self):
        """Test STATE_CHANGING_METHODS is as expected."""
        assert STATE_CHANGING_METHODS == {"POST", "PUT", "PATCH", "DELETE"}


class TestCSRFCookie:
    """Tests for CSRF cookie handling."""

    def test_set_token_cookie(self, csrf):
        """Test setting CSRF token cookie."""
        from fastapi import Response

        response = Response()
        token = csrf.set_token_cookie(response)

        assert token is not None
        assert csrf._validate_token(token) is True

    def test_set_custom_token(self, csrf):
        """Test setting custom CSRF token."""
        from fastapi import Response

        response = Response()
        custom_token = "custom.123456.abcdef0123456789"
        returned = csrf.set_token_cookie(response, token=custom_token)

        assert returned == custom_token
