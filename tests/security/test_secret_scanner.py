"""
Regression tests for tools/ci/check_no_plaintext_secrets.py

Invariants proven:
A) Documentation / literal safety
   - A file using [REDACTED_EXPOSED_PASSWORD] passes the scanner.
   - A file containing the exact blocked literal fails.

B) URL credential scanning is independent of key name
   - DATABASE_URL, FG_DB_URL, REDIS_URL with plaintext password → FAIL
   - DATABASE_URL with CHANGE_ME_* credential → PASS
   - DATABASE_URL with ${VAR} shell ref → PASS
   - Non-secret, non-URL config var → PASS

C) Secret-class direct-value checks still work
   - FG_API_KEY=realvalue → FAIL
   - FG_API_KEY=CHANGE_ME_FG_API_KEY → PASS
   - Non-secret plain config (FG_AUTH_ALLOW_FALLBACK=false) → PASS

D) No double-reporting
   - REDIS_PASSWORD=redis://:plainpass@host is reported once (as URL violation)
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tools.ci.check_no_plaintext_secrets import (
    BLOCKED_LITERALS,
    _extract_url_cred,
    _is_acceptable,
    _is_cred_acceptable,
    _is_secret_var,
    _scan_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_env(tmp_path: Path, content: str) -> Path:
    """Write *content* to a temp env file and return the path."""
    p = tmp_path / "test.env"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def _violations(tmp_path: Path, content: str) -> list[str]:
    return _scan_file(_write_env(tmp_path, content))


# ---------------------------------------------------------------------------
# A) Documentation / literal safety
# ---------------------------------------------------------------------------


def test_redacted_token_in_doc_does_not_fail(tmp_path: Path) -> None:
    """[REDACTED_EXPOSED_PASSWORD] in a file must not trigger the blocked literal."""
    violations = _violations(tmp_path, "# The credential was [REDACTED_EXPOSED_PASSWORD]\n")
    assert violations == []


def test_blocked_literal_in_file_fails(tmp_path: Path) -> None:
    """The exact blocked literal anywhere in a scanned file is a hard failure."""
    literal = BLOCKED_LITERALS[0]
    violations = _violations(tmp_path, f"POSTGRES_PASSWORD={literal}\n")
    # Expect at least one violation (blocklist hit + secret-class hit)
    assert any("known-leaked" in v for v in violations)


def test_blocked_literal_in_comment_still_fails(tmp_path: Path) -> None:
    """Blocked literal in a comment line is still caught by the whole-file scan."""
    literal = BLOCKED_LITERALS[0]
    violations = _violations(tmp_path, f"# old value was {literal}\n")
    assert any("known-leaked" in v for v in violations)


# ---------------------------------------------------------------------------
# B) URL credential scanning — independent of key name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key,url", [
    ("DATABASE_URL", "postgresql://fg_user:realpassword@postgres:5432/frostgate"),
    ("FG_DB_URL",   "postgresql+psycopg://fg_user:realpassword@postgres:5432/frostgate"),
    ("REDIS_URL",   "redis://:realpassword@redis:6379/0"),
    ("FG_NATS_URL", "nats://realtoken@nats:4222"),
    ("AMQP_URL",    "amqp://user:realpassword@broker:5672/vhost"),
])
def test_url_plaintext_cred_fails_regardless_of_key_name(
    tmp_path: Path, key: str, url: str
) -> None:
    """Plaintext credential embedded in any URL value must fail, regardless of key."""
    violations = _violations(tmp_path, f"{key}={url}\n")
    url_violations = [v for v in violations if "URL contains a non-placeholder" in v]
    assert url_violations, (
        f"Expected URL credential violation for {key}={url!r}, got: {violations}"
    )


@pytest.mark.parametrize("key,url", [
    (
        "DATABASE_URL",
        "postgresql+psycopg://fg_user:CHANGE_ME_POSTGRES_APP_PASSWORD@postgres:5432/frostgate",
    ),
    (
        "FG_DB_URL",
        "postgresql+psycopg://fg_user:CHANGE_ME_POSTGRES_APP_PASSWORD@postgres:5432/frostgate",
    ),
    (
        "FG_REDIS_URL",
        "redis://:CHANGE_ME_REDIS_PASSWORD@redis:6379/0",
    ),
    (
        "FG_NATS_URL",
        "nats://CHANGE_ME_NATS_AUTH_TOKEN@nats:4222",
    ),
])
def test_url_change_me_cred_passes(tmp_path: Path, key: str, url: str) -> None:
    """CHANGE_ME_* credential embedded in a URL must pass the scanner."""
    violations = _violations(tmp_path, f"{key}={url}\n")
    assert violations == [], f"Unexpected violations for {key}: {violations}"


def test_url_shell_ref_cred_passes(tmp_path: Path) -> None:
    """Shell-ref credential ${VAR} embedded in a URL must pass the scanner."""
    violations = _violations(
        tmp_path,
        "DATABASE_URL=postgresql://user:${POSTGRES_APP_PASSWORD}@postgres:5432/db\n",
    )
    assert violations == [], f"Unexpected violations: {violations}"


def test_non_secret_non_url_config_passes(tmp_path: Path) -> None:
    """Plain config variables with non-secret names and plain values must pass."""
    violations = _violations(
        tmp_path,
        "FG_AUTH_ALLOW_FALLBACK=false\n"
        "FG_OPA_URL=http://opa:8181\n"
        "FG_ENV=prod\n"
        "FG_MAX_BODY_BYTES=4194304\n",
    )
    assert violations == [], f"Unexpected violations: {violations}"


def test_url_without_credentials_passes(tmp_path: Path) -> None:
    """URLs with no userinfo (no @ segment) must pass regardless of key name."""
    violations = _violations(
        tmp_path,
        "FG_OPA_URL=http://opa:8181\n"
        "SOME_ENDPOINT=https://api.example.com/v1\n",
    )
    assert violations == [], f"Unexpected violations: {violations}"


# ---------------------------------------------------------------------------
# C) Secret-class direct value checks
# ---------------------------------------------------------------------------


def test_secret_class_real_value_fails(tmp_path: Path) -> None:
    """A secret-class variable with a real value must fail."""
    violations = _violations(tmp_path, "FG_API_KEY=some-real-api-key-value\n")
    direct_violations = [v for v in violations if "non-placeholder value" in v]
    assert direct_violations


def test_secret_class_change_me_passes(tmp_path: Path) -> None:
    """A secret-class variable with CHANGE_ME_* must pass."""
    violations = _violations(tmp_path, "FG_API_KEY=CHANGE_ME_FG_API_KEY\n")
    assert violations == [], f"Unexpected violations: {violations}"


def test_secret_class_empty_value_passes(tmp_path: Path) -> None:
    """A secret-class variable with an empty value must pass the file scanner."""
    violations = _violations(tmp_path, "FG_API_KEY=\n")
    assert violations == [], f"Unexpected violations: {violations}"


def test_non_secret_class_real_value_passes(tmp_path: Path) -> None:
    """Non-secret config variables with plain values must pass Check B."""
    violations = _violations(
        tmp_path,
        "FG_AUTH_ALLOW_FALLBACK=false\n"
        "FG_ENFORCEMENT_MODE=enforce\n"
        "FG_LOG_LEVEL=info\n",
    )
    assert violations == [], f"Unexpected violations: {violations}"


# ---------------------------------------------------------------------------
# D) No double-reporting
# ---------------------------------------------------------------------------


def test_url_in_secret_class_var_reports_once(tmp_path: Path) -> None:
    """A URL with plaintext cred in a secret-class var should report exactly once."""
    # REDIS_PASSWORD is secret-class; value is also a URL with embedded cred.
    violations = _violations(
        tmp_path, "REDIS_PASSWORD=redis://:plainpassword@redis:6379/0\n"
    )
    # Must report the URL violation (Check A), not a second direct violation (Check B).
    assert len(violations) == 1
    assert "URL contains a non-placeholder" in violations[0]


# ---------------------------------------------------------------------------
# Unit tests for individual helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key,expected", [
    ("POSTGRES_PASSWORD", True),
    ("FG_SIGNING_SECRET", True),
    ("NATS_AUTH_TOKEN", True),
    ("FG_API_KEY", True),
    ("FG_ENCRYPTION_KEY", True),
    ("FG_JWT_SECRET", True),
    ("FG_WEBHOOK_SECRET", True),
    ("FG_INTERNAL_AUTH_SECRET", True),
    ("FG_SESSION_SECRET", True),
    ("FG_AUTH_ALLOW_FALLBACK", False),   # config boolean — must NOT match
    ("FG_AUTH_ENABLED", False),          # config boolean — must NOT match
    ("FG_ENV", False),
    ("FG_LOG_LEVEL", False),
    ("DATABASE_URL", False),             # URL var — not secret-class by name
    ("FG_OPA_URL", False),
])
def test_is_secret_var(key: str, expected: bool) -> None:
    assert _is_secret_var(key) is expected, f"_is_secret_var({key!r}) expected {expected}"


@pytest.mark.parametrize("value,expected", [
    ("CHANGE_ME_POSTGRES_PASSWORD", True),
    ("CHANGE_ME_FG_API_KEY", True),
    ("${POSTGRES_PASSWORD}", True),
    ("${POSTGRES_PASSWORD:?missing}", True),
    ("$POSTGRES_PASSWORD", True),
    ("realpassword", False),
    ("dev-signing-secret", False),
    ("replace-with-real-value", False),
    # Empty credential in a URL (e.g. redis://:@host) is NOT acceptable —
    # use CHANGE_ME_* or remove the @ entirely.
    ("", False),
])
def test_is_cred_acceptable(value: str, expected: bool) -> None:
    assert _is_cred_acceptable(value) is expected


@pytest.mark.parametrize("url,expected_cred", [
    ("postgresql://user:PASSWORD@host/db", "PASSWORD"),
    ("postgresql+psycopg://fg_user:CHANGE_ME_X@host/db", "CHANGE_ME_X"),
    ("redis://:REDISPASS@host:6379/0", "REDISPASS"),
    ("nats://TOKEN@nats:4222", "TOKEN"),
    ("http://opa:8181", None),           # no @ → no credential
    ("https://api.example.com/v1", None),
])
def test_extract_url_cred(url: str, expected_cred: str | None) -> None:
    assert _extract_url_cred(url) == expected_cred


@pytest.mark.parametrize("value,expected", [
    ("", True),
    ("CHANGE_ME_FG_API_KEY", True),
    ("${FG_API_KEY}", True),
    ("postgresql://user:CHANGE_ME_X@host/db", True),
    ("redis://:CHANGE_ME_REDIS_PASSWORD@host:6379/0", True),
    ("nats://CHANGE_ME_NATS_AUTH_TOKEN@nats:4222", True),
    ("postgresql://user:realpass@host/db", False),
    ("redis://:realpass@host/0", False),
    ("realvalue", False),
    ("http://opa:8181", True),   # no embedded credential → acceptable
])
def test_is_acceptable(value: str, expected: bool) -> None:
    assert _is_acceptable(value) is expected, (
        f"_is_acceptable({value!r}) expected {expected}"
    )
