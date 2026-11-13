"""CODEQL-REMEDIATE-002 — session identifiers must not reach application logs.

CodeQL #53 (py/clear-text-logging-sensitive-data) flagged the raw session id
logged by ``SessionAuthority.create_session``. The same raw id also reached
logs through ``revoke_session`` (INFO), the ``SessionRevokedError`` message,
and the identity auditor's log line on logout. Session ids are the revocation
key and the per-session correlation handle; central log readers must not
receive them.

Logs carry ``sid_ref`` instead: an HMAC-SHA256 of the id under a key derived
from the session secret with a dedicated domain label, truncated to 16 hex
chars. It correlates events for one session but cannot be recomputed from a
log line without the server secret (no unsalted hash).

The hash-chained identity audit record keeps the raw id (governed forensic
store); only the log line changes.

All values below are synthetic.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets

import pytest

from api.logging_config import _JsonFormatter

_SECRET = "synthetic-session-secret-" + "x" * 16
_LOGGER = "frostgate.identity_authority"


@pytest.fixture
def authority(monkeypatch):
    monkeypatch.setenv("FG_SESSION_SECRET", _SECRET)
    monkeypatch.delenv("FG_REDIS_URL", raising=False)
    from api.identity_authority.session_authority import SessionAuthority

    return SessionAuthority()


def _rendered(caplog) -> str:
    """Every captured record, as the JSON line shipped to ELK/Loki plus text."""
    fmt = _JsonFormatter(service="test")
    out = []
    for rec in caplog.records:
        out.append(fmt.format(rec))
        out.append(rec.getMessage())
        out.append(repr(rec.__dict__))
    return "\n".join(out)


def _records(caplog, event: str) -> list[dict]:
    fmt = _JsonFormatter(service="test")
    return [
        json.loads(fmt.format(r)) for r in caplog.records if r.getMessage() == event
    ]


def _create(authority):
    return authority.create_session(
        subject="user-synthetic-1",
        email="synthetic@example.invalid",
        tenant_id="tenant-a",
        provider="oidc",
        mfa_verified=True,
    )


def test_session_created_log_has_no_raw_session_id(authority, caplog):
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    token = _create(authority)

    text = _rendered(caplog)
    assert token.session_id not in text
    assert token.token not in text
    # Approved telemetry is still present.
    (rec,) = _records(caplog, "session_authority.session_created")
    assert rec["provider"] == "oidc"
    assert rec["mfa"] is True
    assert rec["sid_ref"] == authority.session_log_ref(token.session_id)


def test_session_revoked_log_has_no_raw_session_id(authority, caplog):
    token = _create(authority)
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    authority.revoke_session(token.session_id)

    assert token.session_id not in _rendered(caplog)
    (rec,) = _records(caplog, "session_authority.session_revoked")
    assert rec["level"] == "INFO"
    assert rec["sid_ref"] == authority.session_log_ref(token.session_id)


def test_sid_ref_correlates_create_and_revoke(authority, caplog):
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    token = _create(authority)
    authority.revoke_session(token.session_id)
    other = _create(authority)

    created = _records(caplog, "session_authority.session_created")
    (revoked,) = _records(caplog, "session_authority.session_revoked")
    assert created[0]["sid_ref"] == revoked["sid_ref"]
    assert created[1]["sid_ref"] != revoked["sid_ref"]
    assert other.session_id not in _rendered(caplog)


def test_revoked_session_error_does_not_carry_session_id(authority, caplog):
    from api.identity_authority.session_authority import SessionRevokedError

    token = _create(authority)
    authority.revoke_session(token.session_id)
    caplog.set_level(logging.DEBUG, logger=_LOGGER)

    with pytest.raises(SessionRevokedError) as exc_info:
        authority.validate_session(token.token)

    assert token.session_id not in str(exc_info.value)
    assert token.session_id not in repr(exc_info.value)
    assert "revoked" in str(exc_info.value)  # error category retained
    assert token.session_id not in _rendered(caplog)


@pytest.mark.parametrize(
    "mangle",
    [
        lambda t: t[:-4] + "0000",  # bad signature
        lambda t: "not-a-token",  # malformed
        lambda t: "Bearer " + t,  # header value passed through
        lambda t: t.split(".")[0],  # signature stripped
    ],
)
def test_failed_validation_logs_and_errors_have_no_token_material(
    authority, caplog, mangle
):
    from api.identity_authority.session_authority import SessionInvalidError

    token = _create(authority)
    bad = mangle(token.token)
    caplog.set_level(logging.DEBUG, logger=_LOGGER)

    with pytest.raises(SessionInvalidError) as exc_info:
        authority.validate_session(bad)

    text = _rendered(caplog) + str(exc_info.value)
    assert token.session_id not in text
    assert token.token not in text


def test_sid_ref_is_keyed_not_an_unsalted_hash(authority, monkeypatch):
    sid = secrets.token_urlsafe(24)
    ref = authority.session_log_ref(sid)

    assert len(ref) == 16
    assert sid not in ref
    # Not guessable offline from the id alone.
    assert ref != hashlib.sha256(sid.encode()).hexdigest()[:16]
    # Bound to the server secret.
    from api.identity_authority.session_authority import SessionAuthority

    monkeypatch.setenv("FG_SESSION_SECRET", "a-different-synthetic-secret-zzzz")
    assert SessionAuthority().session_log_ref(sid) != ref
    # Domain-separated from token signing: not the signature of the id.
    assert ref != authority._sign(sid)[:16]


def test_logout_audit_log_line_omits_raw_session_id_but_record_keeps_it(
    authority, caplog
):
    from api.identity_authority import audit as audit_mod
    from api.identity_authority.authority import IdentityAuthority

    persisted: list[dict] = []
    auditor = audit_mod.IdentityAuditor()
    auditor._persist = lambda **kw: persisted.append(kw)  # type: ignore[method-assign]
    auditor.set_db_factory(object())
    ia = IdentityAuthority(
        provider_registry=None,  # type: ignore[arg-type]
        session_authority=authority,
        tenant_resolver=None,  # type: ignore[arg-type]
        auditor=auditor,
    )
    token = _create(authority)
    caplog.set_level(logging.DEBUG, logger=_LOGGER)

    ia.logout(token.session_id, subject="user-synthetic-1", correlation_id="req-1")

    assert token.session_id not in _rendered(caplog)
    (line,) = _records(caplog, audit_mod.IdentityEventType.LOGOUT.value)
    assert line["correlation_id"] == "req-1"
    assert line["event_id"]
    assert line["sid_ref"] == authority.session_log_ref(token.session_id)
    # The governed, hash-chained audit record is unchanged: it keeps the id.
    (rec,) = persisted
    assert rec["details"] == {"sid": token.session_id}
    assert rec["event_id"] == line["event_id"]


def _identity_authority(authority):
    """IdentityAuthority over the real SessionAuthority with a capturing auditor."""
    from api.identity_authority import audit as audit_mod
    from api.identity_authority.authority import IdentityAuthority

    persisted: list[dict] = []
    auditor = audit_mod.IdentityAuditor()
    auditor._persist = lambda **kw: persisted.append(kw)  # type: ignore[method-assign]
    auditor.set_db_factory(object())
    ia = IdentityAuthority(
        provider_registry=None,  # type: ignore[arg-type]
        session_authority=authority,
        tenant_resolver=None,  # type: ignore[arg-type]
        auditor=auditor,
    )
    return ia, persisted


def test_identity_authority_session_created_audit_log_omits_raw_session_id(
    authority, caplog, canonical_identity
):
    # Codex review on #866: the SESSION_CREATED audit event also carried the
    # raw sid into the INFO log line.
    from api.identity_authority import audit as audit_mod
    from api.identity_authority.models import AuthorizationContext

    ia, persisted = _identity_authority(authority)
    ctx = AuthorizationContext(
        identity=canonical_identity,
        permissions=frozenset(),
        capabilities=frozenset(),
        tenant_id="tenant-123",
        organization_id=None,
        session_id="",
        session_risk_score=0.0,
        correlation_id="req-create-1",
    )
    caplog.set_level(logging.DEBUG, logger=_LOGGER)

    signed = ia.create_session(ctx)
    sid = authority.validate_session(signed).session_id

    text = _rendered(caplog)
    assert sid not in text
    assert signed not in text
    (line,) = _records(caplog, audit_mod.IdentityEventType.SESSION_CREATED.value)
    assert line["sid_ref"] == authority.session_log_ref(sid)
    assert line["mfa"] is True
    assert line["correlation_id"] == "req-create-1"
    # Correlates with the lower-level session_authority event.
    (low,) = _records(caplog, "session_authority.session_created")
    assert low["sid_ref"] == line["sid_ref"]
    # The governed audit record still holds the raw id.
    (rec,) = persisted
    assert rec["details"] == {"sid": sid, "mfa": True}
    assert rec["event_id"] == line["event_id"]
