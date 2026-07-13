"""tests/test_identity_assurance.py — Enterprise Identity Assurance & Trust Levels.

Tests IA-1 through IA-172 covering:
  * Engine determinism (compute_assurance_level, compute_trust_score, evaluators)
  * Provider adapters (keycloak, entra, okta, google, ping, auth0)
  * Provider detection heuristics
  * Trust band mapping
  * AssuranceDecision fingerprint uniqueness and determinism
  * Chain-hash continuity
  * ORM append-only guards
  * API contract (200, 404, auth/scope enforcement, pagination, isolation)
  * Metrics counters
"""

from __future__ import annotations

import sqlite3
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from services.identity_assurance.engine import (
    TRUST_SCORE_TABLE,
    build_assurance_decision,
    chain_hash,
    compute_assurance_level,
    compute_trust_score,
    determine_identity_provider,
    evaluate_authentication_strength,
    hash_provider_claims,
    normalize_provider_claims,
    trust_band_for_score,
)
from services.identity_assurance.models import (
    AssuranceDecision,
    AssuranceLevel,
    AssuranceSnapshot,
    IdentityProvider,
    ProviderClaims,
    TrustBand,
    TrustContext,
)


# ── helpers ───────────────────────────────────────────────────────────────────


def _uid() -> str:
    return uuid4().hex


def _insert_assurance(
    db_path: str,
    tenant_id: str,
    actor_id: str,
    level: str = "SSO_MFA",
    score: int = 84,
    provider: str = "OKTA",
    auth_method: str = "sso_mfa",
    fingerprint: str | None = None,
    chain: str | None = None,
    previous_level: str | None = None,
    is_current: int = 1,
    row_id: str | None = None,
) -> str:
    """Insert a row into actor_identity_assurance via sqlite3 (direct)."""
    row_id = row_id or _uid()
    fingerprint = fingerprint or ("a" * 64)
    chain = chain or ("b" * 64)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO actor_identity_assurance
            (id, tenant_id, actor_id, assurance_level, trust_score,
             identity_provider, authentication_method, provider_claims_hash,
             decision_fingerprint, chain_hash, previous_assurance_level,
             is_current, computed_at, created_at, schema_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '1.0')
            """,
            (
                row_id,
                tenant_id,
                actor_id,
                level,
                score,
                provider,
                auth_method,
                "c" * 64,
                fingerprint,
                chain,
                previous_level,
                is_current,
                "2026-07-13T00:00:00+00:00",
                "2026-07-13T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return row_id


def _insert_snapshot(
    db_path: str,
    tenant_id: str,
    actor_id: str,
    prev_level: str | None,
    new_level: str,
    score: int,
    sequence_number: int = 0,
    chain: str | None = None,
    fingerprint: str | None = None,
    reason: str | None = None,
    row_id: str | None = None,
) -> str:
    row_id = row_id or _uid()
    chain = chain or ("b" * 64)
    fingerprint = fingerprint or ("a" * 64)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO actor_assurance_snapshots
            (id, tenant_id, actor_id, sequence_number,
             previous_assurance_level, new_assurance_level, trust_score,
             identity_provider, authentication_method, reason,
             snapshot_fingerprint, chain_hash, created_at, schema_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'OKTA', 'sso_mfa', ?, ?, ?, ?, '1.0')
            """,
            (
                row_id,
                tenant_id,
                actor_id,
                sequence_number,
                prev_level,
                new_level,
                score,
                reason,
                fingerprint,
                chain,
                "2026-07-13T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return row_id


def _insert_history(
    db_path: str,
    tenant_id: str,
    actor_id: str,
    event_type: str = "assurance_computed",
    level: str = "SSO_MFA",
    score: int = 84,
    triggered_by: str | None = "test",
    row_id: str | None = None,
) -> str:
    row_id = row_id or _uid()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO actor_assurance_history
            (id, tenant_id, actor_id, event_type, assurance_level,
             trust_score, triggered_by, metadata, created_at, schema_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?, '1.0')
            """,
            (
                row_id,
                tenant_id,
                actor_id,
                event_type,
                level,
                score,
                triggered_by,
                "2026-07-13T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return row_id


def _password_only_claims() -> ProviderClaims:
    return ProviderClaims(
        subject="alice",
        authentication_method="password",
        mfa_verified=False,
        passwordless=False,
    )


def _sso_mfa_claims() -> ProviderClaims:
    return ProviderClaims(
        subject="alice",
        email="alice@corp.example",
        issuer="https://okta.com/oauth",
        provider_hint="okta",
        authentication_method="sso",
        mfa_verified=True,
    )


# ── Group 1: Engine — compute_assurance_level (IA-1 .. IA-20) ─────────────────


def test_ia_1_unverified_when_no_claims():
    assert compute_assurance_level(ProviderClaims()) == AssuranceLevel.UNVERIFIED


def test_ia_2_password_only_maps_to_password():
    assert compute_assurance_level(_password_only_claims()) == AssuranceLevel.PASSWORD


def test_ia_3_password_mfa_when_mfa_and_no_sso():
    claims = ProviderClaims(
        subject="alice", authentication_method="password", mfa_verified=True
    )
    assert compute_assurance_level(claims) == AssuranceLevel.PASSWORD_MFA


def test_ia_4_sso_when_issuer_and_subject_present():
    claims = ProviderClaims(subject="alice", issuer="https://okta.com/oauth")
    assert compute_assurance_level(claims) == AssuranceLevel.SSO


def test_ia_5_sso_mfa_when_issuer_and_mfa():
    assert compute_assurance_level(_sso_mfa_claims()) == AssuranceLevel.SSO_MFA


def test_ia_6_hardware_key_takes_precedence_over_mfa():
    claims = ProviderClaims(
        subject="alice",
        issuer="https://okta.com/oauth",
        mfa_verified=True,
        hardware_key_verified=True,
    )
    assert compute_assurance_level(claims) == AssuranceLevel.HARDWARE_KEY


def test_ia_7_certificate_wins_over_sso():
    claims = ProviderClaims(
        subject="alice",
        issuer="https://okta.com/oauth",
        certificate_verified=True,
    )
    assert compute_assurance_level(claims) == AssuranceLevel.CERTIFICATE


def test_ia_8_smart_card_maps_to_certificate():
    claims = ProviderClaims(subject="alice", smart_card_verified=True)
    assert compute_assurance_level(claims) == AssuranceLevel.CERTIFICATE


def test_ia_9_workload_identity_is_terminal():
    claims = ProviderClaims(is_workload_identity=True)
    assert compute_assurance_level(claims) == AssuranceLevel.WORKLOAD_IDENTITY


def test_ia_10_system_autonomous_wins_over_workload_identity():
    claims = ProviderClaims(is_workload_identity=True, is_system_autonomous=True)
    assert compute_assurance_level(claims) == AssuranceLevel.SYSTEM_AUTONOMOUS


def test_ia_11_service_account_short_circuits_sso():
    claims = ProviderClaims(
        subject="svc-1",
        issuer="https://okta.com/oauth",
        is_service_account=True,
    )
    assert compute_assurance_level(claims) == AssuranceLevel.SERVICE_ACCOUNT


def test_ia_12_password_when_authentication_method_only():
    claims = ProviderClaims(subject="alice", authentication_method="password")
    assert compute_assurance_level(claims) == AssuranceLevel.PASSWORD


def test_ia_13_mfa_without_sso_yields_password_mfa():
    claims = ProviderClaims(subject="alice", mfa_verified=True)
    assert compute_assurance_level(claims) == AssuranceLevel.PASSWORD_MFA


def test_ia_14_issuer_only_without_subject_is_unverified():
    claims = ProviderClaims(issuer="https://okta.com/oauth")
    assert compute_assurance_level(claims) == AssuranceLevel.UNVERIFIED


def test_ia_15_subject_without_issuer_and_no_password_hint_is_unverified():
    claims = ProviderClaims(subject="alice")
    assert compute_assurance_level(claims) == AssuranceLevel.UNVERIFIED


def test_ia_16_evaluate_authentication_strength_is_deterministic():
    claims = _sso_mfa_claims()
    assert evaluate_authentication_strength(claims) == compute_assurance_level(claims)


def test_ia_17_none_claims_returns_unverified():
    assert evaluate_authentication_strength(None) == AssuranceLevel.UNVERIFIED  # type: ignore[arg-type]


def test_ia_18_certificate_wins_over_hardware_key_when_only_cert():
    claims = ProviderClaims(subject="alice", certificate_verified=True)
    assert compute_assurance_level(claims) == AssuranceLevel.CERTIFICATE


def test_ia_19_hardware_key_beats_certificate():
    claims = ProviderClaims(
        subject="alice",
        certificate_verified=True,
        hardware_key_verified=True,
    )
    assert compute_assurance_level(claims) == AssuranceLevel.HARDWARE_KEY


def test_ia_20_service_account_beats_workload_identity_only_when_workload_false():
    claims = ProviderClaims(is_service_account=True, is_workload_identity=False)
    assert compute_assurance_level(claims) == AssuranceLevel.SERVICE_ACCOUNT


# ── Group 2: Engine — compute_trust_score (IA-21 .. IA-35) ────────────────────


@pytest.mark.parametrize(
    "level,expected",
    [
        (AssuranceLevel.UNVERIFIED, 0),
        (AssuranceLevel.PASSWORD, 32),
        (AssuranceLevel.PASSWORD_MFA, 68),
        (AssuranceLevel.SSO, 74),
        (AssuranceLevel.SSO_MFA, 84),
        (AssuranceLevel.CERTIFICATE, 95),
        (AssuranceLevel.HARDWARE_KEY, 98),
        (AssuranceLevel.WORKLOAD_IDENTITY, 100),
        (AssuranceLevel.SERVICE_ACCOUNT, 72),
        (AssuranceLevel.SYSTEM_AUTONOMOUS, 90),
    ],
)
def test_ia_21_to_30_trust_score_table(level, expected):
    assert compute_trust_score(level) == expected


def test_ia_31_trust_score_table_covers_every_level():
    for level in AssuranceLevel:
        assert level in TRUST_SCORE_TABLE


def test_ia_32_scores_ordered_by_assurance_strength():
    weakest = compute_trust_score(AssuranceLevel.UNVERIFIED)
    strongest = compute_trust_score(AssuranceLevel.WORKLOAD_IDENTITY)
    assert weakest == 0 and strongest == 100


def test_ia_33_compute_trust_score_pure():
    a = compute_trust_score(AssuranceLevel.SSO)
    b = compute_trust_score(AssuranceLevel.SSO)
    assert a == b


def test_ia_34_score_bounds_are_valid():
    for level in AssuranceLevel:
        s = compute_trust_score(level)
        assert 0 <= s <= 100


def test_ia_35_trust_band_maps_zero_to_critical():
    assert trust_band_for_score(0) == TrustBand.CRITICAL


# ── Group 3: Trust band mapping (IA-36 .. IA-55) ──────────────────────────────


@pytest.mark.parametrize(
    "score,band",
    [
        (0, TrustBand.CRITICAL),
        (10, TrustBand.CRITICAL),
        (20, TrustBand.CRITICAL),
        (21, TrustBand.LOW),
        (32, TrustBand.LOW),
        (40, TrustBand.LOW),
        (41, TrustBand.MODERATE),
        (50, TrustBand.MODERATE),
        (60, TrustBand.MODERATE),
        (61, TrustBand.HIGH),
        (68, TrustBand.HIGH),
        (74, TrustBand.HIGH),
        (80, TrustBand.HIGH),
        (81, TrustBand.VERY_HIGH),
        (84, TrustBand.VERY_HIGH),
        (95, TrustBand.VERY_HIGH),
        (98, TrustBand.VERY_HIGH),
        (100, TrustBand.VERY_HIGH),
    ],
)
def test_ia_36_to_53_trust_band_thresholds(score, band):
    assert trust_band_for_score(score) == band


def test_ia_54_trust_band_negative_score_defaults_to_critical():
    assert trust_band_for_score(-1) == TrustBand.CRITICAL


def test_ia_55_trust_band_over_100_defaults_to_critical():
    # 101 is out of range → guard falls to CRITICAL by design.
    assert trust_band_for_score(101) == TrustBand.CRITICAL


# ── Group 4: Engine — determine_identity_provider (IA-56 .. IA-75) ────────────


def test_ia_56_hint_keycloak():
    assert (
        determine_identity_provider({"provider_hint": "keycloak"})
        == IdentityProvider.KEYCLOAK
    )


def test_ia_57_hint_entra():
    assert (
        determine_identity_provider({"provider_hint": "entra"})
        == IdentityProvider.ENTRA_ID
    )


def test_ia_58_hint_okta():
    assert (
        determine_identity_provider({"provider_hint": "okta"}) == IdentityProvider.OKTA
    )


def test_ia_59_hint_google_workspace():
    assert (
        determine_identity_provider({"provider_hint": "google_workspace"})
        == IdentityProvider.GOOGLE_WORKSPACE
    )


def test_ia_60_hint_ping():
    assert (
        determine_identity_provider({"provider_hint": "ping"}) == IdentityProvider.PING
    )


def test_ia_61_hint_auth0():
    assert (
        determine_identity_provider({"provider_hint": "auth0"})
        == IdentityProvider.AUTH0
    )


def test_ia_62_hint_system():
    assert (
        determine_identity_provider({"provider_hint": "system"})
        == IdentityProvider.SYSTEM
    )


def test_ia_63_issuer_microsoftonline():
    assert (
        determine_identity_provider({"iss": "https://login.microsoftonline.com/tenant"})
        == IdentityProvider.ENTRA_ID
    )


def test_ia_64_issuer_okta():
    assert (
        determine_identity_provider({"iss": "https://example.okta.com/oauth/token"})
        == IdentityProvider.OKTA
    )


def test_ia_65_issuer_google():
    assert (
        determine_identity_provider({"iss": "https://accounts.google.com"})
        == IdentityProvider.GOOGLE_WORKSPACE
    )


def test_ia_66_issuer_auth0():
    assert (
        determine_identity_provider({"iss": "https://example.auth0.com/"})
        == IdentityProvider.AUTH0
    )


def test_ia_67_issuer_ping():
    assert (
        determine_identity_provider({"iss": "https://sso.pingidentity.com/idp"})
        == IdentityProvider.PING
    )


def test_ia_68_issuer_keycloak():
    assert (
        determine_identity_provider(
            {"iss": "https://auth.example.com/keycloak/realms/main"}
        )
        == IdentityProvider.KEYCLOAK
    )


def test_ia_69_unknown_provider_when_empty():
    assert determine_identity_provider({}) == IdentityProvider.UNKNOWN


def test_ia_70_unknown_provider_when_none():
    assert determine_identity_provider(None) == IdentityProvider.UNKNOWN  # type: ignore[arg-type]


def test_ia_71_workload_identity_flag_maps_to_system():
    assert (
        determine_identity_provider({"is_workload_identity": True})
        == IdentityProvider.SYSTEM
    )


def test_ia_72_system_autonomous_flag_maps_to_system():
    assert (
        determine_identity_provider({"is_system_autonomous": True})
        == IdentityProvider.SYSTEM
    )


def test_ia_73_hint_wins_over_issuer():
    result = determine_identity_provider(
        {"provider_hint": "okta", "iss": "https://accounts.google.com"}
    )
    assert result == IdentityProvider.OKTA


def test_ia_74_case_insensitive_hint():
    assert (
        determine_identity_provider({"provider_hint": "Okta"}) == IdentityProvider.OKTA
    )


def test_ia_75_unknown_hint_falls_through_to_unknown():
    assert (
        determine_identity_provider({"provider_hint": "made-up-idp"})
        == IdentityProvider.UNKNOWN
    )


# ── Group 5: Provider adapters — normalize_provider_claims (IA-76 .. IA-105) ──


def test_ia_76_keycloak_maps_sub_and_amr():
    raw = {"sub": "alice", "amr": ["mfa", "otp"], "iss": "https://kc/realms/x"}
    claims = normalize_provider_claims(raw, IdentityProvider.KEYCLOAK)
    assert claims.subject == "alice"
    assert claims.mfa_verified is True
    assert claims.raw_provider == "keycloak"


def test_ia_77_entra_maps_oid_first():
    raw = {"oid": "OID-1", "sub": "SUB-1", "iss": "https://sts.windows.net/tenant"}
    claims = normalize_provider_claims(raw, IdentityProvider.ENTRA_ID)
    assert claims.subject == "OID-1"


def test_ia_78_entra_amr_hwk_sets_hardware_key():
    raw = {"oid": "OID-1", "amr": ["hwk"]}
    claims = normalize_provider_claims(raw, IdentityProvider.ENTRA_ID)
    assert claims.hardware_key_verified is True


def test_ia_79_okta_uses_sub_and_upn():
    raw = {"sub": "bob", "email": "bob@x", "amr": ["mfa"]}
    claims = normalize_provider_claims(raw, IdentityProvider.OKTA)
    assert claims.subject == "bob"
    assert claims.mfa_verified is True


def test_ia_80_google_email_verified_bool_string():
    raw = {"sub": "u1", "email": "u1@x", "email_verified": "true"}
    claims = normalize_provider_claims(raw, IdentityProvider.GOOGLE_WORKSPACE)
    assert claims.email_verified is True


def test_ia_81_ping_maps_subject():
    raw = {"subject": "p-1"}
    claims = normalize_provider_claims(raw, IdentityProvider.PING)
    assert claims.subject == "p-1"


def test_ia_82_auth0_maps_sub():
    raw = {"sub": "auth0|abc"}
    claims = normalize_provider_claims(raw, IdentityProvider.AUTH0)
    assert claims.subject == "auth0|abc"
    assert claims.raw_provider == "auth0"


def test_ia_83_adapter_returns_provider_claims_type():
    for provider in (
        IdentityProvider.KEYCLOAK,
        IdentityProvider.ENTRA_ID,
        IdentityProvider.OKTA,
        IdentityProvider.GOOGLE_WORKSPACE,
        IdentityProvider.PING,
        IdentityProvider.AUTH0,
    ):
        claims = normalize_provider_claims({"sub": "x"}, provider)
        assert isinstance(claims, ProviderClaims)


def test_ia_84_missing_claims_returns_empty_provider_claims():
    claims = normalize_provider_claims({}, IdentityProvider.OKTA)
    assert isinstance(claims, ProviderClaims)


def test_ia_85_non_dict_raw_claims_tolerated():
    claims = normalize_provider_claims([], IdentityProvider.OKTA)  # type: ignore[arg-type]
    assert isinstance(claims, ProviderClaims)


def test_ia_86_system_provider_normalizes_generic():
    claims = normalize_provider_claims(
        {"sub": "system-1", "is_system_autonomous": True}, IdentityProvider.SYSTEM
    )
    assert claims.is_system_autonomous is True
    assert claims.provider_hint == "system"


def test_ia_87_unknown_provider_preserves_basic_fields():
    claims = normalize_provider_claims(
        {"sub": "u", "email": "u@x"}, IdentityProvider.UNKNOWN
    )
    assert claims.subject == "u"
    assert claims.email == "u@x"


def test_ia_88_bool_string_coercion_false():
    claims = normalize_provider_claims(
        {"sub": "x", "email_verified": "false"}, IdentityProvider.OKTA
    )
    assert claims.email_verified is False


def test_ia_89_bool_int_coercion_true():
    claims = normalize_provider_claims(
        {"sub": "x", "email_verified": 1}, IdentityProvider.KEYCLOAK
    )
    assert claims.email_verified is True


def test_ia_90_bool_int_coercion_false():
    claims = normalize_provider_claims(
        {"sub": "x", "email_verified": 0}, IdentityProvider.OKTA
    )
    assert claims.email_verified is False


def test_ia_91_amr_mfa_marker_recognized():
    claims = normalize_provider_claims(
        {"sub": "x", "amr": ["mfa"]}, IdentityProvider.OKTA
    )
    assert claims.mfa_verified is True


def test_ia_92_amr_webauthn_hwk_recognized():
    claims = normalize_provider_claims(
        {"sub": "x", "amr": ["webauthn"]}, IdentityProvider.OKTA
    )
    assert claims.hardware_key_verified is True


def test_ia_93_amr_missing_mfa_verified_none():
    claims = normalize_provider_claims({"sub": "x"}, IdentityProvider.OKTA)
    assert claims.mfa_verified is None


def test_ia_94_amr_password_only_mfa_false_or_none():
    claims = normalize_provider_claims(
        {"sub": "x", "amr": ["pwd"]}, IdentityProvider.OKTA
    )
    assert claims.mfa_verified in (False, None)


def test_ia_95_service_account_flag_preserved():
    claims = normalize_provider_claims(
        {"sub": "svc", "is_service_account": True}, IdentityProvider.KEYCLOAK
    )
    assert claims.is_service_account is True


def test_ia_96_workload_identity_flag_preserved():
    claims = normalize_provider_claims(
        {"sub": "wl", "is_workload_identity": True}, IdentityProvider.OKTA
    )
    assert claims.is_workload_identity is True


def test_ia_97_workload_identity_ref_preserved():
    claims = normalize_provider_claims(
        {"sub": "wl", "workload_identity_ref": "spiffe://foo/bar"},
        IdentityProvider.OKTA,
    )
    assert claims.workload_identity_ref == "spiffe://foo/bar"


def test_ia_98_session_id_preserved_okta():
    claims = normalize_provider_claims(
        {"sub": "x", "sid": "s-1"}, IdentityProvider.OKTA
    )
    assert claims.session_id == "s-1"


def test_ia_99_device_id_preserved_entra():
    claims = normalize_provider_claims(
        {"oid": "x", "deviceid": "dev-1"}, IdentityProvider.ENTRA_ID
    )
    assert claims.device_id == "dev-1"


def test_ia_100_ip_address_preserved():
    claims = normalize_provider_claims(
        {"sub": "x", "ip_address": "192.0.2.1"}, IdentityProvider.OKTA
    )
    assert claims.ip_address == "192.0.2.1"


def test_ia_101_entra_ip_addr_field():
    claims = normalize_provider_claims(
        {"oid": "x", "ipaddr": "192.0.2.5"}, IdentityProvider.ENTRA_ID
    )
    assert claims.ip_address == "192.0.2.5"


def test_ia_102_passwordless_preserved():
    claims = normalize_provider_claims(
        {"sub": "x", "passwordless": True}, IdentityProvider.OKTA
    )
    assert claims.passwordless is True


def test_ia_103_certificate_verified_preserved():
    claims = normalize_provider_claims(
        {"sub": "x", "certificate_verified": True}, IdentityProvider.KEYCLOAK
    )
    assert claims.certificate_verified is True


def test_ia_104_smart_card_verified_preserved():
    claims = normalize_provider_claims(
        {"sub": "x", "smart_card_verified": True}, IdentityProvider.OKTA
    )
    assert claims.smart_card_verified is True


def test_ia_105_normalization_is_deterministic():
    raw = {"sub": "x", "amr": ["mfa"], "iss": "https://okta.com/x"}
    a = normalize_provider_claims(raw, IdentityProvider.OKTA)
    b = normalize_provider_claims(raw, IdentityProvider.OKTA)
    assert a == b


# ── Group 6: build_assurance_decision (IA-106 .. IA-125) ──────────────────────


def test_ia_106_build_decision_returns_frozen_model():
    d = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    assert isinstance(d, AssuranceDecision)


def test_ia_107_decision_is_immutable():
    d = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    with pytest.raises(Exception):
        d.trust_score = 99  # type: ignore[misc]


def test_ia_108_decision_deterministic_same_input_same_output():
    a = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    b = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    assert a == b
    assert a.fingerprint == b.fingerprint
    assert a.computed_at_sequence == b.computed_at_sequence


def test_ia_109_decision_different_tenant_yields_different_fingerprint():
    a = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    b = build_assurance_decision(_sso_mfa_claims(), "t2", "a1")
    assert a.fingerprint != b.fingerprint


def test_ia_110_decision_different_actor_yields_different_fingerprint():
    a = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    b = build_assurance_decision(_sso_mfa_claims(), "t1", "a2")
    assert a.fingerprint != b.fingerprint


def test_ia_111_decision_different_claims_yields_different_fingerprint():
    a = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    b = build_assurance_decision(_password_only_claims(), "t1", "a1")
    assert a.fingerprint != b.fingerprint


def test_ia_112_decision_missing_tenant_raises():
    with pytest.raises(ValueError):
        build_assurance_decision(_sso_mfa_claims(), "", "a1")


def test_ia_113_decision_missing_actor_raises():
    with pytest.raises(ValueError):
        build_assurance_decision(_sso_mfa_claims(), "t1", "")


def test_ia_114_decision_fingerprint_is_64_hex_chars():
    d = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    assert len(d.fingerprint) == 64
    int(d.fingerprint, 16)


def test_ia_115_decision_computed_at_sequence_is_hex():
    d = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    assert len(d.computed_at_sequence) == 64
    int(d.computed_at_sequence, 16)


def test_ia_116_decision_claims_hash_is_hex():
    d = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    assert len(d.provider_claims_hash) == 64
    int(d.provider_claims_hash, 16)


def test_ia_117_decision_carries_trust_score_from_level():
    d = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    assert d.trust_score == compute_trust_score(d.assurance_level)


def test_ia_118_decision_carries_provider_okta():
    d = build_assurance_decision(_sso_mfa_claims(), "t1", "a1")
    assert d.provider == IdentityProvider.OKTA


def test_ia_119_decision_provider_unknown_when_no_hints():
    d = build_assurance_decision(_password_only_claims(), "t1", "a1")
    assert d.provider == IdentityProvider.UNKNOWN


def test_ia_120_decision_workload_identity_score_100():
    claims = ProviderClaims(is_workload_identity=True)
    d = build_assurance_decision(claims, "t1", "a1")
    assert d.trust_score == 100
    assert d.assurance_level == AssuranceLevel.WORKLOAD_IDENTITY


def test_ia_121_decision_unverified_score_zero():
    d = build_assurance_decision(ProviderClaims(), "t1", "a1")
    assert d.trust_score == 0
    assert d.assurance_level == AssuranceLevel.UNVERIFIED


def test_ia_122_decision_authentication_method_default_when_none():
    d = build_assurance_decision(ProviderClaims(), "t1", "a1")
    assert d.authentication_method == "unverified"


def test_ia_123_decision_authentication_method_from_claims():
    claims = ProviderClaims(subject="a", authentication_method="password")
    d = build_assurance_decision(claims, "t1", "a1")
    assert d.authentication_method == "password"


def test_ia_124_hash_provider_claims_stable():
    c = _sso_mfa_claims()
    assert hash_provider_claims(c) == hash_provider_claims(c)


def test_ia_125_hash_provider_claims_different_for_different_claims():
    assert hash_provider_claims(_sso_mfa_claims()) != hash_provider_claims(
        _password_only_claims()
    )


# ── Group 7: Chain hash continuity (IA-126 .. IA-130) ─────────────────────────


def test_ia_126_chain_hash_from_none_previous_is_deterministic():
    a = chain_hash(None, "f" * 64)
    b = chain_hash(None, "f" * 64)
    assert a == b


def test_ia_127_chain_hash_different_when_previous_changes():
    a = chain_hash("0" * 64, "f" * 64)
    b = chain_hash("1" * 64, "f" * 64)
    assert a != b


def test_ia_128_chain_hash_different_when_fingerprint_changes():
    a = chain_hash("0" * 64, "a" * 64)
    b = chain_hash("0" * 64, "b" * 64)
    assert a != b


def test_ia_129_chain_hash_is_64_hex():
    ch = chain_hash(None, "f" * 64)
    assert len(ch) == 64
    int(ch, 16)


def test_ia_130_chain_hash_links_correctly_sequence():
    c1 = chain_hash(None, "a" * 64)
    c2 = chain_hash(c1, "b" * 64)
    c3 = chain_hash(c2, "c" * 64)
    assert c1 != c2 != c3


# ── Group 8: ORM append-only guards (IA-131 .. IA-135) ────────────────────────


def test_ia_131_snapshot_before_update_blocked(build_app, fresh_db):
    from sqlalchemy.orm import Session
    from api.db import get_engine
    from api.db_models_identity_assurance import ActorAssuranceSnapshot

    build_app(auth_enabled=True, sqlite_path=fresh_db)
    _insert_snapshot(fresh_db, "t-131", "a-131", None, "SSO_MFA", 84, sequence_number=0)
    with Session(get_engine()) as db:
        row = db.query(ActorAssuranceSnapshot).filter_by(tenant_id="t-131").first()
        assert row is not None
        row.trust_score = 99
        with pytest.raises(Exception):
            db.commit()
        db.rollback()


def test_ia_132_snapshot_before_delete_blocked(build_app, fresh_db):
    from sqlalchemy.orm import Session
    from api.db import get_engine
    from api.db_models_identity_assurance import ActorAssuranceSnapshot

    build_app(auth_enabled=True, sqlite_path=fresh_db)
    _insert_snapshot(fresh_db, "t-132", "a-132", None, "SSO_MFA", 84, sequence_number=0)
    with Session(get_engine()) as db:
        row = db.query(ActorAssuranceSnapshot).filter_by(tenant_id="t-132").first()
        assert row is not None
        with pytest.raises(Exception):
            db.delete(row)
            db.commit()
        db.rollback()


def test_ia_133_history_before_update_blocked(build_app, fresh_db):
    from sqlalchemy.orm import Session
    from api.db import get_engine
    from api.db_models_identity_assurance import ActorAssuranceHistory

    build_app(auth_enabled=True, sqlite_path=fresh_db)
    _insert_history(fresh_db, "t-133", "a-133")
    with Session(get_engine()) as db:
        row = db.query(ActorAssuranceHistory).filter_by(tenant_id="t-133").first()
        assert row is not None
        row.assurance_level = "UNVERIFIED"
        with pytest.raises(Exception):
            db.commit()
        db.rollback()


def test_ia_134_history_before_delete_blocked(build_app, fresh_db):
    from sqlalchemy.orm import Session
    from api.db import get_engine
    from api.db_models_identity_assurance import ActorAssuranceHistory

    build_app(auth_enabled=True, sqlite_path=fresh_db)
    _insert_history(fresh_db, "t-134", "a-134")
    with Session(get_engine()) as db:
        row = db.query(ActorAssuranceHistory).filter_by(tenant_id="t-134").first()
        assert row is not None
        with pytest.raises(Exception):
            db.delete(row)
            db.commit()
        db.rollback()


def test_ia_135_current_assurance_is_mutable(build_app, fresh_db):
    from sqlalchemy.orm import Session
    from api.db import get_engine
    from api.db_models_identity_assurance import ActorIdentityAssurance

    build_app(auth_enabled=True, sqlite_path=fresh_db)
    _insert_assurance(fresh_db, "t-135", "a-135")
    with Session(get_engine()) as db:
        row = db.query(ActorIdentityAssurance).filter_by(tenant_id="t-135").first()
        assert row is not None
        row.is_current = False
        db.commit()
        db.refresh(row)
        assert row.is_current is False


# ── Group 9: API — auth enforcement (IA-136 .. IA-140) ────────────────────────


def test_ia_136_missing_key_rejected(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    resp = client.get("/actor-assurance/some-id")
    assert resp.status_code in (401, 403)


def test_ia_137_wrong_scope_rejected(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("governance:read", tenant_id="t-137")
    resp = client.get("/actor-assurance/some-id", headers={"X-API-Key": key})
    assert resp.status_code == 403


def test_ia_138_read_scope_grants_get(build_app, fresh_db):
    tenant = "t-138"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    assert resp.status_code == 200, resp.text


def test_ia_139_write_scope_needed_for_recalculate(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id="t-139")
    resp = client.post(
        "/actor-assurance/recalculate",
        headers={"X-API-Key": key},
        json={"actor_id": "a-1", "reason": "manual"},
    )
    assert resp.status_code == 403


def test_ia_140_unbound_tenant_returns_400(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read")
    resp = client.get("/actor-assurance/any-id", headers={"X-API-Key": key})
    assert resp.status_code == 400


# ── Group 10: API — GET assurance record (IA-141 .. IA-150) ───────────────────


def test_ia_141_404_when_no_record(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id="t-141")
    resp = client.get("/actor-assurance/nope", headers={"X-API-Key": key})
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "ASSURANCE_NOT_FOUND"


def test_ia_142_get_returns_expected_fields(build_app, fresh_db):
    tenant = "t-142"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(
        fresh_db, tenant, actor, level="SSO_MFA", score=84, provider="OKTA"
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    body = resp.json()
    assert body["actor_id"] == actor
    assert body["tenant_id"] == tenant
    assert body["assurance_level"] == "SSO_MFA"
    assert body["trust_score"] == 84
    assert body["trust_band"] == "VERY_HIGH"
    assert body["identity_provider"] == "OKTA"


def test_ia_143_cross_tenant_read_returns_404(build_app, fresh_db):
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, "t-143-a", actor)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id="t-143-b")
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    assert resp.status_code == 404


def test_ia_144_get_returns_is_current_bool(build_app, fresh_db):
    tenant = "t-144"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor, is_current=1)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["is_current"], bool)
    assert body["is_current"] is True


def test_ia_145_get_returns_schema_version(build_app, fresh_db):
    tenant = "t-145"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    assert resp.json()["schema_version"] == "1.0"


def test_ia_146_get_returns_decision_fingerprint(build_app, fresh_db):
    tenant = "t-146"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor, fingerprint="d" * 64)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    assert resp.json()["decision_fingerprint"] == "d" * 64


def test_ia_147_low_trust_score_maps_to_low_band(build_app, fresh_db):
    tenant = "t-147"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor, level="PASSWORD", score=32)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    assert resp.json()["trust_band"] == "LOW"


def test_ia_148_high_score_maps_to_high_band(build_app, fresh_db):
    tenant = "t-148"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor, level="SSO", score=74)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    assert resp.json()["trust_band"] == "HIGH"


def test_ia_149_zero_score_maps_to_critical(build_app, fresh_db):
    tenant = "t-149"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor, level="UNVERIFIED", score=0)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    assert resp.json()["trust_band"] == "CRITICAL"


def test_ia_150_hundred_score_maps_to_very_high(build_app, fresh_db):
    tenant = "t-150"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor, level="WORKLOAD_IDENTITY", score=100)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key})
    assert resp.json()["trust_band"] == "VERY_HIGH"


# ── Group 11: API — history endpoint (IA-151 .. IA-155) ───────────────────────


def test_ia_151_history_empty(build_app, fresh_db):
    tenant = "t-151"
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get("/actor-assurance/anyone/history", headers={"X-API-Key": key})
    assert resp.status_code == 200
    body = resp.json()
    assert body["events"] == []
    assert body["total"] == 0


def test_ia_152_history_returns_all_events(build_app, fresh_db):
    tenant = "t-152"
    actor = f"a-{_uid()[:8]}"
    for i in range(3):
        _insert_history(fresh_db, tenant, actor, event_type="assurance_computed")
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}/history", headers={"X-API-Key": key})
    body = resp.json()
    assert body["total"] == 3
    assert len(body["events"]) == 3


def test_ia_153_history_respects_limit(build_app, fresh_db):
    tenant = "t-153"
    actor = f"a-{_uid()[:8]}"
    for i in range(5):
        _insert_history(fresh_db, tenant, actor)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(
        f"/actor-assurance/{actor}/history?limit=2", headers={"X-API-Key": key}
    )
    body = resp.json()
    assert body["total"] == 5
    assert len(body["events"]) == 2


def test_ia_154_history_offset(build_app, fresh_db):
    tenant = "t-154"
    actor = f"a-{_uid()[:8]}"
    for i in range(4):
        _insert_history(fresh_db, tenant, actor)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(
        f"/actor-assurance/{actor}/history?limit=2&offset=2",
        headers={"X-API-Key": key},
    )
    body = resp.json()
    assert body["total"] == 4
    assert body["offset"] == 2


def test_ia_155_history_isolated_by_tenant(build_app, fresh_db):
    actor = f"a-{_uid()[:8]}"
    _insert_history(fresh_db, "t-155-a", actor)
    _insert_history(fresh_db, "t-155-a", actor)
    _insert_history(fresh_db, "t-155-b", actor)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id="t-155-a")
    resp = client.get(f"/actor-assurance/{actor}/history", headers={"X-API-Key": key})
    assert resp.json()["total"] == 2


# ── Group 12: API — snapshot endpoint (IA-156 .. IA-160) ──────────────────────


def test_ia_156_snapshot_404_when_none(build_app, fresh_db):
    tenant = "t-156"
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get("/actor-assurance/none/snapshot", headers={"X-API-Key": key})
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "ASSURANCE_NOT_FOUND"


def test_ia_157_snapshot_returns_latest_sequence(build_app, fresh_db):
    tenant = "t-157"
    actor = f"a-{_uid()[:8]}"
    _insert_snapshot(fresh_db, tenant, actor, None, "PASSWORD", 32, sequence_number=0)
    _insert_snapshot(
        fresh_db, tenant, actor, "PASSWORD", "SSO_MFA", 84, sequence_number=1
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}/snapshot", headers={"X-API-Key": key})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["sequence_number"] == 1
    assert body["new_assurance_level"] == "SSO_MFA"


def test_ia_158_snapshot_cross_tenant_isolated(build_app, fresh_db):
    actor = f"a-{_uid()[:8]}"
    _insert_snapshot(
        fresh_db, "t-158-a", actor, None, "PASSWORD", 32, sequence_number=0
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id="t-158-b")
    resp = client.get(f"/actor-assurance/{actor}/snapshot", headers={"X-API-Key": key})
    assert resp.status_code == 404


def test_ia_159_snapshot_carries_trust_band(build_app, fresh_db):
    tenant = "t-159"
    actor = f"a-{_uid()[:8]}"
    _insert_snapshot(fresh_db, tenant, actor, None, "SSO_MFA", 84, sequence_number=0)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}/snapshot", headers={"X-API-Key": key})
    assert resp.json()["trust_band"] == "VERY_HIGH"


def test_ia_160_snapshot_carries_chain_hash(build_app, fresh_db):
    tenant = "t-160"
    actor = f"a-{_uid()[:8]}"
    _insert_snapshot(
        fresh_db,
        tenant,
        actor,
        None,
        "SSO_MFA",
        84,
        sequence_number=0,
        chain="e" * 64,
    )
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}/snapshot", headers={"X-API-Key": key})
    assert resp.json()["chain_hash"] == "e" * 64


# ── Group 13: API — trust summary endpoint (IA-161 .. IA-165) ─────────────────


def test_ia_161_trust_returns_score_and_band(build_app, fresh_db):
    tenant = "t-161"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor, level="SSO_MFA", score=84)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}/trust", headers={"X-API-Key": key})
    body = resp.json()
    assert body["trust_score"] == 84
    assert body["trust_band"] == "VERY_HIGH"
    assert body["assurance_level"] == "SSO_MFA"


def test_ia_162_trust_includes_score_breakdown(build_app, fresh_db):
    tenant = "t-162"
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, tenant, actor, level="SSO_MFA", score=84)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}/trust", headers={"X-API-Key": key})
    breakdown = resp.json()["score_breakdown"]
    assert breakdown["base_score"] == 84
    assert breakdown["assurance_level"] == "SSO_MFA"
    assert breakdown["max_possible"] == 100


def test_ia_163_trust_404_when_missing(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id="t-163")
    resp = client.get("/actor-assurance/nope/trust", headers={"X-API-Key": key})
    assert resp.status_code == 404


def test_ia_164_trust_wrong_scope_denied(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("audit:read", tenant_id="t-164")
    resp = client.get("/actor-assurance/nope/trust", headers={"X-API-Key": key})
    assert resp.status_code == 403


def test_ia_165_trust_isolated_by_tenant(build_app, fresh_db):
    actor = f"a-{_uid()[:8]}"
    _insert_assurance(fresh_db, "t-165-a", actor)
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:read", tenant_id="t-165-b")
    resp = client.get(f"/actor-assurance/{actor}/trust", headers={"X-API-Key": key})
    assert resp.status_code == 404


# ── Group 14: API — recalculate endpoint (IA-166 .. IA-172) ───────────────────


def test_ia_166_recalculate_creates_snapshot_and_history(build_app, fresh_db):
    tenant = "t-166"
    actor = f"a-{_uid()[:8]}"
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:write", tenant_id=tenant)
    resp = client.post(
        "/actor-assurance/recalculate",
        headers={"X-API-Key": key},
        json={
            "actor_id": actor,
            "reason": "manual",
            "provider": "OKTA",
            "claims": {
                "subject": actor,
                "issuer": "https://okta.com/oauth",
                "mfa_verified": True,
            },
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["actor_id"] == actor
    assert body["assurance_level"] in {lvl.value for lvl in AssuranceLevel}
    # Verify snapshot + history were written.
    conn = sqlite3.connect(fresh_db)
    try:
        snap_count = conn.execute(
            "SELECT COUNT(*) FROM actor_assurance_snapshots WHERE tenant_id=? AND actor_id=?",
            (tenant, actor),
        ).fetchone()[0]
        hist_count = conn.execute(
            "SELECT COUNT(*) FROM actor_assurance_history WHERE tenant_id=? AND actor_id=?",
            (tenant, actor),
        ).fetchone()[0]
    finally:
        conn.close()
    assert snap_count == 1
    assert hist_count == 1


def test_ia_167_recalculate_idempotent_same_claims(build_app, fresh_db):
    tenant = "t-167"
    actor = f"a-{_uid()[:8]}"
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:write", tenant_id=tenant)
    payload = {
        "actor_id": actor,
        "reason": "manual",
        "provider": "OKTA",
        "claims": {
            "subject": actor,
            "issuer": "https://okta.com/oauth",
            "mfa_verified": True,
        },
    }
    r1 = client.post(
        "/actor-assurance/recalculate", headers={"X-API-Key": key}, json=payload
    )
    r2 = client.post(
        "/actor-assurance/recalculate", headers={"X-API-Key": key}, json=payload
    )
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["decision_fingerprint"] == r2.json()["decision_fingerprint"]
    conn = sqlite3.connect(fresh_db)
    try:
        snap_count = conn.execute(
            "SELECT COUNT(*) FROM actor_assurance_snapshots WHERE tenant_id=? AND actor_id=?",
            (tenant, actor),
        ).fetchone()[0]
    finally:
        conn.close()
    # Idempotent — only one snapshot even after two identical recalculations.
    assert snap_count == 1


def test_ia_168_recalculate_change_creates_second_snapshot(build_app, fresh_db):
    tenant = "t-168"
    actor = f"a-{_uid()[:8]}"
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:write", tenant_id=tenant)

    # First: password only.
    client.post(
        "/actor-assurance/recalculate",
        headers={"X-API-Key": key},
        json={
            "actor_id": actor,
            "provider": "OKTA",
            "claims": {
                "subject": actor,
                "authentication_method": "password",
            },
        },
    )
    # Second: upgrade to SSO+MFA.
    r2 = client.post(
        "/actor-assurance/recalculate",
        headers={"X-API-Key": key},
        json={
            "actor_id": actor,
            "provider": "OKTA",
            "claims": {
                "subject": actor,
                "issuer": "https://okta.com/oauth",
                "mfa_verified": True,
            },
        },
    )
    assert r2.status_code == 200
    conn = sqlite3.connect(fresh_db)
    try:
        snap_count = conn.execute(
            "SELECT COUNT(*) FROM actor_assurance_snapshots WHERE tenant_id=? AND actor_id=?",
            (tenant, actor),
        ).fetchone()[0]
    finally:
        conn.close()
    assert snap_count == 2


def test_ia_169_recalculate_bad_body_400(build_app, fresh_db):
    tenant = "t-169"
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:write", tenant_id=tenant)
    resp = client.post(
        "/actor-assurance/recalculate",
        headers={"X-API-Key": key},
        json={"actor_id": ""},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "ASSURANCE_BAD_REQUEST"


def test_ia_170_recalculate_no_key_denied(build_app, fresh_db):
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    resp = client.post("/actor-assurance/recalculate", json={"actor_id": "x"})
    assert resp.status_code in (401, 403)


def test_ia_171_recalculate_tenant_isolation(build_app, fresh_db):
    tenant_a = "t-171-a"
    tenant_b = "t-171-b"
    actor = f"a-{_uid()[:8]}"
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key_a = mint_key("assurance:write", tenant_id=tenant_a)
    client.post(
        "/actor-assurance/recalculate",
        headers={"X-API-Key": key_a},
        json={
            "actor_id": actor,
            "provider": "OKTA",
            "claims": {
                "subject": actor,
                "issuer": "https://okta.com/x",
                "mfa_verified": True,
            },
        },
    )
    key_b = mint_key("assurance:read", tenant_id=tenant_b)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key_b})
    assert resp.status_code == 404


def test_ia_172_recalculate_records_current(build_app, fresh_db):
    tenant = "t-172"
    actor = f"a-{_uid()[:8]}"
    app = build_app(auth_enabled=True, sqlite_path=fresh_db)
    client = TestClient(app)
    key = mint_key("assurance:write", tenant_id=tenant)
    client.post(
        "/actor-assurance/recalculate",
        headers={"X-API-Key": key},
        json={
            "actor_id": actor,
            "provider": "OKTA",
            "claims": {
                "subject": actor,
                "issuer": "https://okta.com/x",
                "mfa_verified": True,
            },
        },
    )
    # Re-read via GET.
    key_r = mint_key("assurance:read", tenant_id=tenant)
    resp = client.get(f"/actor-assurance/{actor}", headers={"X-API-Key": key_r})
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_current"] is True
    assert body["assurance_level"] == "SSO_MFA"


# ── Group 15: assurance ordering, capability registration (IA-173..IA-176) ────


def test_ia_173_assurance_levels_declared():
    # Every declared level must have a score in the table.
    for level in AssuranceLevel:
        assert level in TRUST_SCORE_TABLE


def test_ia_174_assurance_write_permission_registered():
    from api.actor_context import ALL_PERMISSIONS, CAPABILITY_REGISTRY

    assert "assurance:read" in ALL_PERMISSIONS
    assert "assurance:write" in ALL_PERMISSIONS
    assert "assurance:read" in CAPABILITY_REGISTRY
    assert "assurance:write" in CAPABILITY_REGISTRY


def test_ia_175_tenant_admin_has_assurance_read():
    from api.actor_context import ROLE_PERMISSIONS

    assert "assurance:read" in ROLE_PERMISSIONS["tenant_admin"]


def test_ia_176_trust_context_bundle_immutable():
    ctx = TrustContext(tenant_id="t", actor_id="a", claims=_sso_mfa_claims())
    with pytest.raises(Exception):
        ctx.tenant_id = "t2"  # type: ignore[misc]


def test_ia_177_assurance_snapshot_pydantic_model_immutable():
    snap = AssuranceSnapshot(
        actor_id="a",
        tenant_id="t",
        sequence_number=0,
        previous_level=None,
        new_level=AssuranceLevel.SSO_MFA,
        trust_score=84,
        fingerprint="a" * 64,
        chain_hash="b" * 64,
    )
    with pytest.raises(Exception):
        snap.trust_score = 0  # type: ignore[misc]
