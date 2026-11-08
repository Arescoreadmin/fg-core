"""AUTH-GAP-001 — customer authorization receipt adversarial tests.

L14-SCAN-AUTH-HARDENING-001.  Synthetic data; no network; no Postgres.
"""

from __future__ import annotations

import os
from datetime import timedelta

import pytest

os.environ.setdefault("FG_ENV", "test")

from services.field_assessment import customer_authorization as ca
from services.field_assessment.scan_authorization import (
    ScanAuthorizationError,
    check_scan_authorized,
)

from ._harness import (
    ASSESSOR,
    E1,
    E2,
    T1,
    T2,
    Actor,
    Store,
    approved_receipt,
    request_receipt,
    set_keyring,
    utcnow,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in (
        "FG_SCAN_CONSENT_ATTESTATION_KEYS",
        "FG_SCAN_CONSENT_ATTESTATION_ACTIVE_KID",
        "FG_SCAN_CONSENT_ATTESTATION_REVOKED_KIDS",
        "FG_SCAN_REQUIRE_CUSTOMER_CONSENT",
        "FG_SCAN_CONSENT_REQUIRE_ATTESTATION",
    ):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FG_ENV", "test")


@pytest.fixture()
def store() -> Store:
    return Store()


def _check(
    store,
    *,
    target="app.example.com",
    ttype="fqdn",
    op="web_headers",
    tenant=T1,
    eng=E1,
    now=None,
):
    return check_scan_authorized(
        store.session(),
        tenant_id=tenant,
        engagement_id=eng,
        target=target,
        target_type=ttype,
        operation=op,
        now=now,
    )


# ---------------------------------------------------------------------------
# Valid approval + proof levels
# ---------------------------------------------------------------------------


class TestValidApproval:
    def test_authenticated_approval_digest_only_outside_production(self, store):
        r = approved_receipt(store)
        assert r["status"] == "approved"
        assert (
            r["proof_level"] == ca.ProofLevel.AUTHENTICATED_APPROVAL_DIGEST_ONLY.value
        )
        assert r["payload_digest"].startswith("sha256:")
        assert r["attestation_kid"] is None
        assert (
            ca.verify_receipt_integrity(r)
            is ca.ProofLevel.AUTHENTICATED_APPROVAL_DIGEST_ONLY
        )

    def test_server_attested_approval_with_trusted_key(self, store, monkeypatch):
        set_keyring(monkeypatch)
        r = approved_receipt(store)
        assert r["attestation_kid"] == "kid-2026-a"
        assert r["attestation_alg"] == "HMAC-SHA256"
        assert (
            ca.verify_receipt_integrity(r)
            is ca.ProofLevel.SERVER_ATTESTED_AUTHENTICATED_APPROVAL
        )

    def test_approver_identity_comes_from_actor_context(self, store):
        r = approved_receipt(store)
        assert r["approver_subject"] == "auth0|customer-ciso"
        assert r["approver_authority_basis"] == "client_security_owner"
        assert r["approver_auth_source"] == "oidc_auth0"
        assert r["approver_also_assessor"] is False

    def test_scope_bound_to_receipt_authorizes_and_reports_customer_consent(
        self, store
    ):
        r = approved_receipt(store)
        store.add_scope(receipt_id=str(r["id"]))
        d = _check(store)
        assert d["consent_status"] == "CUSTOMER_APPROVED"
        assert d["customer_receipt_id"] == str(r["id"])
        assert (
            d["proof_level"] == ca.ProofLevel.AUTHENTICATED_APPROVAL_DIGEST_ONLY.value
        )

    def test_identity_holding_both_roles_is_recorded(self, store):
        r = request_receipt(store)
        a = Actor(roles=["client_security_owner", "assessor"])
        out = ca.approve(
            store.session(),
            receipt_id=str(r["id"]),
            tenant_id=T1,
            engagement_id=E1,
            actor_ctx=a,
        )
        assert out["approver_also_assessor"] is True


# ---------------------------------------------------------------------------
# Missing / forged / unauthorized approvals
# ---------------------------------------------------------------------------


class TestApproverValidation:
    @pytest.mark.parametrize(
        "actor, code",
        [
            (Actor(permissions=frozenset({"scan.read"})), "APPROVER_PERMISSION_DENIED"),
            (Actor(roles=["assessor"]), "APPROVER_NOT_CUSTOMER"),
            (Actor(roles=["platform_admin", "tenant_admin"]), "APPROVER_NOT_CUSTOMER"),
            (Actor(auth_source="api_key"), "APPROVER_AUTH_SOURCE_DENIED"),
            (Actor(auth_source="dev_bypass"), "APPROVER_AUTH_SOURCE_DENIED"),
            (Actor(auth_source="system"), "APPROVER_AUTH_SOURCE_DENIED"),
            (Actor(service_principal_id="sp-1"), "APPROVER_NOT_HUMAN"),
            (Actor(email_verified=False), "APPROVER_EMAIL_UNVERIFIED"),
            (Actor(tenant_id=T2), "APPROVER_TENANT_MISMATCH"),
            (Actor(tenant_id=None), "APPROVER_TENANT_MISMATCH"),
            (Actor(subject=ASSESSOR), "APPROVER_SELF_APPROVAL_DENIED"),
            (Actor(subject=""), "APPROVER_IDENTITY_MISSING"),
        ],
    )
    def test_unprivileged_or_untrusted_approver_rejected(self, store, actor, code):
        r = request_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.approve(
                store.session(),
                receipt_id=str(r["id"]),
                tenant_id=T1,
                engagement_id=E1,
                actor_ctx=actor,
            )
        assert ei.value.audit_code == code
        assert store.receipts[str(r["id"])]["status"] == "pending_approval"

    def test_approval_from_other_tenant_cannot_find_receipt(self, store):
        r = request_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.approve(
                store.session(),
                receipt_id=str(r["id"]),
                tenant_id=T2,
                engagement_id=E1,
                actor_ctx=Actor(tenant_id=T2),
            )
        assert ei.value.audit_code == "RECEIPT_NOT_FOUND"

    def test_wrong_engagement_cannot_approve(self, store):
        r = request_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.approve(
                store.session(),
                receipt_id=str(r["id"]),
                tenant_id=T1,
                engagement_id=E2,
                actor_ctx=Actor(),
            )
        assert ei.value.audit_code == "RECEIPT_NOT_FOUND"

    def test_duplicate_approval_submission_rejected(self, store):
        r = approved_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.approve(
                store.session(),
                receipt_id=str(r["id"]),
                tenant_id=T1,
                engagement_id=E1,
                actor_ctx=Actor(),
            )
        assert ei.value.audit_code == "RECEIPT_NOT_PENDING"

    def test_malformed_receipt_id_is_not_found(self, store):
        assert (
            ca.load_receipt(
                store.session(), receipt_id="../etc", tenant_id=T1, engagement_id=E1
            )
            is None
        )

    def test_missing_receipt_when_consent_required_denies_scan(
        self, store, monkeypatch
    ):
        monkeypatch.setenv("FG_SCAN_REQUIRE_CUSTOMER_CONSENT", "1")
        store.add_scope(receipt_id=None)
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store)
        assert ei.value.audit_code == "CUSTOMER_AUTHORIZATION_REQUIRED"

    def test_legacy_scope_is_never_reported_as_customer_verified(self, store):
        store.add_scope(receipt_id=None)
        d = _check(store)
        assert d["consent_status"] == "LEGACY_OPERATOR_ASSERTED"
        assert d["proof_level"] == "LEGACY_OPERATOR_ASSERTED"
        assert d["customer_receipt_id"] is None

    def test_production_always_requires_consent(self, store, monkeypatch):
        monkeypatch.setattr(ca, "_production", lambda: True)
        monkeypatch.setenv(
            "FG_SCAN_REQUIRE_CUSTOMER_CONSENT", "0"
        )  # no downgrade switch
        assert ca.consent_required() is True
        assert ca.attestation_required() is True

    def test_undeterminable_environment_fails_closed(self, monkeypatch):
        import api.config.env as envmod

        def boom():
            raise RuntimeError("FG_ENV unset")

        monkeypatch.setattr(envmod, "is_production_env", boom)
        assert ca._production() is True


# ---------------------------------------------------------------------------
# Receipt integrity — tamper evidence
# ---------------------------------------------------------------------------


class TestReceiptIntegrity:
    @pytest.mark.parametrize(
        "field, value",
        [
            (
                "approved_targets",
                [
                    {
                        "target": "evil.example.net",
                        "type": "fqdn",
                        "operations": ["network_scan"],
                        "allow_subdomains": False,
                    }
                ],
            ),
            (
                "authorized_operations",
                ["network_scan", "web_headers", "dns_email", "exploit"],
            ),
            ("window_end", utcnow() + timedelta(days=300)),
            ("window_start", utcnow() - timedelta(days=300)),
            ("approver_subject", "auth0|someone-else"),
            ("engagement_id", E2),
            ("tenant_id", T2),
            ("customer_org_name", "Other Corp"),
            ("rules_of_engagement_ref", "ROE-FORGED"),
        ],
    )
    def test_altered_material_field_detected(self, store, field, value):
        r = approved_receipt(store)
        tampered = {**r, field: value}
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.verify_receipt_integrity(tampered)
        assert ei.value.audit_code == "RECEIPT_DIGEST_MISMATCH"

    def test_altered_targets_in_store_denies_execution(self, store):
        r = approved_receipt(store)
        store.add_scope(
            receipt_id=str(r["id"]),
            targets=[
                {
                    "target": "evil.example.net",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                }
            ],
        )
        store.receipts[str(r["id"])]["approved_targets"] = [
            {
                "target": "evil.example.net",
                "type": "fqdn",
                "operations": ["web_headers"],
                "allow_subdomains": False,
            }
        ]
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store, target="evil.example.net")
        assert ei.value.audit_code == "RECEIPT_DIGEST_MISMATCH"

    def test_missing_digest_rejected(self, store):
        r = approved_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.verify_receipt_integrity({**r, "payload_digest": None})
        assert ei.value.audit_code == "RECEIPT_DIGEST_MISSING"

    def test_schema_version_mismatch_rejected(self, store):
        r = approved_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.verify_receipt_integrity(
                {**r, "schema_version": "fg.customer_scan_authorization.v0"}
            )
        assert ei.value.audit_code == "RECEIPT_SCHEMA_UNSUPPORTED"

    def test_wrong_verification_key_rejected(self, store, monkeypatch):
        set_keyring(monkeypatch)
        r = approved_receipt(store)
        # Same kid now maps to a different key (key substitution).
        monkeypatch.setenv(
            "FG_SCAN_CONSENT_ATTESTATION_KEYS", '{"kid-2026-a": "' + "33" * 32 + '"}'
        )
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.verify_receipt_integrity(r)
        assert ei.value.audit_code == "RECEIPT_ATTESTATION_INVALID"

    def test_unknown_key_id_rejected(self, store, monkeypatch):
        set_keyring(monkeypatch)
        r = approved_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.verify_receipt_integrity({**r, "attestation_kid": "kid-unknown"})
        assert ei.value.audit_code == "RECEIPT_ATTESTATION_KEY_UNKNOWN"

    def test_revoked_key_id_rejected_for_verification(self, store, monkeypatch):
        set_keyring(monkeypatch)
        r = approved_receipt(store)
        set_keyring(monkeypatch, active="kid-2026-b", revoked="kid-2026-a")
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.verify_receipt_integrity(r)
        assert ei.value.audit_code == "RECEIPT_ATTESTATION_KEY_REVOKED"

    def test_key_rotation_keeps_old_receipts_verifiable(self, store, monkeypatch):
        set_keyring(monkeypatch, active="kid-2026-a")
        old = approved_receipt(store)
        set_keyring(monkeypatch, active="kid-2026-b")
        new = approved_receipt(store)
        assert new["attestation_kid"] == "kid-2026-b"
        assert (
            ca.verify_receipt_integrity(old)
            is ca.ProofLevel.SERVER_ATTESTED_AUTHENTICATED_APPROVAL
        )

    def test_revoked_active_key_blocks_new_approvals(self, store, monkeypatch):
        set_keyring(monkeypatch, active="kid-2026-a", revoked="kid-2026-a")
        r = request_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.approve(
                store.session(),
                receipt_id=str(r["id"]),
                tenant_id=T1,
                engagement_id=E1,
                actor_ctx=Actor(),
            )
        assert ei.value.audit_code == "ATTESTATION_KEY_REVOKED"

    def test_algorithm_downgrade_rejected(self, store, monkeypatch):
        set_keyring(monkeypatch)
        r = approved_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.verify_receipt_integrity({**r, "attestation_alg": "NONE"})
        assert ei.value.audit_code == "RECEIPT_ATTESTATION_ALG_UNSUPPORTED"

    def test_stripping_attestation_rejected_when_required(self, store, monkeypatch):
        set_keyring(monkeypatch)
        r = approved_receipt(store)
        monkeypatch.setenv("FG_SCAN_CONSENT_REQUIRE_ATTESTATION", "1")
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.verify_receipt_integrity(
                {
                    **r,
                    "attestation_kid": None,
                    "attestation_value": None,
                    "attestation_alg": None,
                }
            )
        assert ei.value.audit_code == "RECEIPT_ATTESTATION_MISSING"

    def test_partial_attestation_rejected(self, store, monkeypatch):
        set_keyring(monkeypatch)
        r = approved_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.verify_receipt_integrity({**r, "attestation_value": None})
        assert ei.value.audit_code == "RECEIPT_ATTESTATION_INVALID"

    def test_missing_signing_authority_fails_closed_when_required(
        self, store, monkeypatch
    ):
        monkeypatch.setenv("FG_SCAN_CONSENT_REQUIRE_ATTESTATION", "1")
        r = request_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.approve(
                store.session(),
                receipt_id=str(r["id"]),
                tenant_id=T1,
                engagement_id=E1,
                actor_ctx=Actor(),
            )
        assert ei.value.audit_code == "ATTESTATION_KEY_UNAVAILABLE"
        assert store.receipts[str(r["id"])]["status"] == "pending_approval"

    def test_short_keys_are_never_trusted(self, monkeypatch):
        monkeypatch.setenv("FG_SCAN_CONSENT_ATTESTATION_KEYS", '{"weak": "aabb"}')
        monkeypatch.setenv("FG_SCAN_CONSENT_ATTESTATION_ACTIVE_KID", "weak")
        assert ca._active_attestation_key() is None

    def test_malformed_keyring_error_does_not_echo_key_material(self, monkeypatch):
        monkeypatch.setenv("FG_SCAN_CONSENT_ATTESTATION_KEYS", "{not-json SECRETVALUE")
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca._keyring()
        assert "SECRETVALUE" not in str(ei.value)

    def test_public_view_never_exposes_attestation_value(self, store, monkeypatch):
        set_keyring(monkeypatch)
        view = ca.public_view(approved_receipt(store))
        assert "attestation_value" not in view


# ---------------------------------------------------------------------------
# Lifecycle: expiry, revocation, reapproval
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_expired_receipt_denies_scan_and_is_derived_expired(self, store):
        r = approved_receipt(
            store, window=timedelta(hours=2), start_offset=timedelta(hours=-1)
        )
        store.add_scope(receipt_id=str(r["id"]), expires_in=timedelta(minutes=30))
        later = utcnow() + timedelta(hours=3)
        assert ca.derived_status(store.receipts[str(r["id"])], later) == "expired"
        store.scopes[next(iter(store.scopes))]["expires_at"] = later + timedelta(days=1)
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store, now=later)
        assert ei.value.audit_code == "RECEIPT_EXPIRED"

    def test_not_yet_valid_receipt_denies(self, store):
        r = approved_receipt(store, start_offset=timedelta(hours=1))
        store.add_scope(receipt_id=str(r["id"]))
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store)
        assert ei.value.audit_code == "RECEIPT_NOT_YET_VALID"

    def test_revoked_receipt_denies_and_history_retained(self, store):
        r = approved_receipt(store)
        store.add_scope(receipt_id=str(r["id"]))
        _check(store)
        out = ca.revoke(
            store.session(),
            receipt_id=str(r["id"]),
            tenant_id=T1,
            engagement_id=E1,
            revoked_by_subject="auth0|customer-ciso",
            reason="withdrawn",
        )
        assert out["status"] == "revoked"
        assert out["approver_subject"] == "auth0|customer-ciso"  # history kept
        assert out["payload_digest"] == r["payload_digest"]
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store)
        assert ei.value.audit_code == "RECEIPT_REVOKED"

    def test_revocation_is_idempotent(self, store):
        r = approved_receipt(store)
        ca.revoke(
            store.session(),
            receipt_id=str(r["id"]),
            tenant_id=T1,
            engagement_id=E1,
            revoked_by_subject="x",
            reason="r",
        )
        again = ca.revoke(
            store.session(),
            receipt_id=str(r["id"]),
            tenant_id=T1,
            engagement_id=E1,
            revoked_by_subject="x",
            reason="r",
        )
        assert again["idempotent"] is True

    def test_rejected_receipt_cannot_be_revoked_or_approved(self, store):
        r = request_receipt(store)
        ca.reject(
            store.session(),
            receipt_id=str(r["id"]),
            tenant_id=T1,
            engagement_id=E1,
            actor_ctx=Actor(),
            reason="no",
        )
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.revoke(
                store.session(),
                receipt_id=str(r["id"]),
                tenant_id=T1,
                engagement_id=E1,
                revoked_by_subject="x",
                reason="r",
            )
        assert ei.value.audit_code == "RECEIPT_NOT_REVOCABLE"
        with pytest.raises(ca.CustomerAuthorizationError):
            ca.approve(
                store.session(),
                receipt_id=str(r["id"]),
                tenant_id=T1,
                engagement_id=E1,
                actor_ctx=Actor(),
            )

    def test_reapproval_creates_new_version_not_mutation(self, store):
        r1 = approved_receipt(store)
        r2 = ca.create_request(
            store.session(),
            tenant_id=T1,
            engagement_id=E1,
            requested_by_subject=ASSESSOR,
            customer_org_name="Alpha Corp",
            assessment_purpose="Re-test",
            rules_of_engagement_ref="ROE-2026-002",
            approved_targets=[
                {
                    "target": "app.example.com",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                }
            ],
            authorized_operations=["web_headers"],
            window_start=utcnow(),
            window_end=utcnow() + timedelta(days=1),
            supersedes_receipt_id=str(r1["id"]),
        )
        assert r2["id"] != r1["id"]
        assert str(r2["receipt_group_id"]) == str(r1["receipt_group_id"])
        assert r2["receipt_version"] == 2
        assert store.receipts[str(r1["id"])]["status"] == "approved"

    def test_approval_after_window_end_rejected(self, store):
        r = request_receipt(
            store, window=timedelta(hours=1), start_offset=timedelta(hours=-0.5)
        )
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            ca.approve(
                store.session(),
                receipt_id=str(r["id"]),
                tenant_id=T1,
                engagement_id=E1,
                actor_ctx=Actor(),
                now=utcnow() + timedelta(hours=2),
            )
        assert ei.value.audit_code == "RECEIPT_EXPIRED"


# ---------------------------------------------------------------------------
# Target / operation / tenant binding
# ---------------------------------------------------------------------------


class TestBinding:
    def test_unrelated_host_not_authorized_by_receipt(self, store):
        r = approved_receipt(store)
        # Operator scope (wrongly) includes a host the customer never approved.
        store.add_scope(
            receipt_id=str(r["id"]),
            targets=[
                {
                    "target": "other.example.org",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                }
            ],
        )
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store, target="other.example.org")
        assert ei.value.audit_code == "RECEIPT_TARGET_NOT_APPROVED"

    def test_dns_approval_does_not_authorize_port_scan(self, store):
        r = approved_receipt(
            store,
            targets=[
                {
                    "target": "app.example.com",
                    "type": "fqdn",
                    "operations": ["dns_email"],
                }
            ],
            ops=["dns_email"],
        )
        store.add_scope(
            receipt_id=str(r["id"]),
            targets=[
                {
                    "target": "app.example.com",
                    "type": "fqdn",
                    "operations": ["network_scan", "dns_email"],
                }
            ],
        )
        assert _check(store, op="dns_email")["consent_status"] == "CUSTOMER_APPROVED"
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store, op="network_scan")
        assert ei.value.audit_code == "RECEIPT_OPERATION_NOT_APPROVED"

    def test_prefix_lookalike_host_not_matched(self, store):
        r = approved_receipt(store)
        store.add_scope(
            receipt_id=str(r["id"]),
            targets=[
                {
                    "target": "app.example.com.attacker.net",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                }
            ],
        )
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store, target="app.example.com.attacker.net")
        assert ei.value.audit_code == "RECEIPT_TARGET_NOT_APPROVED"

    def test_subdomain_not_implied(self, store):
        r = approved_receipt(store)
        store.add_scope(
            receipt_id=str(r["id"]),
            targets=[
                {
                    "target": "app.example.com",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                    "allow_subdomains": True,
                }
            ],
        )
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store, target="admin.app.example.com")
        assert ei.value.audit_code == "RECEIPT_TARGET_NOT_APPROVED"

    def test_host_inside_approved_cidr_allowed_outside_denied(self, store):
        r = approved_receipt(store)
        store.add_scope(
            receipt_id=str(r["id"]),
            targets=[
                {
                    "target": "203.0.113.0/24",
                    "type": "cidr",
                    "operations": ["network_scan"],
                }
            ],
        )
        assert _check(store, target="203.0.113.5", ttype="ipv4", op="network_scan")
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store, target="203.0.113.200", ttype="ipv4", op="network_scan")
        assert ei.value.audit_code == "RECEIPT_TARGET_NOT_APPROVED"

    def test_receipt_replay_against_other_engagement_denied(self, store):
        r = approved_receipt(store, engagement_id=E1)
        store.add_scope(engagement_id=E2, receipt_id=str(r["id"]))
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store, eng=E2)
        assert ei.value.audit_code == "CUSTOMER_AUTHORIZATION_NOT_FOUND"

    def test_receipt_replay_against_other_tenant_denied(self, store):
        r = approved_receipt(store, tenant_id=T1)
        store.add_scope(
            tenant_id=T2, engagement_id="eng-bravo-1", receipt_id=str(r["id"])
        )
        with pytest.raises(ScanAuthorizationError) as ei:
            _check(store, tenant=T2, eng="eng-bravo-1")
        assert ei.value.audit_code == "CUSTOMER_AUTHORIZATION_NOT_FOUND"

    def test_receipt_store_unavailable_fails_closed(self, store):
        r = approved_receipt(store)
        store.add_scope(receipt_id=str(r["id"]))
        sess = store.session()

        def hook(sql, p):
            if "fa_customer_authorization_receipts" in sql:
                raise ConnectionError("down")

        store.hook = hook
        with pytest.raises(ScanAuthorizationError) as ei:
            check_scan_authorized(
                sess,
                tenant_id=T1,
                engagement_id=E1,
                target="app.example.com",
                target_type="fqdn",
                operation="web_headers",
            )
        assert ei.value.audit_code == "CUSTOMER_AUTHORIZATION_LOOKUP_FAILED"


class TestScopeCoverage:
    def _eval(self, receipt, targets, expires=None):
        return ca.evaluate_receipt_for_scope(
            receipt,
            scope_targets=targets,
            scope_expires_at=expires or (utcnow() + timedelta(days=1)),
            tenant_id=T1,
            engagement_id=E1,
            now=utcnow(),
        )

    def test_subset_scope_covered(self, store):
        r = approved_receipt(store)
        assert self._eval(
            r,
            [
                {
                    "target": "APP.example.com.",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                }
            ],
        )
        assert self._eval(
            r,
            [
                {
                    "target": "203.0.113.0/29",
                    "type": "cidr",
                    "operations": ["network_scan"],
                }
            ],
        )

    @pytest.mark.parametrize(
        "targets",
        [
            [
                {
                    "target": "app.example.com",
                    "type": "fqdn",
                    "operations": ["web_headers", "exploit"],
                }
            ],
            [
                {
                    "target": "203.0.113.0/24",
                    "type": "cidr",
                    "operations": ["network_scan"],
                }
            ],
            [
                {
                    "target": "203.0.113.0/29",
                    "type": "cidr",
                    "operations": ["web_headers"],
                }
            ],
            [
                {
                    "target": "app.example.com",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                    "allow_subdomains": True,
                }
            ],
            [
                {
                    "target": "other.example.com",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                }
            ],
            [{"target": "app.example.com", "type": "fqdn", "operations": []}],
            ["not-a-dict"],
            [],
        ],
    )
    def test_scope_exceeding_receipt_rejected(self, store, targets):
        r = approved_receipt(store)
        with pytest.raises(ca.CustomerAuthorizationError):
            self._eval(r, targets)

    def test_scope_window_beyond_receipt_rejected(self, store):
        r = approved_receipt(store, window=timedelta(days=2))
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            self._eval(
                r,
                [
                    {
                        "target": "app.example.com",
                        "type": "fqdn",
                        "operations": ["web_headers"],
                    }
                ],
                expires=utcnow() + timedelta(days=30),
            )
        assert ei.value.audit_code == "SCOPE_WINDOW_EXCEEDS_CUSTOMER_APPROVAL"


class TestRequestValidation:
    @pytest.mark.parametrize(
        "targets, ops, code",
        [
            ([], ["web_headers"], "RECEIPT_TARGETS_INVALID"),
            (
                [
                    {
                        "target": "*.example.com",
                        "type": "fqdn",
                        "operations": ["web_headers"],
                    }
                ],
                ["web_headers"],
                "RECEIPT_TARGETS_INVALID",
            ),
            (
                [
                    {
                        "target": "a.example.com",
                        "type": "url",
                        "operations": ["web_headers"],
                    }
                ],
                ["web_headers"],
                "RECEIPT_TARGETS_INVALID",
            ),
            (
                [
                    {
                        "target": "a.example.com",
                        "type": "fqdn",
                        "operations": ["network_scan"],
                    }
                ],
                ["web_headers"],
                "RECEIPT_OPERATIONS_INVALID",
            ),
            (
                [
                    {
                        "target": "a.example.com",
                        "type": "fqdn",
                        "operations": ["web_headers"],
                    }
                ],
                ["exploit"],
                "RECEIPT_OPERATIONS_INVALID",
            ),
            (
                [
                    {
                        "target": "10.0.0.0/8",
                        "type": "cidr",
                        "operations": ["network_scan"],
                        "allow_subdomains": True,
                    }
                ],
                ["network_scan"],
                "RECEIPT_TARGETS_INVALID",
            ),
            (
                [
                    {
                        "target": "a.example.com",
                        "type": "fqdn",
                        "operations": ["web_headers"],
                        "x": 1,
                    }
                ],
                ["web_headers"],
                "RECEIPT_TARGETS_INVALID",
            ),
            (
                [
                    {
                        "target": "a.example.com",
                        "type": "fqdn",
                        "operations": ["web_headers"],
                    },
                    {
                        "target": "A.EXAMPLE.COM.",
                        "type": "fqdn",
                        "operations": ["web_headers"],
                    },
                ],
                ["web_headers"],
                "RECEIPT_TARGETS_INVALID",
            ),
        ],
    )
    def test_invalid_requests_rejected(self, store, targets, ops, code):
        with pytest.raises(ca.CustomerAuthorizationError) as ei:
            request_receipt(store, targets=targets, ops=ops)
        assert ei.value.audit_code == code

    def test_window_constraints(self, store):
        with pytest.raises(ca.CustomerAuthorizationError):
            request_receipt(store, window=timedelta(days=400))
        with pytest.raises(ca.CustomerAuthorizationError):
            request_receipt(
                store, window=timedelta(hours=1), start_offset=timedelta(hours=-5)
            )

    def test_targets_are_normalized_and_sorted(self, store):
        r = request_receipt(
            store,
            targets=[
                {
                    "target": "Z.example.com.",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                },
                {
                    "target": "2001:0db8::0001",
                    "type": "ipv6",
                    "operations": ["network_scan"],
                },
            ],
            ops=["web_headers", "network_scan"],
        )
        assert [t["target"] for t in r["approved_targets"]] == [
            "z.example.com",
            "2001:db8::1",
        ]
