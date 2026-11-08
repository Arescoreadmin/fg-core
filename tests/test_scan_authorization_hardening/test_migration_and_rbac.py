"""Static contract checks for migration 0203 and consent RBAC.

L14-SCAN-AUTH-HARDENING-001.  Live replay runs in CI
(tests/test_migrations_postgres_replay.py).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

os.environ.setdefault("FG_ENV", "test")

from api.actor_context import ALL_PERMISSIONS, ROLE_PERMISSIONS, roles_to_permissions
from services.field_assessment import customer_authorization as ca

from ._harness import Actor

ROOT = Path(__file__).resolve().parents[2]
MIG = ROOT / "migrations" / "postgres" / "0203_scan_customer_authorization.sql"
SQL = MIG.read_text()


def _allowed_event_types() -> set[str]:
    block = SQL.split("ADD CONSTRAINT fa_scan_audit_events_event_type_check", 1)[1]
    block = block.split(");", 1)[0]
    return set(re.findall(r"'(scan\.[a-z_.]+)'", block))


class TestMigration:
    def test_is_latest_and_sequential(self):
        names = sorted(p.name for p in MIG.parent.glob("0*.sql"))
        assert names[-1] == MIG.name
        assert names[-2].startswith("0202_")

    def test_every_scan_audit_event_written_by_code_is_allowed(self):
        """Regression: 0079's CHECK rejected every event type added since 0200."""
        src = (ROOT / "api" / "field_assessment.py").read_text()
        emitted = set()
        for m in re.finditer(r"_c6_write_audit_event\((.*?)\n    \)", src, re.S):
            emitted |= set(re.findall(r'event_type="(scan\.[a-z_.]+)"', m.group(1)))
        emitted |= set(re.findall(r'event_type="(scan\.consent\.[a-z_]+)"', src))
        # conditional expressions inside the guarded worker
        emitted |= {
            "scan.authorization.worker_start_authorized",
            "scan.authorization.worker_start_denied",
        }
        missing = emitted - _allowed_event_types()
        assert not missing, f"event types rejected by DB CHECK: {sorted(missing)}"

    def test_original_event_types_preserved(self):
        for e in (
            "scan.initiated",
            "scan.validation_rejected",
            "scan.running",
            "scan.completed",
            "scan.failed",
            "scan.rate_limited",
        ):
            assert e in _allowed_event_types()

    def test_job_status_constraint_includes_dead_letter_and_cancel_states(self):
        block = SQL.split("ADD CONSTRAINT fa_scan_jobs_status_check", 1)[1].split(
            ");", 1
        )[0]
        for st in (
            "queued",
            "running",
            "complete",
            "failed",
            "cancel_requested",
            "cancelled",
            "dead_letter",
        ):
            assert f"'{st}'" in block

    def test_additive_and_executor_safe(self):
        code = "\n".join(line.split("--", 1)[0] for line in SQL.splitlines())
        upper = code.upper()
        assert "CONCURRENTLY" not in upper
        assert "DROP TABLE" not in upper
        assert "DROP COLUMN" not in upper
        assert "TRUNCATE" not in upper
        assert not re.search(r"\bDELETE\s+FROM\b", upper)
        assert "%" not in SQL  # psycopg pyformat safety

    def test_receipt_immutability_trigger_present(self):
        assert "BEFORE UPDATE OR DELETE ON fa_customer_authorization_receipts" in SQL
        assert "append-only: DELETE is not permitted" in SQL
        assert "request fields are immutable" in SQL

    def test_no_key_material_columns(self):
        cols = re.findall(
            r"^\s{4}(\w+)\s",
            SQL.split(
                "CREATE TABLE IF NOT EXISTS fa_customer_authorization_receipts", 1
            )[1].split(");", 1)[0],
            re.M,
        )
        assert not [
            c for c in cols if "secret" in c or c.endswith("_key") or "private" in c
        ]

    def test_binding_column_nullable_legacy(self):
        assert "ADD COLUMN IF NOT EXISTS customer_receipt_id UUID" in SQL
        assert "customer_receipt_id UUID NOT NULL" not in SQL

    def test_receipt_status_never_stores_expired(self):
        block = SQL.split("status                       TEXT NOT NULL", 1)[1].split(
            ")),", 1
        )[0]
        assert "'expired'" not in block

    def test_select_column_list_matches_migration(self):
        table = SQL.split(
            "CREATE TABLE IF NOT EXISTS fa_customer_authorization_receipts", 1
        )[1].split("CONSTRAINT", 1)[0]
        for col in (c.strip() for c in ca._RECEIPT_COLUMNS.split(",")):
            assert re.search(rf"^\s+{col}\s", table, re.M), col


class TestConsentRbac:
    def test_permissions_registered(self):
        assert {"scan.consent.approve", "scan.consent.revoke"} <= ALL_PERMISSIONS

    def test_only_customer_roles_get_approve(self):
        holders = {
            r for r, p in ROLE_PERMISSIONS.items() if "scan.consent.approve" in p
        }
        assert holders == {"tenant_admin", "client_security_owner", "platform_admin"}

    def test_assessor_cannot_approve_but_can_revoke(self):
        p = roles_to_permissions(["assessor"])
        assert "scan.consent.approve" not in p
        assert "scan.consent.revoke" in p

    def test_platform_admin_permission_is_not_customer_authority(self):
        """platform_admin holds ALL_PERMISSIONS but must never stand in for the customer."""
        actor = Actor(
            roles=["platform_admin"],
            permissions=roles_to_permissions(["platform_admin"]),
        )
        try:
            ca.validate_approver(
                actor, tenant_id=actor.tenant_id, requested_by_subject="someone"
            )
        except ca.CustomerAuthorizationError as exc:
            assert exc.audit_code == "APPROVER_NOT_CUSTOMER"
        else:
            raise AssertionError("platform_admin approved customer consent")

    def test_approve_route_takes_no_identity_fields(self):
        import api.field_assessment as fa

        fields = set(fa.CustomerAuthorizationDecisionBody.model_fields)
        assert fields == {"acknowledge_consent_statement_version"}
        assert (
            fa.CustomerAuthorizationDecisionBody.model_config.get("extra") == "forbid"
        )

    def test_consent_routes_registered_with_permissions(self):
        import api.field_assessment as fa

        paths = {getattr(r, "path", "") for r in fa.router.routes}
        for suffix in (
            "/engagements/{engagement_id}/customer-authorizations",
            "/engagements/{engagement_id}/customer-authorizations/{receipt_id}",
            "/engagements/{engagement_id}/customer-authorizations/{receipt_id}/approve",
            "/engagements/{engagement_id}/customer-authorizations/{receipt_id}/reject",
            "/engagements/{engagement_id}/customer-authorizations/{receipt_id}/revoke",
            "/engagements/{engagement_id}/scan-authorizations/effective-status",
            "/emergency-stop/{stop_id}/clear",
        ):
            assert any(p.endswith(suffix) for p in paths), suffix
