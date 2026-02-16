from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.billing import _stable_device_key
from api.db import get_engine
from api.db_models import (
    BillingCountSyncCheckpoint,
    BillingCountSyncCheckpointEvent,
    BillingIdentityClaim,
    BillingIdentityClaimEvent,
    BillingInvoice,
    PricingVersion,
    TenantContract,
)


def _client_with_key(
    build_app, *scopes: str, tenant_id: str
) -> tuple[TestClient, dict[str, str]]:
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key(*scopes, tenant_id=tenant_id)
    return client, {"x-api-key": key}


def _seed_pricing_and_contract(db: Session, tenant_id: str) -> None:
    db.add(
        PricingVersion(
            pricing_version_id="pv-1",
            effective_at=datetime(2025, 1, 1, tzinfo=UTC),
            rates_json={"plan-pro": 2.0},
            sha256_hash="h" * 64,
        )
    )
    db.add(
        TenantContract(
            tenant_id=tenant_id,
            contract_id="ct-1",
            pricing_version_id="pv-1",
            discount_rules_json={},
            commitment_minimum=10.0,
            start_at=datetime(2025, 1, 1, tzinfo=UTC),
            end_at=None,
        )
    )


def test_identity_dedupe_priority() -> None:
    claim_type, key, confidence = _stable_device_key(
        type(
            "R",
            (),
            {
                "asset_id": "asset-1",
                "asset_verified": True,
                "agent_stable_id": "ag-1",
                "fingerprint_hash": "fp-1",
            },
        )
    )
    assert claim_type == "asset_id"
    assert key == "asset:asset-1"
    assert confidence == 100


def test_identity_conflict_quarantine_and_resolution_events(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )
    first = client.post(
        "/billing/devices/upsert",
        json={"tenant_id": "t-1", "asset_id": "asset-x", "asset_verified": True},
        headers=headers,
    )
    assert first.status_code == 200

    with Session(get_engine()) as db:
        claim = (
            db.query(BillingIdentityClaim)
            .filter(
                BillingIdentityClaim.tenant_id == "t-1",
                BillingIdentityClaim.claimed_id_type == "asset_id",
                BillingIdentityClaim.claimed_id_value == "asset:asset-x",
            )
            .one()
        )
        claim.device_id = "00000000-0000-0000-0000-000000000123"
        db.commit()

    second = client.post(
        "/billing/devices/upsert",
        json={"tenant_id": "t-1", "asset_id": "asset-x", "asset_verified": True},
        headers=headers,
    )
    assert second.status_code == 200
    claim_id = second.json()["claim_id"]
    assert second.json()["conflict_state"] == "conflicted"

    disputes = client.get(
        "/billing/identity/disputes", params={"tenant_id": "t-1"}, headers=headers
    )
    assert disputes.status_code == 200
    assert any(item["claim_id"] == claim_id for item in disputes.json()["items"])

    resolved = client.post(
        f"/billing/identity/disputes/{claim_id}/resolve",
        json={
            "tenant_id": "t-1",
            "resolved_device_id": first.json()["device_id"],
            "reason": "manual review approved",
            "ticket_id": "SOC-123",
            "resolution_type": "manual_review",
            "resolved_by": "ops@example.com",
        },
        headers=headers,
    )
    assert resolved.status_code == 200

    with Session(get_engine()) as db:
        claim = (
            db.query(BillingIdentityClaim)
            .filter(BillingIdentityClaim.id == claim_id)
            .one()
        )
        assert claim.conflict_state == "resolved"
        events = (
            db.query(BillingIdentityClaimEvent)
            .filter(BillingIdentityClaimEvent.claim_id == claim_id)
            .order_by(BillingIdentityClaimEvent.sequence.asc())
            .all()
        )
        assert len(events) >= 3
        assert events[0].transition == "CLAIM_CREATED"
        assert events[-1].transition == "CLAIM_RESOLVED"


def test_device_enrollment_and_activity_proof(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )
    upsert = client.post(
        "/billing/devices/upsert",
        json={
            "tenant_id": "t-1",
            "agent_stable_id": "ag-enroll",
            "device_type": "server",
        },
        headers=headers,
    )
    device_id = upsert.json()["device_id"]

    enroll = client.post(
        "/billing/devices/enroll",
        json={
            "tenant_id": "t-1",
            "device_id": device_id,
            "attestation_type": "agent-possession",
            "attestation_payload_hash": "a" * 64,
            "enrolled_by": "ops@example.com",
        },
        headers=headers,
    )
    assert enroll.status_code == 200

    activity = client.post(
        "/billing/devices/activity",
        json={
            "tenant_id": "t-1",
            "device_id": device_id,
            "activity_day": "2025-02-01",
            "proof_type": "heartbeat",
            "proof_hash": "b" * 64,
        },
        headers=headers,
    )
    assert activity.status_code == 200


def test_invoice_determinism_and_reproduce(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )

    upsert = client.post(
        "/billing/devices/upsert",
        json={"tenant_id": "t-1", "agent_stable_id": "ag-1", "device_type": "server"},
        headers=headers,
    )
    assert upsert.status_code == 200
    device_id = upsert.json()["device_id"]

    with Session(get_engine()) as db:
        _seed_pricing_and_contract(db, "t-1")
        db.commit()

    ts = datetime(2025, 2, 1, tzinfo=UTC)
    change = client.post(
        "/billing/coverage/change",
        json={
            "tenant_id": "t-1",
            "event_id": "evt-1",
            "device_id": device_id,
            "plan_id": "plan-pro",
            "action": "ADD",
            "effective_from": ts.isoformat(),
            "effective_to": (ts + timedelta(days=2)).isoformat(),
            "config_hash": "c" * 64,
            "policy_hash": "p" * 64,
        },
        headers=headers,
    )
    assert change.status_code == 200

    create = client.post(
        "/billing/invoices",
        json={
            "tenant_id": "t-1",
            "invoice_id": "inv-1",
            "period_start": ts.isoformat(),
            "period_end": (ts + timedelta(days=2)).isoformat(),
            "pricing_version_id": "pv-1",
            "config_hash": "c" * 64,
            "policy_hash": "p" * 64,
        },
        headers=headers,
    )
    assert create.status_code == 200
    assert create.json()["pricing_hash"] == "h" * 64

    reproduce = client.post(
        "/billing/invoices/inv-1/reproduce",
        params={"tenant_id": "t-1"},
        headers=headers,
    )
    assert reproduce.status_code == 200


def test_reproduce_mismatch_detection(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )
    with Session(get_engine()) as db:
        _seed_pricing_and_contract(db, "t-1")
        db.add(
            BillingInvoice(
                tenant_id="t-1",
                invoice_id="inv-bad",
                period_start=datetime(2025, 2, 1, tzinfo=UTC),
                period_end=datetime(2025, 2, 2, tzinfo=UTC),
                pricing_version_id="pv-1",
                pricing_hash="h" * 64,
                contract_hash="z" * 64,
                config_hash="c" * 64,
                policy_hash="p" * 64,
                invoice_json={"x": 1},
                invoice_sha256="0" * 64,
            )
        )
        db.commit()

    reproduce = client.post(
        "/billing/invoices/inv-bad/reproduce",
        params={"tenant_id": "t-1"},
        headers=headers,
    )
    assert reproduce.status_code == 409


def test_evidence_export_contains_manifest_and_attestation(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )
    with Session(get_engine()) as db:
        _seed_pricing_and_contract(db, "t-1")
        db.add(
            BillingInvoice(
                tenant_id="t-1",
                invoice_id="inv-e1",
                period_start=datetime(2025, 2, 1, tzinfo=UTC),
                period_end=datetime(2025, 2, 2, tzinfo=UTC),
                pricing_version_id="pv-1",
                pricing_hash="h" * 64,
                contract_hash="c" * 64,
                config_hash="c" * 64,
                policy_hash="p" * 64,
                invoice_json={"x": 1},
                invoice_sha256="1" * 64,
            )
        )
        db.commit()

    response = client.post(
        "/billing/invoices/inv-e1/evidence",
        params={"tenant_id": "t-1"},
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    manifest_path = Path(body["manifest_path"])
    assert manifest_path.exists()
    data = json.loads(manifest_path.read_text())
    assert data["billing_evidence_spec_version"] == "v1"
    assert {entry["path"] for entry in data["files"]} >= {
        "invoice.json",
        "daily_counts.json",
        "coverage_proof.json",
        "verification.txt",
        "server_build_info.json",
    }
    assert Path(body["attestation_sig_path"]).exists()


def test_daily_count_sync_incremental_has_tamper_evident_checkpoint(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )
    upsert = client.post(
        "/billing/devices/upsert",
        json={
            "tenant_id": "t-1",
            "agent_stable_id": "ag-sync",
            "device_type": "server",
        },
        headers=headers,
    )
    device_id = upsert.json()["device_id"]

    ts = datetime(2025, 2, 3, tzinfo=UTC)
    add = client.post(
        "/billing/coverage/change",
        json={
            "tenant_id": "t-1",
            "event_id": "evt-sync",
            "device_id": device_id,
            "plan_id": "plan-pro",
            "action": "ADD",
            "effective_from": ts.isoformat(),
            "effective_to": (ts + timedelta(days=1)).isoformat(),
            "config_hash": "c" * 64,
            "policy_hash": "p" * 64,
        },
        headers=headers,
    )
    assert add.status_code == 200

    sync = client.post(
        "/billing/daily-counts/sync",
        params={"tenant_id": "t-1", "limit": 100},
        headers=headers,
    )
    assert sync.status_code == 200

    with Session(get_engine()) as db:
        cp = db.get(BillingCountSyncCheckpoint, "t-1")
        assert cp is not None
        assert cp.self_hash != "GENESIS"
        events = (
            db.query(BillingCountSyncCheckpointEvent)
            .filter(BillingCountSyncCheckpointEvent.tenant_id == "t-1")
            .order_by(BillingCountSyncCheckpointEvent.sequence.asc())
            .all()
        )
        assert len(events) >= 1
        assert events[-1].self_hash == cp.self_hash


def test_billing_run_model(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )
    run = client.post(
        "/billing/runs",
        json={
            "tenant_id": "t-1",
            "run_id": "run-1",
            "replay_id": "replay-1",
            "pricing_version_id": "pv-1",
            "contract_hash": "c" * 64,
            "period_start": datetime(2025, 2, 1, tzinfo=UTC).isoformat(),
            "period_end": datetime(2025, 2, 2, tzinfo=UTC).isoformat(),
        },
        headers=headers,
    )
    assert run.status_code == 200

    listed = client.get("/billing/runs", params={"tenant_id": "t-1"}, headers=headers)
    assert listed.status_code == 200
    assert listed.json()["items"][0]["run_id"] == "run-1"
    dup = client.post(
        "/billing/runs",
        json={
            "tenant_id": "t-1",
            "run_id": "run-1b",
            "replay_id": "replay-1b",
            "pricing_version_id": "pv-1",
            "contract_hash": "c" * 64,
            "period_start": datetime(2025, 2, 1, tzinfo=UTC).isoformat(),
            "period_end": datetime(2025, 2, 2, tzinfo=UTC).isoformat(),
        },
        headers=headers,
    )
    assert dup.status_code == 200
    assert dup.json()["existing"] is True


def test_coverage_day_contract_metadata(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )
    with Session(get_engine()) as db:
        db.add(
            BillingInvoice(
                tenant_id="t-1",
                invoice_id="inv-meta",
                period_start=datetime(2025, 2, 1, tzinfo=UTC),
                period_end=datetime(2025, 2, 2, tzinfo=UTC),
                pricing_version_id="pv-1",
                pricing_hash="h" * 64,
                contract_hash="c" * 64,
                config_hash="c" * 64,
                policy_hash="p" * 64,
                invoice_json={"x": 1},
                invoice_sha256="1" * 64,
            )
        )
        db.commit()
    details = client.get(
        "/billing/invoices/inv-meta", params={"tenant_id": "t-1"}, headers=headers
    )
    assert details.status_code == 200
    assert details.json()["coverage_day_rule"] == "UTC"
    assert details.json()["invoice_period_boundary"] == "[period_start, period_end)"


def test_credit_note_append_only_flow(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )
    with Session(get_engine()) as db:
        _seed_pricing_and_contract(db, "t-1")
        db.add(
            BillingInvoice(
                tenant_id="t-1",
                invoice_id="inv-credit",
                period_start=datetime(2025, 2, 1, tzinfo=UTC),
                period_end=datetime(2025, 2, 2, tzinfo=UTC),
                pricing_version_id="pv-1",
                pricing_hash="h" * 64,
                contract_hash="c" * 64,
                config_hash="c" * 64,
                policy_hash="p" * 64,
                invoice_json={"total": 100.0},
                invoice_sha256="1" * 64,
                invoice_state="finalized",
            )
        )
        db.commit()

    credit = client.post(
        "/billing/invoices/inv-credit/credits",
        json={
            "tenant_id": "t-1",
            "credit_note_id": "cn-1",
            "amount": 25.0,
            "currency": "USD",
            "reason": "late data correction",
            "ticket_id": "FIN-22",
            "created_by": "billing-ops@example.com",
        },
        headers=headers,
    )
    assert credit.status_code == 200

    listed = client.get(
        "/billing/invoices/inv-credit/credits",
        params={"tenant_id": "t-1"},
        headers=headers,
    )
    assert listed.status_code == 200
    assert listed.json()["items"][0]["credit_note_id"] == "cn-1"

    inv = client.get(
        "/billing/invoices/inv-credit", params={"tenant_id": "t-1"}, headers=headers
    )
    assert inv.status_code == 200
    assert inv.json()["net_total"] == 75.0


def test_invoice_finalize_freezes_evidence(build_app) -> None:
    client, headers = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="t-1"
    )
    with Session(get_engine()) as db:
        _seed_pricing_and_contract(db, "t-1")
        db.add(
            BillingInvoice(
                tenant_id="t-1",
                invoice_id="inv-final",
                period_start=datetime(2025, 2, 1, tzinfo=UTC),
                period_end=datetime(2025, 2, 2, tzinfo=UTC),
                pricing_version_id="pv-1",
                pricing_hash="h" * 64,
                contract_hash="c" * 64,
                config_hash="c" * 64,
                policy_hash="p" * 64,
                invoice_json={"x": 1},
                invoice_sha256="1" * 64,
            )
        )
        db.commit()

    finalized = client.post(
        "/billing/invoices/inv-final/finalize",
        json={
            "tenant_id": "t-1",
            "finalized_by": "ops@example.com",
            "ticket_id": "SOC-999",
            "reason": "period close",
        },
        headers=headers,
    )
    assert finalized.status_code == 200

    blocked = client.post(
        "/billing/invoices/inv-final/evidence",
        params={"tenant_id": "t-1"},
        headers=headers,
    )
    assert blocked.status_code == 409


def test_tenant_isolation_adversarial_reads_and_writes(build_app) -> None:
    client_a, headers_a = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="tenant-a"
    )
    client_b, headers_b = _client_with_key(
        build_app, "admin:read", "admin:write", tenant_id="tenant-b"
    )

    with Session(get_engine()) as db:
        _seed_pricing_and_contract(db, "tenant-a")
        db.add(
            BillingInvoice(
                tenant_id="tenant-a",
                invoice_id="inv-a",
                period_start=datetime(2025, 2, 1, tzinfo=UTC),
                period_end=datetime(2025, 2, 2, tzinfo=UTC),
                pricing_version_id="pv-1",
                pricing_hash="h" * 64,
                contract_hash="c" * 64,
                config_hash="c" * 64,
                policy_hash="p" * 64,
                invoice_json={"x": 1},
                invoice_sha256="1" * 64,
            )
        )
        db.commit()

    read_other = client_b.get(
        "/billing/invoices/inv-a",
        params={"tenant_id": "tenant-b"},
        headers=headers_b,
    )
    assert read_other.status_code == 404

    device = client_a.post(
        "/billing/devices/upsert",
        json={
            "tenant_id": "tenant-a",
            "agent_stable_id": "ag-a",
            "device_type": "agent",
        },
        headers=headers_a,
    )
    device_id = device.json()["device_id"]
    bad_append = client_b.post(
        "/billing/coverage/change",
        json={
            "tenant_id": "tenant-b",
            "event_id": "bad-append",
            "device_id": device_id,
            "plan_id": "plan-pro",
            "action": "ADD",
            "effective_from": datetime(2025, 2, 1, tzinfo=UTC).isoformat(),
            "config_hash": "c" * 64,
            "policy_hash": "p" * 64,
        },
        headers=headers_b,
    )
    assert bad_append.status_code == 404


def test_scope_bypass_denied(build_app) -> None:
    client, headers = _client_with_key(build_app, "stats:read", tenant_id="t-1")
    denied = client.post(
        "/billing/devices/upsert",
        json={"tenant_id": "t-1", "agent_stable_id": "ag-1", "device_type": "agent"},
        headers=headers,
    )
    assert denied.status_code == 403
