"""AUDIT-REPAIR-BILLING-PATH-001: billing evidence bundles stay inside their
tenant's artifact root.

Invoice and credit-note identifiers are persisted from request bodies without
format constraints and later joined into ``artifacts/billing/<tenant>/...``.
These tests pin that a crafted identifier (traversal, absolute path, separator,
control character, oversized segment, reserved name) or a symlink inside the
root is rejected before anything is written, and that ordinary exports are
unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.billing import _billing_artifact_dir
from api.db import get_engine
from api.db_models import BillingCreditNote, BillingInvoice

HMAC_ENV = "FG_BILLING_EVIDENCE_HMAC_KEY"
HMAC_VALUE = "test-billing-hmac-key-32-bytes-x"

UNSAFE_COMPONENTS = [
    "",
    ".",
    "..",
    "../escape",
    "../../etc",
    "a/b",
    "/etc/passwd",
    "/",
    "a\\b",
    "..\\..\\escape",
    "x\x00y",
    "line\nbreak",
    "tab\tname",
    "del\x7f",
    "a" * 256,
]


@pytest.fixture()
def in_tmp_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # The artifact root is relative to the working directory.
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    return workdir


def _files_under(path: Path) -> list[Path]:
    return sorted(p for p in path.rglob("*") if p.is_file()) if path.exists() else []


# ---------------------------------------------------------------- helper unit


def test_plain_components_map_under_root(in_tmp_cwd: Path) -> None:
    assert _billing_artifact_dir("t-1", "inv-e1") == Path(
        "artifacts/billing/t-1/inv-e1"
    )
    assert _billing_artifact_dir("t-1", "credits", "cn-1") == Path(
        "artifacts/billing/t-1/credits/cn-1"
    )


@pytest.mark.parametrize("component", UNSAFE_COMPONENTS)
@pytest.mark.parametrize("position", ["tenant", "identifier"])
def test_unsafe_component_rejected(
    in_tmp_cwd: Path, component: str, position: str
) -> None:
    parts = (component, "inv-1") if position == "tenant" else ("t-1", component)
    with pytest.raises(HTTPException) as exc:
        _billing_artifact_dir(*parts)
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid_billing_artifact_identifier"


@pytest.mark.parametrize(
    "encoded", ["%2e%2e", "%2E%2E%2Fescape", "..%2f..%2f", "%252e"]
)
def test_percent_encoded_traversal_is_an_inert_literal(
    in_tmp_cwd: Path, encoded: str
) -> None:
    # The helper never decodes; an encoded sequence is one literal segment.
    out = _billing_artifact_dir("t-1", encoded)
    assert out.parent == Path("artifacts/billing/t-1")
    assert out.name == encoded


def test_symlinked_tenant_dir_escaping_root_rejected(
    in_tmp_cwd: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = in_tmp_cwd / "artifacts" / "billing"
    root.mkdir(parents=True)
    (root / "t-1").symlink_to(outside, target_is_directory=True)
    with pytest.raises(HTTPException) as exc:
        _billing_artifact_dir("t-1", "inv-1")
    assert exc.value.status_code == 500
    assert exc.value.detail == "billing_artifact_path_not_contained"


def test_symlinked_credits_dir_escaping_root_rejected(
    in_tmp_cwd: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    tenant = in_tmp_cwd / "artifacts" / "billing" / "t-1"
    tenant.mkdir(parents=True)
    (tenant / "credits").symlink_to(outside, target_is_directory=True)
    with pytest.raises(HTTPException) as exc:
        _billing_artifact_dir("t-1", "credits", "cn-1")
    assert exc.value.status_code == 500


def test_symlink_staying_inside_root_is_allowed(in_tmp_cwd: Path) -> None:
    root = in_tmp_cwd / "artifacts" / "billing"
    (root / "t-1" / "real").mkdir(parents=True)
    (root / "t-1" / "alias").symlink_to(root / "t-1" / "real", target_is_directory=True)
    assert _billing_artifact_dir("t-1", "alias") == Path("artifacts/billing/t-1/alias")


# ---------------------------------------------------------------- HTTP level


def _client(build_app, tenant_id: str) -> tuple[TestClient, dict[str, str]]:
    app = build_app(auth_enabled=True)
    key = mint_key("admin:read", "admin:write", tenant_id=tenant_id)
    return TestClient(app), {"x-api-key": key}


def _seed_invoice(tenant_id: str, invoice_id: str, *, finalized: bool = False) -> None:
    with Session(get_engine()) as db:
        db.add(
            BillingInvoice(
                tenant_id=tenant_id,
                invoice_id=invoice_id,
                period_start=datetime(2025, 2, 1, tzinfo=UTC),
                period_end=datetime(2025, 2, 2, tzinfo=UTC),
                pricing_version_id="pv-1",
                pricing_hash="h" * 64,
                contract_hash="c" * 64,
                config_hash="c" * 64,
                policy_hash="p" * 64,
                invoice_json={"total": 100.0},
                invoice_sha256="1" * 64,
                invoice_state="finalized" if finalized else "draft",
            )
        )
        db.commit()


def _create_credit(
    client: TestClient, headers: dict[str, str], tenant_id: str, credit_note_id: str
) -> None:
    resp = client.post(
        "/billing/invoices/inv-credit/credits",
        json={
            "tenant_id": tenant_id,
            "credit_note_id": credit_note_id,
            "amount": 5.0,
            "currency": "USD",
            "reason": "path containment test",
            "ticket_id": "FIN-1",
            "created_by": "billing-ops@example.com",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


def _invoice_evidence_path(tenant_id: str, invoice_id: str) -> str | None:
    with Session(get_engine()) as db:
        row = (
            db.query(BillingInvoice)
            .filter(
                BillingInvoice.tenant_id == tenant_id,
                BillingInvoice.invoice_id == invoice_id,
            )
            .one()
        )
        return row.evidence_path


def _credit_evidence_path(tenant_id: str, credit_note_id: str) -> str | None:
    with Session(get_engine()) as db:
        row = (
            db.query(BillingCreditNote)
            .filter(
                BillingCreditNote.tenant_id == tenant_id,
                BillingCreditNote.credit_note_id == credit_note_id,
            )
            .one()
        )
        return row.evidence_path


def test_legitimate_invoice_and_credit_exports_unchanged(
    build_app, in_tmp_cwd: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(HMAC_ENV, HMAC_VALUE)
    client, headers = _client(build_app, "t-1")
    _seed_invoice("t-1", "inv-ok")
    resp = client.post(
        "/billing/invoices/inv-ok/evidence",
        params={"tenant_id": "t-1"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["bundle_dir"] == "artifacts/billing/t-1/inv-ok"
    assert body["manifest_path"] == "artifacts/billing/t-1/inv-ok/manifest.json"
    assert (in_tmp_cwd / body["manifest_path"]).is_file()

    _seed_invoice("t-1", "inv-credit", finalized=True)
    _create_credit(client, headers, "t-1", "cn-ok")
    resp = client.post(
        "/billing/credits/cn-ok/evidence", params={"tenant_id": "t-1"}, headers=headers
    )
    assert resp.status_code == 200, resp.text
    assert (
        resp.json()["evidence_path"]
        == "artifacts/billing/t-1/credits/cn-ok/manifest.json"
    )
    assert (in_tmp_cwd / resp.json()["evidence_path"]).is_file()


@pytest.mark.parametrize("invoice_id", ["..", "credits"])
def test_persisted_traversal_or_reserved_invoice_id_rejected_over_http(
    build_app, in_tmp_cwd: Path, monkeypatch: pytest.MonkeyPatch, invoice_id: str
) -> None:
    monkeypatch.setenv(HMAC_ENV, HMAC_VALUE)
    client, headers = _client(build_app, "t-1")
    _seed_invoice("t-1", invoice_id)
    # ".." must be sent encoded, or the client collapses the dot segment.
    path_id = "%2E%2E" if invoice_id == ".." else invoice_id
    resp = client.post(
        f"/billing/invoices/{path_id}/evidence",
        params={"tenant_id": "t-1"},
        headers=headers,
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"] == "invalid_billing_artifact_identifier"
    # Fail closed: nothing written anywhere, nothing recorded.
    assert _files_under(in_tmp_cwd) == []
    assert _invoice_evidence_path("t-1", invoice_id) is None


def test_persisted_traversal_credit_note_id_rejected_over_http(
    build_app, in_tmp_cwd: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(HMAC_ENV, HMAC_VALUE)
    client, headers = _client(build_app, "t-1")
    _seed_invoice("t-1", "inv-credit", finalized=True)
    # Accepted at creation: the identifier is only unsafe once it becomes a path.
    _create_credit(client, headers, "t-1", "..")
    resp = client.post(
        "/billing/credits/%2E%2E/evidence", params={"tenant_id": "t-1"}, headers=headers
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"] == "invalid_billing_artifact_identifier"
    assert _files_under(in_tmp_cwd) == []
    assert _credit_evidence_path("t-1", "..") is None


@pytest.mark.parametrize("credit_note_id", ["../../escape", "/tmp/escape", "a\\b"])
def test_unroutable_crafted_credit_ids_cannot_be_exported(
    build_app, in_tmp_cwd: Path, monkeypatch: pytest.MonkeyPatch, credit_note_id: str
) -> None:
    # Identifiers with separators can be persisted but are not addressable as
    # a single path parameter; whatever the router does, nothing is written.
    monkeypatch.setenv(HMAC_ENV, HMAC_VALUE)
    client, headers = _client(build_app, "t-1")
    _seed_invoice("t-1", "inv-credit", finalized=True)
    _create_credit(client, headers, "t-1", credit_note_id)
    from urllib.parse import quote

    resp = client.post(
        f"/billing/credits/{quote(credit_note_id, safe='')}/evidence",
        params={"tenant_id": "t-1"},
        headers=headers,
    )
    assert resp.status_code in {400, 404, 405}, resp.text
    assert _files_under(in_tmp_cwd) == []
    assert _files_under(Path("/tmp/escape")) == []


def test_symlink_escape_fails_closed_over_http(
    build_app, in_tmp_cwd: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(HMAC_ENV, HMAC_VALUE)
    outside = tmp_path / "outside"
    outside.mkdir()
    root = in_tmp_cwd / "artifacts" / "billing"
    root.mkdir(parents=True)
    (root / "t-1").symlink_to(outside, target_is_directory=True)
    client, headers = _client(build_app, "t-1")
    _seed_invoice("t-1", "inv-ok")
    resp = client.post(
        "/billing/invoices/inv-ok/evidence",
        params={"tenant_id": "t-1"},
        headers=headers,
    )
    assert resp.status_code == 500
    assert resp.json()["detail"] == "billing_artifact_path_not_contained"
    assert _files_under(outside) == []
    assert _invoice_evidence_path("t-1", "inv-ok") is None


def test_other_tenant_cannot_export_or_write_into_tenant_root(
    build_app, in_tmp_cwd: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(HMAC_ENV, HMAC_VALUE)
    _client_a, headers_a = _client(build_app, "tenant-a")
    client_b = TestClient(_client_a.app)
    headers_b = {
        "x-api-key": mint_key("admin:read", "admin:write", tenant_id="tenant-b")
    }
    _seed_invoice("tenant-a", "inv-a")
    _seed_invoice("tenant-a", "inv-credit", finalized=True)
    _create_credit(_client_a, headers_a, "tenant-a", "cn-a")

    for path in ("/billing/invoices/inv-a/evidence", "/billing/credits/cn-a/evidence"):
        # tenant-b's key bound to its own tenant does not see tenant-a's rows.
        own = client_b.post(path, params={"tenant_id": "tenant-b"}, headers=headers_b)
        assert own.status_code == 404, own.text
        # and cannot name tenant-a explicitly.
        cross = client_b.post(path, params={"tenant_id": "tenant-a"}, headers=headers_b)
        assert cross.status_code in {400, 403, 404}, cross.text
    assert _files_under(in_tmp_cwd) == []
    _ = headers_a
