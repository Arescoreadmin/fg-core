"""Stateful fake authorization store for L14-SCAN-AUTH-HARDENING-001 tests.

Emulates — with real compare-and-swap semantics — exactly the raw SQL issued by
scan_authorization.py, customer_authorization.py, scan_execution_guard.py and the
guarded worker path in api/field_assessment.py.  Every session opened from the
store reads CURRENT shared state (like separate DB connections), so tests can
mutate authorization state "between" worker boundaries.

No network, no Postgres, synthetic data only.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from services.field_assessment import customer_authorization as ca

T1 = "tenant-alpha"
T2 = "tenant-bravo"
E1 = "eng-alpha-1"
E2 = "eng-alpha-2"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class _Row(tuple):
    """Tuple row that also exposes ``_mapping`` (like SQLAlchemy Row)."""

    def __new__(cls, mapping: dict[str, Any], order: list[str]):
        obj = super().__new__(cls, [mapping[k] for k in order])
        obj._mapping = dict(mapping)
        return obj


class _Result:
    def __init__(self, rows: list[Any] | None = None, rowcount: int = 0) -> None:
        self._rows = rows or []
        self.rowcount = rowcount

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)


_RECEIPT_ORDER = [c.strip() for c in ca._RECEIPT_COLUMNS.split(",")]


@dataclass
class Store:
    receipts: dict[str, dict] = field(default_factory=dict)
    scopes: dict[str, dict] = field(default_factory=dict)
    estops: list[dict] = field(default_factory=list)
    jobs: dict[str, dict] = field(default_factory=dict)
    audit: list[Any] = field(default_factory=list)
    engagements: dict[str, str] = field(
        default_factory=lambda: {E1: T1, E2: T1, "eng-bravo-1": T2}
    )
    unavailable: bool = False
    executed: list[str] = field(default_factory=list)
    # hook(sql, params) called before every statement — lets a test mutate
    # state at a precise boundary.
    hook: Any = None

    def session(self) -> "FakeSession":
        if self.unavailable:
            raise ConnectionError("authorization store unavailable")
        return FakeSession(self)

    # -- fixtures --------------------------------------------------------
    def add_scope(
        self,
        *,
        tenant_id: str = T1,
        engagement_id: str = E1,
        targets: list[dict] | None = None,
        receipt_id: str | None = None,
        expires_in: timedelta = timedelta(days=7),
        status: str = "active",
    ) -> str:
        sid = str(uuid.uuid4())
        self.scopes[sid] = {
            "id": sid,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "approved_targets": targets
            if targets is not None
            else [
                {
                    "target": "app.example.com",
                    "type": "fqdn",
                    "operations": ["web_headers", "network_scan", "dns_email"],
                }
            ],
            "status": status,
            "effective_from": utcnow() - timedelta(hours=1),
            "expires_at": utcnow() + expires_in,
            "revoked_at": None,
            "customer_receipt_id": receipt_id,
            "version": 2,
        }
        return sid

    def add_job(
        self,
        *,
        tenant_id: str = T1,
        engagement_id: str = E1,
        status: str = "queued",
        scanner_type: str = "web_headers",
    ) -> str:
        jid = str(uuid.uuid4())
        self.jobs[jid] = {
            "id": jid,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "status": status,
            "scanner_type": scanner_type,
            "collection_status": None,
            "scan_result_id": None,
            "cancellation_reason": None,
            "cancelled_by": None,
        }
        return jid

    def stop(self, scope: str) -> None:
        self.estops.append({"scope": scope, "is_active": True})

    def revoke_scope(self, sid: str) -> None:
        self.scopes[sid]["status"] = "revoked"
        self.scopes[sid]["revoked_at"] = utcnow()

    def events(self, prefix: str = "") -> list[str]:
        return [e.event_type for e in self.audit if e.event_type.startswith(prefix)]


class FakeSession:
    bind = None  # set_tenant_context() is a no-op for non-postgres binds

    def __init__(self, store: Store) -> None:
        self.s = store
        self.closed = False

    # SQLAlchemy Session surface used by the code under test -------------
    def add(self, obj: Any) -> None:
        self.s.audit.append(obj)

    def commit(self) -> None:  # state is applied immediately
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def execute(self, stmt: Any, params: dict | None = None) -> _Result:
        sql = " ".join(str(stmt).split())
        p = dict(params or {})
        self.s.executed.append(sql)
        if self.s.hook is not None:
            self.s.hook(sql, p)
        if self.s.unavailable:
            raise ConnectionError("authorization store unavailable")
        return self._dispatch(sql, p)

    # ---------------------------------------------------------------------
    def _dispatch(self, sql: str, p: dict) -> _Result:
        s = self.s
        if sql.startswith("SELECT 1 FROM fa_scan_emergency_stops"):
            scopes = {p["s_platform"], p["s_tenant"], p["s_engagement"]}
            hit = any(e["is_active"] and e["scope"] in scopes for e in s.estops)
            return _Result([(1,)] if hit else [])

        if sql.startswith("SELECT id, tenant_id, engagement_id, approved_targets"):
            rows = [
                r
                for r in s.scopes.values()
                if r["tenant_id"] == p["tenant_id"]
                and r["engagement_id"] == p["engagement_id"]
                and r["status"] == "active"
            ]
            rows.sort(key=lambda r: r["effective_from"], reverse=True)
            if not rows:
                return _Result([])
            r = rows[0]
            return _Result(
                [
                    (
                        r["id"],
                        r["tenant_id"],
                        r["engagement_id"],
                        r["approved_targets"],
                        r["status"],
                        r["effective_from"],
                        r["expires_at"],
                        r["revoked_at"],
                        r["customer_receipt_id"],
                        r["version"],
                    )
                ]
            )

        if (
            "FROM fa_customer_authorization_receipts WHERE id = CAST(:rid AS uuid)"
            in sql
        ):
            r = s.receipts.get(p["rid"])
            if r and r["tenant_id"] == p["tid"] and r["engagement_id"] == p["eid"]:
                return _Result([_Row(r, _RECEIPT_ORDER)])
            return _Result([])

        if sql.startswith("SELECT COALESCE(MAX(receipt_version)"):
            vs = [
                r["receipt_version"]
                for r in s.receipts.values()
                if r["receipt_group_id"] == p["gid"] and r["tenant_id"] == p["tid"]
            ]
            return _Result([(max(vs) if vs else 0,)])

        if sql.startswith("INSERT INTO fa_customer_authorization_receipts"):
            rid = str(uuid.uuid4())
            row = {k: None for k in _RECEIPT_ORDER}
            row.update(
                id=rid,
                receipt_group_id=p["gid"],
                receipt_version=p["ver"],
                schema_version=p["schema"],
                tenant_id=p["tid"],
                engagement_id=p["eid"],
                customer_org_name=p["org"],
                assessment_purpose=p["purpose"],
                rules_of_engagement_ref=p["roe"],
                consent_statement_version=p["csv"],
                target_normalization_version=p["tnv"],
                approved_targets=json.loads(p["targets"]),
                authorized_operations=json.loads(p["ops"]),
                window_start=p["wstart"],
                window_end=p["wend"],
                status="pending_approval",
                requested_by_subject=p["req"],
                requested_at=p["now"],
                created_at=p["now"],
            )
            s.receipts[rid] = row
            return _Result([_Row(row, _RECEIPT_ORDER)], 1)

        if sql.startswith(
            "UPDATE fa_customer_authorization_receipts SET status = 'approved'"
        ):
            r = s.receipts.get(p["rid"])
            if not (
                r
                and r["tenant_id"] == p["tid"]
                and r["engagement_id"] == p["eid"]
                and r["status"] == "pending_approval"
            ):
                return _Result([])
            r.update(
                status="approved",
                approver_subject=p["subj"],
                approver_email=p["email"],
                approver_auth_source=p["src"],
                approver_authority_basis=p["basis"],
                approver_membership_id=p["mid"],
                approver_also_assessor=p["also"],
                approved_at=p["now"],
                payload_digest=p["digest"],
                digest_algorithm=p["dalg"],
                attestation_kid=p["kid"],
                attestation_alg=p["alg"],
                attestation_value=p["val"],
                proof_level=p["proof"],
            )
            return _Result([_Row(r, _RECEIPT_ORDER)], 1)

        if sql.startswith(
            "UPDATE fa_customer_authorization_receipts SET status = 'rejected'"
        ):
            r = s.receipts.get(p["rid"])
            if not (
                r and r["tenant_id"] == p["tid"] and r["status"] == "pending_approval"
            ):
                return _Result([])
            r.update(
                status="rejected", rejected_at=p["now"], rejected_by_subject=p["subj"]
            )
            return _Result([_Row(r, _RECEIPT_ORDER)], 1)

        if sql.startswith(
            "UPDATE fa_customer_authorization_receipts SET status = 'revoked'"
        ):
            r = s.receipts.get(p["rid"])
            if not (
                r
                and r["tenant_id"] == p["tid"]
                and r["engagement_id"] == p["eid"]
                and r["status"] in ("approved", "pending_approval")
            ):
                return _Result([])
            r.update(
                status="revoked",
                revoked_at=p["now"],
                revoked_by_subject=p["subj"],
                revocation_reason=p["reason"],
            )
            return _Result([_Row(r, _RECEIPT_ORDER)], 1)

        # ---- jobs ---------------------------------------------------------
        if sql.startswith("SELECT status, tenant_id, engagement_id FROM fa_scan_jobs"):
            j = s.jobs.get(p["id"])
            return _Result(
                [(j["status"], j["tenant_id"], j["engagement_id"])] if j else []
            )

        if sql.startswith("SELECT status FROM fa_scan_jobs WHERE id = :id"):
            j = s.jobs.get(p["id"])
            return _Result([(j["status"],)] if j else [])

        if sql.startswith("UPDATE fa_scan_jobs SET status = 'cancel_requested'"):
            j = s.jobs.get(p["job_id"])
            if (
                j
                and j["tenant_id"] == p["tenant_id"]
                and j["engagement_id"] == p["engagement_id"]
                and j["status"] in ("queued", "running")
            ):
                j.update(
                    status="cancel_requested",
                    cancellation_reason=p["reason"],
                    cancelled_by=p["actor"],
                )
                return _Result([(j["id"], j["status"], p["now"])], 1)
            return _Result([])

        if sql.startswith("SELECT id, status FROM fa_scan_jobs"):
            j = s.jobs.get(p["job_id"])
            if j and j["tenant_id"] == p["tenant_id"]:
                return _Result([(j["id"], j["status"])])
            return _Result([])

        if sql.startswith("UPDATE fa_scan_jobs SET status = 'cancelled'"):
            j = s.jobs.get(p["job_id"])
            if (
                j
                and j["tenant_id"] == p["tenant_id"]
                and j["status"] == "cancel_requested"
            ):
                j["status"] = "cancelled"
                return _Result([(j["id"], "cancelled", p["now"])], 1)
            return _Result([])

        if sql.startswith(
            "SELECT status FROM fa_scan_jobs WHERE id = :job_id AND tenant_id"
        ):
            j = s.jobs.get(p["job_id"])
            if j and j["tenant_id"] == p["tenant_id"]:
                return _Result([(j["status"],)])
            return _Result([])

        if sql.startswith("UPDATE fa_scan_jobs SET collection_status"):
            j = s.jobs.get(p["id"])
            if j and j["tenant_id"] == p["tid"]:
                j["collection_status"] = p["cs"]
                return _Result([], 1)
            return _Result([])

        if sql.startswith("SELECT id FROM fa_engagements"):
            ok = s.engagements.get(p["eid"]) == p["tid"]
            return _Result([(p["eid"],)] if ok else [])

        raise AssertionError(f"harness: unhandled SQL: {sql[:160]}")


class FakeDurableJobs:
    """CAS-equivalent stand-in for DurableJobService over the shared Store.

    The real DurableJobService CAS is tested against SQLite in
    test_job_state_cas.py; this mirrors those exact predicates.
    """

    def __init__(self, store: Store) -> None:
        self.s = store

    def mark_running(self, db: Any, *, job_id: str) -> bool:
        j = self.s.jobs.get(job_id)
        if j and j["status"] == "queued":
            j["status"] = "running"
            return True
        return False

    def mark_complete(
        self, db: Any, *, job_id: str, scan_result_id: str | None = None
    ) -> bool:
        j = self.s.jobs.get(job_id)
        if j and j["status"] == "running":
            j.update(status="complete", scan_result_id=scan_result_id)
            return True
        return False

    def mark_failed(self, db: Any, *, job_id: str, failure_reason: str) -> bool:
        j = self.s.jobs.get(job_id)
        if j and j["status"] in ("queued", "running"):
            j["status"] = "failed"
            return True
        return False


# ---------------------------------------------------------------------------
# Actor + receipt helpers
# ---------------------------------------------------------------------------


@dataclass
class Actor:
    subject: str = "auth0|customer-ciso"
    email: str = "ciso@alpha.example"
    name: str = "Customer CISO"
    permissions: frozenset = frozenset({"scan.consent.approve", "scan.read"})
    roles: list = field(default_factory=lambda: ["client_security_owner"])
    auth_source: str = "oidc_auth0"
    tenant_id: str | None = T1
    email_verified: bool = True
    membership_id: str | None = "mem-1"
    service_principal_id: str | None = None


ASSESSOR = "auth0|assessor-1"

DEFAULT_RECEIPT_TARGETS = [
    {
        "target": "app.example.com",
        "type": "fqdn",
        "operations": ["network_scan", "web_headers", "dns_email"],
    },
    {"target": "203.0.113.0/28", "type": "cidr", "operations": ["network_scan"]},
]


def request_receipt(
    store: Store,
    *,
    tenant_id: str = T1,
    engagement_id: str = E1,
    targets: list | None = None,
    ops: list | None = None,
    window: timedelta = timedelta(days=7),
    start_offset: timedelta = timedelta(hours=-1),
) -> dict:
    return ca.create_request(
        store.session(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        requested_by_subject=ASSESSOR,
        customer_org_name="Alpha Corp",
        assessment_purpose="External attack surface assessment",
        rules_of_engagement_ref="ROE-2026-001",
        approved_targets=targets if targets is not None else DEFAULT_RECEIPT_TARGETS,
        authorized_operations=ops or ["network_scan", "web_headers", "dns_email"],
        window_start=utcnow() + start_offset,
        window_end=utcnow() + start_offset + window,
    )


def approved_receipt(store: Store, **kw: Any) -> dict:
    r = request_receipt(store, **kw)
    return ca.approve(
        store.session(),
        receipt_id=str(r["id"]),
        tenant_id=r["tenant_id"],
        engagement_id=r["engagement_id"],
        actor_ctx=Actor(tenant_id=r["tenant_id"]),
    )


KEYRING = {"kid-2026-a": "11" * 32, "kid-2026-b": "22" * 32}


def set_keyring(
    monkeypatch: Any, *, active: str | None = "kid-2026-a", revoked: str = ""
) -> None:
    monkeypatch.setenv("FG_SCAN_CONSENT_ATTESTATION_KEYS", json.dumps(KEYRING))
    if active:
        monkeypatch.setenv("FG_SCAN_CONSENT_ATTESTATION_ACTIVE_KID", active)
    else:
        monkeypatch.delenv("FG_SCAN_CONSENT_ATTESTATION_ACTIVE_KID", raising=False)
    monkeypatch.setenv("FG_SCAN_CONSENT_ATTESTATION_REVOKED_KIDS", revoked)
