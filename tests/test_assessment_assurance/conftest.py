"""L14-ASSESSMENT-ASSURANCE-001 fixtures.

Reuses the PR #815 Northstar synthetic customer (``tests.test_customer_zero_e2e``)
— same isolated per-test SQLite app, same personas, same production bridges.
Named human reviewers are simulated through ``tests._assurance_actors`` (the
OIDC resolution result only; every authority check runs for real).
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests._assurance_actors import reviewer
from tests.test_customer_zero_e2e import _northstar as N
from tests.test_customer_zero_e2e.conftest import Platform
from tests.test_customer_zero_e2e.test_customer_zero_journey import (
    _engagement,
    provision,
)

pytest.importorskip("reportlab")

QA_SUBJECT = "auth0|northstar-independent-qa"
QA2_SUBJECT = "auth0|northstar-second-qa"


@pytest.fixture()
def platform(build_app, monkeypatch, tmp_path):
    import tools.tenants.registry as registry

    monkeypatch.setattr(registry, "REGISTRY_PATH", tmp_path / "tenants.json")
    monkeypatch.setenv("FG_ADMIN_ENABLED", "1")
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", N.SIGNING_KEY_HEX)
    app = build_app(auth_enabled=True)
    p = Platform(app, os.environ["FG_API_KEY"])
    provision(p, None)
    return p


def gateway(
    platform: Platform, tenant_id: str = N.TENANT, **headers: str
) -> TestClient:
    """Tenant-bound transport credential (as the delegating BFF/console holds).

    Its own permissions are irrelevant when a named human is resolved; it is
    a legacy API key and therefore can never itself make a QA decision.
    """
    from api.auth_scopes import mint_key

    key = mint_key(
        "governance:read",
        "governance:write",
        "governance:qa_approve",
        tenant_id=tenant_id,
    )
    return TestClient(platform.app, headers={"X-API-Key": key, **headers})


def human(
    platform: Platform,
    subject: str = QA_SUBJECT,
    role: str = "qa_reviewer",
    tenant_id: str = N.TENANT,
) -> TestClient:
    return gateway(platform, tenant_id, **reviewer(subject, role))


def generate(platform: Platform, eid: str, client: TestClient | None = None) -> dict:
    c = client or platform.client("assessor")
    r = c.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture()
def northstar(platform):
    """Synthetic engagement with the full PR #815 collection (incl. tampered host)."""
    eid = _engagement(platform)
    N.seed_collection(eid)
    return {"eid": eid, "report": generate(platform, eid)}


@pytest.fixture()
def northstar_clean(platform):
    """Same collection without the out-of-band tamper."""
    eid = _engagement(platform)
    N.seed_collection(eid, tamper=False)
    return {"eid": eid, "report": generate(platform, eid)}


def qa_approve(c: TestClient, eid: str, rid: str) -> Any:
    return c.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qa-approve",
        json={"reviewer_name": "display only"},
    )


def qa_reject(c: TestClient, eid: str, rid: str, **body: Any) -> Any:
    payload = {
        "reason_code": "FINDING_INACCURATE",
        "explanation": "Finding NSM-3 overstates exposure; evidence shows port closed.",
        **body,
    }
    return c.post(
        f"/field-assessment/engagements/{eid}/reports/{rid}/qa-reject", json=payload
    )


def export(c: TestClient, eid: str, version: int, fmt: str = "json") -> Any:
    return c.get(
        f"/field-assessment/engagements/{eid}/reports/{version}/export",
        params={"format": fmt},
    )


def code(resp: Any) -> str:
    try:
        d = resp.json().get("detail")
    except Exception:
        return ""
    return (d or {}).get("code", "") if isinstance(d, dict) else str(d)
