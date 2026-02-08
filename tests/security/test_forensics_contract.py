from __future__ import annotations

import pytest


@pytest.fixture
def app(build_app):
    return build_app()


def test_forensics_chain_verify_does_not_accept_tenant_id_param(app):
    target = None
    for r in app.router.routes:
        if getattr(r, "path", None) == "/forensics/chain/verify":
            target = r
            break

    assert target is not None, "Missing /forensics/chain/verify route"

    endpoint = getattr(target, "endpoint", None)
    assert endpoint is not None, "Route missing endpoint"

    names = endpoint.__code__.co_varnames[: endpoint.__code__.co_argcount]
    assert "tenant_id" not in names, (
        "Regression: tenant_id param reintroduced on /forensics/chain/verify"
    )
