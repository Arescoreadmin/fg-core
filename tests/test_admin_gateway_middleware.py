from __future__ import annotations


def _mw_names(app) -> list[str]:
    return [mw.cls.__name__ for mw in app.user_middleware]


# Exact order we saw from:
# print([mw.cls.__name__ for mw in app.user_middleware])
_EXPECTED = [
    "CORSMiddleware",
    "RequestIdMiddleware",
    "StructuredLoggingMiddleware",
    "SessionCookieMiddleware",
    "SessionMiddleware",
    "CSRFMiddleware",
    "AuthMiddleware",
    "AuthContextMiddleware",
    "AuditMiddleware",
]

# Middleware that may legitimately be present/absent depending on env/config.
# Keep this tight. Add entries only when you *prove* they are optional.
_OPTIONAL = {
    "CORSMiddleware",
}


def test_middleware_order_is_locked_allowing_known_optionals():
    """
    Hardening: lock the chain to prevent slow drift.
    Resilient to *known* optional middleware (ex: CORS toggled by env).
    """
    from admin_gateway.main import build_app

    app = build_app()
    names = _mw_names(app)

    expected_core = [n for n in _EXPECTED if n not in _OPTIONAL]
    names_core = [n for n in names if n not in _OPTIONAL]

    assert names_core == expected_core, (
        f"Middleware core order drifted.\nexpected_core={expected_core}\n got_core={names_core}\nfull={names}"
    )

    # If optional middleware appears, it must appear only where expected.
    for opt in _OPTIONAL:
        if opt in names:
            assert opt in _EXPECTED, (
                f"Optional middleware {opt} present in app but not in expected list."
            )
            assert names.index(opt) == _EXPECTED.index(opt), (
                f"Optional middleware {opt} moved.\nexpected_index={_EXPECTED.index(opt)} got_index={names.index(opt)}\nfull={names}"
            )


def test_audit_middleware_added_once():
    from admin_gateway.main import build_app

    app = build_app()
    names = _mw_names(app)
    assert names.count("AuditMiddleware") == 1, (
        f"AuditMiddleware count={names.count('AuditMiddleware')} names={names}"
    )


def test_audit_runs_after_auth_context_is_present():
    """
    We don't try to “prove” outer/inner wrapping semantics here.
    We lock the *intent*: audit must be able to see auth context.
    """
    from admin_gateway.main import build_app

    app = build_app()
    names = _mw_names(app)

    assert "AuthContextMiddleware" in names, f"names={names}"
    assert "AuditMiddleware" in names, f"names={names}"
    assert names.index("AuditMiddleware") > names.index("AuthContextMiddleware"), (
        f"names={names}"
    )


def test_only_one_audit_middleware_even_if_someone_reorders():
    """
    Extra belt-and-suspenders: if someone adds audit twice “by accident”.
    """
    from admin_gateway.main import build_app

    app = build_app()
    names = _mw_names(app)
    assert names.count("AuditMiddleware") == 1, f"names={names}"


def test_contract_routes_are_not_in_admin_gateway_runtime_routes_unless_intended():
    """
    Optional sanity: keeps people from accidentally exposing internal-only routes.

    IMPORTANT:
    - Uses runtime routes, NOT app.openapi(), to avoid Pydantic v2 deprecation warnings
      that can be treated as errors in strict test configs.
    - If you intentionally publish any of these routes in admin gateway, delete or adjust
      this list.
    """
    from admin_gateway.main import build_app

    app = build_app()

    # Runtime route surface (FastAPI routes + docs endpoints, etc.)
    paths = {getattr(r, "path", None) for r in app.router.routes}
    paths.discard(None)

    # Admin gateway should NOT expose core/public control-plane endpoints.
    # Tune this set to match your intended surface.
    forbidden = {
        "/defend",
        "/ingest",
        "/v1/defend",
        "/approvals",
        "/approvals/verify",
        "/evidence/bundles",
        "/evidence/verify",
        "/forensics/chain/verify",
        "/keys",
        "/keys/rotate",
        "/keys/revoke",
        "/modules",
        "/modules/register",
    }

    leaked = sorted(p for p in paths if p in forbidden)
    assert not leaked, f"Forbidden routes exposed by admin_gateway: {leaked}"
