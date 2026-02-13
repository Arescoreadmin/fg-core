def test_audit_middleware_added_once():
    from admin_gateway.main import build_app

    app = build_app()
    names = [mw.cls.__name__ for mw in app.user_middleware]
    assert names.count("AuditMiddleware") == 1


def test_middleware_relative_order_core_invariants():
    from admin_gateway.main import build_app

    app = build_app()
    names = [mw.cls.__name__ for mw in app.user_middleware]

    # Audit must be after auth context exists (so it can log identity/tenant)
    assert names.index("AuditMiddleware") > names.index("AuthContextMiddleware")

    # CSRF must be enforced before auth handles request (or at least not after audit)
    assert names.index("CSRFMiddleware") < names.index("AuditMiddleware")
