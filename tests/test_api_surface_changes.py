def test_api_surface_smoke_imports():
    """
    Ensures modified API modules import correctly after tenant/auth changes.
    Acts as coverage signal for unit gate mapping.
    """
    import api.admin
    import api.control_plane_v2
    import api.decisions
    import api.dev_events
    import api.ingest
    import api.keys
    import api.schemas
    import api.stats
    import api.ui_dashboards

    assert True