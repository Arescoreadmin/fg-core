from __future__ import annotations

import warnings


from api.main import build_app
from pydantic.warnings import PydanticDeprecatedSince20


def test_framework_authority_and_enterprise_controls_routes_coexist() -> None:
    app = build_app(auth_enabled=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", PydanticDeprecatedSince20)
        paths = app.openapi()["paths"]
    assert "/enterprise-controls/frameworks" in paths
    assert "/frameworks" in paths
    assert "/controls/{control_id}/framework-mappings" in paths
