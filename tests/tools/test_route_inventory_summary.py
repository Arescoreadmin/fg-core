from __future__ import annotations

import pytest

from tools.ci import check_route_inventory


# ---------------------------------------------------------------------------
# _classify_runtime_only unit tests
# ---------------------------------------------------------------------------


def test_classify_runtime_only_all_allowed():
    # Only the 5 explicit allowed_internal prefixes; /ai/ and /ai-plane/ are
    # NOT allowed (routes in those prefixes belong in the public contract).
    routes = [
        "GET /admin/keys",
        "GET /ui/dash",
        "POST /dev/seed",
        "GET /control/testing/health",
        "GET /_debug/routes",
    ]
    allowed, unauthorized = check_route_inventory._classify_runtime_only(routes)
    assert unauthorized == [], f"expected no unauthorized routes, got: {unauthorized}"
    assert set(allowed) == set(routes)


def test_classify_runtime_only_ai_routes_are_unauthorized():
    # /ai/ and /ai-plane/ are no longer allowed_internal;
    # those routes belong in the contract (contracts_gen_core.py FG_AI_PLANE_ENABLED=1).
    routes = ["POST /ai/infer", "GET /ai-plane/policies", "GET /ai-plane/inference"]
    allowed, unauthorized = check_route_inventory._classify_runtime_only(routes)
    assert allowed == [], f"expected no allowed routes for /ai* paths, got: {allowed}"
    assert set(unauthorized) == set(routes)


def test_classify_runtime_only_unauthorized():
    routes = ["GET /secret/endpoint", "POST /unknown/route"]
    allowed, unauthorized = check_route_inventory._classify_runtime_only(routes)
    assert allowed == []
    assert set(unauthorized) == set(routes)


def test_classify_runtime_only_mixed():
    routes = ["GET /admin/keys", "GET /unknown/route"]
    allowed, unauthorized = check_route_inventory._classify_runtime_only(routes)
    assert "GET /admin/keys" in allowed
    assert "GET /unknown/route" in unauthorized
    assert len(allowed) == 1
    assert len(unauthorized) == 1


def test_classify_runtime_only_prefix_exact_match():
    # path exactly equals prefix.rstrip("/")
    routes = ["GET /admin"]
    allowed, unauthorized = check_route_inventory._classify_runtime_only(routes)
    assert allowed == ["GET /admin"]
    assert unauthorized == []


def test_classify_runtime_only_empty():
    allowed, unauthorized = check_route_inventory._classify_runtime_only([])
    assert allowed == []
    assert unauthorized == []


# ---------------------------------------------------------------------------
# main() hard-fail on unauthorized runtime_only
# ---------------------------------------------------------------------------


def _make_summary_monkeypatch(runtime_only: list[str]):
    """Return a _summary_payload stub that sets the given runtime_only list."""
    return lambda cur, expected: {
        "runtime_only": runtime_only,
        "contract_only": [],
    }


def test_main_hard_fails_on_unauthorized_runtime_only(monkeypatch):
    monkeypatch.setattr("sys.argv", ["check_route_inventory.py"])
    monkeypatch.setattr(check_route_inventory, "current_inventory", lambda: [])
    monkeypatch.setattr(
        check_route_inventory,
        "_read_data",
        # Use exact label match: "route_inventory_summary" != "route_inventory"
        lambda path, label: (
            {"routes": []}
            if label == "route_inventory"
            else {"runtime_only": ["GET /unauthorized/route"], "contract_only": []}
        ),
    )
    monkeypatch.setattr(check_route_inventory, "_inventory_from_data", lambda data: [])
    monkeypatch.setattr(
        check_route_inventory, "_route_diff", lambda expected, cur: ([], [], [])
    )
    monkeypatch.setattr(
        check_route_inventory,
        "_summary_payload",
        _make_summary_monkeypatch(["GET /unauthorized/route"]),
    )
    monkeypatch.setattr(
        check_route_inventory,
        "INVENTORY",
        check_route_inventory.REPO / "tools/ci/route_inventory.json",
    )
    assert check_route_inventory.main() == 1


def test_main_passes_on_allowed_internal_only(monkeypatch):
    monkeypatch.setattr("sys.argv", ["check_route_inventory.py"])
    monkeypatch.setattr(check_route_inventory, "current_inventory", lambda: [])
    monkeypatch.setattr(
        check_route_inventory,
        "_read_data",
        lambda path, label: (
            {"routes": []}
            if label == "route_inventory"
            else {
                "runtime_only": ["GET /admin/keys", "GET /ui/dash"],
                "contract_only": [],
            }
        ),
    )
    monkeypatch.setattr(check_route_inventory, "_inventory_from_data", lambda data: [])
    monkeypatch.setattr(
        check_route_inventory, "_route_diff", lambda expected, cur: ([], [], [])
    )
    monkeypatch.setattr(
        check_route_inventory,
        "_summary_payload",
        _make_summary_monkeypatch(["GET /admin/keys", "GET /ui/dash"]),
    )
    monkeypatch.setattr(
        check_route_inventory,
        "INVENTORY",
        check_route_inventory.REPO / "tools/ci/route_inventory.json",
    )
    assert check_route_inventory.main() == 0


# ---------------------------------------------------------------------------
# Original shape test (unchanged)
# ---------------------------------------------------------------------------


def test_route_inventory_summary_object_shape(monkeypatch):
    monkeypatch.setattr("sys.argv", ["check_route_inventory.py"])
    monkeypatch.setattr(check_route_inventory, "current_inventory", lambda: [])
    monkeypatch.setattr(
        check_route_inventory,
        "_read_data",
        lambda path, label: (
            {"routes": []}
            if "route_inventory" in label
            else {"runtime_only": [], "contract_only": []}
        ),
    )
    monkeypatch.setattr(check_route_inventory, "_inventory_from_data", lambda data: [])
    monkeypatch.setattr(
        check_route_inventory, "_route_diff", lambda expected, cur: ([], [], [])
    )
    monkeypatch.setattr(
        check_route_inventory,
        "_summary_payload",
        lambda cur, expected: {"runtime_only": [], "contract_only": []},
    )
    monkeypatch.setattr(
        check_route_inventory,
        "INVENTORY",
        check_route_inventory.REPO / "tools/ci/route_inventory.json",
    )

    assert check_route_inventory.main() == 0


def test_unwrap_v1_with_wrapper() -> None:
    wrapped = {"schema_version": "1", "generated_at": "2026-01-01", "data": [1, 2, 3]}
    assert check_route_inventory._unwrap_v1(wrapped) == [1, 2, 3]


def test_unwrap_v1_without_wrapper() -> None:
    plain: list[object] = [{"method": "GET", "path": "/foo"}]
    assert check_route_inventory._unwrap_v1(plain) is plain
