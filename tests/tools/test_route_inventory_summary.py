from __future__ import annotations

from tools.ci import check_route_inventory


# ---------------------------------------------------------------------------
# _classify_runtime_only unit tests  (returns public_exempt, internal_allowed, invalid_drift)
# ---------------------------------------------------------------------------


def test_classify_runtime_only_all_allowed():
    # Only the explicit allowed_internal prefixes; /ai/ and /ai-plane/ are
    # NOT allowed (those routes belong in the public contract).
    routes = [
        "GET /admin/keys",
        "GET /ui/dash",
        "POST /dev/seed",
        "GET /control/testing/health",
        "GET /_debug/routes",
    ]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert invalid_drift == [], f"expected no invalid_drift routes, got: {invalid_drift}"
    assert set(public_exempt + internal_allowed) == set(routes)


def test_classify_runtime_only_ai_routes_are_invalid_drift():
    # /ai/ and /ai-plane/ are no longer allowed_internal;
    # those routes belong in the contract (contracts_gen_core.py FG_AI_PLANE_ENABLED=1).
    routes = ["POST /ai/infer", "GET /ai-plane/policies", "GET /ai-plane/inference"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert public_exempt == [], f"expected no public_exempt for /ai* paths, got: {public_exempt}"
    assert internal_allowed == [], f"expected no internal_allowed for /ai* paths, got: {internal_allowed}"
    assert set(invalid_drift) == set(routes)


def test_classify_runtime_only_unauthorized():
    routes = ["GET /secret/endpoint", "POST /unknown/route"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert public_exempt == []
    assert internal_allowed == []
    assert set(invalid_drift) == set(routes)


def test_classify_runtime_only_mixed():
    routes = ["GET /admin/keys", "GET /unknown/route"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert "GET /admin/keys" in internal_allowed
    assert "GET /unknown/route" in invalid_drift
    assert len(internal_allowed) == 1
    assert len(invalid_drift) == 1


def test_classify_runtime_only_prefix_exact_match():
    # path exactly equals prefix.rstrip("/")
    routes = ["GET /admin"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert "GET /admin" in internal_allowed
    assert invalid_drift == []


def test_classify_runtime_only_empty():
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only([])
    assert public_exempt == []
    assert internal_allowed == []
    assert invalid_drift == []


def test_classify_runtime_only_health_routes_are_public_exempt():
    # GET /health and HEAD /health are explicit ALLOWED_RUNTIME_ONLY_ROUTES.
    # They are public (in PUBLIC_PATHS_EXACT) and not in contract — public_exempt.
    routes = ["GET /health", "HEAD /health"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert set(public_exempt) == {"GET /health", "HEAD /health"}
    assert internal_allowed == []
    assert invalid_drift == []


def test_classify_runtime_only_health_sub_paths_are_invalid_drift():
    # Exact-route matching must NOT cover sub-paths.
    routes = ["GET /health/debug", "HEAD /health/debug"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert public_exempt == []
    assert internal_allowed == []
    assert set(invalid_drift) == {"GET /health/debug", "HEAD /health/debug"}


def test_classify_runtime_only_metrics_are_public_exempt():
    # /metrics is in ALLOWED_INTERNAL_PREFIXES (not in OpenAPI contract) but also
    # in PUBLIC_PATHS_EXACT (Prometheus scraping needs no API key) → public_exempt.
    routes = ["GET /metrics"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert "GET /metrics" in public_exempt
    assert internal_allowed == []
    assert invalid_drift == []


def test_classify_runtime_only_ui_routes_are_public_exempt():
    # /ui/ is in ALLOWED_INTERNAL_PREFIXES (not in OpenAPI contract) but /ui is in
    # PUBLIC_PATHS_PREFIX (UI layer uses session auth, not API keys) → public_exempt.
    routes = ["GET /ui/dashboard", "POST /ui/data"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert set(public_exempt) == set(routes)
    assert internal_allowed == []
    assert invalid_drift == []


def test_classify_runtime_only_admin_routes_are_internal_allowed():
    # /admin/* is not in any public allowlist → internal_allowed (auth-required).
    routes = ["GET /admin/keys", "POST /admin/users"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert public_exempt == []
    assert set(internal_allowed) == set(routes)
    assert invalid_drift == []


def test_classify_runtime_only_debug_route_is_internal_allowed():
    # /_debug/routes is not in any public allowlist (P0-1 fix removed it from
    # PUBLIC_PATHS_PREFIX) → internal_allowed.
    routes = ["GET /_debug/routes"]
    public_exempt, internal_allowed, invalid_drift = check_route_inventory._classify_runtime_only(routes)
    assert public_exempt == []
    assert internal_allowed == ["GET /_debug/routes"]
    assert invalid_drift == []


def test_internal_allowed_overlap_guard_is_empty():
    # The overlap guard (internal_allowed routes that are also publicly reachable)
    # should always be empty by construction — validate explicitly.
    routes = ["GET /admin/keys", "GET /_debug/routes", "POST /dev/seed"]
    _, internal_allowed, _ = check_route_inventory._classify_runtime_only(routes)
    overlap = [
        r for r in internal_allowed
        if check_route_inventory._is_public_reachable(r.split(" ", 1)[1] if " " in r else r)
    ]
    assert overlap == [], f"internal_allowed routes must not be publicly reachable: {overlap}"


# ---------------------------------------------------------------------------
# main() hard-fail on invalid_drift (unauthorized) runtime_only
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
