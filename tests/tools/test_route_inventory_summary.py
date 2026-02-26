from __future__ import annotations

from tools.ci import check_route_inventory


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
        check_route_inventory, "_write_summary", lambda cur, expected: None
    )
    monkeypatch.setattr(check_route_inventory, "_write_registry_snapshot", lambda: None)
    monkeypatch.setattr(
        check_route_inventory, "_write_attestation_bundle", lambda cur: None
    )
    monkeypatch.setattr(check_route_inventory, "_write_topology_hash", lambda: None)
    monkeypatch.setattr(
        check_route_inventory,
        "INVENTORY",
        check_route_inventory.REPO / "tools/ci/route_inventory.json",
    )

    assert check_route_inventory.main() == 0
