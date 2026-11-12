"""DEP-REMEDIATE-004 — final remediation inventory, reconciliation and guard."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "ci"))

import dep_remediation_final_inventory as inv  # noqa: E402

ROOT_ALERTS = [
    171,
    173,
    174,
    175,
    176,
    179,
    180,
    181,
    182,
    185,
    186,
    187,
    188,
    189,
    190,
    191,
]
MANIFESTS = [
    "package-lock.json",
    "agent/requirements.txt",
    "apps/console/package-lock.json",
    "apps/portal/package-lock.json",
]
# Fields that legitimately move when manifests change after this PR.
VOLATILE = {"versions_now", "vulnerable_now", "root_lock_sha256_now"}


def _strip(obj):
    if isinstance(obj, dict):
        return {k: _strip(v) for k, v in obj.items() if k not in VOLATILE}
    if isinstance(obj, list):
        return [_strip(v) for v in obj]
    return obj


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    for rel in [inv.SNAPSHOT, *MANIFESTS]:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, dst)
    return tmp_path


def _edit_lock(repo: Path, package: str, version: str | None) -> None:
    path = repo / "package-lock.json"
    lock = json.loads(path.read_text())
    key = f"node_modules/{package}"
    if version is None:
        del lock["packages"][key]
    else:
        lock["packages"][key]["version"] = version
    path.write_text(json.dumps(lock))


def _edit_snapshot(repo: Path, fn) -> None:
    path = repo / inv.SNAPSHOT
    path.write_text(json.dumps(fn(json.loads(path.read_text()))))


def test_live_repository_passes_guard():
    assert inv.main(["--repo", str(REPO)]) == 0


def test_generation_is_deterministic():
    a = inv.build(REPO, REPO / inv.SNAPSHOT)
    b = inv.build(REPO, REPO / inv.SNAPSHOT)
    assert [inv.render(x) for x in a[:2]] == [inv.render(x) for x in b[:2]]
    assert a[2] == []


def test_committed_artefacts_match_regeneration():
    inventory, recon, _ = inv.build(REPO, REPO / inv.SNAPSHOT)
    committed_inv = json.loads((REPO / inv.OUT_INVENTORY).read_text())
    committed_recon = json.loads((REPO / inv.OUT_RECON).read_text())
    assert _strip(committed_inv) == _strip(inventory)
    assert _strip(committed_recon) == _strip(recon)


def test_every_alert_has_one_traceable_decision():
    inventory, recon, _ = inv.build(REPO, REPO / inv.SNAPSHOT)
    rows = inventory["alerts"]
    assert len(rows) == inventory["total_open_alerts"] == 20
    assert {r["classification"] for r in rows} <= inv.CLASSES
    assert inventory["by_owner"] == {
        "DEP-REMEDIATE-004": ROOT_ALERTS,
        "DEP-REMEDIATE-005": [1, 2],
        "DEP-REMEDIATE-006": [88, 170],
    }
    assert recon["targeted_alerts"] == ROOT_ALERTS
    for r in rows:
        implemented = r["owner"] == "DEP-REMEDIATE-004"
        assert r["state"] == ("IMPLEMENTED" if implemented else "PLANNED")
        # Planned alerts stay visibly vulnerable until their own PR lands.
        assert bool(r["vulnerable_now"]) is (not implemented)
        assert r["versions_at_base"], r["alert"]


def test_root_manifest_uses_parent_update_and_scoped_overrides_only():
    pkg = json.loads((REPO / "package.json").read_text())
    assert pkg["devDependencies"] == {"markdownlint-cli": "^0.50.0"}
    assert "dependencies" not in pkg
    # Overrides must be scoped to the parent that needs them, never global.
    assert pkg["overrides"] == {
        "markdownlint-cli": {"minimatch": "^11.0.8"},
        "micromark-extension-math": {"katex": "^0.18.11"},
    }


@pytest.mark.parametrize(
    ("package", "version", "alerts"),
    [
        ("js-yaml", "4.1.1", [173, 175, 179, 180]),
        ("markdown-it", "14.3.2", [189, 190]),
        ("minimatch", "10.2.6", [191]),
        ("katex", "0.18.1", [186]),
        ("brace-expansion", "5.0.11", [185]),
        # Base versions: also re-flag the alerts GitHub auto-dismissed.
        ("brace-expansion", "5.0.6", [174, 177, 178, 183, 184, 185]),
        ("linkify-it", "5.0.0", [172, 176]),
    ],
)
def test_regressed_root_version_fails_closed(repo, capsys, package, version, alerts):
    _edit_lock(repo, package, version)
    assert inv.main(["--repo", str(repo)]) == 1
    err = capsys.readouterr().err
    for n in alerts:
        assert f"alert {n}: {package} ['{version}'] still in" in err


def test_github_auto_dismissed_root_alerts_stay_tracked_and_remediated():
    inventory, recon, _ = inv.build(REPO, REPO / inv.SNAPSHOT)
    tracked = inventory["auto_dismissed_by_github_tracked"]
    assert [a["alert"] for a in tracked] == [172, 177, 178, 183, 184]
    for a in tracked:
        assert a["severity"] == "high" and a["github_state"] == "auto_dismissed"
        assert a["versions_now"] and a["vulnerable_now"] == []
        assert all(
            inv.in_range(v, a["vulnerable_range"]) for v in a["versions_at_base"]
        )
    assert [a["alert"] for a in recon["auto_dismissed_by_github_also_remediated"]] == [
        172,
        177,
        178,
        183,
        184,
    ]


def test_implemented_package_that_disappears_must_be_reclassified(repo, capsys):
    _edit_lock(repo, "katex", None)
    assert inv.main(["--repo", str(repo)]) == 1
    assert "alert 186: katex no longer resolves" in capsys.readouterr().err


def test_new_alert_without_decision_fails_closed(repo, capsys):
    def add(alerts):
        extra = json.loads(json.dumps(alerts[0]))
        extra["number"] = 999
        return alerts + [extra]

    _edit_snapshot(repo, add)
    assert inv.main(["--repo", str(repo)]) == 1
    assert "alerts without a remediation decision: [999]" in capsys.readouterr().err


def test_decision_for_vanished_alert_fails_closed(repo, capsys):
    _edit_snapshot(repo, lambda alerts: [a for a in alerts if a["number"] != 191])
    assert inv.main(["--repo", str(repo)]) == 1
    assert "decisions for alerts absent from snapshot: [191]" in capsys.readouterr().err


def test_unclassified_manifest_fails_closed(repo):
    def move(alerts):
        alerts[0]["dependency"]["manifest_path"] = "apps/new/package-lock.json"
        return alerts

    _edit_snapshot(repo, move)
    assert inv.main(["--repo", str(repo)]) == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: (r / "package-lock.json").write_text("{not json"),
        lambda r: (r / "agent/requirements.txt").write_text("requests>=2.0\n"),
        lambda r: (r / "apps/console/package-lock.json").unlink(),
        lambda r: (r / inv.SNAPSHOT).write_text("{}"),
        lambda r: _edit_snapshot(
            r,
            lambda a: [
                {
                    **x,
                    "security_vulnerability": {
                        **x["security_vulnerability"],
                        "vulnerable_version_range": "~4.1",
                    },
                }
                for x in a
            ],
        ),
    ],
    ids=[
        "malformed-lock",
        "unpinned-requirement",
        "missing-lock",
        "snapshot-not-list",
        "unparseable-range",
    ],
)
def test_invalid_input_exits_2(repo, mutate):
    mutate(repo)
    assert inv.main(["--repo", str(repo)]) == 2


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("4.3.1", ">= 4.0.0, < 4.3.2", True),
        ("4.3.2", ">= 4.0.0, < 4.3.2", False),
        ("5.5.0", ">= 4.0.0, < 4.3.2", False),
        ("3.1.5", ">= 7.0.0, < 11.0.1", False),
        ("11.0.0", ">= 7.0.0, < 11.0.1", True),
        ("14.1.1", "<= 14.1.1", True),
        ("2.33", "< 2.33.0", False),
    ],
)
def test_in_range_boundaries(version, spec, expected):
    assert inv.in_range(version, spec) is expected


def test_prerelease_versions_are_rejected_not_guessed():
    with pytest.raises(inv.InventoryInputError):
        inv.in_range("11.0.0-rc.1", "< 11.0.1")
