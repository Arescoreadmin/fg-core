"""DEP-INV-001 — dependency alert inventory classification (offline)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools/ci/dependency_alert_inventory.py"

_spec = importlib.util.spec_from_file_location("_dep_inv", TOOL)
assert _spec and _spec.loader
inv = importlib.util.module_from_spec(_spec)
sys.modules["_dep_inv"] = inv
_spec.loader.exec_module(inv)


def _alert(
    number: int,
    manifest: str,
    package: str = "next",
    severity: str = "critical",
    scope: str | None = "runtime",
    patched: str | None = "15.5.28",
) -> dict[str, Any]:
    return {
        "number": number,
        "dependency": {
            "manifest_path": manifest,
            "scope": scope,
            "relationship": "direct",
        },
        "security_advisory": {
            "severity": severity,
            "ghsa_id": f"GHSA-test-{number:04d}-xxxx",
            "cve_id": None,
            "summary": "test advisory",
        },
        "security_vulnerability": {
            "package": {"name": package, "ecosystem": "npm"},
            "vulnerable_version_range": "< 15.5.28",
            "first_patched_version": {"identifier": patched} if patched else None,
        },
    }


@pytest.mark.parametrize(
    ("manifest", "scope", "expected"),
    [
        ("apps/console/package-lock.json", "runtime", "PRODUCTION_RUNTIME"),
        ("apps/console/package-lock.json", "development", "DEVELOPMENT_ONLY"),
        ("apps/console/pnpm-lock.yaml", "runtime", "NOT_INSTALLED"),
        ("apps/console/console/package-lock.json", "runtime", "NOT_INSTALLED"),
        (
            "apps/portal/package-lock.json",
            "runtime",
            "REPO_RUNTIME_PRODUCTION_DIVERGES",
        ),
        ("apps/web/package-lock.json", "runtime", "REPO_RUNTIME_PRODUCTION_DIVERGES"),
        ("package-lock.json", "runtime", "DEVELOPMENT_ONLY"),
        ("agent/requirements.txt", "runtime", "RUNTIME_NOT_REPO_DEPLOYED"),
    ],
)
def test_exposure_classification(manifest: str, scope: str, expected: str) -> None:
    out = inv.build_inventory([_alert(1, manifest, scope=scope)])
    assert out["alerts"][0]["exposure"] == expected


def test_deployed_runtime_critical_is_never_downgraded_by_dev_status() -> None:
    # A runtime alert on the deployed console lockfile must surface as production.
    out = inv.build_inventory([_alert(9, "apps/console/package-lock.json")])
    assert out["by_exposure"] == {"PRODUCTION_RUNTIME": {"critical": 1}}


def test_unknown_manifest_is_unclassified_and_fails_closed(tmp_path: Path) -> None:
    alerts = tmp_path / "alerts.json"
    alerts.write_text(json.dumps([_alert(5, "apps/new-app/package-lock.json")]))
    out = inv.build_inventory(json.loads(alerts.read_text()))
    assert out["alerts"][0]["exposure"] == "UNCLASSIFIED"
    assert out["unclassified_manifests"] == ["apps/new-app/package-lock.json"]
    assert inv.main(["--alerts", str(alerts), "--out", str(tmp_path / "o.json")]) == 1


@pytest.mark.parametrize(
    "payload", ['{"not": "a list"}', "not json", '[{"number": 1}]']
)
def test_invalid_input_exits_2_and_never_reports_clean(
    tmp_path: Path, payload: str
) -> None:
    alerts = tmp_path / "alerts.json"
    alerts.write_text(payload)
    out = tmp_path / "o.json"
    assert inv.main(["--alerts", str(alerts), "--out", str(out)]) == 2
    assert not out.exists()


def test_missing_input_file_exits_2(tmp_path: Path) -> None:
    assert inv.main(["--alerts", str(tmp_path / "absent.json")]) == 2


def test_no_patch_is_reported() -> None:
    out = inv.build_inventory(
        [_alert(3, "apps/console/package-lock.json", patched=None)]
    )
    assert out["alerts"][0]["remediation"] == "NO_PATCH"


def test_candidate_pr_requires_manifest_and_exact_package_name() -> None:
    prs = [
        {
            "number": 10,
            "title": "Bump next from 15.5.27 to 15.5.28",
            "body": "",
            "files": [{"path": "apps/console/package-lock.json"}],
        },
        # same package, different manifest: not a candidate
        {
            "number": 11,
            "title": "Bump next in /apps/portal",
            "body": "",
            "files": [{"path": "apps/portal/package-lock.json"}],
        },
        # same manifest, package name only as a substring: not a candidate
        {
            "number": 12,
            "title": "Bump next-auth",
            "body": "",
            "files": [{"path": "apps/console/package-lock.json"}],
        },
    ]
    out = inv.build_inventory([_alert(1, "apps/console/package-lock.json")], prs)
    assert out["alerts"][0]["candidate_prs"] == [10]


def test_output_is_deterministic_and_sorted_by_severity() -> None:
    alerts = [
        _alert(2, "package-lock.json", package="js-yaml", severity="high"),
        _alert(1, "apps/console/package-lock.json", severity="critical"),
        _alert(3, "agent/requirements.txt", package="requests", severity="medium"),
    ]
    a = inv.build_inventory(alerts)
    b = inv.build_inventory(list(reversed(alerts)))
    assert a == b
    assert [r["severity"] for r in a["alerts"]] == ["critical", "high", "medium"]
    assert a["total_open_alerts"] == 3


def test_every_tracked_js_lockfile_has_recorded_authority() -> None:
    # A new lockfile must be classified before its alerts can be triaged.
    tracked = subprocess.run(
        ["git", "ls-files", "*package-lock.json", "*pnpm-lock.yaml", "*yarn.lock"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert tracked, "expected tracked lockfiles"
    missing = sorted(set(tracked) - set(inv.MANIFEST_AUTHORITY))
    assert missing == []


def test_cli_runs_isolated_and_writes_inventory(tmp_path: Path) -> None:
    alerts = tmp_path / "alerts.json"
    alerts.write_text(json.dumps([_alert(1, "apps/console/pnpm-lock.yaml")]))
    out = tmp_path / "inv.json"
    proc = subprocess.run(
        [sys.executable, "-I", str(TOOL), "--alerts", str(alerts), "--out", str(out)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    assert data["schema"] == "fg.dependency_alert_inventory/v1"
    assert len(data["alerts_export_sha256"]) == 64
