"""L14-FRONTEND-DEPENDENCY-SEC-001 — frontend dependency gate is fail-closed.

Synthetic, offline tests for ``tools/ci/frontend_dependency_audit.py``:
a synthetic critical advisory must fail the gate, an audit execution error
must never look clean, and exceptions only apply when approved and current.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    # The module is loaded below by file path (as the CI job runs it); this
    # import is for the type checker only.
    from tools.ci.frontend_dependency_audit import AuditRun

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "frontend_dependency_audit", REPO / "tools/ci/frontend_dependency_audit.py"
)
assert _spec and _spec.loader
fda = importlib.util.module_from_spec(_spec)
sys.modules["frontend_dependency_audit"] = fda
_spec.loader.exec_module(fda)

TODAY = dt.date(2026, 11, 10)
GHSA = "GHSA-2464-fhr4-w9xw"


def _report(severity: str | None, *, pkg: str = "next") -> dict:
    counts = {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0}
    vulns: dict = {}
    if severity:
        counts[severity] = 1
        vulns[pkg] = {
            "name": pkg,
            "severity": severity,
            "isDirect": True,
            "via": [
                {
                    "source": 1242817,
                    "name": pkg,
                    "title": "Synthetic RCE",
                    "url": f"https://github.com/advisories/{GHSA}",
                    "severity": severity,
                    "range": "<=15.5.27",
                },
                "postcss",
            ],
            "range": "<=15.5.27",
            "nodes": [f"node_modules/{pkg}"],
            "fixAvailable": True,
        }
    counts["total"] = sum(counts.values())
    return {
        "auditReportVersion": 2,
        "vulnerabilities": vulns,
        "metadata": {"vulnerabilities": counts},
    }


def _run(scope: str, severity: str | None, rc: int | None = None) -> AuditRun:
    rep = _report(severity)
    code = rc if rc is not None else (1 if severity else 0)
    return fda.parse_audit_output(scope, code, json.dumps(rep), "")


def _exc(**over) -> dict:
    base = {
        "id": "FE-EXC-001",
        "app": "web",
        "package": "next",
        "advisory": GHSA,
        "owner": "security",
        "expires": "2026-12-01",
        "approval_status": "APPROVED",
        "approved_by": "founder",
        "runtime_exposure": "image optimizer disabled",
        "compensating_controls": "WAF rule",
        "remediation_plan": "upgrade",
    }
    base.update(over)
    return base


# --- blocking -------------------------------------------------------------


def test_synthetic_critical_production_advisory_fails_gate():
    res = fda.evaluate_app(
        "web", [_run("production", "critical"), _run("all", "critical")], []
    )
    assert res.status == fda.STATUS_FAIL
    assert {b["scope"] for b in res.blocking} == {"production", "all"}
    assert all(fda.ghsa_of(b["url"]) == GHSA for b in res.blocking)
    assert list(res.blocking[0]["paths"]) == ["node_modules/next"]
    assert fda.overall_status([res]) == fda.STATUS_FAIL


def test_high_in_full_tree_blocks_even_when_production_scope_is_clean():
    res = fda.evaluate_app("web", [_run("production", None), _run("all", "high")], [])
    assert res.status == fda.STATUS_FAIL


def test_moderate_only_passes_and_is_reported():
    res = fda.evaluate_app(
        "web", [_run("production", None), _run("all", "moderate")], []
    )
    assert res.status == fda.STATUS_PASS
    assert res.counts["all"]["moderate"] == 1
    assert res.findings["all"][0]["severity"] == "moderate"


# --- audit execution failures are never clean ----------------------------


@pytest.mark.parametrize(
    "rc,stdout,stderr",
    [
        (1, "", "npm ERR! network request to https://registry.npmjs.org failed"),
        (1, "not json", ""),
        (1, json.dumps({"error": {"code": "ENOLOCK", "summary": "no lockfile"}}), ""),
        (1, json.dumps({"vulnerabilities": {}}), ""),
        (2, json.dumps(_report(None)), ""),
        (None, "", ""),
    ],
    ids=["network", "non-json", "npm-error", "no-metadata", "rc-with-zero", "timeout"],
)
def test_audit_execution_error_is_unverified_not_clean(rc, stdout, stderr):
    bad = fda.parse_audit_output("production", rc, stdout, stderr)
    assert bad.error and bad.report is None
    res = fda.evaluate_app("web", [bad, _run("all", None)], [])
    assert res.status == fda.STATUS_UNVERIFIED
    clean = fda.evaluate_app(
        "portal", [_run("production", None), _run("all", None)], []
    )
    assert clean.status == fda.STATUS_PASS
    assert fda.overall_status([clean, res]) == fda.STATUS_UNVERIFIED


def test_cmd_audit_exit_codes_and_evidence(tmp_path, monkeypatch):
    outcomes = {"production": "critical", "all": None}
    monkeypatch.setattr(fda, "run_audit", lambda d, scope: _run(scope, outcomes[scope]))
    rc = fda.main(["audit", "--app", "web", "--out", str(tmp_path)])
    assert rc == 1
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["status"] == "FAIL"
    assert summary["source_sha"] and summary["source_sha"] != "UNKNOWN"
    assert len(summary["apps"]["web"]["lockfile_sha256"]) == 64
    detail = json.loads((tmp_path / "audit-web.json").read_text())
    assert detail["evidence"]["lockfile"] == "apps/web/package-lock.json"
    assert GHSA in (tmp_path / "summary.md").read_text()

    monkeypatch.setattr(
        fda,
        "run_audit",
        lambda d, scope: fda.parse_audit_output(scope, 1, "", "ECONNREFUSED"),
    )
    assert fda.main(["audit", "--app", "web", "--out", str(tmp_path)]) == 2
    assert (
        json.loads((tmp_path / "summary.json").read_text())["status"]
        == "AUDIT_UNVERIFIED"
    )


# --- exceptions -----------------------------------------------------------


def test_approved_current_exception_suppresses_only_its_advisory():
    usable, problems = fda.validate_exceptions({"exceptions": [_exc()]}, TODAY)
    assert problems == [] and len(usable) == 1
    res = fda.evaluate_app(
        "web", [_run("production", "critical"), _run("all", None)], usable
    )
    assert res.status == fda.STATUS_PASS and res.excepted
    other_app = fda.evaluate_app(
        "portal", [_run("production", "critical"), _run("all", None)], usable
    )
    assert other_app.status == fda.STATUS_FAIL


@pytest.mark.parametrize(
    "over,reason",
    [
        ({"approval_status": "PENDING_FOUNDER_APPROVAL"}, "approval_status"),
        ({"approved_by": ""}, "missing fields"),
        ({"owner": ""}, "missing fields"),
        ({"expires": "2026-11-09"}, "expired"),
        ({"expires": "2027-06-01"}, "horizon"),
        ({"expires": "soon"}, "invalid expires"),
    ],
)
def test_unapproved_or_stale_exception_keeps_blocking(over, reason):
    usable, problems = fda.validate_exceptions({"exceptions": [_exc(**over)]}, TODAY)
    assert usable == [] and reason in problems[0]
    res = fda.evaluate_app(
        "web", [_run("production", "critical"), _run("all", None)], usable
    )
    assert res.status == fda.STATUS_FAIL


def _registry() -> dict:
    return json.loads(
        (REPO / "tools/ci/frontend_dependency_exceptions.json").read_text()
    )


# --- FE-EXC-001..003: picomatch GHSA-fc5q-39xc-vjpf (founder-approved) ------

PICO_GHSA = "GHSA-fc5q-39xc-vjpf"
PICO_APPROVED_ON = dt.date(2026, 11, 17)
PICO_EXPIRES = dt.date(2026, 12, 17)


def _pico_report(*extra: tuple[str, str, str]) -> dict:
    """npm audit v2 shape for the real picomatch advisory.

    Only ``picomatch`` carries the advisory object; the packages that depend
    on it (micromatch, tailwindcss, ...) list it as a string edge, exactly as
    ``npm audit --json`` reports them. ``extra`` adds (package, ghsa, severity)
    advisories that must not be covered by the picomatch exception.
    """

    def adv(pkg: str, ghsa: str, severity: str, source: int) -> dict:
        return {
            "source": source,
            "name": pkg,
            "title": f"synthetic {ghsa}",
            "url": f"https://github.com/advisories/{ghsa}",
            "severity": severity,
            "range": "<=4.0.7",
        }

    vulns: dict = {
        "picomatch": {
            "name": "picomatch",
            "severity": "high",
            "isDirect": False,
            "via": [adv("picomatch", PICO_GHSA, "high", 1117001)],
            "range": "<=4.0.7",
            "nodes": [
                "node_modules/picomatch",
                "node_modules/tinyglobby/node_modules/picomatch",
            ],
            "fixAvailable": False,
        },
        "micromatch": {
            "name": "micromatch",
            "severity": "high",
            "isDirect": False,
            "via": ["picomatch"],
            "range": "*",
            "nodes": ["node_modules/micromatch"],
            "fixAvailable": False,
        },
        "tailwindcss": {
            "name": "tailwindcss",
            "severity": "high",
            "isDirect": True,
            "via": ["micromatch", "picomatch"],
            "range": "*",
            "nodes": ["node_modules/tailwindcss"],
            "fixAvailable": False,
        },
    }
    for i, (pkg, ghsa, severity) in enumerate(extra):
        entry = vulns.setdefault(
            pkg,
            {
                "name": pkg,
                "severity": severity,
                "isDirect": True,
                "via": [],
                "range": "*",
                "nodes": [f"node_modules/{pkg}"],
                "fixAvailable": False,
            },
        )
        entry["via"].append(adv(pkg, ghsa, severity, 2000000 + i))
    counts = {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0}
    for v in vulns.values():
        counts[v["severity"]] += 1
    counts["total"] = sum(counts.values())
    return {
        "auditReportVersion": 2,
        "vulnerabilities": vulns,
        "metadata": {"vulnerabilities": counts},
    }


def _pico_runs(*extra: tuple[str, str, str]) -> list:
    clean = json.dumps(_report(None))
    return [
        fda.parse_audit_output("production", 0, clean, ""),
        fda.parse_audit_output("all", 1, json.dumps(_pico_report(*extra)), ""),
    ]


def _pico_usable(today: dt.date = PICO_APPROVED_ON) -> list:
    usable, problems = fda.validate_exceptions(_registry(), today)
    assert problems == []
    return usable


def test_repository_registry_holds_only_the_approved_picomatch_records():
    raw = _registry()
    usable, problems = fda.validate_exceptions(raw, PICO_APPROVED_ON)
    assert problems == [] and len(usable) == len(raw["exceptions"]) == 3
    assert sorted(e["app"] for e in usable) == ["console", "portal", "web"]
    for e in usable:
        assert e["package"] == "picomatch"
        assert e["advisory"] == PICO_GHSA
        assert e["approval_status"] == "APPROVED"
        assert e["approved_by"] == e["owner"] == "Arescoreadmin"
        assert dt.date.fromisoformat(e["expires"]) == PICO_EXPIRES
        for field in ("runtime_exposure", "compensating_controls", "remediation_plan"):
            assert len(e[field]) > 40, field


@pytest.mark.parametrize("app", ["portal", "console", "web"])
def test_picomatch_advisory_is_excepted_only_while_approved(app):
    res = fda.evaluate_app(app, _pico_runs(), _pico_usable())
    assert res.status == fda.STATUS_PASS
    assert [x["package"] for x in res.excepted] == ["picomatch"]
    assert res.blocking == []
    # The finding stays visible in the report; it is not dropped.
    assert any(f["package"] == "picomatch" for f in res.findings["all"])
    assert res.counts["all"]["high"] == 3


@pytest.mark.parametrize("app", ["portal", "console", "web"])
@pytest.mark.parametrize(
    "extra",
    [
        ("picomatch", "GHSA-aaaa-bbbb-cccc", "high"),  # other advisory, same pkg
        ("micromatch", PICO_GHSA, "high"),  # same advisory, other pkg
        ("next", "GHSA-dddd-eeee-ffff", "critical"),  # unrelated critical
        ("zod", "GHSA-mrhx-c7xc-m3w5", "high"),  # unrelated high
    ],
    ids=["other-advisory", "other-package", "unrelated-critical", "unrelated-high"],
)
def test_unrelated_advisories_still_fail_with_picomatch_exception(app, extra):
    res = fda.evaluate_app(app, _pico_runs(extra), _pico_usable())
    assert res.status == fda.STATUS_FAIL
    blocked = {(b["package"], fda.ghsa_of(b["url"])) for b in res.blocking}
    assert blocked == {(extra[0], extra[1])}
    assert [x["package"] for x in res.excepted] == ["picomatch"]


def test_picomatch_exception_does_not_cover_an_unlisted_app():
    res = fda.evaluate_app("admin", _pico_runs(), _pico_usable())
    assert res.status == fda.STATUS_FAIL and res.excepted == []


def test_picomatch_exception_lapses_after_expiry():
    assert _pico_usable(PICO_EXPIRES) != []  # last valid day
    usable, problems = fda.validate_exceptions(
        _registry(), PICO_EXPIRES + dt.timedelta(days=1)
    )
    assert usable == [] and len(problems) == 3
    assert all("expired 2026-12-17" in p for p in problems)
    for app in ("portal", "console", "web"):
        assert fda.evaluate_app(app, _pico_runs(), usable).status == fda.STATUS_FAIL


@pytest.mark.parametrize(
    "over,reason",
    [
        ({"approval_status": "PENDING_FOUNDER_APPROVAL"}, "approval_status"),
        ({"approval_status": "approved"}, "approval_status"),
        ({"approved_by": ""}, "missing fields"),
        ({"owner": "  "}, "missing fields"),
        ({"advisory": ""}, "missing fields"),
        ({"runtime_exposure": ""}, "missing fields"),
        ({"remediation_plan": ""}, "missing fields"),
        ({"expires": "2026-11-16"}, "expired"),
        ({"expires": "2027-03-01"}, "horizon"),
        ({"expires": "17/12/2026"}, "invalid expires"),
    ],
)
def test_altered_picomatch_record_fails_closed(over, reason):
    records = []
    for e in _registry()["exceptions"]:
        bad = dict(e)
        bad.update(over)
        records.append(bad)
    usable, problems = fda.validate_exceptions(
        {"exceptions": records}, PICO_APPROVED_ON
    )
    assert usable == [] and len(problems) == 3
    assert all(reason in p for p in problems)
    for app in ("portal", "console", "web"):
        assert fda.evaluate_app(app, _pico_runs(), usable).status == fda.STATUS_FAIL


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        {},
        {"exceptions": None},
        {"exceptions": "FE-EXC-001"},
    ],
    ids=["null", "list", "no-key", "null-list", "string-list"],
)
def test_malformed_registry_suppresses_nothing(raw):
    usable, problems = fda.validate_exceptions(raw, PICO_APPROVED_ON)
    assert usable == [] and problems and "malformed" in problems[0]
    assert fda.evaluate_app("web", _pico_runs(), usable).status == fda.STATUS_FAIL


def test_malformed_record_is_rejected_without_hiding_valid_ones():
    records = ["picomatch", 7, *_registry()["exceptions"]]
    usable, problems = fda.validate_exceptions(
        {"exceptions": records}, PICO_APPROVED_ON
    )
    assert len(usable) == 3
    assert problems == ["<invalid>: not an object", "<invalid>: not an object"]


def test_unparseable_registry_file_fails_closed(tmp_path, monkeypatch):
    bad = tmp_path / "frontend_dependency_exceptions.json"
    bad.write_text("{not json")
    monkeypatch.setattr(fda, "EXCEPTIONS_PATH", bad)
    usable, problems = fda._load_exceptions(PICO_APPROVED_ON)
    assert usable == [] and "invalid JSON" in problems[0]
    monkeypatch.setattr(fda, "EXCEPTIONS_PATH", tmp_path / "missing.json")
    usable, problems = fda._load_exceptions(PICO_APPROVED_ON)
    assert usable == [] and "not found" in problems[0]


@pytest.mark.parametrize("app", ["portal", "console", "web"])
def test_incomplete_audit_is_never_excepted(app):
    failed = fda.parse_audit_output("production", 1, "", "ECONNREFUSED")
    runs = [failed, _pico_runs()[1]]
    res = fda.evaluate_app(app, runs, _pico_usable())
    assert res.status == fda.STATUS_UNVERIFIED
    assert fda.overall_status([res]) == fda.STATUS_UNVERIFIED


# --- redaction ------------------------------------------------------------


def test_redaction_strips_registry_credentials():
    raw = (
        "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789 "
        "https://user:s3cret@registry.example.com/x Authorization: Bearer eyJabc.def "
        "token ghp_abcdefghijklmnopqrstuvwxyz0123"
    )
    out = fda.redact(raw)
    for secret in ("npm_abcdefghij", "s3cret", "eyJabc.def", "ghp_abcdefghij"):
        assert secret not in out
    bad = fda.parse_audit_output("production", 1, "", raw)
    assert "s3cret" not in (bad.error or "")


# --- SBOM -----------------------------------------------------------------


def _lock() -> dict:
    return {
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"next": "15.5.29", "@fg/ui": "file:../ui"},
                "devDependencies": {"eslint": "8"},
            },
            "node_modules/next": {
                "version": "15.5.29",
                "integrity": "sha512-AAAA",
                "resolved": "https://registry.npmjs.org/next/-/next-15.5.29.tgz",
                "dependencies": {"postcss": "8.4.31"},
            },
            "node_modules/postcss": {"version": "8.5.32"},
            "node_modules/eslint": {"version": "8.57.1", "dev": True},
            "node_modules/@fg/ui": {"resolved": "../ui", "link": True},
            "../ui": {
                "name": "@fg/ui",
                "version": "0.1.0",
                "dependencies": {"clsx": "^2"},
            },
        },
    }


def test_lockfile_sbom_is_valid_bound_and_excludes_dev():
    bom = fda.lockfile_to_cyclonedx(
        _lock(),
        app="app",
        generated_at="2026-11-10T00:00:00Z",
        serial="urn:uuid:1",
        tool="t",
    )
    bom["metadata"]["properties"] += [
        {"name": "fg:source_sha", "value": "abc"},
        {"name": "fg:lockfile_sha256", "value": "f" * 64},
    ]
    names = {c["name"] for c in bom["components"]}
    assert names == {"next", "postcss", "@fg/ui"}  # eslint (dev) excluded
    assert {"ref": "next@15.5.29", "dependsOn": ["postcss@8.5.32"]} in bom[
        "dependencies"
    ]
    unresolved = [
        p["value"]
        for p in bom["metadata"]["properties"]
        if p["name"] == "fg:unresolved_dependency"
    ]
    assert unresolved == ["@fg/ui@0.1.0 -> clsx"]  # recorded, not dropped
    assert fda.validate_sbom(bom, expected_sha="abc", expected_lock_sha="f" * 64) == []
    assert "fg:source_sha does not match source commit" in fda.validate_sbom(
        bom, expected_sha="other", expected_lock_sha="f" * 64
    )
    bom["components"] = []
    assert "components missing or empty" in fda.validate_sbom(
        bom, expected_sha="abc", expected_lock_sha="f" * 64
    )


def test_real_frontend_lockfiles_produce_valid_sboms(tmp_path):
    assert fda.main(["sbom", "--out", str(tmp_path)]) == 0
    manifest = json.loads((tmp_path / "sbom-manifest.json").read_text())
    assert set(manifest["sboms"]) == {"portal", "console", "web"}
    for app, entry in manifest["sboms"].items():
        assert entry["valid"], (app, entry["errors"])
        bom = json.loads((tmp_path / entry["file"]).read_text())
        refs = {c["name"]: c["version"] for c in bom["components"]}
        assert refs["next"] == "15.5.29", app
        if "postcss" in refs:  # patched floor for GHSA-6g55/GHSA-r28c/GHSA-fxqj
            assert tuple(map(int, refs["postcss"].split("."))) >= (8, 5, 23), app


# --- the gate cannot be silently removed or softened ----------------------


def _load_guard():
    spec = importlib.util.spec_from_file_location(
        "check_security_regression_gates",
        REPO / "tools/ci/check_security_regression_gates.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fake_repo(tmp_path: Path, workflow: str | None, makefile: str) -> Path:
    for rel in (
        "tools/ci/frontend_dependency_audit.py",
        "tools/ci/frontend_dependency_exceptions.json",
    ):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    if workflow is not None:
        wf = tmp_path / ".github/workflows/frontend-dependency-security.yml"
        wf.parent.mkdir(parents=True, exist_ok=True)
        wf.write_text(workflow)
    (tmp_path / "Makefile").write_text(makefile)
    return tmp_path


_REAL_WF = (REPO / ".github/workflows/frontend-dependency-security.yml").read_text()


@pytest.mark.parametrize(
    "workflow,makefile,expect",
    [
        (None, "", "asset missing"),
        (_REAL_WF.replace("  schedule:\n", "  sched:\n"), "", "schedule:"),
        (
            _REAL_WF.replace(
                "  pull_request:\n", "  pull_request:\n    paths: [apps/**]\n"
            ),
            "",
            "paths:",
        ),
        (
            _REAL_WF.replace(
                "run: python tools/ci/frontend_dependency_audit.py audit",
                "run: python tools/ci/frontend_dependency_audit.py audit || true",
            ),
            "",
            "|| true",
        ),
        (
            _REAL_WF.replace(
                "timeout-minutes: 20",
                "timeout-minutes: 20\n    continue-on-error: true",
            ),
            "",
            "continue-on-error",
        ),
        (_REAL_WF, "x:\n\tnpm audit --omit=dev || true\n", "non-blocking"),
    ],
    ids=[
        "removed",
        "no-schedule",
        "path-filtered",
        "or-true",
        "continue-on-error",
        "makefile-pilot",
    ],
)
def test_guard_rejects_removed_or_softened_gate(
    tmp_path, monkeypatch, workflow, makefile, expect
):
    guard = _load_guard()
    monkeypatch.setattr(guard, "REPO", _fake_repo(tmp_path, workflow, makefile))
    failures: list[str] = []
    guard.check_frontend_dependency_gate(failures)
    assert any(expect in f for f in failures), failures


def test_guard_accepts_repository_gate():
    guard = _load_guard()
    failures: list[str] = []
    guard.check_frontend_dependency_gate(failures)
    assert failures == []
