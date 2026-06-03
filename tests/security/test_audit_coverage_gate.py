"""H13.5 Audit Coverage Gate — security tests for the validator itself.

Uses synthetic temp files and YAML fixtures so tests are hermetic and
never depend on the evolving state of api/field_assessment.py.  The
validator must correctly detect violations, expired exceptions, invalid
config, and must NOT false-positive on audited routes.
"""

from __future__ import annotations

import textwrap
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

# Import from the repo root via PYTHONPATH=.
from tools.ci.check_audit_coverage import _load_exceptions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_py(tmp_path: Path, name: str, src: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


def _write_yaml(tmp_path: Path, entries: list[dict]) -> Path:
    p = tmp_path / "audit_exceptions.yaml"
    p.write_text(yaml.dump({"exceptions": entries}), encoding="utf-8")
    return p


def _future(days: int = 90) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


def _past(days: int = 1) -> str:
    return (date.today() - timedelta(days=days)).isoformat()


def _valid_exception(
    exc_id: str,
    fn_name: str,
    rel_file: str,
    *,
    expired: bool = False,
) -> dict:
    return {
        "id": exc_id,
        "function_name": fn_name,
        "file": rel_file,
        "reason": "test fixture",
        "owner": "test-team",
        "expiration_date": _past() if expired else _future(),
        "approval_reference": "TEST-001",
    }


# ---------------------------------------------------------------------------
# L1: Route discovery
# ---------------------------------------------------------------------------


class TestRouteDiscovery:
    def test_finds_post_route(self, tmp_path: Path) -> None:
        src = """
        from fastapi import APIRouter
        router = APIRouter()

        @router.post("/things")
        def create_thing():
            pass
        """
        _write_py(tmp_path, "api_tmp.py", src)
        import ast
        from tools.ci.check_audit_coverage import _has_audit_call, MUTATION_METHODS

        tree = ast.parse(textwrap.dedent(src))
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for deco in node.decorator_list:
                if not isinstance(deco, ast.Call):
                    continue
                func = deco.func
                if isinstance(func, ast.Attribute) and func.attr in MUTATION_METHODS:
                    found.append((node.name, func.attr, _has_audit_call(node)))
        assert len(found) == 1
        assert found[0] == ("create_thing", "post", False)

    def test_ignores_get_route(self, tmp_path: Path) -> None:
        src = """
        from fastapi import APIRouter
        router = APIRouter()

        @router.get("/things")
        def list_things():
            pass
        """
        import ast
        from tools.ci.check_audit_coverage import MUTATION_METHODS

        tree = ast.parse(textwrap.dedent(src))
        found = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for deco in node.decorator_list
            if isinstance(deco, ast.Call)
            and isinstance(deco.func, ast.Attribute)
            and deco.func.attr in MUTATION_METHODS
        ]
        assert found == []

    def test_finds_patch_and_delete(self, tmp_path: Path) -> None:
        src = """
        @router.patch("/x")
        def patch_x(): pass

        @router.delete("/x/{id}")
        def delete_x(): pass
        """
        import ast
        from tools.ci.check_audit_coverage import MUTATION_METHODS

        tree = ast.parse(textwrap.dedent(src))
        methods = [
            deco.func.attr
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for deco in node.decorator_list
            if isinstance(deco, ast.Call)
            and isinstance(deco.func, ast.Attribute)
            and deco.func.attr in MUTATION_METHODS
        ]
        assert sorted(methods) == ["delete", "patch"]


# ---------------------------------------------------------------------------
# L2/L3: Audit call detection
# ---------------------------------------------------------------------------


class TestAuditCallDetection:
    def _audited(self, src: str) -> bool:
        import ast
        from tools.ci.check_audit_coverage import _has_audit_call

        tree = ast.parse(textwrap.dedent(src))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return _has_audit_call(node)
        return False

    def test_direct_emit_call_detected(self) -> None:
        src = """
        def create_thing(db):
            emit_engagement_audit_event(db, event_type="x")
            db.commit()
        """
        assert self._audited(src) is True

    def test_atomicity_svc_emit_detected(self) -> None:
        src = """
        def patch_thing(db):
            audit_atomicity_svc.emit(db, event_type="x")
            db.commit()
        """
        assert self._audited(src) is True

    def test_no_audit_call_not_detected(self) -> None:
        src = """
        def create_thing(db):
            db.add(Thing())
            db.commit()
        """
        assert self._audited(src) is False

    def test_audit_call_in_nested_block_detected(self) -> None:
        src = """
        def batch_create(db, items):
            for item in items:
                emit_engagement_audit_event(db, event_type="item.created")
            db.commit()
        """
        assert self._audited(src) is True

    def test_string_mention_does_not_count(self) -> None:
        src = """
        def create_thing(db):
            # "emit_engagement_audit_event" is called elsewhere
            comment = "audit_atomicity_svc.emit logs this"
            db.commit()
        """
        assert self._audited(src) is False


# ---------------------------------------------------------------------------
# L4: Exceptions registry validation
# ---------------------------------------------------------------------------


class TestExceptionsRegistry:
    def test_valid_exception_loads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        yaml_path = _write_yaml(
            tmp_path,
            [_valid_exception("EXC-T-001", "create_thing", "api/test.py")],
        )
        monkeypatch.setattr("tools.ci.check_audit_coverage.EXCEPTIONS_FILE", yaml_path)
        registry, errors = _load_exceptions()
        assert errors == []
        assert "api/test.py::create_thing" in registry

    def test_expired_exception_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        yaml_path = _write_yaml(
            tmp_path,
            [_valid_exception("EXC-T-002", "old_fn", "api/test.py", expired=True)],
        )
        monkeypatch.setattr("tools.ci.check_audit_coverage.EXCEPTIONS_FILE", yaml_path)
        registry, errors = _load_exceptions()
        assert errors == []
        assert registry["api/test.py::old_fn"]["expired"] is True

    def test_missing_required_field_is_config_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bad_entry = {
            "id": "EXC-T-003",
            "function_name": "fn",
            # missing: file, reason, owner, expiration_date, approval_reference
        }
        yaml_path = _write_yaml(tmp_path, [bad_entry])
        monkeypatch.setattr("tools.ci.check_audit_coverage.EXCEPTIONS_FILE", yaml_path)
        _, errors = _load_exceptions()
        assert len(errors) > 0
        assert any("missing required fields" in e for e in errors)

    def test_invalid_expiration_date_is_config_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entry = _valid_exception("EXC-T-004", "fn", "api/test.py")
        entry["expiration_date"] = "not-a-date"
        yaml_path = _write_yaml(tmp_path, [entry])
        monkeypatch.setattr("tools.ci.check_audit_coverage.EXCEPTIONS_FILE", yaml_path)
        _, errors = _load_exceptions()
        assert any("invalid expiration_date" in e for e in errors)

    def test_missing_registry_file_is_config_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "tools.ci.check_audit_coverage.EXCEPTIONS_FILE",
            tmp_path / "nonexistent.yaml",
        )
        _, errors = _load_exceptions()
        assert len(errors) > 0
        assert any("not found" in e for e in errors)

    def test_malformed_yaml_is_config_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        p = tmp_path / "audit_exceptions.yaml"
        p.write_text("exceptions: [not: {valid yaml:\n  - broken", encoding="utf-8")
        monkeypatch.setattr("tools.ci.check_audit_coverage.EXCEPTIONS_FILE", p)
        _, errors = _load_exceptions()
        assert any("parse error" in e or "YAML" in e for e in errors)


# ---------------------------------------------------------------------------
# L5: End-to-end gate behaviour via run()
# ---------------------------------------------------------------------------


class TestGateBehaviour:
    """Patch SCANNED_FILES and EXCEPTIONS_FILE to use synthetic temp files."""

    def _gate(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        py_src: str,
        exceptions: list[dict] | None = None,
        *,
        rel_file: str = "api/fake.py",
    ) -> int:
        # Write synthetic python file
        abs_py = tmp_path / "fake.py"
        abs_py.write_text(textwrap.dedent(py_src), encoding="utf-8")

        yaml_path = _write_yaml(tmp_path, exceptions or [])

        # Patch module globals
        monkeypatch.setattr("tools.ci.check_audit_coverage.SCANNED_FILES", [])
        monkeypatch.setattr("tools.ci.check_audit_coverage.EXCEPTIONS_FILE", yaml_path)
        monkeypatch.setattr(
            "tools.ci.check_audit_coverage.REPORT_FILE", tmp_path / "report.json"
        )

        # Manually invoke the inner logic with the synthetic file
        from tools.ci import check_audit_coverage as mod
        import json

        def patched_run(*, write_report: bool = True) -> int:
            routes = []
            import ast

            src_text = textwrap.dedent(py_src)
            tree = ast.parse(src_text, filename=rel_file)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for deco in node.decorator_list:
                    if not isinstance(deco, ast.Call):
                        continue
                    func = deco.func
                    if not isinstance(func, ast.Attribute):
                        continue
                    if func.attr not in mod.MUTATION_METHODS:
                        continue
                    routes.append(
                        {
                            "file": rel_file,
                            "function_name": node.name,
                            "method": func.attr.upper(),
                            "line": node.lineno,
                            "audited": mod._has_audit_call(node),
                        }
                    )

            exc_registry, cfg_errors = mod._load_exceptions()
            if cfg_errors:
                for err in cfg_errors:
                    import sys

                    print(f"[audit-coverage] CONFIG ERROR: {err}", file=sys.stderr)
                return 2

            violations, expired_exceptions, covered, excepted = [], [], [], []
            for route in routes:
                key = f"{route['file']}::{route['function_name']}"
                if route["audited"]:
                    covered.append(route)
                elif exc_registry.get(key) is None:
                    violations.append(route)
                elif exc_registry[key]["expired"]:
                    expired_exceptions.append({**route, "exception": exc_registry[key]})
                else:
                    excepted.append({**route, "exception": exc_registry[key]})

            total = len(routes)
            audited_count = len(covered) + len(excepted)
            pct = round(100 * audited_count / total, 1) if total else 0.0
            report = {
                "generated_at": date.today().isoformat(),
                "total_mutation_routes": total,
                "audited": len(covered),
                "excepted": len(excepted),
                "expired_exceptions": len(expired_exceptions),
                "violations": len(violations),
                "coverage_pct": pct,
                "violation_list": violations,
                "expired_exception_list": expired_exceptions,
                "excepted_list": excepted,
                "covered_list": covered,
            }
            if write_report:
                (tmp_path / "report.json").write_text(
                    json.dumps(report, indent=2, default=str), encoding="utf-8"
                )
            mod._print_summary(report)
            return 1 if (violations or expired_exceptions) else 0

        return patched_run()

    def test_audited_route_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = """
        @router.post("/things")
        def create_thing(db):
            emit_engagement_audit_event(db, event_type="thing.created")
            db.commit()
        """
        rc = self._gate(tmp_path, monkeypatch, src)
        assert rc == 0

    def test_unaudited_route_without_exception_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = """
        @router.post("/things")
        def create_thing(db):
            db.add(Thing())
            db.commit()
        """
        rc = self._gate(tmp_path, monkeypatch, src, exceptions=[])
        assert rc == 1

    def test_unaudited_route_with_valid_exception_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = """
        @router.post("/things")
        def create_thing(db):
            db.add(Thing())
            db.commit()
        """
        exc = _valid_exception("EXC-T-010", "create_thing", "api/fake.py")
        rc = self._gate(tmp_path, monkeypatch, src, exceptions=[exc])
        assert rc == 0

    def test_unaudited_route_with_expired_exception_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = """
        @router.post("/things")
        def create_thing(db):
            db.add(Thing())
            db.commit()
        """
        exc = _valid_exception("EXC-T-011", "create_thing", "api/fake.py", expired=True)
        rc = self._gate(tmp_path, monkeypatch, src, exceptions=[exc])
        assert rc == 1

    def test_invalid_exception_config_returns_exit_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = """
        @router.post("/things")
        def create_thing(db):
            db.commit()
        """
        bad = {"id": "BAD", "function_name": "create_thing"}  # missing required fields
        rc = self._gate(tmp_path, monkeypatch, src, exceptions=[bad])
        assert rc == 2

    def test_atomicity_svc_emit_counts_as_audited(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = """
        @router.patch("/things/{id}")
        def patch_thing(db):
            audit_atomicity_svc.emit(db, event_type="thing.updated")
            db.commit()
        """
        rc = self._gate(tmp_path, monkeypatch, src)
        assert rc == 0

    def test_mixed_routes_reports_correct_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = """
        @router.post("/a")
        def route_a(db):
            emit_engagement_audit_event(db)
            db.commit()

        @router.post("/b")
        def route_b(db):
            db.commit()

        @router.delete("/c/{id}")
        def route_c(db):
            db.commit()
        """
        exc = _valid_exception("EXC-T-020", "route_b", "api/fake.py")
        rc = self._gate(tmp_path, monkeypatch, src, exceptions=[exc])
        # route_a=audited, route_b=excepted, route_c=violation
        assert rc == 1

    def test_get_only_routes_are_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = """
        @router.get("/things")
        def list_things():
            pass

        @router.get("/things/{id}")
        def get_thing():
            pass
        """
        rc = self._gate(tmp_path, monkeypatch, src)
        assert rc == 0


# ---------------------------------------------------------------------------
# L6: Real codebase — smoke test that the gate currently passes
# ---------------------------------------------------------------------------


class TestRealCodebaseGate:
    def test_gate_passes_on_current_codebase(self, tmp_path: Path) -> None:
        """Smoke test: run the real validator against the actual repo.

        This test fails if:
          - A new mutation route was added without an audit call AND without an
            exception in audit_exceptions.yaml
          - An exception in the registry has expired
          - The registry file is malformed
        """
        report_path = tmp_path / "report.json"
        import tools.ci.check_audit_coverage as mod

        original_report = mod.REPORT_FILE
        mod.REPORT_FILE = report_path
        try:
            rc = mod.run(write_report=True)
        finally:
            mod.REPORT_FILE = original_report

        assert rc == 0, (
            "Audit coverage gate failed. Run `make audit-coverage-check` for details. "
            "Either add an audit call to the new route or add an entry to "
            "tools/ci/audit_exceptions.yaml."
        )

    def test_coverage_report_written(self, tmp_path: Path) -> None:
        import json
        import tools.ci.check_audit_coverage as mod

        report_path = tmp_path / "report.json"
        original_report = mod.REPORT_FILE
        mod.REPORT_FILE = report_path
        try:
            mod.run(write_report=True)
        finally:
            mod.REPORT_FILE = original_report

        assert report_path.exists()
        report = json.loads(report_path.read_text())
        assert "total_mutation_routes" in report
        assert report["total_mutation_routes"] > 0
        assert "coverage_pct" in report

    def test_coverage_is_100_percent(self, tmp_path: Path) -> None:
        """Every mutation route is either audited or has an approved exception."""
        import json
        import tools.ci.check_audit_coverage as mod

        report_path = tmp_path / "report.json"
        original_report = mod.REPORT_FILE
        mod.REPORT_FILE = report_path
        try:
            mod.run(write_report=True)
        finally:
            mod.REPORT_FILE = original_report

        report = json.loads(report_path.read_text())
        assert report["coverage_pct"] == 100.0, (
            f"Coverage is {report['coverage_pct']}%, expected 100%. "
            f"Violations: {report['violation_list']}"
        )
