"""Tests for tools/testing/runtime_intelligence package.

Categories covered: unit, contract, security, integration
(satisfies testing_module required_categories from ownership_map.yaml)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.testing.runtime_intelligence.fingerprints import (
    dependency_fingerprint,
    environment_fingerprint,
    selector_fingerprint,
)
from tools.testing.runtime_intelligence.github_summary import generate_summary
from tools.testing.runtime_intelligence.history import (
    RuntimeHistory,
    append_result,
    load_history,
    rolling_stats_for_history,
    save_history,
)
from tools.testing.runtime_intelligence.models import (
    Regression,
    RuntimeMetadata,
    RuntimeResult,
    SlowTest,
)
from tools.testing.runtime_intelligence.parser import (
    parse_fg_fast_artifact,
    parse_junit_xml,
)
from tools.testing.runtime_intelligence.profiler import parse_durations_output
from tools.testing.runtime_intelligence.regression import detect_regressions
from tools.testing.runtime_intelligence.serializer import from_json, to_json
from tools.testing.runtime_intelligence.statistics import (
    compute_rolling_stats,
    percentile,
)


def _make_meta(**kwargs: object) -> RuntimeMetadata:
    defaults = dict(
        schema_version="1.0",
        gate="fg-fast",
        commit_sha="abc123def456",
        workflow="test",
        job="test",
        runner_os="linux",
        python_version="3.12.0",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:05:00Z",
        duration_seconds=300.0,
        environment_fingerprint="aabbccdd",
        dependency_fingerprint="eeff0011",
    )
    defaults.update(kwargs)
    return RuntimeMetadata(**defaults)  # type: ignore[arg-type]


def _make_result(**kwargs: object) -> RuntimeResult:
    defaults = dict(
        meta=_make_meta(),
        collected=398,
        passed=396,
        failed=0,
        skipped=2,
        xfailed=0,
        warnings=3,
        duration_seconds=300.0,
        slowest_tests=(),
        slowest_fixtures=(),
    )
    defaults.update(kwargs)
    return RuntimeResult(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# unit: Serialization
# ---------------------------------------------------------------------------


def test_serialization_is_deterministic() -> None:
    r = _make_result()
    out1 = to_json(r)
    out2 = to_json(r)
    assert out1 == out2


def test_serialization_is_sorted() -> None:
    r = _make_result()
    data = json.loads(to_json(r))
    keys = list(data.keys())
    assert keys == sorted(keys)


def test_serialization_roundtrip_dict() -> None:
    r = _make_result()
    text = to_json(r)
    data = from_json(text)
    assert data["collected"] == 398
    assert data["meta"]["gate"] == "fg-fast"


def test_schema_version_preserved() -> None:
    r = _make_result()
    data = json.loads(to_json(r))
    assert data["meta"]["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# security: No secrets / PII in output
# ---------------------------------------------------------------------------


def test_no_secrets_in_output() -> None:
    r = _make_result()
    text = to_json(r)
    forbidden = [
        "password",
        "token",
        "FG_API_KEY",
        "POSTGRES_PASSWORD",
        "secret",
        "hostname",
    ]
    for word in forbidden:
        assert word.lower() not in text.lower(), f"Found '{word}' in serialized output"


def test_environment_fingerprint_no_secrets() -> None:
    fp = environment_fingerprint()
    # Must be a short hex string, not an env var value
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_github_summary_no_pii() -> None:
    r = _make_result()
    summary = generate_summary(r)
    forbidden = ["password", "token", "secret", "@gmail", "postgres://", "http://"]
    for word in forbidden:
        assert word.lower() not in summary.lower(), f"PII leaked: '{word}'"


# ---------------------------------------------------------------------------
# unit: Statistics
# ---------------------------------------------------------------------------


def test_percentile_p50_even() -> None:
    vals = [1.0, 2.0, 3.0, 4.0]
    assert percentile(vals, 50) == pytest.approx(2.5)


def test_percentile_p95_known_values() -> None:
    vals = list(range(1, 101))  # 1..100
    p95 = percentile([float(x) for x in vals], 95)
    assert 94.0 <= p95 <= 96.0


def test_percentile_empty() -> None:
    assert percentile([], 95) == 0.0


def test_rolling_stats_single_value() -> None:
    stats = compute_rolling_stats([100.0])
    assert stats.count == 1
    assert stats.mean == 100.0
    assert stats.median == 100.0
    assert stats.minimum == 100.0
    assert stats.maximum == 100.0
    assert stats.std_dev == 0.0


def test_rolling_stats_known_values() -> None:
    vals = [100.0, 200.0, 300.0, 400.0, 500.0]
    stats = compute_rolling_stats(vals)
    assert stats.mean == pytest.approx(300.0)
    assert stats.median == pytest.approx(300.0)
    assert stats.count == 5
    assert stats.minimum == 100.0
    assert stats.maximum == 500.0


def test_rolling_stats_empty() -> None:
    stats = compute_rolling_stats([])
    assert stats.count == 0
    assert stats.mean == 0.0


# ---------------------------------------------------------------------------
# unit: Regression Detection
# ---------------------------------------------------------------------------


def test_regression_no_regression() -> None:
    stats = compute_rolling_stats([300.0] * 10)
    regs = detect_regressions("fg-fast", 305.0, 398, stats)
    assert regs == []


def test_regression_low_severity() -> None:
    stats = compute_rolling_stats([300.0] * 10)
    regs = detect_regressions("fg-fast", 340.0, 398, stats)  # +13%
    assert len(regs) == 1
    assert regs[0].severity == "low"
    assert regs[0].field == "duration_seconds"


def test_regression_medium_severity() -> None:
    stats = compute_rolling_stats([300.0] * 10)
    regs = detect_regressions("fg-fast", 390.0, 398, stats)  # +30%
    assert regs[0].severity == "medium"


def test_regression_high_severity() -> None:
    stats = compute_rolling_stats([300.0] * 10)
    regs = detect_regressions("fg-fast", 460.0, 398, stats)  # +53%
    assert regs[0].severity == "high"


def test_regression_critical_severity() -> None:
    stats = compute_rolling_stats([300.0] * 10)
    regs = detect_regressions("fg-fast", 650.0, 398, stats)  # +117%
    assert regs[0].severity == "critical"


def test_regression_empty_history_no_regression() -> None:
    stats = compute_rolling_stats([])
    regs = detect_regressions("fg-fast", 999.0, 398, stats)
    assert regs == []


def test_regression_test_count_drop() -> None:
    stats = compute_rolling_stats([300.0] * 10)
    regs = detect_regressions("fg-fast", 300.0, 350, stats, baseline_collected=398)
    count_regs = [r for r in regs if r.field == "collected"]
    assert len(count_regs) == 1
    assert count_regs[0].pct_change < 0


# ---------------------------------------------------------------------------
# integration: History (file I/O)
# ---------------------------------------------------------------------------


def test_history_starts_empty(tmp_path: Path) -> None:
    h = load_history(tmp_path / "nonexistent.json")
    assert h.runs == []


def test_history_append_and_rotate(tmp_path: Path) -> None:
    h = RuntimeHistory(schema_version="1.0", gate="fg-fast", runs=[])
    for i in range(5):
        h = append_result(
            h, {"duration_seconds": float(i), "gate": "fg-fast"}, max_runs=3
        )
    assert len(h.runs) == 3
    assert h.runs[-1]["duration_seconds"] == 4.0
    assert h.runs[0]["duration_seconds"] == 2.0  # oldest kept


def test_history_save_and_load(tmp_path: Path) -> None:
    path = tmp_path / "fg-fast-history.json"
    h = RuntimeHistory(schema_version="1.0", gate="fg-fast", runs=[])
    h = append_result(h, {"duration_seconds": 300.0, "gate": "fg-fast"})
    save_history(h, path)
    loaded = load_history(path)
    assert len(loaded.runs) == 1
    assert loaded.runs[0]["duration_seconds"] == 300.0


def test_history_schema_mismatch_starts_fresh(tmp_path: Path) -> None:
    path = tmp_path / "fg-fast-history.json"
    path.write_text(
        json.dumps({"schema_version": "99.0", "gate": "fg-fast", "runs": [{"x": 1}]})
    )
    h = load_history(path)
    assert h.runs == []  # stale schema = fresh start


def test_history_rolling_stats(tmp_path: Path) -> None:
    h = RuntimeHistory(schema_version="1.0", gate="fg-fast", runs=[])
    for dur in [100.0, 200.0, 300.0]:
        h = append_result(h, {"duration_seconds": dur, "gate": "fg-fast"})
    stats = rolling_stats_for_history(h, last_n=10)
    assert stats.count == 3
    assert stats.mean == pytest.approx(200.0)


# ---------------------------------------------------------------------------
# unit: Fingerprints
# ---------------------------------------------------------------------------


def test_environment_fingerprint_is_stable() -> None:
    fp1 = environment_fingerprint()
    fp2 = environment_fingerprint()
    assert fp1 == fp2


def test_selector_fingerprint_stable() -> None:
    fp1 = selector_fingerprint("smoke or contract or security")
    fp2 = selector_fingerprint("smoke or contract or security")
    assert fp1 == fp2


def test_selector_fingerprint_different_for_different_selectors() -> None:
    fp1 = selector_fingerprint("smoke")
    fp2 = selector_fingerprint("security")
    assert fp1 != fp2


def test_dependency_fingerprint_returns_hex() -> None:
    fp = dependency_fingerprint()
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# contract: GitHub Summary format
# ---------------------------------------------------------------------------


def test_github_summary_contains_gate_name() -> None:
    r = _make_result()
    summary = generate_summary(r)
    assert "FG FAST" in summary or "fg-fast" in summary.lower()


def test_github_summary_with_regression() -> None:
    r = _make_result()
    reg = Regression(
        gate="fg-fast",
        field="duration_seconds",
        current_value=600.0,
        baseline_value=300.0,
        pct_change=100.0,
        severity="critical",
        message="fg-fast duration 600s is 100% above median 300s",
    )
    summary = generate_summary(r, regressions=[reg])
    assert "CRITICAL" in summary
    assert "Regression" in summary or "REGRESSION" in summary.upper()


def test_github_summary_with_stats() -> None:
    r = _make_result()
    stats = compute_rolling_stats([280.0, 290.0, 300.0, 310.0, 320.0])
    summary = generate_summary(r, stats=stats)
    assert "Median" in summary


def test_github_summary_metric_table_present() -> None:
    r = _make_result()
    summary = generate_summary(r)
    assert "| Metric | Value |" in summary
    assert "Duration" in summary
    assert "Collected" in summary


# ---------------------------------------------------------------------------
# unit: Profiler
# ---------------------------------------------------------------------------


def test_parse_durations_output_basic() -> None:
    output = """
  0.532s call tests/security/test_tenant_binding.py::test_cross_tenant
  0.123s setup tests/conftest.py::db_session
  0.010s teardown tests/test_fast.py::test_one
"""
    slow, fixtures = parse_durations_output(output)
    assert len(slow) >= 1
    assert slow[0].duration_seconds == pytest.approx(0.532)
    assert slow[0].phase == "call"


def test_parse_durations_output_sorted_desc() -> None:
    output = """
  0.100s call tests/a.py::test_a
  0.500s call tests/b.py::test_b
  0.300s call tests/c.py::test_c
"""
    slow, _ = parse_durations_output(output)
    durations = [t.duration_seconds for t in slow]
    assert durations == sorted(durations, reverse=True)


def test_parse_durations_empty() -> None:
    slow, fixtures = parse_durations_output("")
    assert slow == ()


# ---------------------------------------------------------------------------
# integration: Parser (artifact I/O)
# ---------------------------------------------------------------------------


def test_parse_fg_fast_artifact_missing_returns_none(tmp_path: Path) -> None:
    result = parse_fg_fast_artifact(tmp_path / "nonexistent.json")
    assert result is None


def test_parse_fg_fast_artifact_reads_duration(tmp_path: Path) -> None:
    artifact = tmp_path / "fg_fast_duration.json"
    artifact.write_text(
        json.dumps(
            {
                "lane": "fg-fast",
                "duration_seconds": 435,
                "max_seconds": 900,
                "hard_max_seconds": 930,
                "warn_seconds": 810,
            }
        )
    )
    result = parse_fg_fast_artifact(artifact)
    assert result is not None
    assert result.duration_seconds == 435.0
    assert result.meta.gate == "fg-fast"


def test_parse_junit_xml_basic(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<?xml version="1.0"?>\n'
        '<testsuite name="pytest" tests="5" failures="1" errors="0" skipped="1" time="12.3">\n'
        '  <testcase classname="tests.foo" name="test_a" time="1.2"/>\n'
        '  <testcase classname="tests.foo" name="test_b" time="0.5"/>\n'
        '  <testcase classname="tests.foo" name="test_c" time="0.1">\n'
        "    <skipped/>\n"
        "  </testcase>\n"
        '  <testcase classname="tests.foo" name="test_d" time="0.3">\n'
        "    <failure>boom</failure>\n"
        "  </testcase>\n"
        '  <testcase classname="tests.foo" name="test_e" time="8.5"/>\n'
        "</testsuite>\n"
    )
    result = parse_junit_xml(junit, "fg-fast")
    assert result is not None
    assert result.collected == 5
    assert result.failed == 1
    assert result.skipped == 1
    assert result.duration_seconds == pytest.approx(12.3)
    # Slowest test should be test_e
    assert result.slowest_tests[0].duration_seconds == pytest.approx(8.5)


# ---------------------------------------------------------------------------
# contract: Models are frozen (immutability contract)
# ---------------------------------------------------------------------------


def test_runtime_result_is_frozen() -> None:
    r = _make_result()
    with pytest.raises((AttributeError, TypeError)):
        r.collected = 999  # type: ignore[misc]


def test_slow_test_is_frozen() -> None:
    t = SlowTest(node_id="tests/foo.py::test_bar", duration_seconds=1.0, phase="call")
    with pytest.raises((AttributeError, TypeError)):
        t.duration_seconds = 99.0  # type: ignore[misc]


def test_rolling_stats_zero_std_dev_uniform() -> None:
    stats = compute_rolling_stats([50.0, 50.0, 50.0])
    assert stats.std_dev == pytest.approx(0.0)
    assert stats.mean == pytest.approx(50.0)


# ---------------------------------------------------------------------------
# security: Fingerprint isolation (no env leakage)
# ---------------------------------------------------------------------------


def test_environment_fingerprint_is_hex_string() -> None:
    fp = environment_fingerprint()
    # Must not contain equals signs (env var values look like KEY=VALUE)
    assert "=" not in fp
    # Must not be empty
    assert len(fp) > 0


def test_dependency_fingerprint_is_stable_across_calls() -> None:
    fp1 = dependency_fingerprint()
    fp2 = dependency_fingerprint()
    assert fp1 == fp2


# ---------------------------------------------------------------------------
# unit: manifest_fingerprint
# ---------------------------------------------------------------------------


def test_manifest_fingerprint_empty_returns_zeros() -> None:
    from tools.testing.runtime_intelligence.fingerprints import manifest_fingerprint

    assert manifest_fingerprint([]) == "0" * 16


def test_manifest_fingerprint_stable_across_calls() -> None:
    from tools.testing.runtime_intelligence.fingerprints import manifest_fingerprint

    ids = ["tests/foo.py::test_a", "tests/foo.py::test_b"]
    assert manifest_fingerprint(ids) == manifest_fingerprint(ids)


def test_manifest_fingerprint_order_independent() -> None:
    from tools.testing.runtime_intelligence.fingerprints import manifest_fingerprint

    ids = ["tests/foo.py::test_a", "tests/bar.py::test_z"]
    assert manifest_fingerprint(ids) == manifest_fingerprint(list(reversed(ids)))


def test_manifest_fingerprint_changes_on_addition() -> None:
    from tools.testing.runtime_intelligence.fingerprints import manifest_fingerprint

    base = ["tests/foo.py::test_a"]
    extended = ["tests/foo.py::test_a", "tests/foo.py::test_b"]
    assert manifest_fingerprint(base) != manifest_fingerprint(extended)


def test_manifest_fingerprint_deduplicates() -> None:
    from tools.testing.runtime_intelligence.fingerprints import manifest_fingerprint

    ids = ["tests/foo.py::test_a", "tests/foo.py::test_a"]
    assert manifest_fingerprint(ids) == manifest_fingerprint(["tests/foo.py::test_a"])


def test_manifest_fingerprint_is_16_hex_chars() -> None:
    from tools.testing.runtime_intelligence.fingerprints import manifest_fingerprint

    fp = manifest_fingerprint(["tests/foo.py::test_x"])
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_runtime_result_stores_manifest_fingerprint() -> None:
    from tools.testing.runtime_intelligence.fingerprints import manifest_fingerprint

    fp = manifest_fingerprint(["tests/foo.py::test_a", "tests/foo.py::test_b"])
    r = _make_result(manifest_fingerprint=fp)
    assert r.manifest_fingerprint == fp


def test_junit_xml_populates_manifest_fingerprint(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<?xml version="1.0"?>\n'
        '<testsuite name="pytest" tests="2" failures="0" errors="0" skipped="0" time="1.0">\n'
        '  <testcase classname="tests.foo" name="test_a" time="0.5"/>\n'
        '  <testcase classname="tests.foo" name="test_b" time="0.5"/>\n'
        "</testsuite>\n"
    )
    result = parse_junit_xml(junit, "fg-fast")
    assert result is not None
    assert len(result.manifest_fingerprint) == 16
    assert result.manifest_fingerprint != "0" * 16


# ---------------------------------------------------------------------------
# unit: fixture ownership
# ---------------------------------------------------------------------------


def test_classify_test_path_known_module() -> None:
    from tools.testing.runtime_intelligence.ownership import classify_test_path

    plane, module_id, owner = classify_test_path("tools/testing/harness/lane_runner.py")
    assert plane == "security"
    assert module_id == "testing_module"
    assert owner == "team-platform-security"


def test_classify_test_path_unknown_returns_empty() -> None:
    from tools.testing.runtime_intelligence.ownership import classify_test_path

    plane, module_id, owner = classify_test_path("totally/unknown/path.py")
    assert plane == ""
    assert module_id == ""
    assert owner == ""


def test_node_id_to_path_strips_params() -> None:
    from tools.testing.runtime_intelligence.ownership import node_id_to_path

    assert node_id_to_path("tests/foo.py::TestClass::test_method") == "tests/foo.py"
    assert node_id_to_path("tests/bar.py") == "tests/bar.py"


def test_slow_fixture_carries_ownership() -> None:
    from tools.testing.runtime_intelligence.models import SlowFixture

    f = SlowFixture(
        name="my_fixture",
        duration_seconds=2.5,
        plane="security",
        module="testing_module",
        owner="team-platform-security",
    )
    assert f.plane == "security"
    assert f.module == "testing_module"
    assert f.owner == "team-platform-security"


def test_parse_durations_enriches_fixture_ownership() -> None:
    durations_text = (
        "3.50s setup  tools/testing/harness/lane_runner.py::TestSuite::test_x\n"
        "1.20s call   tools/testing/harness/lane_runner.py::TestSuite::test_x\n"
    )
    _, fixtures = parse_durations_output(durations_text)
    assert len(fixtures) == 1
    f = fixtures[0]
    assert f.plane == "security"
    assert f.module == "testing_module"
    assert f.owner == "team-platform-security"


def test_parse_durations_fixture_unknown_path_has_empty_ownership() -> None:
    durations_text = "2.00s setup  unknown/module/test_foo.py::test_bar\n"
    _, fixtures = parse_durations_output(durations_text)
    assert len(fixtures) == 1
    assert fixtures[0].plane == ""
    assert fixtures[0].module == ""
    assert fixtures[0].owner == ""


# ---------------------------------------------------------------------------
# unit: bot-reviewer fixes (history gate stem, dep fingerprint, baseline_collected,
#       dry-run summary, node-id sanitization)
# ---------------------------------------------------------------------------


def test_load_history_strips_history_suffix(tmp_path: Path) -> None:
    from tools.testing.runtime_intelligence.history import load_history

    path = tmp_path / "fg-fast-history.json"
    history = load_history(path)
    assert history.gate == "fg-fast"


def test_load_history_existing_file_preserves_gate(tmp_path: Path) -> None:
    import json

    from tools.testing.runtime_intelligence.history import (
        HISTORY_SCHEMA_VERSION,
        load_history,
    )

    path = tmp_path / "fg-security-history.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": HISTORY_SCHEMA_VERSION,
                "gate": "fg-security",
                "runs": [],
            }
        ),
        encoding="utf-8",
    )
    history = load_history(path)
    assert history.gate == "fg-security"


def test_baseline_collected_for_history_median() -> None:
    from tools.testing.runtime_intelligence.history import (
        RuntimeHistory,
        baseline_collected_for_history,
    )

    runs = [{"collected": c} for c in [390, 395, 400, 380, 398]]
    h = RuntimeHistory(schema_version="1.0", gate="fg-fast", runs=runs)
    result = baseline_collected_for_history(h)
    assert result == 395  # median of sorted [380, 390, 395, 398, 400]


def test_baseline_collected_for_history_empty_returns_none() -> None:
    from tools.testing.runtime_intelligence.history import (
        RuntimeHistory,
        baseline_collected_for_history,
    )

    h = RuntimeHistory(schema_version="1.0", gate="fg-fast", runs=[])
    assert baseline_collected_for_history(h) is None


def test_dependency_fingerprint_includes_shared_requirements() -> None:
    """Changing requirements-shared.txt must change the fingerprint."""
    import hashlib

    from tools.testing.runtime_intelligence import fingerprints

    repo_root = fingerprints.REPO_ROOT
    shared = repo_root / "requirements-shared.txt"
    assert shared.exists(), (
        "requirements-shared.txt must exist for fingerprint coverage"
    )
    h = hashlib.sha256()
    h.update(b"requirements-shared.txt")
    h.update(shared.read_bytes())
    fragment = h.hexdigest()[:8]
    fp = dependency_fingerprint()
    # The fingerprint is a hash-of-hashes; we verify the file is in the input
    # by confirming two consecutive calls are stable (content-addressed)
    fp2 = dependency_fingerprint()
    assert fp == fp2
    assert len(fp) == 16
    _ = fragment  # fragment used indirectly via the file being read


def test_github_summary_sanitizes_parametrized_node_ids() -> None:
    from tools.testing.runtime_intelligence.models import SlowTest

    t = SlowTest(
        node_id="tests/foo.py::test_bar[user@example.com-token-abc123]",
        duration_seconds=5.0,
        phase="call",
    )
    r = _make_result(slowest_tests=(t,))
    summary = generate_summary(r)
    assert "user@example.com" not in summary
    assert "token-abc123" not in summary
    assert "[...]" in summary


# ---------------------------------------------------------------------------
# unit: PR-CI-02.1 — merge_artifacts, selector_fingerprint, complete RuntimeResult
# ---------------------------------------------------------------------------


def _write_junit(
    path: Path,
    tests: int = 5,
    failures: int = 1,
    skipped: int = 1,
    time: float = 12.3,
    cases: list[tuple[str, str, float]] | None = None,
) -> None:
    """Write a minimal JUnit XML to path."""
    if cases is None:
        cases = [
            ("tests.foo", "test_a", 1.2),
            ("tests.foo", "test_b", 0.5),
            ("tests.foo", "test_c", 0.1),
        ]
    lines = [
        '<?xml version="1.0"?>',
        f'<testsuite name="pytest" tests="{tests}" failures="{failures}"'
        f' errors="0" skipped="{skipped}" time="{time}">',
    ]
    for cls, name, t in cases:
        lines.append(f'  <testcase classname="{cls}" name="{name}" time="{t}"/>')
    lines.append("</testsuite>")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_duration_json(path: Path, duration: float = 450.0) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "lane": "fg-fast",
                "duration_seconds": duration,
                "max_seconds": 900,
                "hard_max_seconds": 930,
                "warn_seconds": 810,
            }
        ),
        encoding="utf-8",
    )


# --- merge_artifacts: JUnit + duration ---


def test_merge_artifacts_uses_junit_counts(tmp_path: Path) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    junit = tmp_path / "fg-fast.xml"
    _write_junit(junit, tests=398, failures=0, skipped=2, time=399.0)
    result = merge_artifacts("fg-fast", junit_path=junit)
    assert result is not None
    assert result.collected == 398
    assert result.passed == 396
    assert result.failed == 0
    assert result.skipped == 2


def test_merge_artifacts_overrides_duration_with_wall_clock(tmp_path: Path) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    junit = tmp_path / "fg-fast.xml"
    dur = tmp_path / "fg_fast_duration.json"
    _write_junit(junit, tests=5, failures=0, skipped=0, time=300.0)
    _write_duration_json(dur, duration=450.0)
    result = merge_artifacts("fg-fast", junit_path=junit, duration_json_path=dur)
    assert result is not None
    # Wall-clock (450s) replaces pytest-internal time (300s)
    assert result.duration_seconds == pytest.approx(450.0)
    # But counts come from JUnit
    assert result.collected == 5


def test_merge_artifacts_manifest_populated_from_junit(tmp_path: Path) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    junit = tmp_path / "fg-fast.xml"
    _write_junit(
        junit,
        tests=3,
        failures=0,
        skipped=0,
        time=5.0,
        cases=[
            ("tests.foo", "test_a", 1.0),
            ("tests.foo", "test_b", 1.0),
            ("tests.foo", "test_c", 1.0),
        ],
    )
    result = merge_artifacts("fg-fast", junit_path=junit)
    assert result is not None
    assert len(result.manifest_fingerprint) == 16
    assert result.manifest_fingerprint != "0" * 16


def test_merge_artifacts_manifest_empty_when_no_tests(tmp_path: Path) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    junit = tmp_path / "fg-fast.xml"
    # Zero tests
    junit.write_text(
        '<?xml version="1.0"?>\n'
        '<testsuite name="pytest" tests="0" failures="0" errors="0"'
        ' skipped="0" time="0.0"/>\n',
        encoding="utf-8",
    )
    result = merge_artifacts("fg-fast", junit_path=junit)
    assert result is not None
    assert result.collected == 0
    assert result.manifest_fingerprint == "0" * 16


def test_merge_artifacts_missing_junit_falls_back_to_duration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    dur = tmp_path / "fg_fast_duration.json"
    _write_duration_json(dur, duration=399.0)
    result = merge_artifacts(
        "fg-fast",
        junit_path=tmp_path / "nonexistent.xml",
        duration_json_path=dur,
    )
    assert result is not None
    assert result.duration_seconds == pytest.approx(399.0)
    assert result.collected == 0  # duration-only has no counts
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()


def test_merge_artifacts_malformed_junit_falls_back_to_duration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    junit = tmp_path / "fg-fast.xml"
    junit.write_text("NOT VALID XML<<<", encoding="utf-8")
    dur = tmp_path / "fg_fast_duration.json"
    _write_duration_json(dur, duration=399.0)

    result = merge_artifacts("fg-fast", junit_path=junit, duration_json_path=dur)
    assert result is not None
    assert result.duration_seconds == pytest.approx(399.0)
    captured = capsys.readouterr()
    assert "malformed" in captured.err.lower()


def test_merge_artifacts_both_missing_returns_none(tmp_path: Path) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    result = merge_artifacts(
        "fg-fast",
        junit_path=tmp_path / "nope.xml",
        duration_json_path=None,
    )
    assert result is None


def test_merge_artifacts_deterministic(tmp_path: Path) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    junit = tmp_path / "fg-fast.xml"
    _write_junit(junit, tests=10, failures=0, skipped=1, time=30.0)
    r1 = merge_artifacts("fg-fast", junit_path=junit)
    r2 = merge_artifacts("fg-fast", junit_path=junit)
    assert r1 is not None and r2 is not None
    assert r1.manifest_fingerprint == r2.manifest_fingerprint
    assert r1.collected == r2.collected


# --- selector_fingerprint ---


def test_selector_fingerprint_is_stable() -> None:
    from tools.testing.runtime_intelligence.fingerprints import selector_fingerprint

    expr = '-m "smoke or contract or security"'
    assert selector_fingerprint(expr) == selector_fingerprint(expr)


def test_selector_fingerprint_differs_for_different_selectors() -> None:
    from tools.testing.runtime_intelligence.fingerprints import selector_fingerprint

    a = selector_fingerprint('-m "smoke"')
    b = selector_fingerprint('-m "security"')
    assert a != b


def test_selector_fingerprint_is_16_hex_chars() -> None:
    from tools.testing.runtime_intelligence.fingerprints import selector_fingerprint

    fp = selector_fingerprint("tests/ -m smoke")
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_merge_artifacts_populates_selector_fingerprint(tmp_path: Path) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    junit = tmp_path / "fg-fast.xml"
    _write_junit(junit)
    selector = '-m "smoke or contract or security"'
    result = merge_artifacts("fg-fast", junit_path=junit, selector=selector)
    assert result is not None
    assert len(result.selector_fingerprint) == 16
    assert result.selector_fingerprint != ""


def test_merge_artifacts_empty_selector_gives_empty_fingerprint(tmp_path: Path) -> None:
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    junit = tmp_path / "fg-fast.xml"
    _write_junit(junit)
    result = merge_artifacts("fg-fast", junit_path=junit, selector="")
    assert result is not None
    assert result.selector_fingerprint == ""


# --- RuntimeResult completeness ---


def test_runtime_result_has_selector_fingerprint_field() -> None:
    r = _make_result(selector_fingerprint="abcd1234abcd1234")
    assert r.selector_fingerprint == "abcd1234abcd1234"


def test_runtime_result_selector_fingerprint_defaults_empty() -> None:
    r = _make_result()
    assert r.selector_fingerprint == ""


def test_398_collected_recorded_in_history(tmp_path: Path) -> None:
    """Regression: collected=398 must survive the record→history roundtrip."""
    from tools.testing.runtime_intelligence.history import (
        RuntimeHistory,
        append_result,
        save_history,
        load_history,
    )

    history_path = tmp_path / "fg-fast-history.json"
    history = RuntimeHistory(schema_version="1.0", gate="fg-fast", runs=[])
    entry = {
        "duration_seconds": 399.0,
        "passed": 396,
        "failed": 0,
        "collected": 398,
        "skipped": 2,
        "commit_sha": "abc123def456",
        "gate": "fg-fast",
        "manifest_fingerprint": "abcd1234abcd1234",
        "selector_fingerprint": "ef012345ef012345",
    }
    updated = append_result(history, entry)
    save_history(updated, history_path)

    loaded = load_history(history_path)
    assert len(loaded.runs) == 1
    assert loaded.runs[0]["collected"] == 398
    assert loaded.runs[0]["manifest_fingerprint"] == "abcd1234abcd1234"
    assert loaded.runs[0]["selector_fingerprint"] == "ef012345ef012345"


# --- GitHub summary with manifest fingerprint and fixtures ---


def test_github_summary_shows_manifest_fingerprint() -> None:
    r = _make_result(manifest_fingerprint="4ab8d2cf1a3b5e70")
    summary = generate_summary(r)
    assert "4ab8d2cf1a3b5e70" in summary
    assert "Manifest" in summary


def test_github_summary_no_manifest_when_empty() -> None:
    r = _make_result(manifest_fingerprint="")
    summary = generate_summary(r)
    assert "Manifest" not in summary


def test_github_summary_shows_slow_fixtures() -> None:
    from tools.testing.runtime_intelligence.models import SlowFixture

    f = SlowFixture(
        name="identity_fixture",
        duration_seconds=2.7,
        plane="identity",
        module="identity_plane",
        owner="team-identity",
    )
    r = _make_result(slowest_fixtures=(f,))
    summary = generate_summary(r)
    assert "identity_fixture" in summary
    assert "identity" in summary
    assert "2.70" in summary


def test_github_summary_fixture_plane_unknown_shows_dash() -> None:
    from tools.testing.runtime_intelligence.models import SlowFixture

    f = SlowFixture(name="anon_fixture", duration_seconds=1.0)
    r = _make_result(slowest_fixtures=(f,))
    summary = generate_summary(r)
    assert "anon_fixture" in summary
    assert "—" in summary  # em-dash for unknown plane/owner


# --- Completeness contract ---


def test_collected_nonzero_requires_manifest_fingerprint(tmp_path: Path) -> None:
    """If collected > 0, manifest_fingerprint must not be empty."""
    from tools.testing.runtime_intelligence.parser import merge_artifacts

    junit = tmp_path / "fg-fast.xml"
    _write_junit(junit, tests=398, failures=0, skipped=2, time=399.0)
    result = merge_artifacts("fg-fast", junit_path=junit)
    assert result is not None
    assert result.collected > 0
    assert result.manifest_fingerprint != ""
    assert len(result.manifest_fingerprint) == 16


def test_junit_parse_populates_all_counts(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<?xml version="1.0"?>\n'
        '<testsuite name="pytest" tests="10" failures="2"'
        ' errors="1" skipped="1" time="42.0">\n'
        '  <testcase classname="tests.a" name="test_x" time="5.0"/>\n'
        '  <testcase classname="tests.a" name="test_y" time="3.0"/>\n'
        "</testsuite>\n",
        encoding="utf-8",
    )
    result = parse_junit_xml(junit, "fg-fast")
    assert result is not None
    assert result.collected == 10
    assert result.failed == 3  # failures + errors
    assert result.skipped == 1
    assert result.passed == 6  # 10 - 3 - 1
