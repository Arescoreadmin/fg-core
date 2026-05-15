"""Safe telemetry static analysis tests.

Verifies that check_safe_telemetry.py:
  - correctly detects forbidden field names in metric labels, span attributes,
    and log extra= dicts (positive cases)
  - does not false-positive on safe field names (negative cases)
  - reports clean on the actual FrostGate codebase (integration gate)
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_source(source: str) -> list[str]:
    """Run the checker on an in-memory source string."""
    import ast

    from tools.ci.check_safe_telemetry import _Checker

    tree = ast.parse(textwrap.dedent(source))
    checker = _Checker(Path("<test>"))
    checker.visit(tree)
    return checker.violations


# ---------------------------------------------------------------------------
# Forbidden metric label names
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_metric_label_raw_prompt_is_forbidden():
    violations = _check_source("""
        from prometheus_client import Counter
        C = Counter("fg_test", "help", ["raw_prompt", "tenant_id"])
    """)
    assert any("raw_prompt" in v and "metric_label" in v for v in violations)


@pytest.mark.smoke
def test_metric_label_api_key_is_forbidden():
    violations = _check_source("""
        from prometheus_client import Histogram
        H = Histogram("fg_test", "help", ["api_key", "provider_id"])
    """)
    assert any("api_key" in v and "metric_label" in v for v in violations)


@pytest.mark.smoke
def test_metric_label_authorization_is_forbidden():
    violations = _check_source("""
        from prometheus_client import Gauge
        G = Gauge("fg_test", "help", ["authorization"])
    """)
    assert any("authorization" in v for v in violations)


@pytest.mark.smoke
def test_metric_label_safe_fields_are_allowed():
    violations = _check_source("""
        from prometheus_client import Counter
        C = Counter("fg_test", "help", ["tenant_id", "provider_id", "status", "mode"])
    """)
    assert not violations, f"False positives: {violations}"


# ---------------------------------------------------------------------------
# Forbidden span attribute keys
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_span_attribute_raw_chunk_is_forbidden():
    violations = _check_source("""
        span.set_attribute("raw_chunk", value)
    """)
    assert any("raw_chunk" in v and "span_attribute" in v for v in violations)


@pytest.mark.smoke
def test_span_attribute_provider_payload_is_forbidden():
    violations = _check_source("""
        span.set_attribute("provider_payload", json.dumps(payload))
    """)
    assert any("provider_payload" in v and "span_attribute" in v for v in violations)


@pytest.mark.smoke
def test_span_attribute_bearer_token_is_forbidden():
    violations = _check_source("""
        span.set_attribute("bearer_token", token)
    """)
    assert any("bearer_token" in v or "bearer" in v for v in violations)


@pytest.mark.smoke
def test_span_attribute_safe_fields_are_allowed():
    violations = _check_source("""
        span.set_attribute("tenant.id", tenant_id)
        span.set_attribute("doc.type", doc_type)
        span.set_attribute("provider.id", provider_id)
        span.set_attribute("policy.version", version)
        span.set_attribute("retrieval.mode", mode)
    """)
    assert not violations, f"False positives: {violations}"


# ---------------------------------------------------------------------------
# Forbidden log extra= keys
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_log_extra_api_key_is_forbidden():
    violations = _check_source("""
        import logging
        logger = logging.getLogger("test")
        logger.info("msg", extra={"api_key": key, "tenant_id": tid})
    """)
    assert any("api_key" in v and "log_extra_key" in v for v in violations)


@pytest.mark.smoke
def test_log_extra_raw_prompt_is_forbidden():
    violations = _check_source("""
        logger.warning("oops", extra={"raw_prompt": prompt, "request_id": rid})
    """)
    assert any("raw_prompt" in v and "log_extra_key" in v for v in violations)


@pytest.mark.smoke
def test_log_extra_safe_fields_are_allowed():
    violations = _check_source("""
        logger.info("req", extra={
            "request_id": rid,
            "tenant_id": tid,
            "trace_id": tid,
            "span_id": sid,
            "duration_ms": ms,
            "status_code": code,
            "provider_id": pid,
        })
    """)
    assert not violations, f"False positives: {violations}"


# ---------------------------------------------------------------------------
# Integration: actual FrostGate codebase must be clean
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_frostgate_codebase_has_no_safe_telemetry_violations():
    """The entire api/ and services/ tree must pass the safe-telemetry check."""
    from tools.ci.check_safe_telemetry import check_file, collect_python_files

    repo_root = Path(__file__).parent.parent
    roots = [repo_root / "api", repo_root / "services"]
    files = collect_python_files(roots)
    assert files, "No Python files found — check roots"

    all_violations: list[str] = []
    for f in files:
        all_violations.extend(check_file(f))

    assert not all_violations, (
        "Safe-telemetry violations in production code:\n"
        + "\n".join(f"  {v}" for v in sorted(all_violations))
    )


@pytest.mark.smoke
def test_safe_telemetry_checker_handles_syntax_error_gracefully():
    """A file with invalid Python must produce no violations (not crash)."""
    from tools.ci.check_safe_telemetry import check_file
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write("def (broken syntax:")
        tmp = Path(f.name)

    try:
        violations = check_file(tmp)
        assert violations == [], "Syntax errors should return empty, not crash"
    finally:
        tmp.unlink(missing_ok=True)
