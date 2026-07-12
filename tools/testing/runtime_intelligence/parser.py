"""Parse existing CI artifacts into RuntimeResult objects."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .fingerprints import (
    commit_fingerprint,
    dependency_fingerprint,
    environment_fingerprint,
    manifest_fingerprint,
    selector_fingerprint as _selector_fp,
)
from .models import RuntimeMetadata, RuntimeResult, SlowFixture, SlowTest  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_VERSION = "1.0"

# Standard JUnit output directory — written by pytest --junitxml
JUNIT_DIR = REPO_ROOT / "artifacts/ci/junit"

# Standard duration artifact path (fg-fast wall-clock timing)
_FAST_DUR_PATH = REPO_ROOT / "artifacts/ci/fg_fast_duration.json"


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _make_meta(gate: str, duration_seconds: float) -> RuntimeMetadata:
    return RuntimeMetadata(
        schema_version=SCHEMA_VERSION,
        gate=gate,
        commit_sha=commit_fingerprint(),
        workflow=os.getenv("GITHUB_WORKFLOW", "local"),
        job=os.getenv("GITHUB_JOB", "local"),
        runner_os=os.getenv("RUNNER_OS", "local"),
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        started_at=_now_iso(),
        completed_at=_now_iso(),
        duration_seconds=duration_seconds,
        environment_fingerprint=environment_fingerprint(),
        dependency_fingerprint=dependency_fingerprint(),
    )


def parse_fg_fast_artifact(artifact_path: Path | None = None) -> RuntimeResult | None:
    """Parse artifacts/ci/fg_fast_duration.json → RuntimeResult with accurate wall-clock."""
    path = artifact_path or _FAST_DUR_PATH
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    dur = float(data.get("duration_seconds", 0))
    meta = _make_meta("fg-fast", dur)
    return RuntimeResult(
        meta=meta,
        collected=0,
        passed=0,
        failed=0,
        skipped=0,
        xfailed=0,
        warnings=0,
        duration_seconds=dur,
        slowest_tests=(),
        slowest_fixtures=(),
    )


def parse_junit_xml(xml_path: Path, gate: str) -> RuntimeResult | None:
    """Parse a JUnit XML file → RuntimeResult. Returns None if file not found."""
    try:
        import xml.etree.ElementTree as ET  # stdlib
    except ImportError:
        return None
    if not xml_path.exists():
        return None
    try:
        tree = ET.parse(str(xml_path))
    except ET.ParseError as exc:
        print(
            f"[runtime-intelligence] malformed JUnit XML {xml_path}: {exc}",
            file=sys.stderr,
        )
        return None
    root = tree.getroot()
    # JUnit XML: <testsuite tests="N" failures="F" errors="E" skipped="S" time="T">
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        return None
    collected = int(suite.get("tests", 0))
    failed = int(suite.get("failures", 0)) + int(suite.get("errors", 0))
    skipped = int(suite.get("skipped", 0))
    passed = collected - failed - skipped
    dur = float(suite.get("time", 0))
    meta = _make_meta(gate, dur)

    # Extract slowest test cases and collect node_ids for manifest fingerprint
    cases: list[SlowTest] = []
    node_ids: list[str] = []
    for tc in suite.iter("testcase"):
        t = float(tc.get("time", 0))
        name = f"{tc.get('classname', '')}.{tc.get('name', '')}".strip(".")
        cases.append(SlowTest(node_id=name, duration_seconds=t, phase="call"))
        node_ids.append(name)
    cases.sort(key=lambda x: x.duration_seconds, reverse=True)

    return RuntimeResult(
        meta=meta,
        collected=collected,
        passed=passed,
        failed=failed,
        skipped=skipped,
        xfailed=0,
        warnings=0,
        duration_seconds=dur,
        slowest_tests=tuple(cases[:25]),
        slowest_fixtures=(),
        manifest_fingerprint=manifest_fingerprint(node_ids),
    )


def merge_artifacts(
    gate: str,
    junit_path: Path | None = None,
    duration_json_path: Path | None = None,
    selector: str = "",
) -> RuntimeResult | None:
    """
    Merge JUnit XML and duration artifact into a complete RuntimeResult.

    Priority:
      - JUnit XML provides: collected/passed/failed/skipped, slowest_tests,
        node_ids, manifest_fingerprint  (authoritative test counts)
      - Duration artifact provides: accurate wall-clock duration
        (pytest's internal `time` attribute under-counts setup overhead)

    Failure behaviour (advisory — never raises):
      - Missing JUnit  → warn, fall back to duration-only result
      - Malformed XML  → warn, fall back to duration-only result
      - Missing duration → use pytest-reported time from JUnit
      - Both missing   → return None
    """
    junit_result: RuntimeResult | None = None
    duration_result: RuntimeResult | None = None

    # Try JUnit (counts + manifest + slowest tests)
    if junit_path is not None:
        if junit_path.exists():
            junit_result = parse_junit_xml(junit_path, gate)
            if junit_result is None:
                print(
                    f"[runtime-intelligence] JUnit XML parse failed: {junit_path}",
                    file=sys.stderr,
                )
        else:
            print(
                f"[runtime-intelligence] JUnit XML not found: {junit_path}",
                file=sys.stderr,
            )

    # Try duration artifact (wall-clock accuracy)
    if duration_json_path is not None and duration_json_path.exists():
        try:
            duration_result = parse_fg_fast_artifact(duration_json_path)
        except Exception as exc:
            print(
                f"[runtime-intelligence] duration artifact parse failed: {exc}",
                file=sys.stderr,
            )

    if junit_result is None and duration_result is None:
        return None

    # Prefer JUnit as base (it has counts); fall back to duration-only
    base = junit_result if junit_result is not None else duration_result
    assert base is not None  # mypy: one of the two is non-None here

    # Use wall-clock duration when available and JUnit also succeeded
    if (
        duration_result is not None
        and junit_result is not None
        and duration_result.duration_seconds > 0
    ):
        wall_dur = duration_result.duration_seconds
        merged_meta = replace(base.meta, duration_seconds=wall_dur)
        base = replace(base, meta=merged_meta, duration_seconds=wall_dur)

    # Attach selector fingerprint
    sfp = _selector_fp(selector) if selector else ""
    return replace(base, selector_fingerprint=sfp)
