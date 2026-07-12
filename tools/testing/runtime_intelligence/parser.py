"""Parse existing CI artifacts into RuntimeResult objects."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .fingerprints import (
    commit_fingerprint,
    dependency_fingerprint,
    environment_fingerprint,
    manifest_fingerprint,
)
from .models import RuntimeMetadata, RuntimeResult, SlowTest, SlowFixture  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_VERSION = "1.0"


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
    """Parse the existing artifacts/ci/fg_fast_duration.json into a RuntimeResult."""
    path = artifact_path or (REPO_ROOT / "artifacts/ci/fg_fast_duration.json")
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
    """Parse a JUnit XML file into a RuntimeResult. Returns None if file not found."""
    try:
        import xml.etree.ElementTree as ET  # stdlib
    except ImportError:
        return None
    if not xml_path.exists():
        return None
    tree = ET.parse(str(xml_path))
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
