"""Runtime Intelligence package — gate telemetry and CI runtime analysis."""

from .fingerprints import (
    commit_fingerprint,
    dependency_fingerprint,
    environment_fingerprint,
    manifest_fingerprint,
)
from .ownership import classify_test_path, node_id_to_path
from .github_summary import generate_summary, write_step_summary
from .history import (
    append_result,
    baseline_collected_for_history,
    load_history,
    save_history,
)
from .models import (
    Regression,
    RollingStats,
    RuntimeMetadata,
    RuntimeResult,
    SlowFixture,
    SlowTest,
)
from .parser import parse_fg_fast_artifact, parse_junit_xml
from .recorder import record_gate_result
from .regression import RegressionSeverity, detect_regressions
from .serializer import from_json, to_json
from .statistics import compute_rolling_stats

__all__ = [
    "Regression",
    "RegressionSeverity",
    "RollingStats",
    "RuntimeMetadata",
    "RuntimeResult",
    "SlowFixture",
    "SlowTest",
    "append_result",
    "baseline_collected_for_history",
    "classify_test_path",
    "commit_fingerprint",
    "compute_rolling_stats",
    "dependency_fingerprint",
    "detect_regressions",
    "environment_fingerprint",
    "from_json",
    "generate_summary",
    "load_history",
    "manifest_fingerprint",
    "node_id_to_path",
    "parse_fg_fast_artifact",
    "parse_junit_xml",
    "record_gate_result",
    "save_history",
    "to_json",
    "write_step_summary",
]
