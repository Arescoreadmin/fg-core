"""Runtime Intelligence package — gate telemetry and CI runtime analysis."""

from .fingerprints import (
    commit_fingerprint,
    dependency_fingerprint,
    environment_fingerprint,
    manifest_fingerprint,
    selector_fingerprint,
)
from .github_summary import generate_summary, write_step_summary
from .history import (
    append_result,
    baseline_collected_for_history,
    build_history_entry,
    load_history,
    save_history,
)
from .manifest import (
    ValidationManifest,
    build_manifest,
    canonical_bytes,
    compute_manifest_hash,
    deserialize_manifest,
    manifest_from_dict,
    manifest_to_dict,
    serialize_manifest,
)
from .manifest_writer import (
    load_manifest,
    write_chain_record,
    write_manifest,
    write_verification_report,
)
from .models import (
    Regression,
    RollingStats,
    RuntimeMetadata,
    RuntimeResult,
    SlowFixture,
    SlowTest,
)
from .ownership import classify_test_path, node_id_to_path
from .parser import merge_artifacts, parse_fg_fast_artifact, parse_junit_xml
from .recorder import record_gate_result
from .regression import RegressionSeverity, detect_regressions
from .serializer import from_json, to_json
from .signing import (
    Ed25519KeyProvider,
    SignatureResult,
    VerificationResult,
    generate_keypair,
    sign_manifest,
    verify_signature_bytes,
)
from .statistics import compute_rolling_stats
from .verification import (
    verify_chain,
    verify_hash,
    verify_manifest,
    verify_runtime,
    verify_signature,
)

__all__ = [
    "Ed25519KeyProvider",
    "Regression",
    "RegressionSeverity",
    "RollingStats",
    "RuntimeMetadata",
    "RuntimeResult",
    "SignatureResult",
    "SlowFixture",
    "SlowTest",
    "ValidationManifest",
    "VerificationResult",
    "append_result",
    "baseline_collected_for_history",
    "build_history_entry",
    "build_manifest",
    "canonical_bytes",
    "classify_test_path",
    "commit_fingerprint",
    "compute_manifest_hash",
    "compute_rolling_stats",
    "dependency_fingerprint",
    "deserialize_manifest",
    "detect_regressions",
    "environment_fingerprint",
    "from_json",
    "generate_keypair",
    "generate_summary",
    "load_history",
    "load_manifest",
    "manifest_fingerprint",
    "manifest_from_dict",
    "manifest_to_dict",
    "merge_artifacts",
    "node_id_to_path",
    "parse_fg_fast_artifact",
    "parse_junit_xml",
    "record_gate_result",
    "save_history",
    "selector_fingerprint",
    "serialize_manifest",
    "sign_manifest",
    "to_json",
    "verify_chain",
    "verify_hash",
    "verify_manifest",
    "verify_runtime",
    "verify_signature",
    "verify_signature_bytes",
    "write_chain_record",
    "write_manifest",
    "write_step_summary",
    "write_verification_report",
]
