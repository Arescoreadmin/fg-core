#!/usr/bin/env python3
"""Runtime Intelligence CLI — record gate results and generate summaries."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.testing.runtime_intelligence.github_summary import (  # noqa: E402
    generate_summary,
    write_step_summary,
)
from tools.testing.runtime_intelligence.history import (  # noqa: E402
    append_result,
    baseline_collected_for_history,
    load_history,
    rolling_stats_for_history,
    save_history,
)
from tools.testing.runtime_intelligence.manifest import (  # noqa: E402
    build_manifest,
    manifest_to_dict,
    serialize_manifest,
)
from tools.testing.runtime_intelligence.manifest_writer import (  # noqa: E402
    MANIFEST_DIR,
    load_manifest,
    write_manifest,
)
from tools.testing.runtime_intelligence.models import RuntimeResult  # noqa: E402
from tools.testing.runtime_intelligence.parser import (  # noqa: E402
    JUNIT_DIR,
    _FAST_DUR_PATH,
    merge_artifacts,
    parse_fg_fast_artifact,
)
from tools.testing.runtime_intelligence.recorder import record_gate_result  # noqa: E402
from tools.testing.runtime_intelligence.regression import detect_regressions  # noqa: E402
from tools.testing.runtime_intelligence.serializer import to_json  # noqa: E402, F401
from tools.testing.runtime_intelligence.signing import (  # noqa: E402
    Ed25519KeyProvider,
    sign_manifest,
)
from tools.testing.runtime_intelligence.verification import (  # noqa: E402
    verify_manifest,
    verify_runtime,
)

# Per-gate default selector expressions (mirrors Makefile PYTEST_*_FILTER values)
_GATE_SELECTORS: dict[str, str] = {
    "fg-fast": '-m "smoke or contract or security"',
    "fg-security": 'tests/security -m "not slow"',
    "fg-full": "",
    "fg-contract": "",
}

# ---------------------------------------------------------------------------
# Manifest subcommand dispatch
# ---------------------------------------------------------------------------

_MANIFEST_SUBCOMMANDS = {
    "create-manifest",
    "sign-manifest",
    "verify-manifest",
    "print-manifest",
    "export-manifest",
    "validate-chain",
    "verify-runtime",
}


def _runtime_result_from_json(text: str) -> RuntimeResult:
    """Reconstruct a :class:`RuntimeResult` from its canonical JSON form."""
    from tools.testing.runtime_intelligence.models import (  # noqa: E402
        RuntimeMetadata,
        SlowFixture,
        SlowTest,
    )

    data = json.loads(text)
    meta = RuntimeMetadata(**data["meta"])
    slowest_tests = tuple(SlowTest(**t) for t in data.get("slowest_tests", []))
    slowest_fixtures = tuple(SlowFixture(**f) for f in data.get("slowest_fixtures", []))
    return RuntimeResult(
        meta=meta,
        collected=int(data.get("collected", 0)),
        passed=int(data.get("passed", 0)),
        failed=int(data.get("failed", 0)),
        skipped=int(data.get("skipped", 0)),
        xfailed=int(data.get("xfailed", 0)),
        warnings=int(data.get("warnings", 0)),
        duration_seconds=float(data.get("duration_seconds", 0.0)),
        slowest_tests=slowest_tests,
        slowest_fixtures=slowest_fixtures,
        manifest_fingerprint=str(data.get("manifest_fingerprint", "")),
        selector_fingerprint=str(data.get("selector_fingerprint", "")),
    )


def _load_runtime_result(gate: str, runtime_dir: Path) -> RuntimeResult | None:
    """Load the canonical runtime JSON artifact for ``gate``."""
    path = runtime_dir / f"{gate.replace('/', '-')}.json"
    if not path.exists():
        return None
    return _runtime_result_from_json(path.read_text(encoding="utf-8"))


def _cmd_create_manifest(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="create-manifest")
    ap.add_argument("--gate", required=True)
    ap.add_argument("--runtime-dir", default="artifacts/ci/runtime")
    ap.add_argument("--output", default=str(MANIFEST_DIR))
    ap.add_argument("--previous-hash", default="")
    ap.add_argument(
        "--status", default="passed", choices=["passed", "failed", "skipped"]
    )
    ap.add_argument("--repository", default="")
    ap.add_argument("--branch", default="")
    ap.add_argument("--commit-sha", default="")
    ap.add_argument("--tree-sha", default="")
    ap.add_argument("--runner", default="")
    args = ap.parse_args(argv)

    runtime_dir = REPO_ROOT / args.runtime_dir
    result = _load_runtime_result(args.gate, runtime_dir)
    if result is None:
        print(
            f"[manifest] no runtime artifact for gate={args.gate} in {runtime_dir}",
            file=sys.stderr,
        )
        return 1

    manifest = build_manifest(
        result=result,
        gate=args.gate,
        validation_status=args.status,
        repository=args.repository,
        branch=args.branch,
        commit_sha=args.commit_sha,
        tree_sha=args.tree_sha,
        runner=args.runner,
        previous_manifest_hash=args.previous_hash,
    )

    # Optionally sign if a private key is present in the environment.
    provider = Ed25519KeyProvider.from_env()
    if os.environ.get(Ed25519KeyProvider.PRIVATE_KEY_ENV, "").strip():
        manifest = sign_manifest(manifest, provider)

    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    path = write_manifest(manifest, output_dir)
    print(f"[manifest] wrote {path}")
    return 0


def _cmd_sign_manifest(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="sign-manifest")
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = REPO_ROOT / manifest_path
    manifest = load_manifest(manifest_path)
    if manifest is None:
        print(f"[manifest] cannot load manifest at {manifest_path}", file=sys.stderr)
        return 1

    provider = Ed25519KeyProvider.from_env()
    if not provider.has_private_key():
        print(
            f"[manifest] {Ed25519KeyProvider.PRIVATE_KEY_ENV} must be set to sign",
            file=sys.stderr,
        )
        return 1

    signed = sign_manifest(manifest, provider)
    manifest_path.write_text(serialize_manifest(signed) + "\n", encoding="utf-8")
    print(f"[manifest] signed {manifest_path} (identity={signed.signing_identity})")
    return 0


def _cmd_verify_manifest(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="verify-manifest")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--key", default="", help="Verification public key (hex)")
    args = ap.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = REPO_ROOT / manifest_path
    manifest = load_manifest(manifest_path)
    if manifest is None:
        print(f"[manifest] cannot load manifest at {manifest_path}", file=sys.stderr)
        return 1

    public_key_hex = (
        args.key or os.environ.get(Ed25519KeyProvider.PUBLIC_KEY_ENV, "").strip()
    )

    checks = verify_manifest(manifest, public_key_hex=public_key_hex)
    report = {
        "manifest_id": manifest.manifest_id,
        "gate": manifest.gate,
        "checks": {
            name: {
                "valid": r.valid,
                "algorithm": r.algorithm,
                "reason": r.reason,
                "detail": r.detail,
            }
            for name, r in checks.items()
        },
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    # Hash mismatch is always fatal; other check failures propagate too.
    if not checks["hash"].valid:
        return 1
    return 0


def _cmd_print_manifest(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="print-manifest")
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = REPO_ROOT / manifest_path
    manifest = load_manifest(manifest_path)
    if manifest is None:
        print(f"[manifest] cannot load manifest at {manifest_path}", file=sys.stderr)
        return 1
    print(json.dumps(manifest_to_dict(manifest), sort_keys=True, indent=2))
    return 0


def _cmd_export_manifest(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="export-manifest")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = REPO_ROOT / manifest_path
    manifest = load_manifest(manifest_path)
    if manifest is None:
        print(f"[manifest] cannot load manifest at {manifest_path}", file=sys.stderr)
        return 1
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = REPO_ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(serialize_manifest(manifest) + "\n", encoding="utf-8")
    print(f"[manifest] exported {output_path}")
    return 0


def _cmd_validate_chain(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="validate-chain")
    ap.add_argument("--manifest-dir", default=str(MANIFEST_DIR))
    args = ap.parse_args(argv)

    manifest_dir = Path(args.manifest_dir)
    if not manifest_dir.is_absolute():
        manifest_dir = REPO_ROOT / manifest_dir
    if not manifest_dir.exists():
        print(f"[manifest] directory does not exist: {manifest_dir}", file=sys.stderr)
        return 1

    entries = sorted(manifest_dir.glob("*.manifest.json"))
    manifests = []
    for entry in entries:
        m = load_manifest(entry)
        if m is None:
            print(f"[manifest] skipping malformed {entry}", file=sys.stderr)
            continue
        manifests.append(m)

    # Order by (previous_manifest_hash empty first, then declared linkage)
    by_hash = {m.manifest_hash: m for m in manifests}
    chain: list = []
    seen: set[str] = set()
    # Start with roots (no previous)
    for m in manifests:
        if not m.previous_manifest_hash and m.manifest_hash not in seen:
            chain.append(m)
            seen.add(m.manifest_hash)
    # Follow links greedily until no more progress
    changed = True
    while changed:
        changed = False
        for m in manifests:
            if m.manifest_hash in seen:
                continue
            if m.previous_manifest_hash in seen:
                chain.append(m)
                seen.add(m.manifest_hash)
                changed = True

    # Anything left is dangling
    dangling = [m for m in manifests if m.manifest_hash not in seen]

    report = {
        "manifest_dir": str(manifest_dir),
        "total": len(manifests),
        "chain_length": len(chain),
        "dangling": [
            {"gate": m.gate, "manifest_hash": m.manifest_hash} for m in dangling
        ],
        "chain": [
            {
                "gate": m.gate,
                "manifest_hash": m.manifest_hash,
                "previous_manifest_hash": m.previous_manifest_hash,
            }
            for m in chain
        ],
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    _ = by_hash  # kept for potential future duplicate-detection logic
    return 0 if not dangling else 1


def _cmd_verify_runtime(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="verify-runtime")
    ap.add_argument("--gate", required=True)
    ap.add_argument("--manifest-dir", default=str(MANIFEST_DIR))
    ap.add_argument("--runtime-dir", default="artifacts/ci/runtime")
    args = ap.parse_args(argv)

    manifest_dir = Path(args.manifest_dir)
    if not manifest_dir.is_absolute():
        manifest_dir = REPO_ROOT / manifest_dir
    runtime_dir = REPO_ROOT / args.runtime_dir

    manifest_path = manifest_dir / f"{args.gate.replace('/', '-')}.manifest.json"
    manifest = load_manifest(manifest_path)
    if manifest is None:
        print(f"[manifest] cannot load manifest at {manifest_path}", file=sys.stderr)
        return 1
    result = _load_runtime_result(args.gate, runtime_dir)
    if result is None:
        print(
            f"[manifest] no runtime artifact for gate={args.gate} in {runtime_dir}",
            file=sys.stderr,
        )
        return 1
    check = verify_runtime(manifest, result)
    report = {
        "gate": args.gate,
        "manifest_id": manifest.manifest_id,
        "valid": check.valid,
        "reason": check.reason,
        "detail": check.detail,
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if check.valid else 1


_SUBCOMMAND_DISPATCH: dict[str, object] = {
    "create-manifest": _cmd_create_manifest,
    "sign-manifest": _cmd_sign_manifest,
    "verify-manifest": _cmd_verify_manifest,
    "print-manifest": _cmd_print_manifest,
    "export-manifest": _cmd_export_manifest,
    "validate-chain": _cmd_validate_chain,
    "verify-runtime": _cmd_verify_runtime,
}


def _dispatch_manifest_subcommand(name: str, argv: list[str]) -> int:
    handler = _SUBCOMMAND_DISPATCH.get(name)
    if handler is None:
        print(f"[manifest] unknown subcommand: {name}", file=sys.stderr)
        return 2
    return handler(argv)  # type: ignore[operator]


def _auto_junit(gate: str, junit_dir: Path) -> Path | None:
    """Return path to the canonical JUnit file for this gate, or None."""
    path = junit_dir / f"{gate}.xml"
    return path if path.exists() else None


def _auto_duration(gate: str) -> Path | None:
    """Return path to duration artifact if it exists."""
    if gate == "fg-fast" and _FAST_DUR_PATH.exists():
        return _FAST_DUR_PATH
    return None


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in _MANIFEST_SUBCOMMANDS:
        return _dispatch_manifest_subcommand(sys.argv[1], sys.argv[2:])
    ap = argparse.ArgumentParser(
        description="Record CI gate runtime and generate summaries"
    )
    ap.add_argument(
        "--gate",
        required=True,
        choices=["fg-fast", "fg-security", "fg-contract", "fg-full"],
    )
    ap.add_argument("--artifact-dir", default="artifacts/ci/runtime")
    ap.add_argument("--history-dir", default="artifacts/ci/runtime/history")
    ap.add_argument("--junit", help="Path to JUnit XML file (auto-detected if absent)")
    ap.add_argument(
        "--junit-dir",
        default=None,
        help="Directory containing gate JUnit files (default: artifacts/ci/junit)",
    )
    ap.add_argument(
        "--selector",
        default=None,
        help="Pytest selector expression for selector_fingerprint",
    )
    ap.add_argument(
        "--github-summary", action="store_true", help="Write GitHub step summary"
    )
    ap.add_argument(
        "--dry-run", action="store_true", help="Parse and print but don't write"
    )
    args = ap.parse_args()

    artifact_dir = REPO_ROOT / args.artifact_dir
    history_dir = REPO_ROOT / args.history_dir
    junit_dir = Path(args.junit_dir) if args.junit_dir else JUNIT_DIR

    # --- Resolve inputs ---
    junit_path: Path | None = None
    if args.junit:
        junit_path = REPO_ROOT / args.junit
    else:
        junit_path = _auto_junit(args.gate, junit_dir)

    duration_path = _auto_duration(args.gate)

    selector = (
        args.selector
        if args.selector is not None
        else _GATE_SELECTORS.get(args.gate, "")
    )

    # --- Merge all available sources into a complete RuntimeResult ---
    result: RuntimeResult | None = merge_artifacts(
        gate=args.gate,
        junit_path=junit_path,
        duration_json_path=duration_path,
        selector=selector,
    )

    # Final fallback: duration-only artifact (fg-fast only)
    if result is None and args.gate == "fg-fast":
        result = parse_fg_fast_artifact()

    if result is None:
        print(
            f"[runtime-intelligence] no artifact found for gate={args.gate}",
            file=sys.stderr,
        )
        return 0  # non-blocking — advisory only

    # --- Regression detection ---
    history_path = history_dir / f"{args.gate}-history.json"
    history = load_history(history_path)
    stats = rolling_stats_for_history(history, last_n=30)
    regressions = detect_regressions(
        gate=args.gate,
        current_duration=result.duration_seconds,
        current_collected=result.collected,
        baseline_stats=stats,
        baseline_collected=baseline_collected_for_history(history, last_n=30),
    )

    if not args.dry_run:
        # Write canonical RuntimeResult artifact
        out = record_gate_result(result, artifact_dir)
        print(f"[runtime-intelligence] wrote {out}")

        # Update rolling history with complete entry
        history_entry: dict[str, object] = {
            "duration_seconds": result.duration_seconds,
            "passed": result.passed,
            "failed": result.failed,
            "collected": result.collected,
            "skipped": result.skipped,
            "commit_sha": result.meta.commit_sha[:12],
            "gate": args.gate,
            "manifest_fingerprint": result.manifest_fingerprint,
            "selector_fingerprint": result.selector_fingerprint,
        }
        updated = append_result(history, history_entry)
        save_history(updated, history_path)
        print(f"[runtime-intelligence] history: {len(updated.runs)} runs recorded")

    # --- GitHub step summary ---
    if args.github_summary or args.dry_run or os.getenv("GITHUB_STEP_SUMMARY"):
        summary = generate_summary(
            result, stats if stats.count > 0 else None, regressions
        )
        if not args.dry_run:
            write_step_summary(summary)
        print(summary)

    # --- Advisory regression printout ---
    for reg in regressions:
        print(
            f"[runtime-intelligence] REGRESSION [{reg.severity.upper()}]: {reg.message}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
